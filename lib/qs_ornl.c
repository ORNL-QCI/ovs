/*
 * Copyright (C) 2016 Ronald Sadlier - Oak Ridge National Laboratory
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#include "qs_ornl.h"
#include "dp-packet.h"
#include "include/openvswitch/vlog.h"
#include <pthread.h>
#include <zmq.h>

OFP_ASSERT(0 < QS_ORNL_CNF_ZMQ_EC && QS_ORNL_CNF_ZMQ_EC < 3);
OFP_ASSERT(QS_ORNL_QS_INIT_CAP > 0);
OFP_ASSERT(QS_ORNL_QS_CAP_GROW > 0);

VLOG_DEFINE_THIS_MODULE(qs_ornl);

const struct qs_net_msg *get_qs_net_msg(const struct dp_packet *packet) {
    const struct tcp_header *th = dp_packet_l4(packet);
    const char *tp = (const char*)dp_packet_get_tcp_payload(packet);
    if(th == NULL || tp == NULL) goto mal_packet;
    
    size_t tp_len = dp_packet_l4_size(packet) - TCP_OFFSET(th->tcp_ctl)*4;
    if(tp_len != sizeof(struct qs_net_msg)) goto mal_packet;
    
    /* Since all members are 1 byte, no need for ntohs */
    return (const struct qs_net_msg*)tp;
    
 mal_packet:
    return NULL;
}

struct qscon_t {
    void *socket;                   /* Holds the zmq socket to the endpoint */
    pthread_mutex_t mutex;          /* Protector of socket operations */
    char ep[32];                    /**/
    
    /* In the future, if we allow multiple connections to the same endpoint, we will have
     * to rewrite this into a more robust cache system. */
    bool cachable;                  /* Whether or not we can take for granted that the
                                     * quantum switch configuration will not change from
                                     * another source. In other words, if we can assume
                                     * the last configuration sent is still how the switch
                                     * is configured at some later time. This allows us
                                     * to skip communication with the quantum switch if
                                     * requesting the same configuration. */
    uint16_t in_port;               /* Last input port configured */
    uint16_t out_port;              /* Last output port configured */

};

/* Holds the zmq context for all sockets and is threadsafe */
void *qscon_zmq_ctx = NULL;

struct qscon_array_t {
    struct qscon_t **array;
    uint16_t capacity;
    uint16_t size;
    pthread_mutex_t mutex; /* Protector when adding, resizing, etc. */
} qscon_array = { .array=NULL, .capacity=0, .size=0 };

/* The following should only be called from threads holding a lock on the qscon_array mutex */
uint16_t _initialize_qscon_t(const char* const ep);
void _terminate_qscon_t(struct qscon_t *c);
void _grow_qscon_array(void);

/* The following should not be called from threads holding a lock on the qscon_array mutex */
void __initialize_qscon_array(void);
void __terminate_qscon_array(void);

void initialize_qs_ornl() {
    int zmajor, zminor, zpatch;
    
    VLOG_INFO("Initializing");
    
    zmq_version(&zmajor, &zminor, &zpatch);
    VLOG_INFO("Found 0MQ library version %d.%d.%d", zmajor, zminor, zpatch);
    
    qscon_zmq_ctx = zmq_ctx_new();
    
    if(!qscon_zmq_ctx) {
        VLOG_ABORT("0MQ context initialization failed with code: %i; %s",
                   errno,
                   zmq_strerror(errno));
    }
    
    __initialize_qscon_array();
}

void terminate_qs_ornl() {
    int rc;
    
    VLOG_INFO("Terminating");
    
    __terminate_qscon_array();
    
    #ifdef QS_ORNL_STATE_EC
    /* Only happens on programming error */
    if(!qscon_zmq_ctx) {
        VLOG_ABORT("Unexpected zmq context state.");
    }
    #endif
    
    /* This "will cause any blocking operations currently in progress on sockets open
     * within context to return immediately with an error code of ETERM." */
    rc = zmq_ctx_shutdown(qscon_zmq_ctx);
    if(rc) {
        VLOG_ERR("0MQ context shutdown failed with code: %i; %s",
                 errno,
                 zmq_strerror(errno));
        errno = 0;
    }
    
    rc = zmq_ctx_term(qscon_zmq_ctx);
    if(rc) {
        VLOG_ERR("0MQ context termination failed with code: %i; %s",
                 errno,
                 zmq_strerror(errno));
        errno = 0;
    }
    qscon_zmq_ctx = NULL;
}

bool configure_qs(uint16_t id, uint16_t in_port, uint16_t out_port) {
    int rc;
    struct qscon_t *c;
    zmq_msg_t rmsg;
    
    /* TODO:we need a lock on this */
    c = qscon_array.array[id];
    rc = pthread_mutex_lock(&c->mutex);
    
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
    
    if(c->cachable && c->in_port == in_port && c->out_port == out_port) {
        /*VLOG_DBG("Cache hit for socket id %u, skipping configuration request.", id);*/
        goto success;
    }
    
    /* Having the string preallocated for the maximum size port lengths saves us from
     * doing fancy string manipulation and allows us to store it on the stack. However,
     * per javascript spec, a number leading with 0 is in octal form and since JSON just
     * outright banned leading 0s, we must have spaces not zeros, e.g. we have to use
     * '    1' instead of '00001'
     */
    char msg[67] = "{\"method\":\"configure\",\"parameters\":[     ,     ],\"action\":\"push\"}";
    sprintf(&msg[36], "%*d", 5, in_port);
    sprintf(&msg[42], "%*d", 5, out_port);
    /* Replace null-terminators added with sprintf() */
    msg[41] = ',';
    msg[47] = ']';
    
    /* Zero copy until it goes on the wire, valid since we block waiting for a reply */
    rc = zmq_send_const(c->socket, msg, sizeof(msg), 0);
    if(rc < 0) {
        VLOG_ABORT("0MQ send failed with: %i; %s",
                   errno,
                   zmq_strerror(errno));
        goto error;
    }
    
    rc = zmq_msg_init(&rmsg);
    #if QS_ORNL_CNF_ZMQ_EC >= 2
    if(rc) {
        VLOG_ERR("0MQ message initialize failed with: %i; %s",
                 errno,
                 zmq_strerror(errno));
        goto error;
    }
    #endif
    
    rc = zmq_msg_recv(&rmsg, c->socket, 0);
    if(rc < 0) {
        VLOG_ERR("0MQ receive failed with: %i; %s",
                 errno,
                 zmq_strerror(errno));
        /* Ignore rc on this */
        rc = zmq_msg_close(&rmsg);
        goto error;
    }
    
    // todo: analyze return message
    c->in_port = in_port;
    c->out_port = out_port;
    
    rc = zmq_msg_close(&rmsg);
    #if QS_ORNL_CNF_ZMQ_EC >= 2
    if(rc) {
        VLOG_ERR("0MQ message close failed with: %i; %s",
                 errno,
                 zmq_strerror(errno));
        goto error;
    }
    #endif
    
success:
    rc = pthread_mutex_unlock(&c->mutex);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
    
    return true;

error:
    rc = pthread_mutex_unlock(&c->mutex);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
 
    return false;
}

uint16_t decode_endp_str(const char* const ep) {
    int rc;
    uint16_t id;
    
    id = 0;
    rc = pthread_mutex_lock(&qscon_array.mutex);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
    
    while(id < qscon_array.size) {
        if(strcmp(qscon_array.array[id]->ep, ep) == 0) {
            goto ret_id;
        }
        id++;
    }
    
    id = _initialize_qscon_t(ep);
    
ret_id:
    rc = pthread_mutex_unlock(&qscon_array.mutex);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
    
    return id;
}

uint16_t _initialize_qscon_t(const char* const ep) {
    struct qscon_t *c;
    size_t eplen;
    int rc;
    uint16_t id;
    
    VLOG_DBG("Adding quantum switch connection with endpoint: %s", ep);
    
    eplen = strlen(ep) + 1;
    c = malloc(sizeof(struct qscon_t));
    
    if(!c) {
        VLOG_ABORT("Malloc() returned NULL.");
    }
    
    /* This should be caught before we get to this point, but this avoids fires */
    if(eplen > sizeof(c->ep)) {
        VLOG_ABORT("Tried to put string of length %lu into container of length %lu",
                   eplen,
                   sizeof(c->ep));
    }
    
    memcpy(c->ep, ep, eplen);
    
    c->socket = zmq_socket(qscon_zmq_ctx, ZMQ_PAIR);
    if(!c->socket) {
        VLOG_ABORT("0MQ socket creation failed with: %i; %s",
                   errno,
                   zmq_strerror(errno));
    }
    rc = zmq_connect(c->socket, c->ep);
    if(rc) {
        VLOG_ABORT("0MQ socket connection failed with: %i; %s",
                   errno,
                   zmq_strerror(errno));
    }
    
    c->cachable = true;
    c->in_port = 0;
    c->out_port = 0;
    
    rc = pthread_mutex_init(&c->mutex, NULL);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
    
    /* We already have a lock on the qscon_array mutex */
    if(qscon_array.size == qscon_array.capacity) {
        /* Reallocation */
       _grow_qscon_array();
    }
    
    id = qscon_array.size++;
    qscon_array.array[id] = c;
    
    return id;
}

void _terminate_qscon_t(struct qscon_t *c) {
    int rc;
    
    rc = zmq_close(c->socket);
    if(rc) {
        VLOG_ERR("0MQ socket termination failed with: %i; %s",
                 errno,
                 zmq_strerror(errno));
        errno = 0;
    }
    
    rc = pthread_mutex_destroy(&c->mutex);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
}

void __initialize_qscon_array() {
    int rc;
    
    #ifdef QS_ORNL_STATE_EC
    /* Only happens on programming error */
    if(qscon_array.array || qscon_array.size || qscon_array.capacity) {
        VLOG_ABORT("Unexpected array state.");
    }
    #endif
    
    VLOG_DBG("Initialize qscon array with capacity %u", QS_ORNL_QS_INIT_CAP);
    qscon_array.capacity = QS_ORNL_QS_INIT_CAP;
    qscon_array.array = malloc(sizeof(*qscon_array.array)*qscon_array.capacity);
    
    if(!qscon_array.array) {
        VLOG_ABORT("Malloc() returned NULL.");
    }
    
    rc = pthread_mutex_init(&qscon_array.mutex, NULL);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
}

void _grow_qscon_array() {
    struct qscon_t **temp;
    
    #ifdef QS_ORNL_STATE_EC
    /* Only happens on programming error */
    if(!qscon_array.array || qscon_array.capacity) {
        VLOG_ABORT("Unexpected array state.");
    }
    #endif
    
    qscon_array.capacity += QS_ORNL_QS_CAP_GROW;
    VLOG_DBG("Increasing qscon array capacity to %u", qscon_array.capacity);
    
    temp = malloc(sizeof(*qscon_array.array)*qscon_array.capacity);
    
    if(!temp) {
        VLOG_ABORT("Malloc() returned NULL.");
    }
    
    memcpy(temp, &temp[qscon_array.size-1], sizeof(temp[0])*qscon_array.size);
    free(qscon_array.array);
    qscon_array.array = temp;
}

void __terminate_qscon_array() {
    int rc;
    
    #ifdef QS_ORNL_STATE_EC
    /* Only happens on programming error */
    if(!qscon_array.array || !qscon_array.capacity) {
        VLOG_ABORT("Unexpected array state.");
    }
    #endif
    
    for(uint16_t i = 0; i < qscon_array.size; i++) {
        _terminate_qscon_t(qscon_array.array[i]);
    }
    
    free(qscon_array.array);
    qscon_array.array = NULL;
    qscon_array.size = 0;
    qscon_array.capacity = 0;
    
    rc = pthread_mutex_destroy(&qscon_array.mutex);
    #ifdef QS_ORNL_MUTEX_EC
    if(rc) {
        VLOG_ABORT("Mutex operation failed.");
    }
    #endif
}