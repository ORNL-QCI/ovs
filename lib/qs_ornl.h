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

#ifndef OFPROTO_QS_ORNL_H
#define OFPROTO_QS_ORNL_H 1

#include <stdbool.h>
#include <stdint.h>

/* Error check unexpected states from programming errors */
//#define QS_ORNL_STATE_EC 1
/* Error check return values of mutex operations */
//#define QS_ORNL_MUTEX_EC 1
/* 1: check send,recv, 2: check everything */
#define QS_ORNL_CNF_ZMQ_EC 1
/* Initialize number of elements */
#define QS_ORNL_QS_INIT_CAP 4
/* elements to add each reallocation */
#define QS_ORNL_QS_CAP_GROW 4

struct dp_packet;




#define QS_NET_ACTION_SYN 1
#define QS_NET_ACTION_ACT 2

struct qs_net_msg {
    uint8_t proto_ver;
    uint8_t action;
    uint8_t flags; // TODO: move this first
    uint8_t _reserved1;
};




/* Return a quantum communication handshake struct given a raw packet from the wire. If
 * the raw packet does not appear to contain a valid handshake, or if there are any other
 * problems, returns NULL. */
const struct qs_net_msg *get_qs_net_msg(const struct dp_packet *packet);





/* Creates storage containers for future quantum switch connections. This should only be
 * called from the beginning of the  main() function for the daemon. The calling thread
 * should not hold any mutexes from this module. Calls to any other function in the module
 * will not be successful before this is executed. */
void initialize_qs_ornl(void);

/* Close any connections that are open and free any memory we have allocated. This should
 * only be called at the end of the main() function for the daemon. The calling thread
 * should not hold any mutexes from this module. */
void terminate_qs_ornl(void);

/* This is called within an action that wants to configure a quantum switch. This function
 * requires a numerical id that was previously returned by decode_endp_str(), as well
 * as the input port and output port.
 * 
 * This function may or may not contact the quantum switch, but it does guarentee that the
 * quantums witch is in the request state. It may cache the last connection for the
 * quantum switch, depending on if the request process has a lot of overhead and if the
 * quantum switch supports us caching.
 */
bool configure_qs(uint16_t id, uint16_t in_port, uint16_t out_port);

/* When a new action is accepted it contains an endpoint. This endpoint may or may not be
 * shared with other actions. While we could create one socket per action, this requires
 * heavy multithreading on the part of the receiver and it doesn't necessarily get rid of
 * the mutex requirement (depending on how the flow match is constructed). While we still
 * store the original endpoint string with each action, we store the socket, mutex, and
 * other information here behind a numerical label. In this setup, one classical switch
 * may contain many flows that reference the same endpoint. Only one socket is used.
 * 
 * 
 * It may be possible, and required in the future, to create some logic that allows more
 * than one socket per endpoint to share the load evenly. */
uint16_t decode_endp_str(const char* const str);

#endif