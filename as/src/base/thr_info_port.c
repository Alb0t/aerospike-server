/*
 * thr_info_port.c
 *
 * Copyright (C) 2008-2020 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/
 */

#include "base/thr_info_port.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "citrusleaf/alloc.h"

#include "cf_str.h"
#include "cf_thread.h"
#include "dynbuf.h"
#include "log.h"
#include "socket.h"

#include "base/cfg.h"
#include "base/thr_info.h"
#include "storage/storage.h"
#include "base/datamodel.h"
#include "base/cfg_info.h"
extern as_config g_config;

#define POLL_SZ 1024

// State for any open info port.
typedef struct {
	int			recv_pos;
	int			recv_alloc;
	uint8_t		*recv_buf;

	int			xmit_pos;    // where we're currently writing
	int			xmit_limit;  // the end of the write buffer
	int			xmit_alloc;
	uint8_t		*xmit_buf;

	cf_socket	sock;

} info_port_state;

cf_serv_cfg g_info_bind = { .n_cfgs = 0 };
cf_ip_port g_info_port = 0;

static cf_sockets g_sockets;

// Using int for 4-byte size, but maintaining bool semantics.
static volatile int g_started = false;

void
info_port_state_free(info_port_state *ips)
{
	if (ips->recv_buf) cf_free(ips->recv_buf);
	if (ips->xmit_buf) cf_free(ips->xmit_buf);
	cf_socket_close(&ips->sock);
	cf_socket_term(&ips->sock);
	memset(ips, -1, sizeof(info_port_state));
	cf_free(ips);
}


int
thr_info_port_readable(info_port_state *ips)
{
	int sz = cf_socket_available(&ips->sock);

	if (sz == 0) {
		return 0;
	}

	// Make sure we've got some reasonable space in the read buffer.
	if (ips->recv_alloc - ips->recv_pos < sz) {
		int new_sz = sz + ips->recv_pos + 100;
		ips->recv_buf = cf_realloc(ips->recv_buf, new_sz);
		ips->recv_alloc = new_sz;
	}

	int n = cf_socket_recv(&ips->sock, ips->recv_buf + ips->recv_pos, ips->recv_alloc - ips->recv_pos, 0);
	if (n < 0) {
		if (errno != EAGAIN) {
			cf_detail(AS_INFO_PORT, "info socket: read fail: error: rv %d sz was %d errno %d", n, ips->recv_alloc - ips->recv_pos, errno);
		}
		return -1;
	}
	ips->recv_pos += n;

	// What about a control-c?
	if (-1 != cf_str_strnchr(ips->recv_buf, ips->recv_pos, 0xFF)) {
		cf_debug(AS_INFO_PORT, "recived a control c, aborting");
		return -1;
	}

	// See if we've got a CR or LF in the buf yet.
	int cr = cf_str_strnchr(ips->recv_buf, ips->recv_pos, '\r');
	int lf = cf_str_strnchr(ips->recv_buf, ips->recv_pos, '\n');
	if ((cr >= 0) || (lf >= 0)) {
		size_t len;
		// Take the closest of cr or lf.
		if (-1 == lf) {
			len = cr;
		}
		else if (-1 == cr) {
			len = lf;
		}
		else {
			len = lf < cr ? lf : cr;
		}

		// We have a message. Process it.
		cf_dyn_buf_define(db);

		ips->recv_buf[len] = '\n';
		len++;

		// Fill out the db buffer with the response (always returns 0).
		as_info_buffer(ips->recv_buf, len, &db);
		if (db.used_sz == 0)   			cf_dyn_buf_append_char(&db, '\n');

		// See if it has a tab, get that location. It probably does.
		int tab = cf_str_strnchr(db.buf, db.used_sz , '\t');
		tab++;

		while (len < ips->recv_pos &&
				((ips->recv_buf[len] == '\r') || (ips->recv_buf[len] == '\n'))) {

			len ++ ;
		}

		// Move transmit buffer forward.
		if (ips->recv_pos - len > 0) {
			memmove(ips->recv_buf, ips->recv_buf + len, ips->recv_pos - len);
			ips->recv_pos -= len;
		}
		else {
			ips->recv_pos = 0;
		}

		// Queue the response - set to the xmit buf.
		if (ips->xmit_alloc - ips->xmit_limit < db.used_sz) {
			ips->xmit_buf = cf_realloc(ips->xmit_buf, db.used_sz + ips->xmit_limit);
			ips->xmit_alloc = db.used_sz + ips->xmit_limit;
		}
		memcpy(ips->xmit_buf + ips->xmit_limit, db.buf + tab, db.used_sz - tab);
		ips->xmit_limit += db.used_sz - tab;

		cf_dyn_buf_free(&db);
	}

	return 0;
}


int
thr_info_port_writable(info_port_state *ips)
{
	// Do we have bytes to write?
	if (ips->xmit_limit > 0) {

		// Write them!
		int rv = cf_socket_send(&ips->sock, ips->xmit_buf + ips->xmit_pos, ips->xmit_limit - ips->xmit_pos , MSG_NOSIGNAL);
		if (rv < 0) {
			if (errno != EAGAIN) {
				return -1;
			}
		}
		else if (rv == 0) {
			cf_debug(AS_INFO_PORT, "send with return value 0");
			return 0;
		}
		else {
			ips->xmit_pos += rv;
			if (ips->xmit_pos == ips->xmit_limit) {
				ips->xmit_pos = ips->xmit_limit = 0;
			}
		}
	}

	return 0;
}


// Demarshal info socket connections.
void *
run_defrag_tuner(void *arg)
{
	cf_info(AS_INFO, "defrag tuner started");
  	// TODO: Add flag to allow user to stop this loop
  	// run indefinitely
	while (42 == 42) {

        sleep(1);
        // loop through each namespace
        cf_dyn_buf db;
        cf_dyn_buf_init_heap(&db, 128);
		char *cmd = (char*)malloc(128 * sizeof(char));

		// goal: change exactly 1 config parameter per namespace to get defrag in better shape.
		// asinfo command is executed at the bottom
		for (uint32_t ns_ix = 0; ns_ix < g_config.n_namespaces; ns_ix++) {
			uint32_t avail_pct;
			struct as_namespace_s *ns = g_config.namespaces[ns_ix];
			// fetch current avail_pct from as_storage_stats
            as_storage_stats(ns, &avail_pct, NULL);
            uint32_t current_lwm = ns->storage_defrag_lwm_pct;
            uint32_t current_defrag_sleep = ns->storage_defrag_sleep;

            // log example: "ns_ix 0 avail pct is 3 for test with lwm-pct 16"
			cf_info(AS_INFO,
                    "ns_ix: %d, avail_pct: %d,ns->name: %s, lwm-pct: %d, current_defrag_sleep: %d",
                    ns_ix,
                    avail_pct,
                    ns->name,
                    current_lwm,
                    current_defrag_sleep
                    );

            // add a ticker to output the defrag/write-q as observed from this function
            uint32_t defrag_q_sz_total = 0;
            uint32_t write_q_sz_total = 0;

            for (uint32_t storage_ix = 0; storage_ix < g_config.namespaces[ns_ix]->n_storage_files; storage_ix++) {
              	storage_device_stats stats;
				as_storage_device_stats(ns, storage_ix, &stats);
                cf_info(AS_INFO, "defrag_q_sz=%u", stats.defrag_q_sz);
                defrag_q_sz_total += stats.defrag_q_sz;
                write_q_sz_total += stats.write_q_sz;
            }
            cf_info(AS_INFO,"total defrag-q-sz: %u, write-q total sz: %u", defrag_q_sz_total, write_q_sz_total);
			//	uint32_t write_q_sz;

            // TODO: can this be percent based? I dont like hard coded numbers here.
			bool io_limited = write_q_sz_total > 100;
            bool defrag_piled_up = defrag_q_sz_total > 100;
            // TODO: move these static values
            bool below_avail_threshold = avail_pct < 20;
            bool above_avail_threshold = avail_pct > 30;

            bool above_defrag_sleep_threshold = current_defrag_sleep > 100000;
            bool below_defrag_sleep_target = current_defrag_sleep < 100;

            bool above_defrag_lwm_limit = current_lwm > 50;
            bool below_defrag_lwm_limit = current_lwm < 5;


            // debug stats
     		cf_info(AS_INFO, "io_limited: %u, defrag_piled_up: %u, below_avail_threshold: %u, above_avail_threshold: %u", io_limited, defrag_piled_up, below_avail_threshold, above_avail_threshold );


			// should be a happy medium here between above/below.
//            if (
//                    !below_avail_threshold &&
//                    !above_avail_threshold &&
//
//                    ){
//            	cf_info(AS_INFO, "We are happy with the current LWM tuning.");
//				break;
//            }

            // We need more avail, so we want to increase LWM.. but need to worry about causing an IO issue.
            // if defrag_q is already full, increasing LWM will just make it worse.
            if (below_avail_threshold) {
              	// dont do anything if our drives are choked.
    			if (io_limited){
        			cf_info(AS_INFO, "Want to increase LWM, but IO is limited (write-q full)... aborting");
       				break;
 				}
                // if defrag_q is piled up, try to decrease defrag-sleep
                if (defrag_piled_up){
                  	if (below_defrag_sleep_target){
                    	cf_info(AS_INFO, "defrag_q is piled up, but we're already running a really low defrag-sleep: %u.. aborting", current_defrag_sleep);
                    	break;
                  	}
                  	uint32_t new_val = (current_defrag_sleep * 80) / 100;
                	cf_info(AS_INFO, "defrag_q is piled up. Decreasing defrag-sleep by 20pct from %u to %u", current_defrag_sleep, new_val);
		 			snprintf(cmd, 128, "context=namespace;id=%s;defrag-sleep=%u", ns->name, new_val);
                                                    as_cfg_info_cmd_config_set(NULL, cmd, &db); //forgive me

                    break;
                }
                // if defrag_q isn't piled up, lets see if we can increase the lwm
                if (!defrag_piled_up){
                	if (above_defrag_lwm_limit){
                  		cf_info(AS_INFO, "want to increase lwm, but we're at the limits of the autotuner safety limit.. aborting");
                        break;
					}
					uint32_t new_val = current_lwm + 1;
            		cf_info(AS_INFO, "Increasing LWM from %u to %u", current_lwm, new_val );
		 			snprintf(cmd, 128, "context=namespace;id=%s;defrag-lwm-pct=%u", ns->name, new_val);
                                                    as_cfg_info_cmd_config_set(NULL, cmd, &db); //forgive me

                    break;
    			}
            }
            // instead of reinventing the wheel, just call asinfo commands. How gross is that?
         	// TODO: should this avoid defrag sweep? May be worth conditionally triggering defrag-sweep. The operation seems cheap enough, but I'm jaded

            // we have lots of wiggle room, lets relax defrag
            if (above_avail_threshold){
              	// decrease LWM until we hit target.
              	if (!below_defrag_lwm_limit){
                	uint32_t new_val = current_lwm - 1;
            		cf_info(AS_INFO, "Decreasing LWM from %u to %u", current_lwm, new_val );
		 			snprintf(cmd, 128, "context=namespace;id=%s;defrag-lwm-pct=%u", ns->name, new_val);
                    as_cfg_info_cmd_config_set(NULL, cmd, &db); //forgive me
                    // break; // actually lets mess with defrag-sleep too in same loop
              	}
                // if LWM is already dialed in, we need to try tuning defrag-sleep next.
				if (!above_defrag_sleep_threshold){
                    uint32_t new_val = (current_defrag_sleep * 120) / 100;
		 			snprintf(cmd, 128, "context=namespace;id=%s;defrag-sleep=%u", ns->name, new_val);
					cf_info(AS_INFO, "increasing defrag-sleep by 20-pct from %u to %u", current_defrag_sleep, new_val);
                    as_cfg_info_cmd_config_set(NULL, cmd, &db); //forgive me

				}
                break;
            }
        }
        free(cmd); // i think i need to do this.. im no programmer though.
	}
}

// Demarshal info socket connections.
void *
run_info_port(void *arg)
{
	cf_poll poll;
	cf_debug(AS_INFO_PORT, "Info port process started");

	// Start the listener socket. Note that because this is done after privilege
	// de-escalation, we can't use privileged ports.

	if (cf_socket_init_server(&g_info_bind, &g_sockets) < 0) {
		cf_crash(AS_INFO_PORT, "Couldn't initialize service sockets");
	}

	cf_poll_create(&poll);
	cf_poll_add_sockets(poll, &g_sockets, EPOLLIN | EPOLLERR | EPOLLHUP);
	cf_socket_show_server(AS_INFO_PORT, "info", &g_sockets);

	g_started = true;

	while (true) {
		cf_poll_event events[POLL_SZ];
		int32_t n_ev = cf_poll_wait(poll, events, POLL_SZ, -1);

		for (int32_t i = 0; i < n_ev; ++i) {
			cf_socket *ssock = events[i].data;

			if (cf_sockets_has_socket(&g_sockets, ssock)) {
				cf_socket csock;
				cf_sock_addr addr;

				if (cf_socket_accept(ssock, &csock, &addr) < 0) {
					// This means we're out of file descriptors.
					if (errno == EMFILE) {
						cf_warning(AS_INFO_PORT, "Too many file descriptors in use, consider raising limit");
						continue;
					}

					cf_crash(AS_INFO_PORT, "cf_socket_accept() failed");
				}

				cf_detail(AS_INFO_PORT, "New connection: %s", cf_sock_addr_print(&addr));
				info_port_state *ips = cf_malloc(sizeof(info_port_state));

				ips->recv_pos = 0;
				ips->recv_alloc = 100;
				ips->recv_buf = cf_malloc(100);
				ips->xmit_limit = ips->xmit_pos = 0;
				ips->xmit_alloc = 100;
				ips->xmit_buf = cf_malloc(100);
				cf_socket_copy(&csock, &ips->sock);

				cf_poll_add_socket(poll, &csock, EPOLLIN | EPOLLOUT | EPOLLET | EPOLLRDHUP, ips);
			}
			else {
				info_port_state *ips = events[i].data;

				if (ips == NULL) {
					cf_crash(AS_INFO_PORT, "Event with null handle");
				}

				cf_detail(AS_INFO_PORT, "Events %x on FD %d", events[i].events, CSFD(&ips->sock));

				if (events[i].events & (EPOLLRDHUP | EPOLLERR | EPOLLHUP)) {
					cf_detail(AS_INFO_PORT, "Remote close on FD %d", CSFD(&ips->sock));
					cf_poll_delete_socket(poll, &ips->sock);
					info_port_state_free(ips);
					continue;
				}

				if ((events[i].events & EPOLLIN) != 0 && thr_info_port_readable(ips) < 0) {
					cf_poll_delete_socket(poll, &ips->sock);
					info_port_state_free(ips);
					continue;
				}

				if ((events[i].events & EPOLLOUT) != 0 && thr_info_port_writable(ips) < 0) {
					cf_poll_delete_socket(poll, &ips->sock);
					info_port_state_free(ips);
					continue;
				}
			}
		}
	}

	return NULL;
}


void
as_info_port_start()
{
	if (g_info_port == 0) {
		return;
	}

	cf_info(AS_INFO_PORT, "starting info port thread");

	cf_thread_create_detached(run_info_port, NULL);

	// For orderly startup log, wait for endpoint setup.
	while (! g_started) {
		usleep(1000);
	}
}


void
as_defrag_tuner_start()
{
	cf_info(AS_INFO, "starting defrag tuner");
	cf_thread_create_detached(run_defrag_tuner, NULL);
}