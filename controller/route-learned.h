/*
 * Copyright (c) 2025, Canonical, Ltd.
 * Copyright (c) 2025, STACKIT GmbH & Co. KG
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

#ifndef ROUTE_LEARNED_H
#define ROUTE_LEARNED_H 1

#include "openvswitch/hmap.h"
#include "openvswitch/uuid.h"
#include "ovsdb-idl.h"
#include "ofctrl.h"
#include "ovn-sb-idl.h"
#include "unixctl.h"

struct vector;

struct ovsdb_idl_index;
struct re_nl_received_route_node;

void route_learned_sync(const struct vector *learned_routes,
                        const struct sbrec_datapath_binding *datapath,
                        const struct smap *bound_ports,
                        struct ovsdb_idl_index *sbrec_port_binding_by_name);

/* Mark every in-memory learned route stale.  Call before a sync pass, then
 * call route_learned_remove_stale() after so datapaths that left
 * dynamic-routing lose their routes. */
void route_learned_mark_all_stale(void);
void route_learned_remove_stale(void);

/* If reinstall_all is true, (re)install flows for every group into a
 * freshly cleared desired flow table.  Otherwise only update groups marked
 * dirty since the last of_run. */
void route_learned_of_run(struct ovn_desired_flow_table *flow_table,
                          struct ovn_extend_table *group_table,
                          bool reinstall_all);

void route_learned_list(struct unixctl_conn *conn, int argc,
                        const char *argv[], void *data OVS_UNUSED);

void route_learned_destroy(void);

#endif /* ROUTE_LEARNED_H */
