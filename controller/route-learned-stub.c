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

#include <config.h>

#include "openvswitch/compiler.h"
#include "route-learned.h"

void
route_learned_sync(const struct vector *learned_routes OVS_UNUSED,
                   const struct sbrec_datapath_binding *datapath OVS_UNUSED,
                   const struct smap *bound_ports OVS_UNUSED,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name OVS_UNUSED)
{
}

void
route_learned_mark_all_stale(void)
{
}

void
route_learned_remove_stale(void)
{
}

void
route_learned_of_run(struct ovn_desired_flow_table *flow_table OVS_UNUSED,
                     struct ovn_extend_table *group_table OVS_UNUSED,
                     bool reinstall_all OVS_UNUSED)
{
}

void
route_learned_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *data OVS_UNUSED)
{
    unixctl_command_reply(conn, "");
}

void
route_learned_destroy(void)
{
}
