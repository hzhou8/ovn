/*
 * Copyright (c) 2025 Canonical, Ltd.
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

#ifndef ROUTE_EXCHANGE_H
#define ROUTE_EXCHANGE_H 1

#include "openvswitch/hmap.h"

struct route_exchange_ctx_in {
    struct ovsdb_idl_txn *ovnsb_idl_txn;
    struct ovsdb_idl_index *sbrec_port_binding_by_name;
    struct ovsdb_idl_index *sbrec_learned_route_by_datapath;

    /* Contains struct advertise_datapath_entry */
    const struct hmap *announce_routes;

    /* Contains struct nexthop_entry, the kernel nexthop objects used to
     * resolve learned routes that reference their next hop through a nexthop
     * id. */
    const struct hmap *nexthops;
};

struct route_exchange_ctx_out {
    /* Populated by route_exchange_run() only, NULL otherwise. */
    struct vector *route_table_watches;
    bool sb_changes_pending;
};

/* What route_exchange knows about the kernel routing tables it syncs, kept
 * between runs so that a change to one of them can be applied without reading
 * them all again. */
struct route_exchange_state;

struct route_exchange_state *route_exchange_state_create(void);
void route_exchange_state_destroy(struct route_exchange_state *);

void route_exchange_run(struct route_exchange_state *,
                        const struct route_exchange_ctx_in *,
                        struct route_exchange_ctx_out *);

enum route_exchange_handled {
    /* The change cannot be applied to what the last route_exchange_run() left
     * behind, so it has to run again. */
    ROUTE_EXCHANGE_UNHANDLED,
    /* The change does not affect the routes OVN learned. */
    ROUTE_EXCHANGE_UNCHANGED,
    ROUTE_EXCHANGE_UPDATED,
};

/* Updates the routes OVN learned after the kernel reported the route changes
 * in 'changed_routes' ('struct ovn_route_msg *'), or after the kernel nexthop
 * objects with the ids in 'changed_nhids' (uint32_t) changed. */
enum route_exchange_handled route_exchange_handle_route_changes(
    struct route_exchange_state *, const struct route_exchange_ctx_in *,
    struct route_exchange_ctx_out *, const struct vector *changed_routes);
enum route_exchange_handled route_exchange_handle_nexthop_changes(
    struct route_exchange_state *, const struct route_exchange_ctx_in *,
    struct route_exchange_ctx_out *, const struct vector *changed_nhids);

void route_exchange_cleanup_vrfs(void);
void route_exchange_destroy(void);

int route_exchange_status_run(void);

#endif /* ROUTE_EXCHANGE_H */
