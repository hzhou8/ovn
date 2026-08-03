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

#include <config.h>

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>

#include "hmapx.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/vlog.h"
#include "openvswitch/list.h"

#include "binding.h"
#include "route.h"
#include "route-exchange.h"
#include "route-exchange-netlink.h"
#include "route-learned.h"
#include "vec.h"

VLOG_DEFINE_THIS_MODULE(route_exchange);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

struct maintained_route_table_entry {
    struct hmap_node node;
    uint32_t table_id;
};

static struct hmap _maintained_route_tables =
    HMAP_INITIALIZER(&_maintained_route_tables);
static struct sset _maintained_vrfs = SSET_INITIALIZER(&_maintained_vrfs);

static uint32_t
maintained_route_table_hash(uint32_t table_id)
{
    return hash_int(table_id, 0);
}

static bool
maintained_route_table_contains(uint32_t table_id)
{
    uint32_t hash = maintained_route_table_hash(table_id);
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_WITH_HASH (mrt, node, hash,
                             &_maintained_route_tables) {
        if (mrt->table_id == table_id) {
            return true;
        }
    }
    return false;
}

static void
maintained_route_table_add(uint32_t table_id)
{
    if (maintained_route_table_contains(table_id)) {
        return;
    }
    uint32_t hash = maintained_route_table_hash(table_id);
    struct maintained_route_table_entry *mrt = xmalloc(sizeof *mrt);
    mrt->table_id = table_id;
    hmap_insert(&_maintained_route_tables, &mrt->node, hash);
}

/* Last route_exchange netlink operation. */
static int route_exchange_nl_status;

#define CLEAR_ROUTE_EXCHANGE_NL_STATUS() \
    do {                                 \
        route_exchange_nl_status = 0;    \
    } while (0)

#define SET_ROUTE_EXCHANGE_NL_STATUS(error)     \
    do {                                        \
        if (!route_exchange_nl_status) {        \
            route_exchange_nl_status = (error); \
            if (error) {                        \
                poll_immediate_wake();          \
            }                                   \
        }                                       \
    } while (0)

struct advertised_routes_entry {
    struct hmap_node node;

    struct hmapx datapaths;
    const struct hmap *routes;
    uint32_t table_id;
    bool can_sync;
};

void
route_exchange_run(const struct route_exchange_ctx_in *r_ctx_in,
                   struct route_exchange_ctx_out *r_ctx_out)
{
    struct hmap advertised_routes = HMAP_INITIALIZER(&advertised_routes);
    struct sset old_maintained_vrfs = SSET_INITIALIZER(&old_maintained_vrfs);
    sset_swap(&_maintained_vrfs, &old_maintained_vrfs);
    struct hmap old_maintained_route_table =
        HMAP_INITIALIZER(&old_maintained_route_table);
    hmap_swap(&_maintained_route_tables, &old_maintained_route_table);
    int error;

    CLEAR_ROUTE_EXCHANGE_NL_STATUS();
    route_learned_mark_all_stale();
    const struct advertise_datapath_entry *ad;
    HMAP_FOR_EACH (ad, node, r_ctx_in->announce_routes) {
        uint32_t table_id = route_get_table_id(ad->db);
        if (!TABLE_ID_VALID(table_id)) {
            VLOG_WARN_RL(&rl, "Unable to sync routes for datapath "UUID_FMT": "
                         "invalid table id: %"PRIu32,
                         UUID_ARGS(&ad->db->header_.uuid), table_id);
            continue;
        }

        if (ad->maintain_vrf) {
            if (!sset_contains(&old_maintained_vrfs, ad->vrf_name)) {
                error = re_nl_create_vrf(ad->vrf_name, table_id);
                if (error && error != EEXIST) {
                    VLOG_WARN_RL(&rl,
                                 "Unable to create VRF %s for datapath "
                                 UUID_FMT": %s.", ad->vrf_name,
                                 UUID_ARGS(&ad->db->header_.uuid),
                                 ovs_strerror(error));
                    SET_ROUTE_EXCHANGE_NL_STATUS(error);
                    continue;
                }
            }
            sset_add(&_maintained_vrfs, ad->vrf_name);
        } else {
            /* A previous maintain-vrf flag was removed. We should therefore
             * also not delete it even if we created it previously. */
            sset_find_and_delete(&_maintained_vrfs, ad->vrf_name);
            sset_find_and_delete(&old_maintained_vrfs, ad->vrf_name);
        }

        struct advertised_routes_entry *entry = NULL;
        uint32_t hash = maintained_route_table_hash(table_id);
        HMAP_FOR_EACH_WITH_HASH (entry, node, hash, &advertised_routes) {
            if (entry->table_id == table_id) {
                if (!hmap_is_empty(&ad->routes)) {
                    if (entry->routes && !hmap_is_empty(entry->routes)) {
                        VLOG_WARN_RL(&rl,
                                     "Multiple datapaths are distributing "
                                     "routes on routing table %"PRIu32,
                                     table_id);
                        entry->can_sync = false;
                    } else {
                        entry->routes = &ad->routes;
                    }
                }
                break;
            }
        }

        if (entry == NULL) {
            entry = xmalloc(sizeof *entry);
            *entry = (struct advertised_routes_entry) {
                .datapaths = HMAPX_INITIALIZER(&entry->datapaths),
                .routes = &ad->routes,
                .table_id = table_id,
                .can_sync = true,
            };
            hmap_insert(&advertised_routes, &entry->node, hash);
        }

        if (!entry->can_sync) {
            continue;
        }

        hmapx_add(&entry->datapaths, CONST_CAST(void *, ad->db));
    }

    struct advertised_routes_entry *arte;
    HMAP_FOR_EACH_POP (arte, node, &advertised_routes) {
        maintained_route_table_add(arte->table_id);
        if (arte->can_sync) {
            struct vector received_routes =
                VECTOR_EMPTY_INITIALIZER(struct re_nl_received_route_node);
            error = re_nl_sync_routes(arte->table_id, arte->routes,
                                      &received_routes);
            SET_ROUTE_EXCHANGE_NL_STATUS(error);

            struct hmapx_node *dp_node;
            HMAPX_FOR_EACH (dp_node, &arte->datapaths) {
                const struct sbrec_datapath_binding *db = dp_node->data;
                struct advertise_datapath_entry *adpe =
                    advertise_datapath_find(r_ctx_in->announce_routes,
                                            db);
                if (!adpe) {
                    VLOG_WARN_RL(&rl, "Cannot sync datapath binding "
                                 UUID_FMT", bound ports not found",
                                 UUID_ARGS(&db->header_.uuid));
                    continue;
                }
                route_learned_sync(&received_routes, db,
                                   &adpe->bound_ports,
                                   r_ctx_in->sbrec_port_binding_by_name);
            }
            vector_push(r_ctx_out->route_table_watches, &arte->table_id);
            vector_destroy(&received_routes);
        }

        hmapx_destroy(&arte->datapaths);
        free(arte);
    }

    /* Remove routes in tables previously maintained by us. */
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_POP (mrt, node, &old_maintained_route_table) {
        if (!maintained_route_table_contains(mrt->table_id)) {
            error = re_nl_cleanup_routes(mrt->table_id);
            if (error) {
                /* If netlink transaction fails, we will retry next time. */
                maintained_route_table_add(mrt->table_id);
                SET_ROUTE_EXCHANGE_NL_STATUS(error);
            }
        }
        free(mrt);
    }
    hmap_destroy(&old_maintained_route_table);

    /* Remove VRFs previously maintained by us not found in the above loop. */
    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &old_maintained_vrfs) {
        if (!sset_contains(&_maintained_vrfs, vrf_name)) {
            error = re_nl_delete_vrf(vrf_name);
            if (error && error != ENODEV) {
                /* If netlink transaction fails, we will retry next time. */
                sset_add(&_maintained_vrfs, vrf_name);
                SET_ROUTE_EXCHANGE_NL_STATUS(error);
            }
        }
        sset_delete(&old_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }
    sset_destroy(&old_maintained_vrfs);
    hmap_destroy(&advertised_routes);
    route_learned_remove_stale();
}

void
route_exchange_cleanup_vrfs(void)
{
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH (mrt, node, &_maintained_route_tables) {
        re_nl_cleanup_routes(mrt->table_id);
    }

    const char *vrf_name;
    SSET_FOR_EACH (vrf_name, &_maintained_vrfs) {
        re_nl_delete_vrf(vrf_name);
    }
}

void
route_exchange_destroy(void)
{
    struct maintained_route_table_entry *mrt;
    HMAP_FOR_EACH_POP (mrt, node, &_maintained_route_tables) {
        free(mrt);
    }

    const char *vrf_name;
    SSET_FOR_EACH_SAFE (vrf_name, &_maintained_vrfs) {
        sset_delete(&_maintained_vrfs, SSET_NODE_FROM_NAME(vrf_name));
    }

    sset_destroy(&_maintained_vrfs);
    hmap_destroy(&_maintained_route_tables);
}

int
route_exchange_status_run(void)
{
    return route_exchange_nl_status;
}
