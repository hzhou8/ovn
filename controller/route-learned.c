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

#include "route-learned.h"

#include <inttypes.h>

#include "binding.h"
#include "coverage.h"
#include "id-pool.h"
#include "lflow.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "vec.h"
#include "ovn/actions.h"
#include "ovn/logical-fields.h"
#include "ovn-route-prio.h"
#include "ovn-util.h"
#include "route-exchange-netlink.h"
#include "uuidset.h"

VLOG_DEFINE_THIS_MODULE(route_learned);

/* Incremented once per OpenFlow flow added for a learned route.  A single
 * route change must only install flows for the group it belongs to, so this
 * grows by a small constant per change rather than by the total route
 * count. */
COVERAGE_DEFINE(route_learned_flow_install);

#define LR_IN_IP_ROUTING_TABLE 16
#define LR_IN_IP_ROUTING_ECMP_TABLE 17

/* ECMP group IDs for locally learned routes.  Northd uses small integers
 * starting from 0; keep learned-route ECMP IDs in the high range. */
#define LEARNED_ECMP_GROUP_ID_BASE 0x8000
#define LEARNED_ECMP_GROUP_N_IDS   0x8000

struct learned_route_group;

struct learned_route_entry {
    struct hmap_node node;
    struct uuid flow_uuid;
    uint64_t dp_key;
    uint64_t port_key;
    struct in6_addr prefix;
    unsigned int plen;
    struct in6_addr nexthop;
    uint32_t route_table_id;
    char *lrp_addr_s;
    char *eth_src;
    char *logical_port;
    bool stale;
    struct learned_route_group *group;
};

struct learned_route_group_key {
    uint64_t dp_key;
    struct in6_addr prefix;
    unsigned int plen;
    uint32_t route_table_id;
};

struct learned_route_group {
    struct hmap_node node;
    struct learned_route_group_key key;
    /* Elements are struct learned_route_entry *. */
    struct vector routes;
    uint16_t ecmp_group_id;
    bool ecmp_id_assigned;
    bool dirty;
    /* Flow UUIDs currently installed in the desired flow table for this
     * group. */
    struct uuidset installed_uuids;
};

static struct hmap learned_routes = HMAP_INITIALIZER(&learned_routes);
static struct hmap learned_route_groups =
    HMAP_INITIALIZER(&learned_route_groups);
static struct shash route_learned_symtab = SHASH_INITIALIZER(&route_learned_symtab);
static bool route_learned_symtab_inited;
static struct id_pool *ecmp_group_ids;

static uint32_t
learned_route_hash(const struct sbrec_datapath_binding *datapath,
                   const struct sbrec_port_binding *logical_port,
                   const struct in6_addr *prefix, unsigned int plen,
                   const struct in6_addr *nexthop)
{
    uint32_t hash = uuid_hash(&datapath->header_.uuid);
    hash = hash_int(logical_port->tunnel_key, hash);
    hash = hash_bytes(prefix, sizeof *prefix, hash);
    hash = hash_int(plen, hash);
    hash = hash_bytes(nexthop, sizeof *nexthop, hash);
    return hash;
}

static uint32_t
learned_route_group_hash(uint64_t dp_key, const struct in6_addr *prefix,
                         unsigned int plen, uint32_t route_table_id)
{
    uint32_t hash = hash_uint64_basis(dp_key, 0);
    hash = hash_bytes(prefix, sizeof *prefix, hash);
    hash = hash_int(plen, hash);
    return hash_int(route_table_id, hash);
}

static struct learned_route_entry *
learned_route_find(const struct sbrec_datapath_binding *datapath,
                   const struct sbrec_port_binding *logical_port,
                   const struct in6_addr *prefix, unsigned int plen,
                   const struct in6_addr *nexthop)
{
    uint32_t hash = learned_route_hash(datapath, logical_port, prefix, plen,
                                       nexthop);
    struct learned_route_entry *e;
    HMAP_FOR_EACH_WITH_HASH (e, node, hash, &learned_routes) {
        if (e->dp_key != (uint64_t) datapath->tunnel_key
            || e->port_key != (uint64_t) logical_port->tunnel_key
            || e->plen != plen
            || !ipv6_addr_equals(&e->prefix, prefix)
            || !ipv6_addr_equals(&e->nexthop, nexthop)) {
            continue;
        }
        return e;
    }
    return NULL;
}

static void
learned_route_entry_destroy(struct learned_route_entry *e)
{
    free(e->lrp_addr_s);
    free(e->eth_src);
    free(e->logical_port);
    free(e);
}

static void
learned_route_group_destroy(struct learned_route_group *g)
{
    if (g->ecmp_id_assigned) {
        id_pool_free_id(ecmp_group_ids, g->ecmp_group_id);
    }
    vector_destroy(&g->routes);
    uuidset_destroy(&g->installed_uuids);
    free(g);
}

static struct learned_route_group *
learned_route_group_find(uint64_t dp_key, const struct in6_addr *prefix,
                         unsigned int plen, uint32_t route_table_id)
{
    uint32_t hash = learned_route_group_hash(dp_key, prefix, plen,
                                             route_table_id);
    struct learned_route_group *g;
    HMAP_FOR_EACH_WITH_HASH (g, node, hash, &learned_route_groups) {
        if (g->key.dp_key == dp_key
            && g->key.plen == plen
            && g->key.route_table_id == route_table_id
            && ipv6_addr_equals(&g->key.prefix, prefix)) {
            return g;
        }
    }
    return NULL;
}

static struct learned_route_group *
learned_route_group_insert(uint64_t dp_key, const struct in6_addr *prefix,
                           unsigned int plen, uint32_t route_table_id)
{
    struct learned_route_group *g = xzalloc(sizeof *g);
    g->key.dp_key = dp_key;
    g->key.prefix = *prefix;
    g->key.plen = plen;
    g->key.route_table_id = route_table_id;
    g->routes = VECTOR_EMPTY_INITIALIZER(struct learned_route_entry *);
    uuidset_init(&g->installed_uuids);
    g->dirty = true;

    uint32_t hash = learned_route_group_hash(dp_key, prefix, plen,
                                             route_table_id);
    hmap_insert(&learned_route_groups, &g->node, hash);
    return g;
}

static void
learned_route_group_assign_ecmp_id(struct learned_route_group *g)
{
    if (g->ecmp_id_assigned) {
        return;
    }
    if (!ecmp_group_ids) {
        ecmp_group_ids = id_pool_create(LEARNED_ECMP_GROUP_ID_BASE,
                                        LEARNED_ECMP_GROUP_N_IDS);
    }

    uint32_t id;
    if (!id_pool_alloc_id(ecmp_group_ids, &id)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "too many learned ECMP groups");
        return;
    }
    g->ecmp_group_id = id;
    g->ecmp_id_assigned = true;
}

static void
learned_route_group_add_entry(struct learned_route_group *g,
                              struct learned_route_entry *e)
{
    vector_push(&g->routes, &e);
    e->group = g;
    g->dirty = true;
    if (vector_len(&g->routes) > 1) {
        learned_route_group_assign_ecmp_id(g);
    }
}

static void
learned_route_group_remove_entry(struct learned_route_entry *e)
{
    struct learned_route_group *g = e->group;
    if (!g) {
        return;
    }

    for (size_t i = 0; i < vector_len(&g->routes); i++) {
        if (vector_get(&g->routes, i, struct learned_route_entry *) == e) {
            vector_remove(&g->routes, i, NULL);
            break;
        }
    }
    e->group = NULL;
    g->dirty = true;
}

static bool
learned_route_resolve_port(const struct sbrec_port_binding *logical_port,
                           const struct in6_addr *nexthop,
                           char **eth_src_out, char **lrp_addr_s_out)
{
    struct lport_addresses laddrs;
    init_lport_addresses(&laddrs);
    bool ok = false;

    for (size_t i = 0; i < logical_port->n_mac; i++) {
        if (extract_lsp_addresses(logical_port->mac[i], &laddrs)) {
            ok = true;
            break;
        }
    }
    if (!ok) {
        destroy_lport_addresses(&laddrs);
        return false;
    }

    *eth_src_out = xstrdup(laddrs.ea_s);
    char *nexthop_s = normalize_v46(nexthop);
    const char *lrp_addr = find_lport_address(&laddrs, nexthop_s);
    free(nexthop_s);
    if (lrp_addr) {
        *lrp_addr_s_out = xstrdup(lrp_addr);
    } else if (laddrs.n_ipv4_addrs) {
        *lrp_addr_s_out = xstrdup(laddrs.ipv4_addrs[0].addr_s);
    } else if (laddrs.n_ipv6_addrs) {
        *lrp_addr_s_out = xstrdup(laddrs.ipv6_addrs[0].addr_s);
    } else {
        free(*eth_src_out);
        *eth_src_out = NULL;
        destroy_lport_addresses(&laddrs);
        return false;
    }

    destroy_lport_addresses(&laddrs);
    return true;
}

static struct learned_route_entry *
learned_route_entry_create(const struct sbrec_datapath_binding *datapath,
                           const struct sbrec_port_binding *logical_port,
                           const struct in6_addr *prefix, unsigned int plen,
                           const struct in6_addr *nexthop)
{
    char *eth_src = NULL;
    char *lrp_addr_s = NULL;
    if (!learned_route_resolve_port(logical_port, nexthop, &eth_src,
                                    &lrp_addr_s)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl,
                     "Could not resolve output port %s for learned route",
                     logical_port->logical_port);
        return NULL;
    }

    struct learned_route_entry *e = xzalloc(sizeof *e);
    e->flow_uuid = uuid_random();
    e->dp_key = datapath->tunnel_key;
    e->port_key = logical_port->tunnel_key;
    e->prefix = *prefix;
    e->plen = plen;
    e->nexthop = *nexthop;
    e->route_table_id = 0;
    e->lrp_addr_s = lrp_addr_s;
    e->eth_src = eth_src;
    e->logical_port = xstrdup(logical_port->logical_port);

    uint32_t hash = learned_route_hash(datapath, logical_port, prefix, plen,
                                       nexthop);
    hmap_insert(&learned_routes, &e->node, hash);

    struct learned_route_group *g =
        learned_route_group_find(e->dp_key, &e->prefix, e->plen,
                                 e->route_table_id);
    if (!g) {
        g = learned_route_group_insert(e->dp_key, &e->prefix, e->plen,
                                       e->route_table_id);
    }
    learned_route_group_add_entry(g, e);
    return e;
}

void
route_learned_sync(const struct vector *kernel_routes,
                   const struct sbrec_datapath_binding *datapath,
                   const struct smap *bound_ports,
                   struct ovsdb_idl_index *sbrec_port_binding_by_name)
{
    const struct re_nl_received_route_node *learned_route;
    VECTOR_FOR_EACH_PTR (kernel_routes, learned_route) {
        char *ip_prefix = normalize_v46_prefix(&learned_route->prefix,
                                               learned_route->plen);
        char *nexthop_s = normalize_v46(&learned_route->nexthop);
        struct in6_addr nexthop;
        unsigned int nh_plen;
        if (!ip46_parse_cidr(nexthop_s, &nexthop, &nh_plen)) {
            free(ip_prefix);
            free(nexthop_s);
            continue;
        }

        struct smap_node *port_node;
        SMAP_FOR_EACH (port_node, bound_ports) {
            if (port_node->value && strcmp(port_node->value,
                                           learned_route->ifname)) {
                continue;
            }

            const struct sbrec_port_binding *logical_port =
                lport_lookup_by_name(sbrec_port_binding_by_name,
                                     port_node->key);
            if (!logical_port) {
                continue;
            }

            if (smap_get_bool(&logical_port->options,
                              "dynamic-routing-no-learning", false)) {
                continue;
            }

            struct learned_route_entry *e =
                learned_route_find(datapath, logical_port,
                                   &learned_route->prefix,
                                   learned_route->plen, &nexthop);
            if (e) {
                e->stale = false;
            } else {
                learned_route_entry_create(datapath, logical_port,
                                           &learned_route->prefix,
                                           learned_route->plen, &nexthop);
            }
        }
        free(ip_prefix);
        free(nexthop_s);
    }
}

void
route_learned_mark_all_stale(void)
{
    struct learned_route_entry *e;
    HMAP_FOR_EACH (e, node, &learned_routes) {
        e->stale = true;
    }
}

void
route_learned_remove_stale(void)
{
    struct learned_route_entry *e, *next;
    HMAP_FOR_EACH_SAFE (e, next, node, &learned_routes) {
        if (e->stale) {
            learned_route_group_remove_entry(e);
            hmap_remove(&learned_routes, &e->node);
            learned_route_entry_destroy(e);
        }
    }
}

static int
compare_learned_route_entry(const void *a_, const void *b_)
{
    const struct learned_route_entry *const *a = a_;
    const struct learned_route_entry *const *b = b_;
    return (*a)->port_key > (*b)->port_key ? 1 :
           (*a)->port_key < (*b)->port_key ? -1 : 0;
}

/* encode_LOAD() calls ep->lookup_port() unconditionally when loading a
 * string field such as outport = "lrp0".  We already resolved the port's
 * tunnel key when the route was learned, so look it up from that. */
struct route_learned_lookup_aux {
    const char *port_name;
    uint32_t port_key;
};

static bool
route_learned_lookup_port(const void *aux_, const char *port_name,
                          unsigned int *portp)
{
    const struct route_learned_lookup_aux *aux = aux_;

    if (!strcmp(port_name, "none")) {
        *portp = 0;
        return true;
    }
    if (aux && aux->port_name && !strcmp(port_name, aux->port_name)) {
        *portp = aux->port_key;
        return true;
    }
    return false;
}

static bool
route_learned_encode_actions(const char *actions_s, struct ofpbuf *ofpacts,
                             struct ovn_extend_table *group_table,
                             const struct learned_route_entry *out_port)
{
    if (!route_learned_symtab_inited) {
        ovn_init_symtab(&route_learned_symtab);
        route_learned_symtab_inited = true;
    }

    struct ovnact_parse_params pp = {
        .symtab = &route_learned_symtab,
        .pipeline = OVNACT_P_INGRESS,
        .n_tables = LOG_PIPELINE_INGRESS_LEN,
        .cur_ltable = LR_IN_IP_ROUTING_TABLE,
    };

    uint64_t ovnacts_stub[1024 / 8];
    struct ofpbuf ovnacts = OFPBUF_STUB_INITIALIZER(ovnacts_stub);
    struct expr *prereqs = NULL;
    char *error = ovnacts_parse_string(actions_s, &pp, &ovnacts, &prereqs);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 1);
        VLOG_WARN_RL(&rl, "error parsing learned route actions \"%s\": %s",
                     actions_s, error);
        free(error);
        expr_destroy(prereqs);
        ovnacts_free(ovnacts.data, ovnacts.size);
        ofpbuf_uninit(&ovnacts);
        return false;
    }

    struct route_learned_lookup_aux aux = {
        .port_name = out_port ? out_port->logical_port : NULL,
        .port_key = out_port ? out_port->port_key : 0,
    };
    struct ovnact_encode_params ep = {
        .lookup_port = route_learned_lookup_port,
        .aux = &aux,
        .is_switch = false,
        .group_table = group_table,
        .pipeline = OVNACT_P_INGRESS,
        .ingress_ptable = OFTABLE_LOG_INGRESS_PIPELINE,
        .egress_ptable = OFTABLE_LOG_EGRESS_PIPELINE,
        .output_ptable = OFTABLE_OUTPUT_INIT,
        .mac_bind_ptable = OFTABLE_MAC_BINDING,
        .mac_lookup_ptable = OFTABLE_MAC_LOOKUP,
        .lb_hairpin_ptable = OFTABLE_CHK_LB_HAIRPIN,
        .lb_hairpin_reply_ptable = OFTABLE_CHK_LB_HAIRPIN_REPLY,
        .ct_snat_vip_ptable = OFTABLE_CT_SNAT_HAIRPIN,
        .fdb_ptable = OFTABLE_GET_FDB,
        .remote_fdb_ptable = OFTABLE_GET_REMOTE_FDB,
        .fdb_lookup_ptable = OFTABLE_LOOKUP_FDB,
        .in_port_sec_ptable = OFTABLE_CHK_IN_PORT_SEC,
        .out_port_sec_ptable = OFTABLE_CHK_OUT_PORT_SEC,
        .mac_cache_use_table = OFTABLE_MAC_CACHE_USE,
        .ct_nw_dst_load_table = OFTABLE_CT_ORIG_NW_DST_LOAD,
        .ct_ip6_dst_load_table = OFTABLE_CT_ORIG_IP6_DST_LOAD,
        .ct_tp_dst_load_table = OFTABLE_CT_ORIG_TP_DST_LOAD,
        .ct_proto_load_table = OFTABLE_CT_ORIG_PROTO_LOAD,
        .flood_remote_table = OFTABLE_FLOOD_REMOTE_CHASSIS,
        .ct_state_save_table = OFTABLE_CT_STATE_SAVE,
        .evpn_arp_ptable = OFTABLE_EVPN_ARP_LOOKUP,
    };
    ovnacts_encode(ovnacts.data, ovnacts.size, &ep, ofpacts);
    expr_destroy(prereqs);
    ovnacts_free(ovnacts.data, ovnacts.size);
    ofpbuf_uninit(&ovnacts);
    return true;
}

static void
learned_route_build_match(const struct learned_route_entry *e,
                          struct match *match)
{
    match_init_catchall(match);
    match_set_metadata(match, htonll(e->dp_key));
    match_set_reg(match, 7, e->route_table_id);

    if (IN6_IS_ADDR_V4MAPPED(&e->prefix)) {
        match_set_dl_type(match, htons(ETH_TYPE_IP));
        match_set_nw_dst_masked(match,
                                in6_addr_get_mapped_ipv4(&e->prefix),
                                be32_prefix_mask(e->plen));
    } else {
        match_set_dl_type(match, htons(ETH_TYPE_IPV6));
        struct in6_addr mask = ipv6_create_mask(e->plen);
        match_set_ipv6_dst_masked(match, &e->prefix, &mask);
    }
}

static void
learned_route_add_flows(struct learned_route_group *group,
                        struct ovn_desired_flow_table *flow_table,
                        struct ovn_extend_table *group_table)
{
    size_t n_routes = vector_len(&group->routes);
    ovs_assert(n_routes > 0);

    if (n_routes > 1 && !group->ecmp_id_assigned) {
        /* Without an ID the select action would collide with northd's ECMP
         * groups; leave the route unprogrammed instead. */
        return;
    }

    const struct learned_route_entry *first =
        vector_get(&group->routes, 0, struct learned_route_entry *);
    uint16_t priority = ovn_route_calc_priority(first->plen,
                                                OVN_ROUTE_SOURCE_LEARNED,
                                                false, false, false);
    uint8_t ptable = OFTABLE_LOG_INGRESS_PIPELINE + LR_IN_IP_ROUTING_TABLE;
    uint8_t ecmp_ptable = OFTABLE_LOG_INGRESS_PIPELINE +
                          LR_IN_IP_ROUTING_ECMP_TABLE;

    struct match match;
    learned_route_build_match(first, &match);

    struct ds actions = DS_EMPTY_INITIALIZER;
    if (n_routes == 1) {
        const struct learned_route_entry *e = first;
        bool is_ipv4_nh = IN6_IS_ADDR_V4MAPPED(&e->nexthop);
        char *nexthop_s = normalize_v46(&e->nexthop);
        ds_put_cstr(&actions, "ip.ttl--; reg8[0..15] = 0; ");
        if (is_ipv4_nh) {
            ds_put_format(&actions, "reg0 = %s; ", nexthop_s);
            if (e->lrp_addr_s) {
                ds_put_format(&actions, "reg5 = %s; ", e->lrp_addr_s);
            }
        } else {
            ds_put_format(&actions, "xxreg0 = %s; ", nexthop_s);
            if (e->lrp_addr_s) {
                ds_put_format(&actions, "xxreg1 = %s; ", e->lrp_addr_s);
            }
        }
        free(nexthop_s);
        ds_put_format(&actions,
                      "eth.src = %s; outport = \"%s\"; "
                      "flags.loopback = 1; reg9[9] = %d; next;",
                      e->eth_src, e->logical_port, is_ipv4_nh);
    } else {
        ds_put_format(&actions,
                      "ip.ttl--; flags.loopback = 1; "
                      "reg8[0..15] = %"PRIu16"; reg8[16..31] = select(",
                      group->ecmp_group_id);
        for (size_t i = 0; i < n_routes; i++) {
            if (i) {
                ds_put_cstr(&actions, ", ");
            }
            ds_put_format(&actions, "%"PRIuSIZE, i);
        }
        ds_put_cstr(&actions, "); next;");
    }

    uint64_t stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(stub);
    /* Single-route actions load outport by name; ECMP select does not. */
    if (route_learned_encode_actions(ds_cstr(&actions), &ofpacts, group_table,
                                     n_routes == 1 ? first : NULL)) {
        ofctrl_add_flow(flow_table, ptable, priority,
                        first->flow_uuid.parts[0], &match, &ofpacts,
                        &first->flow_uuid);
        uuidset_insert(&group->installed_uuids, &first->flow_uuid);
        COVERAGE_INC(route_learned_flow_install);
    }
    ofpbuf_uninit(&ofpacts);

    if (n_routes <= 1) {
        ds_destroy(&actions);
        return;
    }

    for (size_t i = 0; i < n_routes; i++) {
        const struct learned_route_entry *e =
            vector_get(&group->routes, i, struct learned_route_entry *);
        bool is_ipv4_nh = IN6_IS_ADDR_V4MAPPED(&e->nexthop);
        char *nexthop_s = normalize_v46(&e->nexthop);

        match_init_catchall(&match);
        match_set_reg(&match, 8,
                      ((uint32_t) i << 16) | group->ecmp_group_id);

        ds_clear(&actions);
        if (is_ipv4_nh) {
            ds_put_format(&actions, "reg0 = %s; ", nexthop_s);
            if (e->lrp_addr_s) {
                ds_put_format(&actions, "reg5 = %s; ", e->lrp_addr_s);
            }
        } else {
            ds_put_format(&actions, "xxreg0 = %s; ", nexthop_s);
            if (e->lrp_addr_s) {
                ds_put_format(&actions, "xxreg1 = %s; ", e->lrp_addr_s);
            }
        }
        free(nexthop_s);
        ds_put_format(&actions,
                      "eth.src = %s; outport = \"%s\"; "
                      "reg9[9] = %d; next;",
                      e->eth_src, e->logical_port, is_ipv4_nh);

        ofpbuf_init(&ofpacts, 0);
        ofpbuf_use_stub(&ofpacts, stub, sizeof stub);
        if (route_learned_encode_actions(ds_cstr(&actions), &ofpacts,
                                         group_table, e)) {
            ofctrl_add_flow(flow_table, ecmp_ptable, 100,
                            e->flow_uuid.parts[0], &match, &ofpacts,
                            &e->flow_uuid);
            uuidset_insert(&group->installed_uuids, &e->flow_uuid);
            COVERAGE_INC(route_learned_flow_install);
        }
        ofpbuf_uninit(&ofpacts);
    }
    ds_destroy(&actions);
}

static void
learned_route_group_remove_installed_flows(
    struct learned_route_group *g,
    struct ovn_desired_flow_table *flow_table)
{
    struct uuidset_node *uuid_node;
    UUIDSET_FOR_EACH_SAFE (uuid_node, &g->installed_uuids) {
        ofctrl_remove_flows(flow_table, &uuid_node->uuid);
        uuidset_delete(&g->installed_uuids, uuid_node);
    }
}

void
route_learned_of_run(struct ovn_desired_flow_table *flow_table,
                     struct ovn_extend_table *group_table,
                     bool reinstall_all)
{
    struct learned_route_group *g, *next;

    HMAP_FOR_EACH_SAFE (g, next, node, &learned_route_groups) {
        if (!reinstall_all && !g->dirty) {
            continue;
        }

        if (reinstall_all) {
            /* Desired flow table was cleared by the caller; drop tracking
             * without ofctrl_remove_flows(). */
            uuidset_clear(&g->installed_uuids);
        } else {
            learned_route_group_remove_installed_flows(g, flow_table);
        }

        if (vector_is_empty(&g->routes)) {
            hmap_remove(&learned_route_groups, &g->node);
            learned_route_group_destroy(g);
            continue;
        }

        vector_qsort(&g->routes, compare_learned_route_entry);
        learned_route_add_flows(g, flow_table, group_table);
        g->dirty = false;
    }
}

void
route_learned_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *data OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct learned_route_entry *e;

    HMAP_FOR_EACH (e, node, &learned_routes) {
        char *prefix_s = normalize_v46_prefix(&e->prefix, e->plen);
        char *nexthop_s = normalize_v46(&e->nexthop);
        uint16_t priority = ovn_route_calc_priority(
            e->plen, OVN_ROUTE_SOURCE_LEARNED, false, false, false);
        ds_put_format(&ds,
                      "datapath=%"PRIu64" logical_port=%s ip_prefix=%s "
                      "nexthop=%s priority=%"PRIu16"\n",
                      e->dp_key, e->logical_port, prefix_s, nexthop_s,
                      priority);
        free(prefix_s);
        free(nexthop_s);
    }

    unixctl_command_reply(conn, ds_cstr_ro(&ds));
    ds_destroy(&ds);
}

void
route_learned_destroy(void)
{
    struct learned_route_entry *e;
    HMAP_FOR_EACH_POP (e, node, &learned_routes) {
        e->group = NULL;
        learned_route_entry_destroy(e);
    }

    struct learned_route_group *g;
    HMAP_FOR_EACH_POP (g, node, &learned_route_groups) {
        learned_route_group_destroy(g);
    }

    id_pool_destroy(ecmp_group_ids);
    ecmp_group_ids = NULL;

    if (route_learned_symtab_inited) {
        expr_symtab_destroy(&route_learned_symtab);
        shash_destroy(&route_learned_symtab);
        route_learned_symtab_inited = false;
    }
}
