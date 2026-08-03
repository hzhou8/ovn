/*
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

#ifndef OVN_ROUTE_PRIO_H
#define OVN_ROUTE_PRIO_H 1

#include <stdint.h>

#include "ovn-util.h"

enum ovn_route_source {
    OVN_ROUTE_SOURCE_CONNECTED,
    OVN_ROUTE_SOURCE_STATIC,
    OVN_ROUTE_SOURCE_LEARNED,
    OVN_ROUTE_SOURCE_NAT,
    OVN_ROUTE_SOURCE_LB,
    OVN_ROUTE_SOURCE_CONNECTED_AS_HOST,
    OVN_ROUTE_SOURCE_IC_DYNAMIC,
};

#define OVN_ROUTE_PRIO_OFFSET_MULTIPLIER 12
#define OVN_ROUTE_PRIO_OFFSET_PRIORITY_STATIC 10
#define OVN_ROUTE_PRIO_OFFSET_IC_LEARNED_CONNECTED_WITH_TABLEID 8
#define OVN_ROUTE_PRIO_OFFSET_CONNECTED 6
#define OVN_ROUTE_PRIO_OFFSET_STATIC 4
#define OVN_ROUTE_PRIO_OFFSET_LEARNED 2

#define OVN_ROUTE_PRIO_BASE_SHIFT ((MAX_PREFIX_LEN + 1) * \
                                   OVN_ROUTE_PRIO_OFFSET_MULTIPLIER)

uint16_t ovn_route_calc_priority(int plen, enum ovn_route_source source,
                                 bool override_connected,
                                 bool is_src_route,
                                 bool has_protocol_match);

#endif /* OVN_ROUTE_PRIO_H */
