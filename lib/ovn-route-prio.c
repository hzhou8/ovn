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

#include <config.h>

#include "ovn-route-prio.h"

#include "util.h"

static int
get_route_offset(enum ovn_route_source source, bool override_connected)
{
    switch (source) {
    case OVN_ROUTE_SOURCE_CONNECTED:
    case OVN_ROUTE_SOURCE_IC_DYNAMIC:
        return override_connected
               ? OVN_ROUTE_PRIO_OFFSET_IC_LEARNED_CONNECTED_WITH_TABLEID
               : OVN_ROUTE_PRIO_OFFSET_CONNECTED;

    case OVN_ROUTE_SOURCE_STATIC:
        return override_connected
               ? OVN_ROUTE_PRIO_OFFSET_PRIORITY_STATIC
               : OVN_ROUTE_PRIO_OFFSET_STATIC;

    case OVN_ROUTE_SOURCE_LEARNED:
        return OVN_ROUTE_PRIO_OFFSET_LEARNED;

    case OVN_ROUTE_SOURCE_NAT:
    case OVN_ROUTE_SOURCE_LB:
    case OVN_ROUTE_SOURCE_CONNECTED_AS_HOST:
    default:
        OVS_NOT_REACHED();
    }
}

uint16_t
ovn_route_calc_priority(int plen, enum ovn_route_source source,
                        bool override_connected, bool is_src_route,
                        bool has_protocol_match)
{
    int priority = is_src_route ? 0 :
                   get_route_offset(source, override_connected);

    priority += (plen * OVN_ROUTE_PRIO_OFFSET_MULTIPLIER) + has_protocol_match;

    return priority + OVN_ROUTE_PRIO_BASE_SHIFT;
}
