/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Internet Protocol (IP)                                              */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */


#include "nx_api.h"
#include "nx_ip.h"
#include "nx_ipv6.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxd_ip_raw_packet_send                             PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a raw IP packet to the specified destination    */
/*    without the caller naming a source. IPv4 uses the primary           */
/*    interface; IPv6 selects a source address for the destination.       */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*    destination_ip                        Destination IP address        */
/*    protocol                              Value for the protocol field  */
/*    ttl                                   Value for ttl or hop limit    */
/*    tos                                   Value for tos or traffic      */
/*                                            class and flow label        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Actual completion status      */
/*    NX_NOT_ENABLED                        Raw IP processing not enabled */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nxd_ip_raw_packet_source_send        Core raw packet send service  */
/*    _nxd_ipv6_interface_find              Find a suitable source address*/
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application                                                         */
/*                                                                        */
/**************************************************************************/
UINT  _nxd_ip_raw_packet_send(NX_IP *ip_ptr, NX_PACKET *packet_ptr,
                              NXD_ADDRESS *destination_ip, ULONG protocol, UINT ttl, ULONG tos)
{

UINT              status;
UINT              address_index = 0;
#ifdef FEATURE_NX_IPV6
NXD_IPV6_ADDRESS *source_address;
#endif /* FEATURE_NX_IPV6 */

#ifdef FEATURE_NX_IPV6
    if (destination_ip -> nxd_ip_version == NX_IP_VERSION_V6)
    {

        /* No source was specified, so pick one for the destination the same way
           the IPv4 path asks _nx_ip_route_find for an outgoing interface.  */
        status = _nxd_ipv6_interface_find(ip_ptr, destination_ip -> nxd_ip_address.v6, &source_address, NX_NULL);

        /* Cannot find a usable source address. */
        if (status != NX_SUCCESS)
        {
            return(status);
        }

        /*lint -e{644} suppress variable might not be initialized, since "source_address" was initialized in _nxd_ipv6_interface_find. */
        address_index = (UINT)(source_address -> nxd_ipv6_address_index);
    }
#endif /* FEATURE_NX_IPV6 */

    status = _nxd_ip_raw_packet_source_send(ip_ptr, packet_ptr, destination_ip, address_index, protocol, ttl, tos);

    return(status);
}

