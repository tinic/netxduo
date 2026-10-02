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
/**   Neighbor Discovery Cache                                            */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_nd_cache.h"
#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nxd_nd_cache_entry_set                             PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function creates an entry with the specified IPv6 address and  */
/*    hardware MAC address mapping and adds it to the Neighbor Discovery  */
/*    (ND) cache.                                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to the IP instance    */
/*    dest_ip                               Pointer to the IP address     */
/*                                            to add (map)                */
/*    interface_index                       Index to the network          */
/*                                            interface                   */
/*    mac                                   Pointer to the MAC address to */
/*                                            be added (map)              */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_nd_cache_add                      Actual function to add an     */
/*                                             entry to the cache.        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT _nxd_nd_cache_entry_set(NX_IP *ip_ptr, ULONG *dest_ip, UINT interface_index, CHAR *mac)
{
#ifdef FEATURE_NX_IPV6

ND_CACHE_ENTRY   *nd_cache_entry;
NX_INTERFACE     *interface_ptr;
NXD_IPV6_ADDRESS *iface_address;
UINT              status;
UINT              i;


    /* If trace is enabled, insert this event into the trace buffer. */
    NX_TRACE_IN_LINE_INSERT(NXD_TRACE_ND_CACHE_ENTRY_SET, dest_ip[3], ((mac[0] << 16) | mac[1]), ((mac[2] << 24) | (mac[3] << 16) | (mac[4] << 8) | mac[5]),
                            0, NX_TRACE_ARP_EVENTS, 0, 0);

    /* Obtain the protection. */
    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    /* Validate the interface index before indexing the interface table. */
    if (interface_index >= NX_MAX_IP_INTERFACES)
    {

        /* Release the protection, and return the error status. */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_INVALID_INTERFACE);
    }

    interface_ptr = &(ip_ptr -> nx_ip_interface[interface_index]);

    /* Locate an IPv6 address attached to the requested interface to use as the
       entry's outgoing source address. */
    iface_address = NX_NULL;
    for (i = 0; i < (UINT)(NX_MAX_IPV6_ADDRESSES + NX_LOOPBACK_IPV6_ENABLED); i++)
    {

        if (ip_ptr -> nx_ipv6_address[i].nxd_ipv6_address_attached == interface_ptr)
        {
            iface_address = &(ip_ptr -> nx_ipv6_address[i]);
            break;
        }
    }

    /* Refuse when the interface has no configured IPv6 address: the ND entry
       cannot carry a valid interface/source address without one. */
    if (iface_address == NX_NULL)
    {

        /* Release the protection, and return the error status. */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));

        return(NX_NO_INTERFACE_ADDRESS);
    }

    /* Call the actual cache entry add service. */
    status = _nx_nd_cache_add(ip_ptr, dest_ip, interface_ptr, mac, 1, ND_CACHE_STATE_REACHABLE, iface_address, &nd_cache_entry);

    /* Release the protection. */
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(status);

#else /* !FEATURE_NX_IPV6 */
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(dest_ip);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(mac);

    return(NX_NOT_SUPPORTED);

#endif /* FEATURE_NX_IPV6 */
}

