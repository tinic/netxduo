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
/**   Multicast Listener Discovery (MLD)                                  */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE

#include "nx_api.h"

#if defined(FEATURE_NX_IPV6) && defined(NX_ENABLE_MLD)
#include "nx_ip.h"
#include "nx_ipv6.h"
#include "nx_mld.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_group_find                                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Return the membership entry for a group on an interface, or NULL.   */
/*    The caller holds the IP protection mutex.                           */
/*                                                                        */
/**************************************************************************/
NX_MLD_GROUP *_nx_mld_group_find(NX_IP *ip_ptr, ULONG *group_address, NX_INTERFACE *nx_interface)
{

UINT          i;
NX_MLD_GROUP *group_ptr;

    for (i = 0; i < NX_MLD_MAX_GROUPS; i++)
    {

        group_ptr = &ip_ptr -> nx_ip_mld_groups[i];

        if ((group_ptr -> nx_mld_group_interface == nx_interface) &&
            CHECK_IPV6_ADDRESSES_SAME(group_ptr -> nx_mld_group_address, group_address))
        {
            return(group_ptr);
        }
    }

    return(NX_NULL);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_group_reportable                                            */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    RFC 9777 section 6: a report is sent for every multicast address a  */
/*    node listens to, EXCEPT the link-scope all-nodes address and any    */
/*    address of scope 0 (reserved) or 1 (interface-local).  Scope is     */
/*    the four bits after the flags, RFC 4291 section 2.7.                */
/*                                                                        */
/*    ff02::1 is excepted because every node is a member of it by         */
/*    definition, so reporting it tells a router nothing it does not      */
/*    already have to assume.                                             */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_group_reportable(ULONG *group_address)
{

ULONG scope;

    /* Not a multicast address at all.  */
    if ((group_address[0] & 0xFF000000UL) != 0xFF000000UL)
    {
        return(NX_FALSE);
    }

    scope = (group_address[0] >> 16) & 0xFUL;

    if (scope < 2)
    {
        return(NX_FALSE);
    }

    /* ff02::1, the link-scope all-nodes address.  */
    if ((group_address[0] == 0xFF020000UL) && (group_address[1] == 0UL) &&
        (group_address[2] == 0UL) && (group_address[3] == 1UL))
    {
        return(NX_FALSE);
    }

    return(NX_TRUE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_interface_index                                             */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Index of an interface in the IP instance, or                        */
/*    NX_MAX_PHYSICAL_INTERFACES when it does not belong to it.           */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_interface_index(NX_IP *ip_ptr, NX_INTERFACE *nx_interface)
{

UINT i;

    for (i = 0; i < NX_MAX_PHYSICAL_INTERFACES; i++)
    {
        if (&ip_ptr -> nx_ip_interface[i] == nx_interface)
        {
            return(i);
        }
    }

    return(NX_MAX_PHYSICAL_INTERFACES);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_v1_mode                                                     */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    NX_TRUE while an MLDv1 querier is present on the interface.  A host */
/*    starts in MLDv2 (RFC 9777 section 8.2.1) and falls back for         */
/*    Older Version Querier Present Timeout after each MLDv1 query.       */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_v1_mode(NX_IP *ip_ptr, NX_INTERFACE *nx_interface)
{

UINT index;

    index = _nx_mld_interface_index(ip_ptr, nx_interface);

    if (index >= NX_MAX_PHYSICAL_INTERFACES)
    {
        return(NX_FALSE);
    }

    return((ip_ptr -> nx_ip_mld_v1_querier_present[index] != 0) ? NX_TRUE : NX_FALSE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_random_delay                                                */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    A delay of 1..max_seconds.  RFC 2710 section 4 wants it uniform     */
/*    over [0, Maximum Response Delay]; the timer here ticks once a       */
/*    second, so zero would mean "send at the next tick" and is folded    */
/*    into one.  A max of zero means send now, which is the caller's job. */
/*                                                                        */
/**************************************************************************/
ULONG _nx_mld_random_delay(ULONG max_seconds)
{

ULONG value;

    if (max_seconds <= 1)
    {
        return(1);
    }

    value = (ULONG)NX_RAND();

    return((value % max_seconds) + 1);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                                              */
/*                                                                        */
/*    _nx_mld_group_schedule                                              */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Arm a group's report timer for a random delay no longer than        */
/*    max_seconds.  RFC 2710 section 4: a timer already running for less  */
/*    than the new delay is left alone, so a burst of queries cannot push */
/*    a pending report further out.                                       */
/*                                                                        */
/**************************************************************************/
VOID _nx_mld_group_schedule(NX_IP *ip_ptr, NX_MLD_GROUP *group_ptr,
                            ULONG max_seconds, UCHAR record_type)
{

ULONG delay;

    NX_PARAMETER_NOT_USED(ip_ptr);

    delay = _nx_mld_random_delay(max_seconds);

    if ((group_ptr -> nx_mld_group_timer != 0) &&
        (group_ptr -> nx_mld_group_timer <= delay))
    {

        /* A sooner report is already pending.  */
        return;
    }

    group_ptr -> nx_mld_group_timer = delay;
    group_ptr -> nx_mld_group_state = NX_MLD_STATE_DELAYING_LISTENER;
    group_ptr -> nx_mld_group_record_type = record_type;
}

#endif /* FEATURE_NX_IPV6 && NX_ENABLE_MLD */
