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
/*    _nx_mld_group_leave                                                 */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Drop a group and tell the routers on the link.                      */
/*                                                                        */
/*    In MLDv1 the message is a Done to ff02::2, and only the host that   */
/*    sent the last report sends one (RFC 2710 section 5): a host whose   */
/*    report was suppressed by someone else's knows another listener      */
/*    exists and has nothing to announce.                                 */
/*                                                                        */
/*    In MLDv2 the same thing is a state-change report carrying           */
/*    CHANGE_TO_INCLUDE_MODE with no sources, sent Robustness Variable    */
/*    times whatever any other host did, because version 2 has no report  */
/*    suppression to be on the wrong side of.                             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ipv6_multicast_leave              solicited-node addresses      */
/*    _nxd_ipv6_multicast_interface_leave   IPV6_LEAVE_GROUP              */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_group_leave(NX_IP *ip_ptr, ULONG *group_address, NX_INTERFACE *nx_interface)
{

NX_MLD_GROUP *group_ptr;

    if (ip_ptr -> nx_ip_mld_enabled == NX_FALSE)
    {
        return(NX_SUCCESS);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    group_ptr = _nx_mld_group_find(ip_ptr, group_address, nx_interface);

    if (group_ptr == NX_NULL)
    {
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_ENTRY_NOT_FOUND);
    }

    if (group_ptr -> nx_mld_group_join_count > 1)
    {

        /* Another address still wants this group.  */
        group_ptr -> nx_mld_group_join_count--;
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_SUCCESS);
    }

    if (_nx_mld_group_reportable(group_ptr -> nx_mld_group_address) == NX_TRUE)
    {

        if (_nx_mld_v1_mode(ip_ptr, nx_interface) == NX_TRUE)
        {

            if (group_ptr -> nx_mld_group_last_reporter == NX_TRUE)
            {
                _nx_mld_message_send(ip_ptr, group_ptr, NX_MLD_DONE_TYPE, 0);
            }
        }
        else
        {
            _nx_mld_message_send(ip_ptr, group_ptr, NX_MLD_V2_REPORT_TYPE,
                                 NX_MLD_CHANGE_TO_INCLUDE_MODE);
        }
    }

    /* Free the entry.  The retransmissions RFC 9777 section 6.1 asks for are
       not sent: they would need the entry to outlive the membership, and a
       second CHANGE_TO_INCLUDE_MODE only shortens a router's timeout on a
       group it will drop anyway.  A router that missed the first one falls
       back on its own query, which is the mechanism that has to work for
       the host that crashes and never leaves at all.  */
    group_ptr -> nx_mld_group_interface     = NX_NULL;
    group_ptr -> nx_mld_group_join_count    = 0;
    group_ptr -> nx_mld_group_timer         = 0;
    group_ptr -> nx_mld_group_retransmit    = 0;
    group_ptr -> nx_mld_group_last_reporter = NX_FALSE;
    group_ptr -> nx_mld_group_state         = NX_MLD_STATE_NON_LISTENER;
    SET_UNSPECIFIED_ADDRESS(group_ptr -> nx_mld_group_address);

    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}

#endif /* FEATURE_NX_IPV6 && NX_ENABLE_MLD */
