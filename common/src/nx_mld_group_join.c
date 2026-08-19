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
/*    _nx_mld_group_join                                                  */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Record a group this host now listens to and announce it.            */
/*                                                                        */
/*    RFC 9777 section 6: the report is sent at once, not after a delay.  */
/*    A snooping switch learns the port from it, and the group that       */
/*    matters most is a solicited-node address, which is joined so that   */
/*    duplicate address detection can run.  Waiting would put a random    */
/*    delay in front of every address this stack ever configures.         */
/*                                                                        */
/*    It is then repeated Robustness Variable - 1 more times after random */
/*    delays, because it is unacknowledged and one lost frame would       */
/*    otherwise cost the group until the next query.                      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ipv6_multicast_join               solicited-node and all-nodes  */
/*    _nxd_ipv6_multicast_interface_join    IPV6_JOIN_GROUP               */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_group_join(NX_IP *ip_ptr, ULONG *group_address, NX_INTERFACE *nx_interface)
{

UINT          i;
UINT          status = NX_SUCCESS;
NX_MLD_GROUP *group_ptr;
NX_MLD_GROUP *free_ptr = NX_NULL;

    if (ip_ptr -> nx_ip_mld_enabled == NX_FALSE)
    {
        return(NX_SUCCESS);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    group_ptr = _nx_mld_group_find(ip_ptr, group_address, nx_interface);

    if (group_ptr != NX_NULL)
    {

        /* Already listening.  Two IPv6 addresses agreeing in their low 24
           bits share one solicited-node group, and this is that case.  */
        group_ptr -> nx_mld_group_join_count++;

        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_SUCCESS);
    }

    for (i = 0; i < NX_MLD_MAX_GROUPS; i++)
    {
        if (ip_ptr -> nx_ip_mld_groups[i].nx_mld_group_interface == NX_NULL)
        {
            free_ptr = &ip_ptr -> nx_ip_mld_groups[i];
            break;
        }
    }

    if (free_ptr == NX_NULL)
    {

        /* The table is full.  The driver has already been told to accept the
           group, so reception works and only the announcement is lost; say
           so rather than failing the join.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_NO_MORE_ENTRIES);
    }

    COPY_IPV6_ADDRESS(group_address, free_ptr -> nx_mld_group_address);
    free_ptr -> nx_mld_group_interface     = nx_interface;
    free_ptr -> nx_mld_group_join_count    = 1;
    free_ptr -> nx_mld_group_timer         = 0;
    free_ptr -> nx_mld_group_retransmit    = 0;
    free_ptr -> nx_mld_group_last_reporter = NX_FALSE;
    free_ptr -> nx_mld_group_record_type   = 0;
    free_ptr -> nx_mld_group_state         = NX_MLD_STATE_IDLE_LISTENER;

    if (_nx_mld_group_reportable(group_address) == NX_FALSE)
    {

        /* ff02::1 and anything below link scope.  Held in the table so a
           query for it can be answered with silence knowingly, and so the
           leave path finds it.  */
        tx_mutex_put(&(ip_ptr -> nx_ip_protection));
        return(NX_SUCCESS);
    }

    if (_nx_mld_v1_mode(ip_ptr, nx_interface) == NX_TRUE)
    {
        _nx_mld_message_send(ip_ptr, free_ptr, NX_MLD_V1_REPORT_TYPE, 0);
        free_ptr -> nx_mld_group_timer = _nx_mld_random_delay(NX_MLD_V1_UNSOLICITED_REPORT_INTERVAL);
    }
    else
    {
        _nx_mld_message_send(ip_ptr, free_ptr, NX_MLD_V2_REPORT_TYPE, NX_MLD_CHANGE_TO_EXCLUDE_MODE);
        free_ptr -> nx_mld_group_timer = _nx_mld_random_delay(NX_MLD_V2_UNSOLICITED_REPORT_INTERVAL);
    }

    free_ptr -> nx_mld_group_retransmit  = (UCHAR)(NX_MLD_ROBUSTNESS_VARIABLE - 1);
    free_ptr -> nx_mld_group_record_type = NX_MLD_CHANGE_TO_EXCLUDE_MODE;
    free_ptr -> nx_mld_group_state       = NX_MLD_STATE_DELAYING_LISTENER;

    if (free_ptr -> nx_mld_group_retransmit == 0)
    {
        free_ptr -> nx_mld_group_timer = 0;
        free_ptr -> nx_mld_group_state = NX_MLD_STATE_IDLE_LISTENER;
    }

    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(status);
}

#endif /* FEATURE_NX_IPV6 && NX_ENABLE_MLD */
