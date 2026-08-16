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
/*    _nx_mld_enable                                                      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Start reporting multicast listeners on this IP instance.            */
/*                                                                        */
/*    Call it before nxd_ipv6_enable(), the way nx_igmp_enable() is       */
/*    called before an interface exists: joins made while this is off are */
/*    not in the table and are never announced.  The IP control block is  */
/*    zeroed at creation, so there is nothing else to initialise.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/**************************************************************************/
UINT _nx_mld_enable(NX_IP *ip_ptr)
{

    if (ip_ptr == NX_NULL)
    {
        return(NX_PTR_ERROR);
    }

    if (ip_ptr -> nx_ip_id != NX_IP_ID)
    {
        return(NX_PTR_ERROR);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);

    ip_ptr -> nx_ip_mld_enabled = NX_TRUE;

    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);
}

#endif /* FEATURE_NX_IPV6 && NX_ENABLE_MLD */
