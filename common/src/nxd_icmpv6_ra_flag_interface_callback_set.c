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

/*
 * AmiNetXDuo: nxd_icmpv6_ra_flag_callback_set() with the interface.  The
 * existing callback fires before the receiving interface is known, so a host
 * with more than one IPv6 link cannot tell whose advertisement it is.  This
 * one fires once it is, with its index; the other is unchanged.
 */

#define NX_SOURCE_CODE

#include "nx_api.h"
#include "nx_icmpv6.h"

UINT  _nxd_icmpv6_ra_flag_interface_callback_set(NX_IP *ip_ptr,
                                                 VOID (*icmpv6_ra_flag_interface_callback)(NX_IP *ip_ptr,
                                                                                           UINT interface_index,
                                                                                           UINT ra_flag))
{

#ifdef FEATURE_NX_IPV6
    if (ip_ptr == NX_NULL)
    {
        return(NX_PTR_ERROR);
    }

    tx_mutex_get(&(ip_ptr -> nx_ip_protection), TX_WAIT_FOREVER);
    ip_ptr -> nx_icmpv6_ra_flag_interface_callback = icmpv6_ra_flag_interface_callback;
    tx_mutex_put(&(ip_ptr -> nx_ip_protection));

    return(NX_SUCCESS);

#else /* !FEATURE_NX_IPV6 */
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(icmpv6_ra_flag_interface_callback);

    return(NX_NOT_SUPPORTED);

#endif /* FEATURE_NX_IPV6 */
}
