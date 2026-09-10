/***************************************************************************
 * Copyright (c) 2026 Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/

#define NX_SOURCE_CODE

#include "nx_api.h"
#include "nx_ip.h"

NX_CALLER_CHECKING_EXTERNS

UINT _nxe_ip_gateway_interface_address_set(NX_IP *ip_ptr, UINT interface_index,
                                           ULONG ip_address)
{
#ifndef NX_DISABLE_IPV4
    if ((ip_ptr == NX_NULL) || (ip_ptr->nx_ip_id != NX_IP_ID))
        return NX_PTR_ERROR;

    if ((interface_index >= (UINT)NX_MAX_PHYSICAL_INTERFACES) ||
        (ip_ptr->nx_ip_interface[interface_index].nx_interface_valid == 0))
        return NX_INVALID_INTERFACE;

    if (ip_address == IP_ADDRESS(0, 0, 0, 0))
        return NX_IP_ADDRESS_ERROR;

    NX_INIT_AND_THREADS_CALLER_CHECKING

    return _nx_ip_gateway_interface_address_set(ip_ptr, interface_index,
                                                 ip_address);
#else
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(ip_address);
    return NX_NOT_SUPPORTED;
#endif
}
