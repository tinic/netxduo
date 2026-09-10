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

/* Set the one IPv4 default gateway through a particular interface.  Unlike
   nx_ip_gateway_address_set(), this is unambiguous when several interfaces
   have addresses on the same subnet. */
UINT _nx_ip_gateway_interface_address_set(NX_IP *ip_ptr, UINT interface_index,
                                          ULONG ip_address)
{
#ifndef NX_DISABLE_IPV4
    NX_INTERFACE *interface_ptr;
    TX_INTERRUPT_SAVE_AREA

    NX_TRACE_IN_LINE_INSERT(NX_TRACE_IP_GATEWAY_ADDRESS_SET, ip_ptr,
                            ip_address, interface_index, 0,
                            NX_TRACE_IP_EVENTS, 0, 0);

    tx_mutex_get(&(ip_ptr->nx_ip_protection), TX_WAIT_FOREVER);

    interface_ptr = &(ip_ptr->nx_ip_interface[interface_index]);
    if ((interface_ptr->nx_interface_valid == 0) ||
        ((ip_address & interface_ptr->nx_interface_ip_network_mask) !=
         interface_ptr->nx_interface_ip_network))
    {
        tx_mutex_put(&(ip_ptr->nx_ip_protection));
        return NX_IP_ADDRESS_ERROR;
    }

    TX_DISABLE
    ip_ptr->nx_ip_gateway_address = ip_address;
    ip_ptr->nx_ip_gateway_interface = interface_ptr;
    TX_RESTORE

    tx_mutex_put(&(ip_ptr->nx_ip_protection));
    return NX_SUCCESS;
#else
    NX_PARAMETER_NOT_USED(ip_ptr);
    NX_PARAMETER_NOT_USED(interface_index);
    NX_PARAMETER_NOT_USED(ip_address);
    return NX_NOT_SUPPORTED;
#endif
}
