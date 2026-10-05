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
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_tcp.h"


/* Open a receive pass on this IP instance: from here until the matching
   _nx_tcp_receive_pass_complete(), every socket that takes in-order data is
   marked with the pass's number.  Called with nx_ip_protection held, by a
   caller that delivers a run of segments under it -- a driver's receive
   loop.  Nested opens join the outer pass; the outermost completes it.  */
VOID  _nx_tcp_receive_pass_begin(NX_IP *ip_ptr)
{

    if (ip_ptr -> nx_ip_tcp_rx_pass_open++ != 0)
    {
        return;
    }

    /* Zero is "never" on a socket, so the count skips it.  */
    if (++ip_ptr -> nx_ip_tcp_rx_pass == 0)
    {
        ip_ptr -> nx_ip_tcp_rx_pass = 1;
    }
    ip_ptr -> nx_ip_tcp_rx_pass_touched = 0;
}
