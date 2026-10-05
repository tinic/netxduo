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

/* The receive window to advertise, in bytes (NX_TCP_RX_WINDOW_ADVERTISED,
   nx_tcp.h): the open window at or above the SWS floor; below it what is
   left of the window last sent, or the open window if that is less (RFC 1122
   4.2.3.3, RFC 9293 3.8.6.2.2).  */
ULONG  _nx_tcp_socket_rx_window_advertised(NX_TCP_SOCKET *socket_ptr)
{
ULONG  open = _nx_tcp_socket_rx_window_open(socket_ptr);

    if ((open >= NX_TCP_SWS_FLOOR(socket_ptr)) ||
        (open <= socket_ptr -> nx_tcp_socket_rx_window_last_sent))
    {
        return(open);
    }

    return(socket_ptr -> nx_tcp_socket_rx_window_last_sent);
}
