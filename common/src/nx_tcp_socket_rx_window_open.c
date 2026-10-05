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

/* The receive window open to the sender: the free space, or the socket's
   cap (nx_tcp_socket_rx_window_cap) when that is less.  The cap never pulls
   back a right edge already put on the wire (RFC 9293 3.8.6.2.2): what is
   left of the window last sent stays open whatever the cap.

   The cap is for a receiver that can take only so much from the wire at
   once but can hold more: a network card with a small ring and no flow
   control.  With the buffer the size of the burst, every burst filled it,
   the acknowledgment of the burst advertised zero, and the sender waited for
   the application's read and a window update before it sent again.
   Measured on an A3000 (68060 at 50 MHz, X-Surf 100, 11,680-byte window,
   2026-10-05): that wait was 0.7 ms of every 5.75 ms cycle.  A buffer twice
   the cap keeps the burst the card can take and leaves the window open when
   the burst is acknowledged.  */
ULONG  _nx_tcp_socket_rx_window_open(NX_TCP_SOCKET *socket_ptr)
{
ULONG  open = socket_ptr -> nx_tcp_socket_rx_window_current;
ULONG  cap = _nx_tcp_socket_rx_window_cap(socket_ptr);

    if ((cap != 0) && (open > cap))
    {
        if (cap < socket_ptr -> nx_tcp_socket_rx_window_last_sent)
        {
            cap = socket_ptr -> nx_tcp_socket_rx_window_last_sent;
        }
        if (open > cap)
        {
            open = cap;
        }
    }

    return(open);
}


/* The cap in force (0 = none): the socket's own once it has one, until then
   the interface's the connection is on.  A connection is capped from its
   first segment: the SYN or SYN-ACK goes out before anything has settled a
   cap of its own, and the handshake's own ACK on an active open precedes
   the establish notification.  */
ULONG  _nx_tcp_socket_rx_window_cap(NX_TCP_SOCKET *socket_ptr)
{
ULONG  cap = socket_ptr -> nx_tcp_socket_rx_window_cap;

    if ((cap == 0) && (socket_ptr -> nx_tcp_socket_connect_interface != NX_NULL))
    {
        cap = socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_tcp_rx_window_cap;
    }

    return((cap == NX_TCP_RX_WINDOW_CAP_NONE) ? 0 : cap);
}


/* The window a SYN or SYN-ACK offers: the free space, or the cap in force
   when that is less.  Nothing has been offered before it, so there is no
   right edge for it to keep.  The window scale is still derived from the
   buffer (nx_tcp_packet_send_syn.c), so the cap costs the connection none of
   the window it may grow to.  */
ULONG  _nx_tcp_socket_rx_window_syn(NX_TCP_SOCKET *socket_ptr)
{
ULONG  window = socket_ptr -> nx_tcp_socket_rx_window_current;
ULONG  cap = _nx_tcp_socket_rx_window_cap(socket_ptr);

    if ((cap != 0) && (window > cap))
    {
        window = cap;
    }

    return(window);
}
