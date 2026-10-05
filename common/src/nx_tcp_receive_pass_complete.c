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


/* Close a receive pass, and acknowledge what it left unacknowledged.

   A segment's acknowledgment is decided as it is taken in
   (nx_tcp_socket_state_data_check.c): one leaves when the data outstanding
   reaches the threshold, which ramps to a step of the window offered.  What
   arrives after the last such crossing in a pass waits for the next segment
   or the delayed-ACK timer.  On a path where the sender has its whole window
   in flight, the next segment is a round trip away: it cannot be sent until
   this data is acknowledged.  Measured on an A3000 (X-Surf 100, 46720-byte
   window, 25 ms path) with the driver's receive delivering runs of at most
   16 segments against a 16-segment threshold: a window that arrived as
   16 + 14 or 16 + 2 held the tail a whole round trip, 8.4 against 10.4
   Mbit/s for one that arrived as 16 + 16.

   So when a pass ends, a socket it took data on that still has two
   full-sized segments or more unacknowledged is acknowledged now, through
   the ordinary acknowledgment path, once.  Less than two stays with the
   delayed-ACK policy (RFC 1122 4.2.3.2).  One that a segment's own decision
   already acknowledged has nothing outstanding and gets nothing more.  A
   failed allocation leaves the data unacknowledged for the delayed-ACK
   timer, as any acknowledgment does.

   Only sockets marked with this pass's number are acted on; the created
   list is walked to find them only when the pass marked any, and never
   further than its count.  Each mark is cleared as it is visited, so a
   socket carries a pass's number only while that pass is open, and the
   counter wrapping onto an old number finds no socket still holding it.

   Lifetime: nothing is held but a number.  Sockets are reached only
   through the IP instance's created list, under nx_ip_protection, which
   the whole pass holds; nx_tcp_socket_delete() unlinks a socket from that
   list under the same mutex, so a socket deleted inside the pass -- by a
   callback run from it -- is simply not found, and one reused there is
   seen in its new state, which the state test below decides on.  Called
   with nx_ip_protection held.  */
VOID  _nx_tcp_receive_pass_complete(NX_IP *ip_ptr)
{

NX_TCP_SOCKET *socket_ptr;
ULONG          count;
ULONG          pass;


    if (ip_ptr -> nx_ip_tcp_rx_pass_open == 0)
    {
        return;
    }
    if (--ip_ptr -> nx_ip_tcp_rx_pass_open != 0)
    {
        return;
    }
    if (ip_ptr -> nx_ip_tcp_rx_pass_touched == 0)
    {
        return;
    }
    ip_ptr -> nx_ip_tcp_rx_pass_touched = 0;

    pass = ip_ptr -> nx_ip_tcp_rx_pass;
    socket_ptr = ip_ptr -> nx_ip_tcp_created_sockets_ptr;
    count = ip_ptr -> nx_ip_tcp_created_sockets_count;

    while ((count-- != 0) && (socket_ptr != NX_NULL))
    {
        if (socket_ptr -> nx_tcp_socket_rx_pass == pass)
        {
            socket_ptr -> nx_tcp_socket_rx_pass = 0;

            if (((socket_ptr -> nx_tcp_socket_state == NX_TCP_ESTABLISHED) ||
                 (socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
                 (socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_2)) &&
                ((socket_ptr -> nx_tcp_socket_rx_sequence -
                  socket_ptr -> nx_tcp_socket_rx_sequence_acked) >=
                 ((ULONG)socket_ptr -> nx_tcp_socket_connect_mss << 1)))
            {
                _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
            }
        }

        socket_ptr = socket_ptr -> nx_tcp_socket_created_next;
    }
}
