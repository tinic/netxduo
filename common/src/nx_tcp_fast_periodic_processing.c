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
#include "nx_ip.h"
#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */
#include "nx_packet.h"
#include "nx_tcp.h"


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the fast periodic TCP processing for        */
/*    sending delayed ACK messages for previous receive operations and    */
/*    for re-transmitting packets that have not been ACKed by the other   */
/*    side of the connection.                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_packet_send_ack               Send a delayed ACK            */
/*    _nx_tcp_packet_send_syn               Send initial SYN again        */
/*    _nx_tcp_socket_connection_reset       Reset connection on timeout   */
/*    _nx_tcp_socket_block_cleanup          Cleanup the socket block      */
/*    _nx_tcp_socket_retransmit             Retransmit packet             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_ip_thread_entry                   IP helper thread              */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_fast_periodic_processing(NX_IP *ip_ptr)
{

NX_TCP_SOCKET *socket_ptr;
ULONG          sockets;
ULONG          timer_rate;
ULONG          max_retries;
ULONG          retry_shift;


    /* Pickup this timer's periodic rate.  */
    timer_rate =  _nx_tcp_fast_timer_rate;

    /* Pickup the number of created TCP sockets.  */
    sockets =  ip_ptr -> nx_ip_tcp_created_sockets_count;

    /* Pickup the first socket.  */
    socket_ptr =  ip_ptr -> nx_ip_tcp_created_sockets_ptr;

    /* Loop through the created sockets.  */
    while (sockets--)
    {

        /* Determine if the socket is in an established or disconnect state and has delayed sending an ACK
           from a previous receive packet event.  */
        /* The window-update arm carries the same RFC 1122 4.2.3.3 floor the
           receive path applies.  Without it the floor was worth nothing: any
           read at all left rx_window_last_sent behind rx_window_current, and
           this timer then announced the difference however small, which is the
           silly-window advertisement the floor exists to suppress.  The
           unacknowledged-data arm has no floor and must not have one.  */
        if ((socket_ptr -> nx_tcp_socket_state >= NX_TCP_ESTABLISHED) &&
            ((socket_ptr -> nx_tcp_socket_rx_sequence != socket_ptr -> nx_tcp_socket_rx_sequence_acked) ||
             ((socket_ptr -> nx_tcp_socket_rx_window_current - socket_ptr -> nx_tcp_socket_rx_window_last_sent) >=
              _nx_tcp_socket_window_update_step(socket_ptr))))
        {

            /* Determine if the ACK has expired.  */
            if (socket_ptr -> nx_tcp_socket_delayed_ack_timeout <= timer_rate)
            {

                /* Send the delayed ACK, which also resets the ACK timeout.  */
                _nx_tcp_packet_send_ack(socket_ptr, socket_ptr -> nx_tcp_socket_tx_sequence);
            }
            else
            {

                /* No, it hasn't expired yet.  Just decrement it for now.  */
                socket_ptr -> nx_tcp_socket_delayed_ack_timeout -= timer_rate;
            }
        }

        /* R2, RFC 1122 4.2.3.5.  A connection request has its own, because
           MUST-23 asks for three minutes of retransmission on a SYN and the
           same section asks only a hundred seconds on data.  */
        max_retries =  socket_ptr -> nx_tcp_socket_timeout_max_retries;

        if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
            (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED))
        {

            if (max_retries < NX_TCP_SYN_MAXIMUM_RETRIES)
            {
                max_retries =  NX_TCP_SYN_MAXIMUM_RETRIES;
            }
        }

        /* Determine if a timeout is active.  */
        if (socket_ptr -> nx_tcp_socket_timeout)
        {

            /* Yes, a timeout is active.  Determine if it has expired.  */
            if (socket_ptr -> nx_tcp_socket_timeout > timer_rate)
            {

                /* No, it hasn't expired yet.  Just decrement the timeout value.  */
                socket_ptr -> nx_tcp_socket_timeout -= timer_rate;
            }
            else if (((socket_ptr -> nx_tcp_socket_timeout_retries >= max_retries) &&
                      (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_FALSE)) ||
                     ((socket_ptr -> nx_tcp_socket_zero_window_probe_failure >= socket_ptr -> nx_tcp_socket_timeout_max_retries) &&
                      (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_TRUE))
                    )
            {

                /* Number of retries has been exceeded.  */

                /* Close the socket via a connection reset.  */
                _nx_tcp_socket_connection_reset(socket_ptr);
            }
            /* YUXIN MODIFIED HERE */
            else if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
                     (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED))
            {

                /* Yes, the timeout on the SYN message has expired.  */

                /* Increment the retry counter.  */
                socket_ptr -> nx_tcp_socket_timeout_retries++;

                /* Setup the next timeout.  The shift is capped, so the ladder
                   spends its extra retries at the ceiling rather than doubling
                   past it -- the difference between R2 landing on 191 seconds
                   and on 255.  */
                retry_shift = socket_ptr -> nx_tcp_socket_timeout_retries *
                              socket_ptr -> nx_tcp_socket_timeout_shift;

                if (retry_shift > NX_TCP_SYN_RETRY_SHIFT_MAX)
                {
                    retry_shift = NX_TCP_SYN_RETRY_SHIFT_MAX;
                }

                socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate << retry_shift;

                /* Send the initial SYN message again.  Adjust the sequence number before and
                   after to ensure the same sequence as the initial SYN.  */
                _nx_tcp_packet_send_syn(socket_ptr, (socket_ptr -> nx_tcp_socket_tx_sequence - 1));
            }
            /* Has the TCP timeout for transmit packet or probing zero window expired?  */
            else if (socket_ptr -> nx_tcp_socket_transmit_sent_head ||
                     ((socket_ptr -> nx_tcp_socket_tx_window_advertised == 0) &&
                      (socket_ptr -> nx_tcp_socket_state <= NX_TCP_CLOSE_WAIT)))
            {

                /* Update the transmit sequence that entered fast transmit. */
                socket_ptr -> nx_tcp_socket_tx_sequence_recover = socket_ptr -> nx_tcp_socket_tx_sequence - 1;

                /* Retransmit the packet. */
                _nx_tcp_socket_retransmit(ip_ptr, socket_ptr, NX_FALSE);

                /* Exit fast recovery procedure. */
                socket_ptr -> nx_tcp_socket_fast_recovery = NX_FALSE;
                socket_ptr -> nx_tcp_socket_tx_window_congestion = socket_ptr -> nx_tcp_socket_tx_slow_start_threshold;
            }
            else if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_FIN_WAIT_1) ||
                     (socket_ptr -> nx_tcp_socket_state == NX_TCP_CLOSING)    ||
                     (socket_ptr -> nx_tcp_socket_state == NX_TCP_LAST_ACK))
            {

                /* We have a timeout condition on sending the FIN... so it needs to be
                   retried.  */

                /* Increment the retry counter.  */
                socket_ptr -> nx_tcp_socket_timeout_retries++;

                /* Setup the next timeout.  */
                socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate <<
                    (socket_ptr -> nx_tcp_socket_timeout_retries * socket_ptr -> nx_tcp_socket_timeout_shift);

                /* Send another FIN packet.  */
                _nx_tcp_packet_send_fin(socket_ptr, (socket_ptr -> nx_tcp_socket_tx_sequence - 1));
            }
            else if (socket_ptr -> nx_tcp_socket_state == NX_TCP_TIMED_WAIT)
            {

                /* Clean the transmission control block.  */
                _nx_tcp_socket_block_cleanup(socket_ptr);
            }
        }

        /* Move to the next TCP socket.  */
        socket_ptr =  socket_ptr -> nx_tcp_socket_created_next;
    }
}

