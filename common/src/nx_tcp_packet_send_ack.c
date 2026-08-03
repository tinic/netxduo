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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_packet_send_ack                             PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends an ACK from the specified socket.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*    tx_sequence                           Transmit sequence number      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_packet_send_control           Send TCP control packet       */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing      Delayed ACK processing        */
/*    _nx_tcp_periodic_processing           Regular periodic processing   */
/*    _nx_tcp_socket_receive                Packet receive processing     */
/*    _nx_tcp_socket_state_ack_check        Socket state ACK processing   */
/*    _nx_tcp_socket_state_data_check       Socket state date processing  */
/*    _nx_tcp_socket_state_established      Socket state established      */
/*                                            processing                  */
/*    _nx_tcp_socket_state_fin_wait2        Socket state FIN wait-2       */
/*                                            processing                  */
/*    _nx_tcp_socket_state_fin_wait1        Socket state FIN wait         */
/*                                            processing                  */
/*    _nx_tcp_socket_state_syn_sent         Socket state SYN sent         */
/*                                            processing                  */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_packet_send_ack(NX_TCP_SOCKET *socket_ptr, ULONG tx_sequence)
{

#ifdef NX_ENABLE_TCP_SACK
UCHAR sack_option[NX_TCP_SACK_OPTION_MAX_SIZE];
UINT  sack_option_size;

    /* RFC 2018 section 3: an acknowledgment that does not cover everything the
       socket holds describes the rest in SACK blocks, so the peer retransmits
       the hole rather than everything after it.  Nothing to report costs one
       comparison and leaves the header five words long.  */
    sack_option_size = _nx_tcp_sack_option_build(socket_ptr, sack_option);

    _nx_tcp_packet_send_control(socket_ptr, NX_TCP_ACK_BIT, tx_sequence,
                                socket_ptr -> nx_tcp_socket_rx_sequence, 0, 0,
                                sack_option, sack_option_size, NX_NULL);
#else
    _nx_tcp_packet_send_control(socket_ptr, NX_TCP_ACK_BIT, tx_sequence,
                                socket_ptr -> nx_tcp_socket_rx_sequence, 0, 0,
                                NX_NULL, 0, NX_NULL);
#endif /* NX_ENABLE_TCP_SACK */

    /* Setup a new delayed ACK timeout.  */
    socket_ptr -> nx_tcp_socket_delayed_ack_timeout =  _nx_tcp_ack_timer_rate;
}

