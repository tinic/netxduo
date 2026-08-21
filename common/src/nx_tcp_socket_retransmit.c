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
#include "nx_packet.h"
#include "nx_ip.h"
#include "nx_tcp.h"
#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */
#ifdef NX_IPSEC_ENABLE
#include "nx_ipsec.h"
#endif /* NX_IPSEC_ENABLE */

/* What a queued segment carries beyond its payload.  Below the includes:
   NX_ENABLE_TCP_TIMESTAMP comes from nx_user.h by way of nx_api.h.  */
#ifdef NX_ENABLE_TCP_TIMESTAMP
#define NX_TCP_SEGMENT_HEADER_LENGTH                                          \
    ((ULONG)sizeof(NX_TCP_HEADER) +                                           \
     (((socket_ptr -> nx_tcp_socket_timestamp_enabled) == NX_TRUE) ?          \
      (ULONG)NX_TCP_TIMESTAMP_OPTION_SIZE : (ULONG)0))
#else
#define NX_TCP_SEGMENT_HEADER_LENGTH    ((ULONG)sizeof(NX_TCP_HEADER))
#endif /* NX_ENABLE_TCP_TIMESTAMP */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_retransmit_packet                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends one segment that is already on the transmit      */
/*    queue again: it refreshes the acknowledgment number, the window and  */
/*    the timestamp option, recomputes the checksum and hands the packet   */
/*    to the IP layer.                                                     */
/*                                                                        */
/*    It was the body of _nx_tcp_socket_retransmit()'s queue walk, and is  */
/*    a function of its own because that walk is not the only thing that   */
/*    needs to resend a queued segment.  RFC 8985 section 7.3's tail loss  */
/*    probe sends the LAST unacknowledged segment, not the first, and the  */
/*    walk can only start at nx_tcp_socket_transmit_sent_head.             */
/*                                                                        */
/*    It decides nothing.  The congestion window, the retry ladder and     */
/*    what the peer reported are the caller's business; this rebuilds one  */
/*    header and sends one packet.                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    socket_ptr                            Pointer to owning socket      */
/*    packet_ptr                            The queued segment to resend  */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_ip_checksum_compute               Calculate TCP checksum        */
/*    _nx_tcp_timestamp_option_add          Refresh the timestamp option  */
/*    _nx_ip_packet_send                    Resend the transmit packet    */
/*    _nx_ipv6_packet_send                  Resend the transmit packet    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_socket_retransmit             The queue walk                */
/*    _nx_tcp_socket_retransmit_tail        The tail loss probe           */
/*                                                                        */
/**************************************************************************/
static VOID  _nx_tcp_socket_retransmit_packet(NX_IP *ip_ptr, NX_TCP_SOCKET *socket_ptr, NX_PACKET *packet_ptr)
{
ULONG          checksum;
ULONG          original_acknowledgment_number;
ULONG          original_header_word_3;
ULONG          original_header_word_4;
ULONG          window_size;
NX_TCP_HEADER *header_ptr;
ULONG         *source_ip = NX_NULL, *dest_ip = NX_NULL;
#if defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE)
UINT           compute_checksum = 1;
#endif /* defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE) */

#ifdef NX_DISABLE_TCP_TX_CHECKSUM
    compute_checksum = 0;
#endif /* NX_DISABLE_TCP_TX_CHECKSUM */


#ifndef NX_DISABLE_IPV4
    /* Is this an IPv4 connection? */
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {

        packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V4;

        /* Get the source and destination addresses. */
        source_ip = &socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_ip_address;
        dest_ip = &socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4;
    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
    {

        /* Set the packet for IPv6 connectivity. */
        packet_ptr -> nx_packet_ip_version = NX_IP_VERSION_V6;

        /* Get the source and destination addresses. */
        source_ip = socket_ptr -> nx_tcp_socket_ipv6_addr -> nxd_ipv6_address;
        dest_ip = socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6;
    }
#endif /* FEATURE_NX_IPV6 */

    /* Pick up the pointer to the head of the TCP packet.  */
    /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
    header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Record the original data.  */
    original_acknowledgment_number = header_ptr -> nx_tcp_acknowledgment_number;
    original_header_word_3 = header_ptr -> nx_tcp_header_word_3;
    original_header_word_4 = header_ptr -> nx_tcp_header_word_4;

    /* Update the ACK number in the TCP header.  */
    header_ptr -> nx_tcp_acknowledgment_number = socket_ptr -> nx_tcp_socket_rx_sequence;

    /* Convert to network byte order for checksum */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_acknowledgment_number);

    /* Set window size. */
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    window_size = socket_ptr -> nx_tcp_socket_rx_window_current >> socket_ptr -> nx_tcp_rcv_win_scale_value;

    /* Make sure the window_size is less than 0xFFFF. */
    if (window_size > 0xFFFF)
    {
        window_size = 0xFFFF;
    }
#else
    window_size = socket_ptr -> nx_tcp_socket_rx_window_current;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

#ifdef NX_ENABLE_TCP_TIMESTAMP
    if (socket_ptr -> nx_tcp_socket_timestamp_enabled == NX_TRUE)
    {

        /* The queued segment was built with an eight word header and the
           option still sits behind this one, so the data offset has to say
           eight.  Writing five here would hand the peer the twelve option
           bytes as payload and corrupt the stream from the first
           retransmission onwards.  */
        header_ptr -> nx_tcp_header_word_3 = NX_TCP_HEADER_SIZE_TIMESTAMP | NX_TCP_ACK_BIT | NX_TCP_PSH_BIT | window_size;

        /* RFC 1323 section 4.1: the retransmission carries the current
           clock, not the clock of the transmission it replaces, so the
           peer's own estimate measures what actually crossed the wire.
           TSecr is refreshed for the same reason the ACK number above is.  */
        _nx_tcp_timestamp_option_add(((UCHAR *)header_ptr) + sizeof(NX_TCP_HEADER),
                                     (ULONG)tx_time_get(),
                                     socket_ptr -> nx_tcp_socket_ts_recent);

        socket_ptr -> nx_tcp_socket_last_ack_sent = socket_ptr -> nx_tcp_socket_rx_sequence;
    }
    else
#endif /* NX_ENABLE_TCP_TIMESTAMP */
    {
        header_ptr -> nx_tcp_header_word_3 =        NX_TCP_HEADER_SIZE | NX_TCP_ACK_BIT | NX_TCP_PSH_BIT | window_size;
    }

    /* Swap the content to network byte order. */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);

    /* Convert back to host byte order to so we can zero out the checksum. */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);

    /* Remember the last ACKed sequence and the last reported window size.  */
    socket_ptr -> nx_tcp_socket_rx_sequence_acked =    socket_ptr -> nx_tcp_socket_rx_sequence;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent =  socket_ptr -> nx_tcp_socket_rx_window_current;

    /* Zero out existing checksum before computing new one. */
    header_ptr -> nx_tcp_header_word_4 = header_ptr -> nx_tcp_header_word_4 & 0x0000FFFF;

    /* Convert back to network byte order to so we can do the checksum. */
    NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);


#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    if (socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM)
    {
        compute_checksum = 0;
    }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

#ifdef NX_IPSEC_ENABLE
    if ((packet_ptr -> nx_packet_ipsec_sa_ptr != NX_NULL) &&
        (((NX_IPSEC_SA *)(packet_ptr -> nx_packet_ipsec_sa_ptr)) -> nx_ipsec_sa_encryption_method != NX_CRYPTO_NONE))
    {
        compute_checksum = 1;
    }
#endif /* NX_IPSEC_ENABLE */

#if defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE)
    if (compute_checksum)
#endif /* defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE) */
    {
        /* Calculate the TCP checksum without protection.  */
        checksum =  _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                            packet_ptr -> nx_packet_length,
                                            source_ip, dest_ip);
        checksum = ~checksum & NX_LOWER_16_MASK;

        /* Convert back to host byte order */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);

        /* Move the checksum into header.  */
        header_ptr -> nx_tcp_header_word_4 =  header_ptr -> nx_tcp_header_word_4 | (checksum << NX_SHIFT_BY_16);

        /* Convert back to network byte order for transmit. */
        NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_4);
    }
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    else
    {
        packet_ptr -> nx_packet_interface_capability_flag |= NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM;
    }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

    /* Determine if the retransmitted packet is identical to the original packet.
       RFC1122, Section3.2.1.5, Page32-33. RFC1122, Section4.2.2.15, Page90-91.  */
    if ((header_ptr -> nx_tcp_acknowledgment_number == original_acknowledgment_number) &&
        (header_ptr -> nx_tcp_header_word_3 == original_header_word_3) &&
        (header_ptr -> nx_tcp_header_word_4 == original_header_word_4))
    {

        /* Yes, identical packet, update the identification flag.  */
        packet_ptr -> nx_packet_identical_copy = NX_TRUE;
    }
    else
    {

        /* No.  The flag has to be cleared as well as set: a packet on the
           retransmit queue is retransmitted more than once, and only
           nx_packet_allocate() and nx_packet_release() ever cleared this.
           A packet that went out identical once kept the flag, so when a
           later retransmission of the same packet carried a moved ACK or
           window -- which is the usual case, not a corner one --
           _nx_ip_header_add() still took the early exit and re-sent the
           original IPv4 identification on a datagram whose bytes had
           changed.  RFC 6864 4.1 forbids repeating an ID within the
           maximum datagram lifetime for a source/destination/protocol
           tuple unless the datagram is atomic, and these are not: every
           socket here is created with NX_FRAGMENT_OKAY, so DF is clear.
           Two unlike datagrams sharing an ID is what makes a downstream
           reassembly join the wrong fragments.  */
        packet_ptr -> nx_packet_identical_copy = NX_FALSE;
    }


#ifndef NX_DISABLE_TCP_INFO
    /* Increment the TCP retransmit count.  */
    ip_ptr -> nx_ip_tcp_retransmit_packets++;

    /* Increment the TCP retransmit count for the socket.  */
    socket_ptr -> nx_tcp_socket_retransmit_packets++;
#endif

#ifdef NX_ENABLE_VLAN
    if (socket_ptr -> nx_tcp_socket_vlan_priority != NX_VLAN_PRIORITY_INVALID)
    {
        packet_ptr -> nx_packet_vlan_priority = socket_ptr -> nx_tcp_socket_vlan_priority;
    }
#endif /* NX_ENABLE_VLAN */
        
    /* If trace is enabled, insert this event into the trace buffer.  */
    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_RETRY, ip_ptr, socket_ptr, packet_ptr, socket_ptr -> nx_tcp_socket_timeout_retries, NX_TRACE_INTERNAL_EVENTS, 0, 0);

    /* Clear the queue next pointer.  */
    packet_ptr -> nx_packet_queue_next =  NX_NULL;

    /* Yes, the driver has finished with the packet at the head of the
       transmit sent list... so it can be sent again!  */

#ifndef NX_DISABLE_IPV4
    /* Is this an IPv4 connection? */
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        _nx_ip_packet_send(ip_ptr, packet_ptr,
                           socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4,
                           socket_ptr -> nx_tcp_socket_type_of_service,
                           socket_ptr -> nx_tcp_socket_time_to_live, NX_IP_TCP,
                           socket_ptr -> nx_tcp_socket_fragment_enable,
                           socket_ptr -> nx_tcp_socket_next_hop_address);
    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
    {

        /* Handle for an IPv6 connection. */
        /* Set the packet transmit interface before sending. */
        packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = socket_ptr -> nx_tcp_socket_ipv6_addr;

        _nx_ipv6_packet_send(ip_ptr, packet_ptr, NX_PROTOCOL_TCP,
                             packet_ptr -> nx_packet_length, ip_ptr -> nx_ipv6_hop_limit, 0,
                             socket_ptr -> nx_tcp_socket_ipv6_addr -> nxd_ipv6_address,
                             socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6);
    }
#endif /* FEATURE_NX_IPV6 */
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_retransmit                           PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function retransmit a TCP packet.                              */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    socket_ptr                            Pointer to owning socket      */
/*    need_fast_retransmit                  Need fast retransmit or not   */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_packet_send_probe             Send zero window probe        */
/*    _nx_ip_checksum_compute               Calculate TCP checksum        */
/*    _nx_ip_packet_send                    Resend the transmit packet    */
/*    _nx_ipv6_packet_send                  Resend the transmit packet    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing      Process TCP packet for socket */
/*    _nx_tcp_socket_state_ack_check        Process ACK number            */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_socket_retransmit(NX_IP *ip_ptr, NX_TCP_SOCKET *socket_ptr, UINT need_fast_retransmit)
{
NX_PACKET *packet_ptr;
ULONG      window;
ULONG      available;
#ifdef NX_ENABLE_TCP_SACK
ULONG      sack_left[NX_TCP_SACK_MAX_BLOCKS];
ULONG      sack_right[NX_TCP_SACK_MAX_BLOCKS];
ULONG      sack_high;
ULONG      sacked_bytes;
ULONG      unacked;
ULONG      in_flight;
UINT       sack_blocks;
UINT       sack_index;
#endif /* NX_ENABLE_TCP_SACK */

#ifdef NX_ENABLE_TCP_RTT_ESTIMATOR

    /* Karn's algorithm, RFC 6298 section 3.  Whatever is about to go out again
       carries a sequence number that has already been sent, so an
       acknowledgment covering it says nothing about which transmission it
       answers.  Abandon the measurement in progress; the next segment carrying
       new data starts another one, and section 5.5's backoff holds the timeout
       up in the meantime.  */
    socket_ptr -> nx_tcp_socket_rtt_timing = NX_FALSE;
#endif /* NX_ENABLE_TCP_RTT_ESTIMATOR */

    /* If the receiver winodw is zero, we enter the zero window probe phase
       RFC 793 Sec 3.7, p42: keep send new data.

       In the zero window probe phase, we send the zero window probe, and increase
       exponentially the interval between successive probes.
       RFC 1122 Sec 4.2.2.17, p92.  */
    if (socket_ptr -> nx_tcp_socket_tx_window_advertised == 0)
    {

        /* Pickup the head of the transmit queue.  */
        packet_ptr =  socket_ptr -> nx_tcp_socket_transmit_sent_head;

        if (packet_ptr)
        {

        /* Get one byte from send queue. */
        /* Pick up the pointer to the head of the TCP packet.  */
        /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
        NX_TCP_HEADER *header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

            NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);
            NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_sequence_number);

            /* Get sequence number and first byte. */
            socket_ptr -> nx_tcp_socket_zero_window_probe_data = *(packet_ptr -> nx_packet_prepend_ptr + ((header_ptr -> nx_tcp_header_word_3 >> 28) << 2));

            /* Now set zero window probe started. */
            socket_ptr -> nx_tcp_socket_zero_window_probe_sequence = header_ptr -> nx_tcp_sequence_number;

            /* The failure count belongs to the probe, not to each attempt at
               it: clear it only when a new probe starts, as the two places in
               nx_tcp_socket_send_internal.c that arm one do.  Clearing it
               here on every attempt pinned it at one, so the retry limit that
               _nx_tcp_fast_periodic_processing() tests against it during a
               zero window could never be reached and a peer that stopped
               answering its probes was never given up on.  A peer that does
               answer still clears it (nx_tcp_socket_state_ack_check.c).  */
            if (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_FALSE)
            {
                socket_ptr -> nx_tcp_socket_zero_window_probe_has_data = NX_TRUE;
                socket_ptr -> nx_tcp_socket_zero_window_probe_failure = 0;
            }

            NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_sequence_number);
            NX_CHANGE_ULONG_ENDIAN(header_ptr -> nx_tcp_header_word_3);
        }
        else if (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_FALSE)
        {
            return;
        }

        /* In the zero window probe phase, we send the zero window probe, and increase
           exponentially the interval between successive probes.  */

        /* Increment the retry counter.  */
        socket_ptr -> nx_tcp_socket_timeout_retries++;
        socket_ptr -> nx_tcp_socket_zero_window_probe_failure++;

        /* Setup the next timeout.  */
        socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate <<
            (socket_ptr -> nx_tcp_socket_timeout_retries * socket_ptr -> nx_tcp_socket_timeout_shift);

        /* Send the zero window probe.  */
        _nx_tcp_packet_send_probe(socket_ptr, socket_ptr -> nx_tcp_socket_zero_window_probe_sequence,
                                  socket_ptr -> nx_tcp_socket_zero_window_probe_data);

        return;
    }
    else if (socket_ptr -> nx_tcp_socket_zero_window_probe_has_data == NX_TRUE)
    {

        /* If advertised window isn't zero, reset zero window probe flag. */
        socket_ptr -> nx_tcp_socket_zero_window_probe_has_data = NX_FALSE;
    }

#ifdef NX_ENABLE_TCP_SACK

    /* RFC 6675 section 5.1: a retransmission timeout says the connection has
       lost track of what the peer holds, so what it reported is dropped and
       the queue is resent from the front.  A fast retransmit, and the partial
       acknowledgments that follow it, are the case the blocks exist for and
       keep them.  */
    if ((need_fast_retransmit == NX_FALSE) && (socket_ptr -> nx_tcp_socket_fast_recovery == NX_FALSE))
    {
        socket_ptr -> nx_tcp_socket_sack_block_count = 0;
    }
#endif /* NX_ENABLE_TCP_SACK */

    /* Increment the retry counter only if the receiver window is open. */
    /* Increment the retry counter.  */
    socket_ptr -> nx_tcp_socket_timeout_retries++;

    if ((need_fast_retransmit == NX_TRUE) || (socket_ptr -> nx_tcp_socket_fast_recovery == NX_FALSE))
    {

        /* Timed out on an outgoing packet.  Enter slow start mode. */
        /* Compute the flight size / 2 value. */
        window = socket_ptr -> nx_tcp_socket_tx_outstanding_bytes >> 1;

        /* Make sure we have at least 2 * MSS */
        if (window < (socket_ptr -> nx_tcp_socket_connect_mss << 1))
        {
            window = socket_ptr -> nx_tcp_socket_connect_mss << 1;
        }

        /* Set the slow_start_threshold */
        socket_ptr -> nx_tcp_socket_tx_slow_start_threshold = window;

        /* Set the current window to be MSS size. */
        socket_ptr -> nx_tcp_socket_tx_window_congestion = socket_ptr -> nx_tcp_socket_connect_mss;

        /* Determine if this socket needs fast retransmit.  */
        if (need_fast_retransmit == NX_TRUE)
        {

            /* Update cwnd to ssthreshold plus 3 * MSS.  */
            socket_ptr -> nx_tcp_socket_tx_window_congestion += window + (socket_ptr -> nx_tcp_socket_connect_mss << 1);

            /* Now TCP is in fast recovery procedure. */
            socket_ptr -> nx_tcp_socket_fast_recovery = NX_TRUE;

            /* Update the transmit sequence that enters fast transmit. */
            socket_ptr -> nx_tcp_socket_tx_sequence_recover = socket_ptr -> nx_tcp_socket_tx_sequence - 1;
        }
    }

    /* Setup the next timeout.  */
    socket_ptr -> nx_tcp_socket_timeout = socket_ptr -> nx_tcp_socket_timeout_rate <<
        (socket_ptr -> nx_tcp_socket_timeout_retries * socket_ptr -> nx_tcp_socket_timeout_shift);

    /* Get available size of packet that can be sent. */
    available = socket_ptr -> nx_tcp_socket_tx_window_congestion;

#ifdef NX_ENABLE_TCP_SACK

    /* Take the blocks the peer reported that still describe unacknowledged
       data.  A block at or below the cumulative acknowledgment, or past what
       has been sent, is stale -- the window has moved over it since -- and is
       dropped here rather than trusted, so a block can never outlive the data
       it described.  */
    unacked = socket_ptr -> nx_tcp_socket_tx_sequence - socket_ptr -> nx_tcp_socket_tx_outstanding_bytes;
    sack_high = unacked;
    sacked_bytes = 0;
    sack_blocks = 0;

    for (sack_index = 0; sack_index < (UINT)socket_ptr -> nx_tcp_socket_sack_block_count; sack_index++)
    {

        if ((((INT)(socket_ptr -> nx_tcp_socket_sack_left[sack_index] - unacked)) <= 0) ||
            (((INT)(socket_ptr -> nx_tcp_socket_tx_sequence -
                    socket_ptr -> nx_tcp_socket_sack_right[sack_index])) < 0))
        {
            continue;
        }

        sack_left[sack_blocks] = socket_ptr -> nx_tcp_socket_sack_left[sack_index];
        sack_right[sack_blocks] = socket_ptr -> nx_tcp_socket_sack_right[sack_index];
        sacked_bytes = sacked_bytes + (sack_right[sack_blocks] - sack_left[sack_blocks]);

        if (((INT)(sack_right[sack_blocks] - sack_high)) > 0)
        {
            sack_high = sack_right[sack_blocks];
        }

        sack_blocks++;
    }

    if ((sack_blocks > 0) && (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE))
    {

        /* The blocks say how much of what is outstanding the peer already has,
           so what is still in the network is the rest.  RFC 6675 section 3
           calls that the pipe, and the room under the congestion window is
           what may go out now.  That is what lets every hole the peer
           described leave in this round instead of one per round trip, which
           is all NewReno on its own can infer.  Never less than the one
           segment that would have been sent without the blocks.  */
        if (socket_ptr -> nx_tcp_socket_tx_outstanding_bytes > sacked_bytes)
        {
            in_flight = socket_ptr -> nx_tcp_socket_tx_outstanding_bytes - sacked_bytes;
        }
        else
        {
            in_flight = 0;
        }

        if (available > in_flight)
        {
            available = available - in_flight;
        }
        else
        {
            available = 0;
        }

        if (available < socket_ptr -> nx_tcp_socket_connect_mss)
        {
            available = socket_ptr -> nx_tcp_socket_connect_mss;
        }
    }
#endif /* NX_ENABLE_TCP_SACK */

    /* Pickup the head of the transmit queue.  */
    packet_ptr =  socket_ptr -> nx_tcp_socket_transmit_sent_head;

    /* Determine if the packet has been released by the
       application I/O driver.  */
    /*lint -e{923} suppress cast of ULONG to pointer.  */
    while (packet_ptr && (packet_ptr -> nx_packet_queue_next == (NX_PACKET *)NX_DRIVER_TX_DONE))
    {

    NX_PACKET     *next_ptr;
#ifdef NX_ENABLE_TCP_SACK
    ULONG          queued_word;
    ULONG          queued_begin;
    ULONG          queued_end;
    UINT           peer_holds_it = NX_FALSE;

        if (sack_blocks > 0)
        {

            /* Where this packet sits in the sequence space.  A queued packet
               that the driver has finished with holds its header at the
               prepend pointer, in network order.  */
            /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
            queued_word = ((NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr) -> nx_tcp_sequence_number;
            NX_CHANGE_ULONG_ENDIAN(queued_word);
            queued_begin = queued_word;

            /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
            queued_word = ((NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr) -> nx_tcp_header_word_3;
            NX_CHANGE_ULONG_ENDIAN(queued_word);
            queued_end = queued_begin + (packet_ptr -> nx_packet_length -
                                         ((queued_word >> NX_TCP_HEADER_SHIFT) * (ULONG)sizeof(ULONG)));

            /* Nothing at or above the highest byte the peer reported holding
               has been shown to be missing.  RFC 6675 section 4 draws the same
               line from a count of SACKed segments above; one is enough here,
               where the transmit queue is a few packets deep and this is only
               reached after three duplicate acknowledgments.  Sending on any
               weaker evidence than that is guessing.  */
            if (((INT)(queued_begin - sack_high)) >= 0)
            {
                break;
            }

            /* A packet whose whole payload falls inside a block is one the
               peer has said it holds, so it is stepped over.  Stepped over and
               nothing more: the packet stays on the queue and stays counted,
               because RFC 2018 section 4 lets a receiver discard data it has
               already reported and the cumulative acknowledgment is the only
               thing that may release anything.

               A segment carrying no payload is never skipped.  A FIN occupies
               a sequence number that its length does not account for, so a
               block reaching up to it does not mean the peer saw it.  */
            if (((INT)(queued_end - queued_begin)) > 0)
            {
                for (sack_index = 0; sack_index < sack_blocks; sack_index++)
                {
                    if ((((INT)(queued_begin - sack_left[sack_index])) >= 0) &&
                        (((INT)(sack_right[sack_index] - queued_end)) >= 0))
                    {
                        peer_holds_it = NX_TRUE;
                        break;
                    }
                }
            }

            if (peer_holds_it == NX_TRUE)
            {

                next_ptr = packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next;

                /*lint -e{923} suppress cast of ULONG to pointer.  */
                if (next_ptr == (NX_PACKET *)NX_PACKET_ENQUEUED)
                {
                    break;
                }

                packet_ptr = next_ptr;
                continue;
            }
        }
#endif /* NX_ENABLE_TCP_SACK */

        if (packet_ptr -> nx_packet_length > (available + NX_TCP_SEGMENT_HEADER_LENGTH))
        {

            /* This packet can not be sent. */
            break;
        }

        /* Decrease the available size. */
        available -= (packet_ptr -> nx_packet_length - NX_TCP_SEGMENT_HEADER_LENGTH);

        /* Pickup next packet. */
        next_ptr = packet_ptr -> nx_packet_union_next.nx_packet_tcp_queue_next;

        /* Rebuild this segment's header and send it. */
        _nx_tcp_socket_retransmit_packet(ip_ptr, socket_ptr, packet_ptr);

        /* Move to next packet. */
        /* During fast recovery, only one packet is retransmitted at once. */
        /* After a timeout, the sending data can be at most one SMSS. */
        /*lint -e{923} suppress cast of ULONG to pointer.  */
        if (next_ptr == (NX_PACKET *)NX_PACKET_ENQUEUED)
        {
            break;
        }
#ifdef NX_ENABLE_TCP_SACK
        else if ((socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE) && (sack_blocks == 0))
        {

            /* One segment per round trip is all a sender without blocks can
               infer.  With them the walk carries on, so every hole the peer
               described leaves in this round, under the window computed
               above.  */
            break;
        }
#else
        else if (socket_ptr -> nx_tcp_socket_fast_recovery == NX_TRUE)
        {
            break;
        }
#endif /* NX_ENABLE_TCP_SACK */
        else
        {
            packet_ptr = next_ptr;
        }
    }
}


#if defined(NX_ENABLE_TCP_LOSS_PROBE) && defined(NX_ENABLE_TCP_RTT_ESTIMATOR)

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_socket_retransmit_tail                      PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends RFC 8985 section 7.3's tail loss probe: one      */
/*    extra copy of the LAST unacknowledged segment.                       */
/*                                                                        */
/*    Section 7.3 asks for unsent data first and the last unacknowledged   */
/*    segment otherwise.  There is no unsent data to ask for here: this    */
/*    stack blocks the application in _nx_tcp_socket_send() rather than    */
/*    queueing what the window will not carry, so everything on            */
/*    nx_tcp_socket_transmit_sent_head has been sent once already and the  */
/*    second clause is the only one that can apply.                        */
/*                                                                        */
/*    WHY NOT _nx_tcp_socket_retransmit().  That walks from the HEAD of    */
/*    the queue, so on a flight of more than one segment it probed the     */
/*    oldest -- the one three duplicate acknowledgments and the timeout    */
/*    both already recover -- and left the tail, which is the only         */
/*    segment neither of them can reach and the whole reason section 7.2   */
/*    exists.  On a flight of one the two are the same packet, which is    */
/*    why the request/response shape the probe was added for never showed  */
/*    it.                                                                  */
/*                                                                        */
/*    It also decided things a probe has no business deciding.  Its RFC    */
/*    6675 section 5.1 clause drops what the peer reported whenever this   */
/*    is neither a fast retransmit nor recovery, which is exactly a        */
/*    probe's precondition, so every probe emptied                         */
/*    nx_tcp_socket_sack_block_count and the next fast retransmit had to   */
/*    rebuild the block list from nothing.  The caller saved and restored  */
/*    the congestion window, the slow start threshold, the retry count and */
/*    the timeout, and could not save that.  Going straight to the packet  */
/*    leaves all five alone by construction, and the caller's save and     */
/*    restore is gone with it.                                             */
/*                                                                        */
/*    RFC 8985 section 7.3 permits the probe to exceed the congestion      */
/*    window by this one segment, so no window is consulted.                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                IP instance pointer           */
/*    socket_ptr                            Pointer to owning socket      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_tcp_socket_retransmit_packet      Rebuild and send one segment  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_fast_periodic_processing      The probe timer               */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_socket_retransmit_tail(NX_IP *ip_ptr, NX_TCP_SOCKET *socket_ptr)
{
NX_PACKET *packet_ptr;


    packet_ptr = socket_ptr -> nx_tcp_socket_transmit_sent_tail;

    /* Nothing queued, or the driver has not handed this one back yet.  A
       packet still with the driver is going out on its own.  */
    /*lint -e{923} suppress cast of ULONG to pointer.  */
    if ((packet_ptr == NX_NULL) ||
        (packet_ptr -> nx_packet_queue_next != (NX_PACKET *)NX_DRIVER_TX_DONE))
    {
        return;
    }

    /* Karn's algorithm, RFC 6298 section 3.  A probe carries a sequence
       number that has already been sent, so an acknowledgment covering it
       does not say which copy it answers.  */
    socket_ptr -> nx_tcp_socket_rtt_timing = NX_FALSE;

    _nx_tcp_socket_retransmit_packet(ip_ptr, socket_ptr, packet_ptr);
}

#endif /* NX_ENABLE_TCP_LOSS_PROBE && NX_ENABLE_TCP_RTT_ESTIMATOR */
