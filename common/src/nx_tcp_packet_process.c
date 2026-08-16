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
#include "nx_packet.h"
#include "nx_ip.h"

#ifdef FEATURE_NX_IPV6
#include "nx_ipv6.h"
#endif /* FEATURE_NX_IPV6 */

#ifdef NX_IPSEC_ENABLE
#include "nx_ipsec.h"
#endif /* NX_IPSEC_ENABLE */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_packet_process                              PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes an incoming TCP packet, which includes      */
/*    matching the packet to an existing connection and dispatching to    */
/*    the socket specific processing routine.  If no connection is        */
/*    found, this routine checks for a new connection request and if      */
/*    found, hands it to the SYN cache -- which is where a connection to  */
/*    a listening port lives until its handshake finishes, and why one    */
/*    that never finishes costs this machine no socket and no packet.     */
/*    See nx_tcp_syncache.c.                                             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    ip_ptr                                Pointer to IP control block   */
/*    packet_ptr                            Pointer to packet to send     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_release                    Packet release function       */
/*    _nx_ip_checksum_compute               Calculate TCP packet checksum */
/*    _nx_tcp_mss_option_get                Get peer MSS option           */
/*    _nx_tcp_no_connection_reset           Reset on no connection        */
/*    _nx_tcp_socket_packet_process         Socket specific packet        */
/*                                            processing routine          */
/*    _nx_tcp_syncache_syn_received         Record a half-open connection */
/*    _nx_tcp_syncache_ack_received         Finish one, or check a cookie */
/*    _nx_tcp_syncache_reset_received       Cancel one                    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_queue_process                 Process TCP packet queue      */
/*    _nx_tcp_packet_receive                Receive packet processing     */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_packet_process(NX_IP *ip_ptr, NX_PACKET *packet_ptr)
{

UINT                         index;
UINT                         port;
ULONG                       *source_ip = NX_NULL;
ULONG                       *dest_ip = NX_NULL;
UINT                         source_port;
NX_TCP_SOCKET               *socket_ptr;
NX_TCP_HEADER               *tcp_header_ptr;
struct NX_TCP_LISTEN_STRUCT *listen_ptr;
ULONG                        option_words;
ULONG                        mss = 0;
ULONG                        checksum;
NX_INTERFACE                *interface_ptr = NX_NULL;
#if defined(NX_DISABLE_TCP_RX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE)
UINT                         compute_checksum = 1;
#endif /* defined(NX_DISABLE_TCP_RX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE) */
UINT                         is_valid_option_flag = NX_TRUE;
UINT                         status;
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
ULONG                        rwin_scale = 0xFF;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
#ifdef NX_ENABLE_TCP_SACK
ULONG                        sack_permitted = NX_FALSE;
#endif /* NX_ENABLE_TCP_SACK */
#ifdef NX_ENABLE_TCP_TIMESTAMP
ULONG                        timestamp_present = NX_FALSE;
ULONG                        timestamp_value = 0;
ULONG                        timestamp_echo = 0;
#endif /* NX_ENABLE_TCP_TIMESTAMP */

#ifdef NX_DISABLE_TCP_RX_CHECKSUM
    compute_checksum = 0;
#endif /* NX_DISABLE_TCP_RX_CHECKSUM */

    /* Add debug information. */
    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

    /* Pickup the source IP address.  */
#ifndef NX_DISABLE_IPV4
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
    {

    NX_IPV4_HEADER *ip_header_ptr;

        /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
        ip_header_ptr = (NX_IPV4_HEADER *)packet_ptr -> nx_packet_ip_header;

        source_ip = &ip_header_ptr -> nx_ip_header_source_ip;

        dest_ip = &ip_header_ptr -> nx_ip_header_destination_ip;

        mss = 536;

        interface_ptr = packet_ptr -> nx_packet_address.nx_packet_interface_ptr;

        /* A TCP segment addressed to a broadcast or a multicast destination
           must be silently discarded, outlined in RFC 1122, Section 4.2.3.10,
           Page 105.  Every host on the link received it, so any answer -- a
           SYN/ACK from a listening port, a RST from a closed one -- is sent
           by all of them at once to whatever source address the segment
           carried.  */
        if (((*dest_ip & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE) ||
            (*dest_ip == NX_IP_LIMITED_BROADCAST) ||
            (((*dest_ip & interface_ptr -> nx_interface_ip_network_mask) ==
              interface_ptr -> nx_interface_ip_network) &&
             ((*dest_ip & ~(interface_ptr -> nx_interface_ip_network_mask)) ==
              ~(interface_ptr -> nx_interface_ip_network_mask))))
        {

#ifndef NX_DISABLE_TCP_INFO

            /* Increment the TCP invalid packet error count.  */
            ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

            /* Release the packet.  */
            _nx_packet_release(packet_ptr);

            /* Finished processing, simply return!  */
            return;
        }
    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
    {

    /* IPv6 */
    NX_IPV6_HEADER *ipv6_header;

        /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
        ipv6_header = (NX_IPV6_HEADER *)packet_ptr -> nx_packet_ip_header;

        source_ip = &ipv6_header -> nx_ip_header_source_ip[0];

        dest_ip = &ipv6_header -> nx_ip_header_destination_ip[0];

        mss = 1220;

        interface_ptr = packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr -> nxd_ipv6_address_attached;
    }
#endif /* FEATURE_NX_IPV6 */

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    if ((interface_ptr -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM) &&
        (packet_ptr -> nx_packet_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_RX_CHECKSUM))
    {
        compute_checksum = 0;
    }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY */

#ifdef NX_IPSEC_ENABLE
    if ((packet_ptr -> nx_packet_ipsec_sa_ptr != NX_NULL) && (((NX_IPSEC_SA *)(packet_ptr -> nx_packet_ipsec_sa_ptr)) -> nx_ipsec_sa_encryption_method != NX_CRYPTO_NONE))
    {
        compute_checksum = 1;
    }
#endif /* NX_IPSEC_ENABLE */

#if defined(NX_DISABLE_TCP_RX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE)
    if (compute_checksum)
#endif /* defined(NX_DISABLE_TCP_RX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE) */
    {
        checksum = _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                           (UINT)packet_ptr -> nx_packet_length,
                                           source_ip, dest_ip);

        checksum = NX_LOWER_16_MASK & ~checksum;

        /* Calculate the checksum.  */
        if (checksum != 0)
        {

#ifndef NX_DISABLE_TCP_INFO

            /* Increment the TCP invalid packet error count.  */
            ip_ptr -> nx_ip_tcp_invalid_packets++;

            /* Increment the TCP packet checksum error count.  */
            ip_ptr -> nx_ip_tcp_checksum_errors++;
#endif

            /* Checksum error, just release the packet.  */
            _nx_packet_release(packet_ptr);
            return;
        }
    }

#ifndef NX_DISABLE_RX_SIZE_CHECKING
    /* Make sure the TCP header is in the first packet.  */
    if ((UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) < sizeof(NX_TCP_HEADER))
    {

#ifndef NX_DISABLE_TCP_INFO
        /* Increment the TCP invalid packet error.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif

        /* Not supported.  */
        _nx_packet_release(packet_ptr);
        return;
    }
#endif /* NX_DISABLE_RX_SIZE_CHECKING */

    /* Pickup the pointer to the head of the TCP packet.  */
    /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
    tcp_header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the TCP header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Determine if there are any option words...  Note there are always 5 words in a TCP header.  */
    option_words =  (tcp_header_ptr -> nx_tcp_header_word_3 >> 28) - 5;

#ifndef NX_DISABLE_RX_SIZE_CHECKING
    /* Check for valid packet length.  */
    if (((INT)option_words < 0) ||
        ((UINT)(packet_ptr -> nx_packet_append_ptr - packet_ptr -> nx_packet_prepend_ptr) <
         (sizeof(NX_TCP_HEADER) + (option_words << 2))))
    {

#ifndef NX_DISABLE_TCP_INFO
        /* Increment the TCP invalid packet error.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif

        /* Invalid packet length, just release it.  */
        _nx_packet_release(packet_ptr);

        /* The function is complete, just return!  */
        return;
    }
#endif

    if (option_words)
    {
        /* MSS, window scaling and SACK-permitted are SYN-only: each is a
           separate walk of the option area, and the values are consumed
           below only under the SYN bit.  Timestamps put options on every
           segment, so without this test all three run on every packet of an
           established connection and can never match.  Measured at 162 of
           the 825 samples timestamps add to a 6 MB write on an A1200.  */
        if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
        {

            /* Derive the Maximum Segment Size (MSS) in the option words.  */
            status = _nx_tcp_mss_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words * (ULONG)sizeof(ULONG), &mss);

            /* Check the status. if status is NX_FALSE, means Option Length is invalid.  */
            if (status == NX_FALSE)
            {

                /* The option is invalid.  */
                is_valid_option_flag = NX_FALSE;
            }
            else
            {

                /* Set the default MSS if the MSS value was not found.  */
                /*lint -e{644} suppress variable might not be initialized, since "mss" was initialized in _nx_tcp_mss_option_get. */
                if (mss == 0)
                {
#ifndef NX_DISABLE_IPV4
                    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
                    {
                        mss = 536;
                    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
                    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
                    {
                        mss = 1220;
                    }
#endif /* FEATURE_NX_IPV6 */
                }
            }

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
            status = _nx_tcp_window_scaling_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words * (ULONG)sizeof(ULONG), &rwin_scale);

            /* Check the status. if status is NX_FALSE, means Option Length is invalid.  */
            if (status == NX_FALSE)
            {
                is_valid_option_flag = NX_FALSE;
            }
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

#ifdef NX_ENABLE_TCP_SACK
            status = _nx_tcp_sack_permitted_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)), option_words * (ULONG)sizeof(ULONG), &sack_permitted);

            /* Check the status. if status is NX_FALSE, means Option Length is invalid.  */
            if (status == NX_FALSE)
            {
                is_valid_option_flag = NX_FALSE;
            }
#endif /* NX_ENABLE_TCP_SACK */
        }

#ifdef NX_ENABLE_TCP_TIMESTAMP

        /* RFC 1323 section 3.2.  A SYN carrying the option is the offer; both
           SYNs have to carry it before either side may send timestamps on
           anything else.  */
        timestamp_present = (ULONG)_nx_tcp_timestamp_option_get((packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER)),
                                                                option_words * (ULONG)sizeof(ULONG),
                                                                &timestamp_value, &timestamp_echo);
#endif /* NX_ENABLE_TCP_TIMESTAMP */
    }

    /* Pickup the destination TCP port.  */
    port =  (UINT)(tcp_header_ptr -> nx_tcp_header_word_0 & NX_LOWER_16_MASK);

    /* Pickup the source TCP port.  */
    source_port =  (UINT)(tcp_header_ptr -> nx_tcp_header_word_0 >> NX_SHIFT_BY_16);

    /* Calculate the hash index in the TCP port array of the associated IP instance.  */
    index =  (UINT)((port + (port >> 8)) & NX_TCP_PORT_TABLE_MASK);

    /* Search the bound sockets in this index for the particular port.  */
    socket_ptr =  ip_ptr -> nx_ip_tcp_port_table[index];

    /* Determine if there are any sockets bound on this port index.  */
    if (socket_ptr)
    {

    INT find_a_match;

        /*  Yes, loop to examine the list of bound ports on this index.  */
        do
        {

            find_a_match = 0;

            /* Determine if the port has been found.  */
            if ((socket_ptr -> nx_tcp_socket_port == port) &&
                (socket_ptr -> nx_tcp_socket_connect_port == source_port))
            {

                /* Make sure they are the same IP protocol */
                if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == packet_ptr -> nx_packet_ip_version)
                {

#ifndef NX_DISABLE_IPV4
                    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
                    {

                        if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4 == *source_ip)
                        {
                            find_a_match = 1;
                        }
                    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
                    if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
                    {
                        if (CHECK_IPV6_ADDRESSES_SAME(socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6, source_ip))
                        {
                            find_a_match = 1;
                        }
                    }
#endif /* FEATURE_NX_IPV6 */
                }

                if (find_a_match)
                {

                    /* Yes, we have a match!  */

                    /* Determine if we need to update the tcp port head pointer.  This should
                       only be done if the found socket pointer is not the head pointer and
                       the mutex for this IP instance is available.  */

                    /* Move the port head pointer to this socket.  */
                    ip_ptr -> nx_ip_tcp_port_table[index] = socket_ptr;

                    /* A SYN carries the options that settle a connection, so it is
                       read only while one is still being settled.  RFC 5961 section 4
                       answers a SYN in a synchronised state with a challenge
                       acknowledgment and leaves the connection as it was, which
                       _nx_tcp_socket_packet_process does -- but this runs first, so
                       without the state test one stray SYN rewrote the MSS, the peer's
                       window scale and SACK permission on a live connection.  A bare
                       SYN does it and needs no sequence number to be accepted here:
                       the three fall back to 536, to 0xFF and to false.  */
                    if ((tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT) &&
                        ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
                         (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED)))
                    {

                        /* Record the MSS value if it is present and the   Otherwise use 536, as
                           outlined in RFC 1122 section 4.2.2.6. */
                        socket_ptr -> nx_tcp_socket_peer_mss = mss;

                        if ((mss > socket_ptr -> nx_tcp_socket_mss) && socket_ptr -> nx_tcp_socket_mss)
                        {
                            socket_ptr -> nx_tcp_socket_connect_mss  = socket_ptr -> nx_tcp_socket_mss;
                        }
                        else if ((socket_ptr -> nx_tcp_socket_state != NX_TCP_SYN_SENT) ||
                                 (socket_ptr -> nx_tcp_socket_connect_mss > mss))
                        {
                            socket_ptr -> nx_tcp_socket_connect_mss  = mss;
                        }

                        /* Compute the SMSS * SMSS value, so later TCP module doesn't need to redo the multiplication. */
                        socket_ptr -> nx_tcp_socket_connect_mss2 =
                            socket_ptr -> nx_tcp_socket_connect_mss * socket_ptr -> nx_tcp_socket_connect_mss;
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
                        /*
                           Simply record the peer's window scale value. When we move to the
                           ESTABLISHED state, we will set the peer window scale to 0 if the
                           peer does not support this feature.
                         */
                        socket_ptr -> nx_tcp_snd_win_scale_value = rwin_scale;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

#ifdef NX_ENABLE_TCP_SACK

                        /* RFC 2018 section 2: the option has to be on both SYNs, so what the
                           peer's SYN carried decides whether this side may describe its
                           holes in blocks.  */
                        socket_ptr -> nx_tcp_socket_sack_permitted = (UCHAR)sack_permitted;

                        /* Nothing a previous connection on this socket reported survives
                           into this one.  */
                        socket_ptr -> nx_tcp_socket_sack_block_count = 0;
#endif /* NX_ENABLE_TCP_SACK */

#ifdef NX_ENABLE_TCP_TIMESTAMP

                        /* RFC 1323 section 3.2, the same rule for the same reason.
                           Clearing the flag with segments already on the transmit
                           queue also makes the segment header twelve bytes shorter
                           than the header those segments were built with, so the
                           retransmission accounts and rebuilds them wrongly.  */
                        socket_ptr -> nx_tcp_socket_timestamp_enabled = (UCHAR)timestamp_present;
                        if (timestamp_present == NX_TRUE)
                        {
                            socket_ptr -> nx_tcp_socket_ts_recent = timestamp_value;
                        }
#endif /* NX_ENABLE_TCP_TIMESTAMP */
                    }

                    /* Process the packet within an existing TCP connection.  */
                    _nx_tcp_socket_packet_process(socket_ptr, packet_ptr);

                    /* Get out of the search loop and this function!  */
                    return;
                }
            }

            /* Move to the next entry in the bound index.  */
            socket_ptr =  socket_ptr -> nx_tcp_socket_bound_next;
        } while (socket_ptr != ip_ptr -> nx_ip_tcp_port_table[index]);
    }

    /* At this point, we know there is not an existing TCP connection.  */

    /* If this packet contains the valid option.  */
    if (is_valid_option_flag == NX_FALSE)
    {

        /* Send RST message.
           TCP MUST be prepared to handle an illegal option length (e.g., zero) without crashing;
           a suggested procedure is to reset the connection and log the reason, outlined in RFC 1122, Section 4.2.2.5, Page85. */

        /* A RESET is never answered with a RESET, RFC 793 Section 3.4 Page 36.
           The no-connection path at the end of this function already tests for
           it; a malformed option arrives here first and must not skip it.  */
        if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
        {
            _nx_tcp_no_connection_reset(ip_ptr, packet_ptr, tcp_header_ptr);
        }

#ifndef NX_DISABLE_TCP_INFO
        /* Increment the TCP invalid packet error count.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

        /* Not a connection request, just release the packet.  */
        _nx_packet_release(packet_ptr);

        return;
    }

#ifdef NX_ENABLE_TCP_MSS_CHECK
    /* Optionally check for a user specified minimum MSS. The user application may choose to
       define a minimum MSS value, and reject a TCP connection if peer MSS value does not
       meet the minimum. */
    if (mss < NX_TCP_MSS_MINIMUM)
    {

        /* Send RST message.  */
        _nx_tcp_no_connection_reset(ip_ptr, packet_ptr, tcp_header_ptr);

#ifndef NX_DISABLE_TCP_INFO
        /* Increment the TCP invalid packet error count.  */
        ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

        /* Handle this as an invalid connection request. */
        _nx_packet_release(packet_ptr);

        return;
    }
#endif

    /* Handle new connection requests without ACK bit in NX_TCP_SYN_RECEIVED state.
       NX_TCP_SYN_RECEIVED state is equal of LISTEN state of RFC.
       RFC793, Section3.9, Page65.

       The ACK that finishes a handshake the SYN cache is holding gets here
       too, and has to: no socket is bound to that connection yet, so the
       search above found nothing for it.  The test admits everything except a
       SYN+ACK, which is a segment no listening port ever has an answer for.
       nx_tcp_syncache.c says what the three cases below do with it.  */
    if ((ip_ptr -> nx_ip_tcp_active_listen_requests) &&
        ((!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)) ||
         (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT))))
    {

#ifndef NX_DISABLE_IPV4
        if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V4)
        {

            /* Check for LAND attack packet. This is an incoming packet with matching
               Source and Destination IP address, and matching source and destination port. */
            if ((*source_ip == *dest_ip) && (source_port == port))
            {

                /* Bogus packet. Drop it! */

#ifndef NX_DISABLE_TCP_INFO
                /* Increment the TCP invalid packet error count.  */
                ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

                /* Release the packet we will not process any further.  */
                _nx_packet_release(packet_ptr);
                return;
            }

            /* It shall not make connections if the source IP address
               is broadcast or multicast.   */
            if (
                /* Check for Multicast address */
                ((*source_ip & NX_IP_CLASS_D_MASK) == NX_IP_CLASS_D_TYPE) ||
                /* Check for subnet-directed broadcast */
                (((*source_ip & interface_ptr -> nx_interface_ip_network_mask) == interface_ptr -> nx_interface_ip_network) &&
                 ((*source_ip & ~(interface_ptr -> nx_interface_ip_network_mask)) == ~(interface_ptr -> nx_interface_ip_network_mask))) ||
                /* Check for local subnet address */
                (*source_ip == interface_ptr -> nx_interface_ip_network)  ||
                /* Check for limited broadcast */
                (*source_ip == NX_IP_LIMITED_BROADCAST)
               )
            {

#ifndef NX_DISABLE_TCP_INFO
                /* Increment the TCP invalid packet error count.  */
                ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

                /* Release the packet.  */
                _nx_packet_release(packet_ptr);

                /* Finished processing, simply return!  */
                return;
            }
        }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
        if (packet_ptr -> nx_packet_ip_version == NX_IP_VERSION_V6)
        {

            /* Check for LAND attack packet. This is an incoming packet with matching
               Source and Destination IP address, and matching source and destination port. */
            if ((CHECK_IPV6_ADDRESSES_SAME(source_ip, dest_ip)) && (source_port == port))
            {

                /* Bogus packet. Drop it! */

#ifndef NX_DISABLE_TCP_INFO
                /* Increment the TCP invalid packet error count.  */
                ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

                /* Release the packet we will not process any further.  */
                _nx_packet_release(packet_ptr);
                return;
            }

            /* It shall not make connections if the source IP address
               is broadcast or multicast.   */
            if (IPv6_Address_Type(source_ip) & IPV6_ADDRESS_MULTICAST)
            {

#ifndef NX_DISABLE_TCP_INFO
                /* Increment the TCP invalid packet error count.  */
                ip_ptr -> nx_ip_tcp_invalid_packets++;
#endif /* NX_DISABLE_TCP_INFO */

                /* Release the packet.  */
                _nx_packet_release(packet_ptr);

                /* Finished processing, simply return!  */
                return;
            }
        }
#endif /* FEATURE_NX_IPV6*/

        /* Search all ports in listen mode for a match. */
        listen_ptr =  ip_ptr -> nx_ip_tcp_active_listen_requests;
        do
        {

            /* Determine if this port is in a listen mode.  */
            if (listen_ptr -> nx_tcp_listen_port == port)
            {

                /* A SYN opens a connection, an ACK finishes one the SYN
                   cache is holding, and a RST cancels one.  Fourth other
                   text or control, RFC 793 section 3.9 page 66: nothing.  */
                if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT)
                {

                    /* A half-open connection this end is holding for that
                       peer is over.  There is nothing else to release: the
                       cache holds no packet and has committed no socket.  */
                    _nx_tcp_syncache_reset_received(ip_ptr, source_ip,
                                                    packet_ptr -> nx_packet_ip_version,
                                                    port, source_port);

#ifndef NX_DISABLE_TCP_INFO
                    /* Increment the TCP dropped packet count.  */
                    ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif

                    _nx_packet_release(packet_ptr);

                    return;
                }

                if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
                {

#ifndef NX_DISABLE_TCP_INFO
                    /* A connection has been requested.  It is not a
                       connection yet -- nx_ip_tcp_connections counts the ones
                       whose handshake finished, which under a flood is the
                       difference that matters.  */
                    ip_ptr -> nx_ip_tcp_passive_connections++;
#endif

                    /* If trace is enabled, insert this event into the trace buffer.  */
                    NX_TRACE_IN_LINE_INSERT(NX_TRACE_INTERNAL_TCP_SYN_RECEIVE, ip_ptr, NX_NULL, packet_ptr, tcp_header_ptr -> nx_tcp_sequence_number, NX_TRACE_INTERNAL_EVENTS, 0, 0);

                    /* Record the half-open connection, or answer it with a
                       cookie if there is no room left to record one.  No
                       socket is committed and no packet is held either way:
                       that is the whole of the defence, and nx_tcp_syncache.c
                       is where it is described.  */
                    _nx_tcp_syncache_syn_received(ip_ptr, listen_ptr, packet_ptr, tcp_header_ptr,
                                                  source_ip, dest_ip, source_port, interface_ptr,
                                                  mss,
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
                                                  rwin_scale,
#else
                                                  0xFF,
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
#ifdef NX_ENABLE_TCP_SACK
                                                  sack_permitted,
#else
                                                  NX_FALSE,
#endif /* NX_ENABLE_TCP_SACK */
#ifdef NX_ENABLE_TCP_TIMESTAMP
                                                  timestamp_present, timestamp_value
#else
                                                  NX_FALSE, 0
#endif /* NX_ENABLE_TCP_TIMESTAMP */
                                                  );

                    _nx_packet_release(packet_ptr);

                    return;
                }

                if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_ACK_BIT)
                {

                    /* The third segment of a handshake, or a stray.  If it is
                       ours the connection is built here and a socket is
                       committed to it for the first time.  */
                    if (_nx_tcp_syncache_ack_received(ip_ptr, listen_ptr, packet_ptr, tcp_header_ptr,
                                                      source_ip, dest_ip, source_port, interface_ptr,
#ifdef NX_ENABLE_TCP_TIMESTAMP
                                                      timestamp_present, timestamp_value
#else
                                                      NX_FALSE, 0
#endif /* NX_ENABLE_TCP_TIMESTAMP */
                                                      ) != NX_TRUE)
                    {

#ifndef NX_DISABLE_TCP_INFO
                        /* Not a handshake this end started.  Dropped rather
                           than reset: a reset per unmatched acknowledgment is
                           a segment an attacker gets this machine to send for
                           nothing, and a peer holding a connection this end
                           has forgotten learns that from its own retransmit
                           timer.  */
                        ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif
                    }

                    _nx_packet_release(packet_ptr);

                    return;
                }

#ifndef NX_DISABLE_TCP_INFO
                /* Neither of the three.  */
                ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif /* NX_DISABLE_TCP_INFO */

                /* Release the packet.  */
                _nx_packet_release(packet_ptr);

                /* Finished processing, just return.  */
                return;
            }

            /* Move to the next listen request.  */
            listen_ptr = listen_ptr -> nx_tcp_listen_next;
        } while (listen_ptr != ip_ptr -> nx_ip_tcp_active_listen_requests);
    }

#ifndef NX_DISABLE_TCP_INFO

    /* Determine if a connection request is present.  */
    if (tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_SYN_BIT)
    {

        /* Yes, increment the TCP connections dropped count.  */
        ip_ptr -> nx_ip_tcp_connections_dropped++;
    }

    /* Increment the TCP dropped packet count.  */
    ip_ptr -> nx_ip_tcp_receive_packets_dropped++;
#endif /* NX_DISABLE_TCP_INFO  */

    /* Determine if a RST is present. If so, don't send a RST in response.  */
    if (!(tcp_header_ptr -> nx_tcp_header_word_3 & NX_TCP_RST_BIT))
    {

        /* Non RST is present, send reset when no connection is present.  */
        _nx_tcp_no_connection_reset(ip_ptr, packet_ptr, tcp_header_ptr);
    }

    /* Not a connection request, just release the packet.  */
    _nx_packet_release(packet_ptr);

    return;
}

