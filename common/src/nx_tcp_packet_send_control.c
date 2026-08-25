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
#ifdef NX_IPSEC_ENABLE
#include "nx_ipsec.h"
#endif /* NX_IPSEC_ENABLE */


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_packet_send_control                         PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a TCP control packet from the specified socket. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    socket_ptr                            Pointer to socket             */
/*    control_bits                          TCP control bits              */
/*    tx_sequence                           Transmit sequence number      */
/*    ack_number                            Transmit acknowledge number   */
/*    option_word_1                         First SYN option word         */
/*    option_word_2                         Second SYN option word        */
/*    option_ptr                            Option bytes to append after  */
/*                                            the SYN option words, or    */
/*                                            NX_NULL                     */
/*    option_size                           Size of those bytes, a        */
/*                                            multiple of four            */
/*    data                                  Data of zero window probe     */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_packet_allocate                   Allocate a packet             */
/*    _nx_ip_checksum_compute               Calculate TCP checksum        */
/*    _nx_ip_packet_send                    Send IPv4 packet              */
/*    _nx_ipv6_packet_send                  Send IPv6 packet              */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_send_syn               Send SYN packet               */
/*    _nx_tcp_packet_send_ack               Send ACK packet               */
/*    _nx_tcp_packet_send_fin               Send FIN packet               */
/*    _nx_tcp_packet_send_rst               Send RST packet               */
/*    _nx_tcp_packet_send_probe             Send zero window probe packet */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_packet_send_control(NX_TCP_SOCKET *socket_ptr, ULONG control_bits, ULONG tx_sequence,
                                  ULONG ack_number, ULONG option_word_1, ULONG option_word_2,
                                  UCHAR *option_ptr, UINT option_size, UCHAR *data)
{

NX_IP         *ip_ptr;
NX_PACKET     *packet_ptr;
NX_TCP_HEADER *tcp_header_ptr;
ULONG          checksum;
ULONG          data_offset = 0;
ULONG         *source_ip = NX_NULL, *dest_ip = NX_NULL;
#if defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE)
UINT           compute_checksum = 1;
#endif /* defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE) */
ULONG          header_size;
ULONG          window_size;
#ifdef NX_ENABLE_TCP_TIMESTAMP
UINT           timestamp_size = 0;
#endif /* NX_ENABLE_TCP_TIMESTAMP */

#ifdef NX_DISABLE_TCP_TX_CHECKSUM
    compute_checksum = 0;
#endif /* NX_DISABLE_TCP_TX_CHECKSUM */

    /* Setup the IP pointer.  */
    ip_ptr =  socket_ptr -> nx_tcp_socket_ip_ptr;

    if (control_bits & NX_TCP_SYN_BIT)
    {

        /* Set header size. */
        header_size = NX_TCP_SYN_HEADER;
        window_size = socket_ptr -> nx_tcp_socket_rx_window_current;
    }
    else
    {

        /* Set header size. */
        header_size = NX_TCP_HEADER_SIZE;

        /* Set window size.  Clamped before the shift: the floor is in real
           bytes and the scaled field is not. */
        window_size = socket_ptr -> nx_tcp_socket_rx_window_current;

        if (window_size < NX_TCP_SWS_FLOOR(socket_ptr))
        {
            window_size = 0;
        }

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
        window_size = window_size >> socket_ptr -> nx_tcp_rcv_win_scale_value;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
    }

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    /* Make sure the window_size is less than 0xFFFF. */
    if (window_size > 0xFFFF)
    {
        window_size = 0xFFFF;
    }
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

    /* Options appended after the SYN option words widen the header.  The data
       offset field is what tells the peer where the payload starts, so it has
       to be grown here, before the header word is built.  */
    if ((option_ptr == NX_NULL) || ((option_size & 3) != 0))
    {

        /* Nothing to append, or a size that is not a whole number of option
           words and could not be described by the data offset field.  */
        option_size = 0;
    }
    else
    {
        header_size += ((ULONG)(option_size >> 2)) << NX_TCP_HEADER_SHIFT;
    }

#ifdef NX_ENABLE_TCP_TIMESTAMP

    /* RFC 1323 section 3.2: once negotiated the option belongs on every segment
       of the connection, not only the ones carrying data, or the peer's own
       round-trip estimate stops working across an exchange this side only
       acknowledges.

       Not on a SYN, which _nx_tcp_packet_send_syn builds its own option words
       for, and not on a reset, which is answering a connection this side may
       no longer have state for.  */
    if ((socket_ptr -> nx_tcp_socket_timestamp_enabled == NX_TRUE) &&
        (!(control_bits & NX_TCP_SYN_BIT)) &&
        (!(control_bits & NX_TCP_RST_BIT)))
    {
        timestamp_size = (UINT)NX_TCP_TIMESTAMP_OPTION_SIZE;
        header_size += ((ULONG)(timestamp_size >> 2)) << NX_TCP_HEADER_SHIFT;
    }
#endif /* NX_ENABLE_TCP_TIMESTAMP */

#ifdef NX_IPSEC_ENABLE
    /* Get data offset from socket directly. */
    data_offset = socket_ptr -> nx_tcp_socket_egress_sa_data_offset;
#endif /* NX_IPSEC_ENABLE */

#ifdef NX_ENABLE_DUAL_PACKET_POOL
    /* Allocate from auxiliary packet pool first. */
    if (_nx_packet_allocate(ip_ptr -> nx_ip_auxiliary_packet_pool, &packet_ptr, NX_IP_PACKET + data_offset, NX_NO_WAIT))
    {
        if (ip_ptr -> nx_ip_auxiliary_packet_pool != ip_ptr -> nx_ip_default_packet_pool)
#endif /* NX_ENABLE_DUAL_PACKET_POOL */
        {

            /*lint -e{835} -e{845} suppress operating on zero. */
            if (_nx_packet_allocate(ip_ptr -> nx_ip_default_packet_pool,
                                    &packet_ptr, NX_IP_PACKET + data_offset, NX_NO_WAIT) != NX_SUCCESS)
            {

                /* Just give up and return.  */
                return;
            }
        }
#ifdef NX_ENABLE_DUAL_PACKET_POOL
        else
        {

            /* Just give up and return.  */
            return;
        }
    }
#endif /* NX_ENABLE_DUAL_PACKET_POOL */

#ifdef NX_ENABLE_VLAN
    if (socket_ptr -> nx_tcp_socket_vlan_priority != NX_VLAN_PRIORITY_INVALID)
    {
        packet_ptr -> nx_packet_vlan_priority = socket_ptr -> nx_tcp_socket_vlan_priority;
    }
#endif /* NX_ENABLE_VLAN */

    /* Check to see if the packet has enough room to fill with the max TCP header (SYN + appended options + probe data).  */
#ifdef NX_ENABLE_TCP_TIMESTAMP
    if ((UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr) < (NX_TCP_SYN_SIZE + option_size + timestamp_size + 1))
#else
    if ((UINT)(packet_ptr -> nx_packet_data_end - packet_ptr -> nx_packet_prepend_ptr) < (NX_TCP_SYN_SIZE + option_size + 1))
#endif /* NX_ENABLE_TCP_TIMESTAMP */
    {

        /* Error getting packet, so just get out!  */
        _nx_packet_release(packet_ptr);
        return;
    }

    /*lint -e{644} suppress variable might not be initialized, since "packet_ptr" was initialized in _nx_packet_allocate. */
    packet_ptr -> nx_packet_ip_version = (UCHAR)(socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version);

    /* Allocate a packet for the control message.  */
#ifndef NX_DISABLE_IPV4
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {

        /* The outgoing interface should have been stored in the socket structure. */
        packet_ptr -> nx_packet_address.nx_packet_interface_ptr = socket_ptr -> nx_tcp_socket_connect_interface;
    }
#endif /* !NX_DISABLE_IPV4  */

    /* Add debug information. */
    NX_PACKET_DEBUG(__FILE__, __LINE__, packet_ptr);

#ifdef NX_IPSEC_ENABLE
    packet_ptr -> nx_packet_ipsec_sa_ptr = socket_ptr -> nx_tcp_socket_egress_sa;
#endif

    /* Setup the packet payload pointers and length for a basic TCP packet.  */
    packet_ptr -> nx_packet_append_ptr =  packet_ptr -> nx_packet_prepend_ptr + sizeof(NX_TCP_HEADER);

    /* Setup the packet length.  */
    packet_ptr -> nx_packet_length =  sizeof(NX_TCP_HEADER);

    /* Pickup the pointer to the head of the TCP packet.  */
    /*lint -e{927} -e{826} suppress cast of pointer to pointer, since it is necessary  */
    tcp_header_ptr =  (NX_TCP_HEADER *)packet_ptr -> nx_packet_prepend_ptr;

    /* Build the control request in the TCP header.  */
    tcp_header_ptr -> nx_tcp_header_word_0 =        (((ULONG)(socket_ptr -> nx_tcp_socket_port)) << NX_SHIFT_BY_16) | (ULONG)socket_ptr -> nx_tcp_socket_connect_port;
    tcp_header_ptr -> nx_tcp_sequence_number =      tx_sequence;
    tcp_header_ptr -> nx_tcp_acknowledgment_number = ack_number;
    tcp_header_ptr -> nx_tcp_header_word_3 =        header_size | control_bits | window_size;
    tcp_header_ptr -> nx_tcp_header_word_4 =        0;

    /* Remember the last ACKed sequence and the last reported window size.  */
    socket_ptr -> nx_tcp_socket_rx_sequence_acked =    ack_number;
    socket_ptr -> nx_tcp_socket_rx_window_last_sent =  socket_ptr -> nx_tcp_socket_rx_window_current;

#ifdef NX_ENABLE_TCP_TIMESTAMP

    /* Last.ACK.sent, RFC 1323 section 4.2.1: the sequence number this segment
       acknowledges, which is what a later segment's own sequence is measured
       against before it may replace TS.Recent.  */
    if (control_bits & NX_TCP_ACK_BIT)
    {
        socket_ptr -> nx_tcp_socket_last_ack_sent = ack_number;
    }
#endif /* NX_ENABLE_TCP_TIMESTAMP */

    /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
       swap the endian of the TCP header.  */
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_0);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_sequence_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_acknowledgment_number);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_3);
    NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);

    /* Options come before payload: the data offset field says where the payload
       starts, so anything written after it is payload whatever it holds.  */

    /* Whether it is a SYN packet. */
    if (control_bits & NX_TCP_SYN_BIT)
    {

        /* Endian swapping logic.  If NX_LITTLE_ENDIAN is specified, these macros will
           swap the endian of the TCP header.  */
        NX_CHANGE_ULONG_ENDIAN(option_word_1);
        NX_CHANGE_ULONG_ENDIAN(option_word_2);

        /* Set options. */
        /*lint --e{927} --e{826} suppress cast of pointer to pointer, since it is necessary  */
        *((ULONG *)packet_ptr -> nx_packet_append_ptr) = option_word_1;
        *(((ULONG *)packet_ptr -> nx_packet_append_ptr) + 1) = option_word_2;

        /* Adjust packet information. */
        packet_ptr -> nx_packet_append_ptr += (sizeof(ULONG) << 1);
        packet_ptr -> nx_packet_length += (ULONG)(sizeof(ULONG) << 1);
    }

#ifdef NX_ENABLE_TCP_TIMESTAMP

    /* Before any appended option, so a SACK-carrying acknowledgment comes out
       [nop,nop,TS,nop,nop,sack ...], the order every stack sends.  */
    if (timestamp_size)
    {
        _nx_tcp_timestamp_option_add(packet_ptr -> nx_packet_append_ptr,
                                     (ULONG)tx_time_get(),
                                     socket_ptr -> nx_tcp_socket_ts_recent);

        packet_ptr -> nx_packet_append_ptr += NX_TCP_TIMESTAMP_OPTION_SIZE;
        packet_ptr -> nx_packet_length += (ULONG)NX_TCP_TIMESTAMP_OPTION_SIZE;
    }
#endif /* NX_ENABLE_TCP_TIMESTAMP */

    /* Appended options, already in network byte order and copied a byte at a
       time because the append pointer carries no alignment guarantee.  */
    if (option_size)
    {
    UINT i;

        for (i = 0; i < option_size; i++)
        {
            *packet_ptr -> nx_packet_append_ptr++ = option_ptr[i];
        }
        packet_ptr -> nx_packet_length += option_size;
    }

    /* Check whether or not data is set. */
    if (data)
    {

        /* Zero window probe data exist. */
        *packet_ptr -> nx_packet_append_ptr++ = *data;
        packet_ptr -> nx_packet_length++;
    }

#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    if (socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_capability_flag & NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM)
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

#if defined(NX_DISABLE_TCP_TX_CHECKSUM) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE)
    if (compute_checksum)
#endif /* defined(NX_DISABLE_TCP_TX_CHECKSUM ) || defined(NX_ENABLE_INTERFACE_CAPABILITY) || defined(NX_IPSEC_ENABLE) */
    {


        /* Set the packet source IP address. */
#ifndef NX_DISABLE_IPV4
        if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
        {

            /* For IPv4 the IP instance has only one global address. */
            source_ip = &socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_ip_address;

            /* Set the destination address to the other side of the TCP connection. */
            dest_ip = &socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4;
        }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
        if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
        {

            /* For IPv6, use the source address specified in the socket outgoing interface. */
            source_ip = socket_ptr -> nx_tcp_socket_ipv6_addr -> nxd_ipv6_address;

            /* Set the destination address to the other side of the TCP connection. */
            dest_ip = socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6;
        }
#endif /* FEATURE_NX_IPV6 */

        /* Calculate the TCP checksum.  */
        checksum =  _nx_ip_checksum_compute(packet_ptr, NX_PROTOCOL_TCP,
                                            (UINT)packet_ptr -> nx_packet_length, source_ip, dest_ip);

        checksum = ~checksum & NX_LOWER_16_MASK;

        /* Move the checksum into header.  */
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
        tcp_header_ptr -> nx_tcp_header_word_4 =  (checksum << NX_SHIFT_BY_16);
        NX_CHANGE_ULONG_ENDIAN(tcp_header_ptr -> nx_tcp_header_word_4);
    }
#ifdef NX_ENABLE_INTERFACE_CAPABILITY
    else
    {
        packet_ptr -> nx_packet_interface_capability_flag |= NX_INTERFACE_CAPABILITY_TCP_TX_CHECKSUM;
    }
#endif /* NX_ENABLE_INTERFACE_CAPABILITY  */

#ifndef NX_DISABLE_IPV4
    /* Send the TCP packet to the IP component.  */
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {

        _nx_ip_packet_send(ip_ptr, packet_ptr, socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v4,
                           socket_ptr -> nx_tcp_socket_type_of_service, socket_ptr -> nx_tcp_socket_time_to_live, NX_IP_TCP,
                           socket_ptr -> nx_tcp_socket_fragment_enable,
                           socket_ptr -> nx_tcp_socket_next_hop_address);
    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
    {

        /* The IPv6 packet interface must be set before sending. Set to the TCP socket outgoing interface. */
        packet_ptr -> nx_packet_address.nx_packet_ipv6_address_ptr = socket_ptr -> nx_tcp_socket_ipv6_addr;

        _nx_ipv6_packet_send(ip_ptr, packet_ptr, NX_PROTOCOL_TCP, packet_ptr -> nx_packet_length, ip_ptr -> nx_ipv6_hop_limit, 0,
                             socket_ptr -> nx_tcp_socket_ipv6_addr -> nxd_ipv6_address,
                             socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_address.v6);
    }
#endif /* FEATURE_NX_IPV6 */
}

