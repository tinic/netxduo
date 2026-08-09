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
/*    _nx_tcp_packet_send_syn                             PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Yuxin Zhou, Microsoft Corporation                                   */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends a SYN from the specified socket.                */
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
/*    _nx_packet_egress_sa_lookup           IPsec process                 */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_client_socket_connect         Client connect processing     */
/*    _nx_tcp_periodic_processing           Connection retry processing   */
/*    _nx_tcp_packet_process                Server connect response       */
/*                                            processing                  */
/*    _nx_tcp_server_socket_accept          Server socket accept          */
/*                                            processing                  */
/*    _nx_tcp_socket_state_syn_sent         Socket SYN sent processing    */
/*                                                                        */
/**************************************************************************/
VOID  _nx_tcp_packet_send_syn(NX_TCP_SOCKET *socket_ptr, ULONG tx_sequence)
{

#ifdef NX_IPSEC_ENABLE
ULONG        data_offset = 0;
NXD_ADDRESS  src_addr;
UINT         ret;
NX_IPSEC_SA *cur_sa_ptr = NX_NULL;
#endif /* NX_IPSEC_ENABLE */
ULONG        option_word_1;
ULONG        option_word_2;
UCHAR       *option_ptr = NX_NULL;
UINT         option_size = 0;
#ifdef NX_ENABLE_TCP_WINDOW_SCALING
UINT         include_window_scaling = NX_FALSE;
UINT         scale_factor;
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
#if defined(NX_ENABLE_TCP_SACK) && defined(NX_ENABLE_TCP_WINDOW_SCALING)
UCHAR        sack_permitted_option[4];
#endif /* NX_ENABLE_TCP_SACK && NX_ENABLE_TCP_WINDOW_SCALING */
#ifdef NX_ENABLE_TCP_TIMESTAMP
/* Whatever trails the two option words shares one buffer, because
   _nx_tcp_packet_send_control takes a single trailing block: SACK-Permitted is
   four bytes and the timestamp twelve.  Declared independently of the other
   two options, which are guarded on each other.  Sized past the sixteen those
   two need, because nothing here bounds the copy.  */
UCHAR        trailing_options[24];
UINT         trailing_length = 0;
ULONG        timestamp_value;
#endif /* NX_ENABLE_TCP_TIMESTAMP */
ULONG        mss = 0;

#ifdef NX_IPSEC_ENABLE
#ifndef NX_DISABLE_IPV4
    /* Look for egress SA first. */
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        src_addr.nxd_ip_version = NX_IP_VERSION_V4;
        src_addr.nxd_ip_address.v4 = socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_ip_address;
    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
    {
        /* IPv6 case. */
        src_addr.nxd_ip_version = NX_IP_VERSION_V6;
        COPY_IPV6_ADDRESS(socket_ptr -> nx_tcp_socket_ipv6_addr -> nxd_ipv6_address, src_addr.nxd_ip_address.v6);
    }
#endif /* FEATURE_NX_IPV6 */

    /* Check for possible SA match. */
    if (socket_ptr -> nx_tcp_socket_ip_ptr -> nx_ip_packet_egress_sa_lookup != NX_NULL)                   /* IPsec is enabled. */
    {

        /* If the SA has not been set. */
        ret = socket_ptr -> nx_tcp_socket_ip_ptr -> nx_ip_packet_egress_sa_lookup(socket_ptr -> nx_tcp_socket_ip_ptr,        /* IP ptr */
                                                                                  &src_addr,                                 /* src_addr */
                                                                                  &socket_ptr -> nx_tcp_socket_connect_ip,   /* dest_addr */
                                                                                  NX_PROTOCOL_TCP,                           /* protocol */
                                                                                  socket_ptr -> nx_tcp_socket_port,          /* src_port */
                                                                                  socket_ptr -> nx_tcp_socket_connect_port,  /* dest_port */
                                                                                  &data_offset, (VOID *)&cur_sa_ptr, 0);
        if (ret == NX_IPSEC_TRAFFIC_PROTECT)
        {

            /* Save the SA to the socket. */
            socket_ptr -> nx_tcp_socket_egress_sa = cur_sa_ptr;
            socket_ptr -> nx_tcp_socket_egress_sa_data_offset = data_offset;
        }
        else if (ret == NX_IPSEC_TRAFFIC_DROP || ret == NX_IPSEC_TRAFFIC_PENDING_IKEV2)
        {

            return;
        }
        else
        {

            /* Zero out SA information. */
            socket_ptr -> nx_tcp_socket_egress_sa = NX_NULL;
            socket_ptr -> nx_tcp_socket_egress_sa_data_offset = 0;
        }
    }
    else
    {
        socket_ptr -> nx_tcp_socket_egress_sa = NX_NULL;
    }
#endif /* NX_IPSEC_ENABLE */

#ifndef NX_DISABLE_IPV4
    /* Update the mss value based on IP version type. */
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V4)
    {
        mss = (ULONG)((socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_ip_mtu_size - sizeof(NX_IPV4_HEADER)) - sizeof(NX_TCP_HEADER));

#ifdef NX_IPSEC_ENABLE
        if (cur_sa_ptr != NX_NULL)
        {

            /* Update the mss value based on sa mode.  */
            if (cur_sa_ptr -> nx_ipsec_sa_protocol == NX_PROTOCOL_NEXT_HEADER_ENCAP_SECURITY)
            {

                /* Update the mss value. minus the ESP HEADER's pad length and IV size , */
                mss = mss - sizeof(NX_IPSEC_ESP_HEADER) -
                    (cur_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_block_size_in_bytes) -
                    ((cur_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_IV_size_in_bits) >> 3) -
                    ((cur_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_ICV_size_in_bits) >> 3);
            }

            if (cur_sa_ptr -> nx_ipsec_sa_protocol == NX_PROTOCOL_NEXT_HEADER_AUTHENTICATION)
            {

                /* Update the mss value. minus the ESP HEADER's IV size and ICV size. */
                mss = mss - sizeof(NX_IPSEC_AUTHENTICATION_HEADER) -
                    (cur_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_IV_size_in_bits >> 3) -
                    (cur_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_ICV_size_in_bits >> 3);
            }

            /* If the sa is tunnel mode, the mss value should minus the IPV4 header size .  */
            if (cur_sa_ptr -> nx_ipsec_sa_mode == NX_IPSEC_TUNNEL_MODE)
            {
                mss -=  (sizeof(NX_IPV4_HEADER));
            }
        }
#endif /* NX_IPSEC_ENABLE */

    }
#endif /* !NX_DISABLE_IPV4  */

#ifdef FEATURE_NX_IPV6
    if (socket_ptr -> nx_tcp_socket_connect_ip.nxd_ip_version == NX_IP_VERSION_V6)
    {
        mss = (ULONG)((socket_ptr -> nx_tcp_socket_connect_interface -> nx_interface_ip_mtu_size - sizeof(NX_IPV6_HEADER)) - sizeof(NX_TCP_HEADER));

#ifdef NX_IPSEC_ENABLE
        if (cur_sa_ptr != NX_NULL)
        {

            /* Update the mss value based on sa mode.  */
            if (cur_sa_ptr -> nx_ipsec_sa_protocol == NX_PROTOCOL_NEXT_HEADER_ENCAP_SECURITY)
            {

                /* Update the mss value. minus the ESP header's pad length and IV size , */
                mss = mss - sizeof(NX_IPSEC_ESP_HEADER) -
                    (cur_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_block_size_in_bytes) -
                    ((cur_sa_ptr -> nx_ipsec_sa_encryption_method -> nx_crypto_IV_size_in_bits) >> 3) -
                    ((cur_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_ICV_size_in_bits) >> 3);
            }

            if (cur_sa_ptr -> nx_ipsec_sa_protocol == NX_PROTOCOL_NEXT_HEADER_AUTHENTICATION)
            {

                /* Update the mss value. minus the ESP HEADER's IV size and ICV size. */
                mss = mss - sizeof(NX_IPSEC_AUTHENTICATION_HEADER) -
                    (cur_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_IV_size_in_bits >> 3) -
                    (cur_sa_ptr -> nx_ipsec_sa_integrity_method -> nx_crypto_ICV_size_in_bits >> 3);
            }

            /* If the sa mode is tunnel mode,the mss value should minus the IPV6 header size .  */
            if (cur_sa_ptr -> nx_ipsec_sa_mode == NX_IPSEC_TUNNEL_MODE)
            {
                mss -=  (sizeof(NX_IPV6_HEADER));
            }
        }
#endif /* NX_IPSEC_ENABLE */
    }
#endif /* FEATURE_NX_IPV6 */

    mss &= 0x0000FFFFUL;

    if ((socket_ptr -> nx_tcp_socket_mss < mss) && socket_ptr -> nx_tcp_socket_mss)
    {

        /* Use the custom MSS. */
        mss = socket_ptr -> nx_tcp_socket_mss;
    }

    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_RECEIVED)
    {

        /* Update the connect MSS for TCP server socket. */
        if (mss < socket_ptr -> nx_tcp_socket_peer_mss)
        {
            socket_ptr -> nx_tcp_socket_connect_mss  = mss;
        }
        else
        {
            socket_ptr -> nx_tcp_socket_connect_mss =  socket_ptr -> nx_tcp_socket_peer_mss;
        }

        /* Compute the SMSS * SMSS value, so later TCP module doesn't need to redo the multiplication. */
        socket_ptr -> nx_tcp_socket_connect_mss2 =
            socket_ptr -> nx_tcp_socket_connect_mss * socket_ptr -> nx_tcp_socket_connect_mss;
    }
    else
    {

        /* Set the MSS. */
        socket_ptr -> nx_tcp_socket_connect_mss = mss;
    }

    /* Build the MSS option.  */
    option_word_1 = NX_TCP_MSS_OPTION | mss;

    /* Set default option word2. */
    option_word_2 = NX_TCP_OPTION_END;

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
    /* Include window scaling option if we initiates the SYN, or the peer supports Window Scaling. */
    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT)
    {
        include_window_scaling = NX_TRUE;
    }
    else if (socket_ptr -> nx_tcp_snd_win_scale_value != 0xFF)
    {
        include_window_scaling = NX_TRUE;
    }

    if (include_window_scaling)
    {

        /* Sets the window scaling option. */
        option_word_2 = NX_TCP_RWIN_OPTION;

        /* Compute the window scaling factor */
        for (scale_factor = 0; scale_factor < 15; scale_factor++)
        {

            if ((socket_ptr -> nx_tcp_socket_rx_window_current >> scale_factor) < 65536)
            {
                break;
            }
        }

        /*  Make sure window scale is limited to 14, per RFC 1323 pp.11. */
        if (scale_factor == 15)
        {
            scale_factor = 14;
            socket_ptr -> nx_tcp_socket_rx_window_default = (1 << 30) - 1;
            socket_ptr -> nx_tcp_socket_rx_window_current = (1 << 30) - 1;
        }

        option_word_2 |= scale_factor << 8;

        /* Update the socket with the scale factor. */
        socket_ptr -> nx_tcp_rcv_win_scale_value = scale_factor;
    }
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */

#ifdef NX_ENABLE_TCP_SACK

    /* RFC 2018 section 2: offer SACK on a SYN of our own, and on a SYN+ACK only
       when the peer's SYN offered it.  nx_tcp_socket_sack_permitted is what the
       peer's SYN left behind, and it is also what allows blocks to be sent
       later, so a connection where either end stayed quiet sends none.  */
    if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
        (socket_ptr -> nx_tcp_socket_sack_permitted == NX_TRUE))
    {

#ifdef NX_ENABLE_TCP_WINDOW_SCALING
        if (include_window_scaling)
        {

            /* The window scale has taken the second option word, so
               SACK-Permitted needs a third.  */
            sack_permitted_option[0] = NX_TCP_SACK_PERMITTED_KIND;
            sack_permitted_option[1] = 2;
            sack_permitted_option[2] = NX_TCP_NOP_KIND;
            sack_permitted_option[3] = NX_TCP_NOP_KIND;

            option_ptr = sack_permitted_option;
            option_size = sizeof(sack_permitted_option);
        }
        else
#endif /* NX_ENABLE_TCP_WINDOW_SCALING */
        {

            /* The second option word is otherwise only padding.  */
            option_word_2 = NX_TCP_SACK_PERMITTED_OPTION;
        }
    }
#endif /* NX_ENABLE_TCP_SACK */

#ifdef NX_ENABLE_TCP_TIMESTAMP

    /* RFC 1323 section 3.2: offer timestamps on a SYN of our own, and on a
       SYN+ACK only when the peer's SYN carried the option.  Anything SACK
       already put in the trailing block is carried over first, so the two
       options coexist.  */
    if ((socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT) ||
        (socket_ptr -> nx_tcp_socket_timestamp_enabled == NX_TRUE))
    {

        if ((option_size != 0) && (option_ptr != NX_NULL))
        {
            for (trailing_length = 0; trailing_length < option_size; trailing_length++)
            {
                trailing_options[trailing_length] = option_ptr[trailing_length];
            }
        }

        /* NOP, NOP, kind, length: the two pads put TSval and TSecr on word
           boundaries, which is the layout every other stack sends.  */
        trailing_options[trailing_length++] = NX_TCP_NOP_KIND;
        trailing_options[trailing_length++] = NX_TCP_NOP_KIND;
        trailing_options[trailing_length++] = NX_TCP_TIMESTAMP_KIND;
        trailing_options[trailing_length++] = (UCHAR)NX_TCP_TIMESTAMP_LENGTH;

        timestamp_value = (ULONG)tx_time_get();

        trailing_options[trailing_length++] = (UCHAR)(timestamp_value >> 24);
        trailing_options[trailing_length++] = (UCHAR)(timestamp_value >> 16);
        trailing_options[trailing_length++] = (UCHAR)(timestamp_value >> 8);
        trailing_options[trailing_length++] = (UCHAR)(timestamp_value);

        /* TSecr is zero on a SYN this side originates -- there is nothing to
           echo yet -- and the peer's TSval on a SYN+ACK.  */
        if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT)
        {
            timestamp_value = 0;
        }
        else
        {
            timestamp_value = socket_ptr -> nx_tcp_socket_ts_recent;
        }

        trailing_options[trailing_length++] = (UCHAR)(timestamp_value >> 24);
        trailing_options[trailing_length++] = (UCHAR)(timestamp_value >> 16);
        trailing_options[trailing_length++] = (UCHAR)(timestamp_value >> 8);
        trailing_options[trailing_length++] = (UCHAR)(timestamp_value);

        option_ptr  = trailing_options;
        option_size = trailing_length;
    }
#endif /* NX_ENABLE_TCP_TIMESTAMP */

    /* Send SYN or SYN+ACK packet according to socket state. */
    if (socket_ptr -> nx_tcp_socket_state == NX_TCP_SYN_SENT)
    {
        _nx_tcp_packet_send_control(socket_ptr, NX_TCP_SYN_BIT, tx_sequence,
                                    0, option_word_1, option_word_2, option_ptr, option_size, NX_NULL);
    }
    else
    {
        _nx_tcp_packet_send_control(socket_ptr, (NX_TCP_SYN_BIT | NX_TCP_ACK_BIT), tx_sequence,
                                    socket_ptr -> nx_tcp_socket_rx_sequence, option_word_1, option_word_2,
                                    option_ptr, option_size, NX_NULL);
    }

    /* Initialize recover sequence and previous cumulative acknowledgment. */
    socket_ptr -> nx_tcp_socket_tx_sequence_recover = tx_sequence;
    socket_ptr -> nx_tcp_socket_previous_highest_ack = tx_sequence;
}

