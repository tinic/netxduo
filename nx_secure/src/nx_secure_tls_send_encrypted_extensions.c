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
/** NetX Secure Component                                                 */
/**                                                                       */
/**    Transport Layer Security (TLS)                                     */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SECURE_SOURCE_CODE

#include "nx_secure_tls.h"

#if (NX_SECURE_TLS_TLS_1_3_ENABLED)
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_tls_send_encrypted_extensions            PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function sends the encrypted extensions delivered after a      */
/*    ServerHello message in a TLS 1.3 encrypted handshake.               */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    tls_session                           TLS control block             */
/*    packet_buffer                         Pointer to message data       */
/*    message_length                        Length of message data (bytes)*/
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_tls_ciphersuite_lookup     Lookup current ciphersuite    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_tls_server_handshake       Process extensions            */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_tls_send_encrypted_extensions(NX_SECURE_TLS_SESSION *tls_session, NX_PACKET *send_packet)
{
UINT   status;
ULONG  offset;
ULONG  available;
USHORT extension_length = 0;

    status = NX_SUCCESS;

    available = (ULONG)(send_packet -> nx_packet_data_end) -
                (ULONG)(send_packet -> nx_packet_append_ptr);

    /* Even an empty list needs its length field (16 bits). */
    if (available < 2u)
    {

        /* Packet buffer too small. */
        return(NX_SECURE_TLS_PACKET_BUFFER_TOO_SMALL);
    }

    /*
     * RFC 8446 4.3.1 and RFC 7301.  A TLS 1.3 server answers ALPN here and not
     * in the ServerHello, which is in the clear.  Nothing is written when
     * _nx_secure_tls_alpn_process_offer() selected nothing, and the list is
     * then the empty one this function has always sent.
     */
    offset = 2;
    status = _nx_secure_tls_alpn_send_extension(tls_session,
                                                send_packet -> nx_packet_append_ptr,
                                                &offset, &extension_length,
                                                available, NX_TRUE);
    if (status != NX_SUCCESS)
    {
        return(status);
    }

    send_packet -> nx_packet_append_ptr[0] = (UCHAR)((extension_length & 0xFF00) >> 8);
    send_packet -> nx_packet_append_ptr[1] = (UCHAR)(extension_length & 0x00FF);
    send_packet -> nx_packet_append_ptr = send_packet -> nx_packet_append_ptr + 2 +
                                          extension_length;
    send_packet -> nx_packet_length = 2u + extension_length;

    return(status);
}
#endif

