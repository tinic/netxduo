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
/*    _nx_secure_tls_process_encrypted_extensions         PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function processes the encrypted extensions received after a   */
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
UINT _nx_secure_tls_process_encrypted_extensions(NX_SECURE_TLS_SESSION *tls_session,
                                                 UCHAR *packet_buffer, UINT message_length)
{
UINT   status;
UINT   offset;
UINT   list_length;
USHORT extension_id;
USHORT extension_length;

    status = NX_SUCCESS;

    /*
     * RFC 8446 4.3.1.  The body is a two-byte extension-list length and then
     * the extensions, and until now every byte of it was discarded.  ALPN is
     * the only one this stack acts on; anything else is skipped, which is the
     * required behaviour for an extension a client does not know.
     */
    if (message_length >= 2u)
    {
        list_length = (UINT)((packet_buffer[0] << 8) + packet_buffer[1]);

        if ((list_length + 2u) > message_length)
        {
            return(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH);
        }

        offset = 2;

        while ((offset + 4u) <= (list_length + 2u))
        {
            extension_id = (USHORT)((packet_buffer[offset] << 8) + packet_buffer[offset + 1]);
            extension_length = (USHORT)((packet_buffer[offset + 2] << 8) +
                                        packet_buffer[offset + 3]);

            if ((offset + 4u + extension_length) > (list_length + 2u))
            {
                return(NX_SECURE_TLS_INCORRECT_MESSAGE_LENGTH);
            }

            if (extension_id == NX_SECURE_TLS_EXTENSION_ALPN)
            {
                status = _nx_secure_tls_alpn_process_response(tls_session,
                                                              &packet_buffer[offset + 2],
                                                              message_length - (offset + 2u));
                if (status != NX_SUCCESS)
                {
                    return(status);
                }
            }

            offset += 4u + extension_length;
        }
    }

#ifndef NX_SECURE_TLS_CLIENT_DISABLED

    /* Set our state to indicate we successfully parsed the Certificate message. */
    tls_session -> nx_secure_tls_client_state = NX_SECURE_TLS_CLIENT_STATE_ENCRYPTED_EXTENSIONS;
#else
    NX_PARAMETER_NOT_USED(tls_session);
#endif


    return(status);
}
#endif

