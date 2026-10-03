/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* The ClientHello offers encrypt_then_mac (RFC 7366) always, and
   extended_master_secret (RFC 7627) only in a build where the client cannot
   negotiate TLS 1.0 or 1.1: there the extension would need session_hash over
   MD5 and SHA-1, which is not built, and a server that echoed it would derive
   other keys than this client.  */

#include "nx_api.h"
#include "nx_secure_tls_api.h"
#include "nx_secure_tls.h"
#include "tls_test_utility.h"

extern VOID    test_control_return(UINT status);
extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static NX_SECURE_TLS_SESSION tls_session;
static UCHAR crypto_metadata[16000];
static UCHAR extensions[1024];

static UINT extension_present(UCHAR *buffer, ULONG length, USHORT type)
{
ULONG offset = 0;

    while (offset + 4 <= length)
    {
        if ((USHORT)((buffer[offset] << 8) | buffer[offset + 1]) == type)
        {
            return(NX_TRUE);
        }
        offset += 4 + (ULONG)((buffer[offset + 2] << 8) | buffer[offset + 3]);
    }
    return(NX_FALSE);
}

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_ems_offer_test_application_define(void *first_unused_memory)
#endif
{
#if !defined(NX_SECURE_TLS_CLIENT_DISABLED) && !defined(NX_SECURE_DISABLE_X509) && (NX_SECURE_TLS_TLS_1_2_ENABLED)
UINT  status;
ULONG length = 0;
ULONG extensions_length = 0;

    printf("NetX Secure Test:   TLS EMS Offer Test.................................");

    status = nx_secure_tls_session_create(&tls_session, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata));
    EXPECT_EQ(NX_SUCCESS, status);
    tls_session.nx_secure_tls_socket_type = NX_SECURE_TLS_SESSION_TYPE_CLIENT;

    status = _nx_secure_tls_send_clienthello_extensions(&tls_session, extensions, &length, &extensions_length, sizeof(extensions));
    EXPECT_EQ(NX_SUCCESS, status);

    EXPECT_EQ(NX_TRUE, extension_present(extensions, length, NX_SECURE_TLS_EXTENSION_ENCRYPT_THEN_MAC));
#if (NX_SECURE_TLS_TLS_1_0_ENABLED || NX_SECURE_TLS_TLS_1_1_ENABLED)
    EXPECT_EQ(NX_FALSE, extension_present(extensions, length, NX_SECURE_TLS_EXTENSION_EXTENDED_MASTER_SECRET));
#else
    EXPECT_EQ(NX_TRUE, extension_present(extensions, length, NX_SECURE_TLS_EXTENSION_EXTENDED_MASTER_SECRET));
#endif

    nx_secure_tls_session_delete(&tls_session);

    printf("SUCCESS!\n");
    test_control_return(0);
#else
    printf("NetX Secure Test:   TLS EMS Offer Test.................................N/A\n");
    test_control_return(3);
#endif
}
