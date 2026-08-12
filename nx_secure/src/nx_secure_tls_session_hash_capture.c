/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


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


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_tls_session_hash_capture                 PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    RFC 7627 3: session_hash is the hash of every handshake message      */
/*    through ClientKeyExchange, and the master secret is derived from it  */
/*    instead of from the two random values.  That is what binds a session */
/*    to the certificate and the key exchange that produced it, and what   */
/*    makes the triple handshake fail: the attacker's two connections no   */
/*    longer arrive at the same master secret.                             */
/*                                                                        */
/*    It has to be captured at the moment ClientKeyExchange is hashed, not */
/*    at the point the keys are generated.  Between the two the client may */
/*    send CertificateVerify, which RFC 7627 excludes -- and must, since   */
/*    CertificateVerify signs the transcript and cannot be inside a hash   */
/*    it depends on.                                                       */
/*                                                                        */
/*    The running hash is cloned into the scratch area rather than         */
/*    finalized, exactly as _nx_secure_tls_finished_hash_generate does it, */
/*    so the transcript continues for the Finished messages that follow.   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    tls_session                           TLS control block             */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_tls_client_handshake       TLS client state machine      */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_tls_session_hash_capture(NX_SECURE_TLS_SESSION *tls_session)
{
#if (NX_SECURE_TLS_TLS_1_2_ENABLED)
const NX_CRYPTO_METHOD *method_ptr;
VOID                   *handler;
UINT                    status;
UCHAR                   hash[NX_SECURE_TLS_MAX_HASH_SIZE];

    tls_session -> nx_secure_tls_key_material.nx_secure_tls_session_hash_length = 0;

    if (tls_session -> nx_secure_tls_extended_master_secret != NX_TRUE)
    {
        return(NX_SUCCESS);
    }

#ifdef NX_SECURE_ENABLE_DTLS
    if ((tls_session -> nx_secure_tls_protocol_version != NX_SECURE_TLS_VERSION_TLS_1_2) &&
        (tls_session -> nx_secure_tls_protocol_version != NX_SECURE_DTLS_VERSION_1_2))
#else
    if (tls_session -> nx_secure_tls_protocol_version != NX_SECURE_TLS_VERSION_TLS_1_2)
#endif /* NX_SECURE_ENABLE_DTLS */
    {

        /* TLS 1.0 and 1.1 build session_hash from MD5 and SHA-1 together.
           Neither is offered by this build, so rather than carry a second
           construction, the extension simply does not take effect there. */
        tls_session -> nx_secure_tls_extended_master_secret = NX_FALSE;
        return(NX_SUCCESS);
    }

    method_ptr = tls_session -> nx_secure_tls_crypto_table -> nx_secure_tls_handshake_hash_sha256_method;
    handler = tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_handler;

    if (method_ptr == NX_NULL || method_ptr -> nx_crypto_operation == NX_NULL)
    {
        return(NX_SECURE_TLS_MISSING_CRYPTO_ROUTINE);
    }

    NX_SECURE_HASH_METADATA_CLONE(tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch, /* lgtm[cpp/banned-api-usage-required-any] */
                                  tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata,
                                  tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata_size); /* Use case of memcpy is verified. */

    status = method_ptr -> nx_crypto_operation(NX_CRYPTO_HASH_CALCULATE,
                                               handler,
                                               (NX_CRYPTO_METHOD *)method_ptr,
                                               NX_NULL, 0, NX_NULL, 0, NX_NULL,
                                               &hash[0], sizeof(hash),
                                               tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch,
                                               tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata_size,
                                               NX_NULL, NX_NULL);

    NX_SECURE_HASH_CLONE_CLEANUP(tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_scratch,
                                 tls_session -> nx_secure_tls_handshake_hash.nx_secure_tls_handshake_hash_sha256_metadata_size);

    if (status != NX_CRYPTO_SUCCESS)
    {
        return(status);
    }

    NX_SECURE_MEMCPY(tls_session -> nx_secure_tls_key_material.nx_secure_tls_session_hash,
                     hash, NX_SECURE_TLS_MAX_HASH_SIZE); /* Use case of memcpy is verified. */
    tls_session -> nx_secure_tls_key_material.nx_secure_tls_session_hash_length = NX_SECURE_TLS_MAX_HASH_SIZE;

#ifdef NX_SECURE_KEY_CLEAR
    NX_SECURE_MEMSET(hash, 0, sizeof(hash));
#endif /* NX_SECURE_KEY_CLEAR */

    return(NX_SUCCESS);
#else
    tls_session -> nx_secure_tls_extended_master_secret = NX_FALSE;
    tls_session -> nx_secure_tls_key_material.nx_secure_tls_session_hash_length = 0;
    return(NX_SUCCESS);
#endif /* NX_SECURE_TLS_TLS_1_2_ENABLED */
}
