/***************************************************************************/
/* Copyright (c) 2026 Eclipse ThreadX contributors                         */
/*                                                                         */
/* This program and the accompanying materials are made available under    */
/* the terms of the MIT License which is available at                      */
/* https://opensource.org/licenses/MIT.                                    */
/*                                                                         */
/* SPDX-License-Identifier: MIT                                            */
/***************************************************************************/

/* A certificate whose only (critical) extendedKeyUsage is timeStamping is
   not a TLS credential (RFC 5280 4.2.1.12): a TLS client refuses it from a
   server, and a TLS server from a client, with
   NX_SECURE_X509_EXT_KEY_USAGE_NOT_FOUND.  certificate_with_policies from
   tls_two_test_certs.c is such a certificate on a chain that otherwise
   verifies at the tests' pinned clock, so the refusal is the purpose alone.
   nx_secure_tls_hash_clone_test presented it as its server until it got a
   copy with serverAuth (make_hash_clone_test_certs.py).  */

#include <stdio.h>
#include "nx_secure_tls_api.h"
#include "tls_test_utility.h"

extern VOID test_control_return(UINT status);

#if !defined(NX_SECURE_DISABLE_X509)
static TX_THREAD thread_0;
static void    thread_0_entry(ULONG thread_input);
#define DEMO_STACK_SIZE 4096
static CHAR thread_stack[DEMO_STACK_SIZE];
#endif

#ifdef CTEST
void test_application_define(void *first_unused_memory);
void test_application_define(void *first_unused_memory)
#else
void nx_secure_tls_eku_timestamping_only_test_application_define(void *first_unused_memory)
#endif
{
#if !defined(NX_SECURE_DISABLE_X509)
    tx_thread_create(&thread_0, "thread 0", thread_0_entry, 0,
                     thread_stack, DEMO_STACK_SIZE,
                     4, 4, TX_NO_TIME_SLICE, TX_AUTO_START);
#else
    printf("NetX Secure Test:   TLS EKU Timestamping Only Test.......................N/A\n");
    test_control_return(3);
#endif
}

#if !defined(NX_SECURE_DISABLE_X509)

#include "test_ca_cert.c"
#include "tls_two_test_certs.c"

/* The clock the TLS tests pin: 11/01/2018.  */
#define TEST_TIME 0x5BDA4200UL

extern const NX_SECURE_TLS_CRYPTO nx_crypto_tls_ciphers;

static NX_SECURE_TLS_SESSION session;
static CHAR crypto_metadata[16000];
static UCHAR packet_buffer[2000];
static NX_SECURE_X509_CERT root_cert;
static NX_SECURE_X509_CERT ica_cert;
static NX_SECURE_X509_CERT leaf_cert;
static CHAR ica_buf1[8000];
static CHAR ica_buf2[3000];
static CHAR leaf_buf1[8000];
static CHAR leaf_buf2[3000];
static ULONG error_counter;

static VOID check(UINT condition)
{
    if (!condition)
    {
        error_counter++;
    }
}

static ULONG test_time(VOID)
{
    return(TEST_TIME);
}

static VOID remote_add(NX_SECURE_X509_CERT *cert, const UCHAR *der, UINT der_len, CHAR *buf1, UINT buf1_size, CHAR *buf2, UINT buf2_size)
{
    check(_nx_secure_x509_certificate_initialize(cert, (UCHAR *)der, (USHORT)der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE) == NX_SUCCESS);
    check(_nx_secure_x509_certificate_list_add(&session.nx_secure_tls_credentials.nx_secure_tls_certificate_store.nx_secure_x509_remote_certificates,
                                               cert, NX_TRUE) == NX_SUCCESS);
    cert -> nx_secure_x509_public_cipher_metadata_area = buf1;
    cert -> nx_secure_x509_public_cipher_metadata_size = buf1_size;
    cert -> nx_secure_x509_hash_metadata_area = buf2;
    cert -> nx_secure_x509_hash_metadata_size = buf2_size;
    cert -> nx_secure_x509_cipher_table = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table;
    cert -> nx_secure_x509_cipher_table_size = session.nx_secure_tls_crypto_table -> nx_secure_tls_x509_cipher_table_size;
}

/* A fresh session of the given role whose trusted store holds the root and
   which has received the intermediate and certificate_with_policies.  */
static VOID session_setup(UINT socket_type)
{
    memset(&session, 0, sizeof(session));
    check(nx_secure_tls_session_create(&session, &nx_crypto_tls_ciphers, crypto_metadata, sizeof(crypto_metadata)) == NX_SUCCESS);
    check(_nx_secure_tls_session_packet_buffer_set(&session, packet_buffer, sizeof(packet_buffer)) == NX_SUCCESS);
    check(_nx_secure_tls_session_time_function_set(&session, test_time) == NX_SUCCESS);
    session.nx_secure_tls_socket_type = socket_type;

    memset(&root_cert, 0, sizeof(root_cert));
    memset(&ica_cert, 0, sizeof(ica_cert));
    memset(&leaf_cert, 0, sizeof(leaf_cert));
    check(_nx_secure_x509_certificate_initialize(&root_cert, test_ca_cert_der, (USHORT)test_ca_cert_der_len, NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE) == NX_SUCCESS);
    check(_nx_secure_tls_trusted_certificate_add(&session, &root_cert) == NX_SUCCESS);
    remote_add(&ica_cert, ica_cert_der, ica_cert_der_len, ica_buf1, sizeof(ica_buf1), ica_buf2, sizeof(ica_buf2));
    remote_add(&leaf_cert, test_device_cert_der, test_device_cert_der_len, leaf_buf1, sizeof(leaf_buf1), leaf_buf2, sizeof(leaf_buf2));
}

static void    thread_0_entry(ULONG thread_input)
{
NX_SECURE_X509_CERTIFICATE_STORE *store = &session.nx_secure_tls_credentials.nx_secure_tls_certificate_store;

    NX_PARAMETER_NOT_USED(thread_input);
    printf("NetX Secure Test:   TLS EKU Timestamping Only Test.......................");

    nx_secure_tls_initialize();

    /* The chain itself verifies, and the certificate is good for its one
       purpose, so what follows is refused on the purpose alone.  */
    session_setup(NX_SECURE_TLS_SESSION_TYPE_CLIENT);
    check(_nx_secure_x509_certificate_chain_verify(store, &leaf_cert, TEST_TIME) == NX_SECURE_X509_SUCCESS);
    check(_nx_secure_x509_extended_key_usage_chain_check(store, &leaf_cert, NX_SECURE_TLS_X509_TYPE_PKIX_KP_TIME_STAMPING) ==
          NX_SECURE_X509_SUCCESS);

    /* A TLS client authenticating a server.  */
    check(_nx_secure_tls_remote_certificate_verify(&session) == NX_SECURE_X509_EXT_KEY_USAGE_NOT_FOUND);
    nx_secure_tls_session_delete(&session);

    /* A TLS server authenticating a client.  */
    session_setup(NX_SECURE_TLS_SESSION_TYPE_SERVER);
    check(_nx_secure_tls_remote_certificate_verify(&session) == NX_SECURE_X509_EXT_KEY_USAGE_NOT_FOUND);
    nx_secure_tls_session_delete(&session);

    if (error_counter)
    {
        printf("ERROR!\n");
        test_control_return(1);
    }
    printf("SUCCESS!\n");
    test_control_return(0);
}

#endif
