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
/**    X.509 Digital Certificates                                         */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SECURE_SOURCE_CODE

#include "nx_secure_x509.h"

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_certificate_chain_verify            PORTABLE C      */
/*                                                           6.1.12       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function verifies a certificate chain (built using the service */
/*    nx_secure_certificate_chain_build) by checking each issuer back to  */
/*    a certificate in the trusted store of the given X509 store.         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    store                                 Pointer to certificate store  */
/*    certificate                           Pointer to cert chain         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_certificate_verify    Verify a certificate          */
/*    _nx_secure_x509_store_certificate_find                              */
/*                                          Find a cert in a store        */
/*    _nx_secure_x509_distinguished_name_compare                          */
/*                                          Compare distinguished name    */
/*    _nx_secure_x509_basic_constraints_extension_parse                   */
/*                                          Parse basicConstraints        */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_tls_remote_certificate_verify                            */
/*                                          Verify the server certificate */
/*    _nx_secure_x509_crl_revocation_check  Check revocation in crl       */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_certificate_chain_verify(NX_SECURE_X509_CERTIFICATE_STORE *store,
                                              NX_SECURE_X509_CERT *certificate, ULONG current_time)
{
UINT                 status;
NX_SECURE_X509_CERT *current_certificate;
NX_SECURE_X509_CERT *issuer_certificate;
UINT                 issuer_location = NX_SECURE_X509_CERT_LOCATION_NONE;
INT                  compare_result;
UINT                 depth = 0;
#ifndef NX_SECURE_X509_DISABLE_BASIC_CONSTRAINTS_CHECK
UINT                 issuer_is_ca;
INT                  issuer_path_length;
#endif

    /* Process, following X509 basic certificate authentication (RFC 5280):
     *    1. Last certificate in chain is the end entity - start with it.
     *    2. Build chain from issuer to issuer - linked list of issuers. Find in stores: [ Remote, Trusted ]
     *    3. Walk list from end certificate back to a root CA in the trusted store, verifying each signature.
     *       Additionally, any policy enforcement should be done at each step.
     */

    /* Get working pointer to certificate chain entry. */
    current_certificate = certificate;

    while (current_certificate != NX_CRYPTO_NULL)
    {

        /* The walk follows issuer links, and those can form a cycle: a pair of
           cross-signed CAs name each other, so nothing below ever reaches the
           trusted store and nothing else ends the loop. */
        if (depth > NX_SECURE_X509_MAX_VERIFY_DEPTH)
        {
            return(NX_SECURE_X509_CHAIN_TOO_LONG);
        }

        /* Check the certificate expiration against the current time. */
        if (current_time != 0)
        {
            status = _nx_secure_x509_expiration_check(current_certificate, current_time);

            if (status != NX_SECURE_X509_SUCCESS)
            {
                return(status);
            }
        }

        /* See if the certificate is self-signed or not. */
        compare_result = _nx_secure_x509_distinguished_name_compare(&current_certificate -> nx_secure_x509_distinguished_name,
                                                                    &current_certificate -> nx_secure_x509_issuer, NX_SECURE_X509_NAME_ALL_FIELDS);

        if (compare_result != 0)
        {
            /* Find the certificate issuer in the store. */
            status = _nx_secure_x509_store_certificate_find(store, &current_certificate -> nx_secure_x509_issuer, 0, &issuer_certificate, &issuer_location);

            if (status != NX_SECURE_X509_SUCCESS)
            {
                return(NX_SECURE_X509_ISSUER_CERTIFICATE_NOT_FOUND);
            }

#ifndef NX_SECURE_X509_DISABLE_BASIC_CONSTRAINTS_CHECK
            /* RFC 5280 6.1.4 (k) and (l): a certificate that issued another one
               is a CA, and has to say so. Without this the issuer is found by
               subject name and signature alone, so any end-entity certificate
               whose private key an attacker holds can issue a certificate for
               any name and present the two together -- the chain from the forged
               certificate up to the trust anchor verifies at every step. */
            status = _nx_secure_x509_basic_constraints_extension_parse(issuer_certificate,
                                                                       &issuer_is_ca,
                                                                       &issuer_path_length);

            if (status != NX_SECURE_X509_SUCCESS || issuer_is_ca != NX_CRYPTO_TRUE)
            {
                /* No extension at all is also a failure. The extension is what
                   makes a CA a CA, and treating its absence as permission is
                   what the paragraph above describes. */
                return(NX_SECURE_X509_INVALID_CA_CERTIFICATE);
            }

            /* RFC 5280 6.1.4 (m): pathLenConstraint counts the non-self-issued
               certificates that may follow this one, which is how many have been
               walked past to get here. */
            if (issuer_path_length >= 0 && (UINT)issuer_path_length < depth)
            {
                return(NX_SECURE_X509_INVALID_CA_CERTIFICATE);
            }
#endif /* NX_SECURE_X509_DISABLE_BASIC_CONSTRAINTS_CHECK */
        }
        else
        {
#ifndef NX_SECURE_ALLOW_SELF_SIGNED_CERTIFICATES
            /* The certificate is self-signed. If we don't allow that, return error. */
            return(NX_SECURE_X509_INVALID_SELF_SIGNED_CERT);
#else
            /* Certificate is self-signed and we are configured to accept them. */
            issuer_certificate = current_certificate;
#endif
        }

        /* Verify the current certificate against its issuer certificate. */
        status = _nx_secure_x509_certificate_verify(store, current_certificate, issuer_certificate);

        if (status != 0)
        {
            return(status);
        }
        else
        {
            /* The comparison passed, so we have a valid issuer. If the issuer is in the trusted
               store, our chain verification is complete. If the issuer is not in the trusted store,
               then continue the verification process. */
            if (issuer_location == NX_SECURE_X509_CERT_LOCATION_TRUSTED)
            {
                return(NX_SECURE_X509_SUCCESS);
            }

#ifdef NX_SECURE_ALLOW_SELF_SIGNED_CERTIFICATES
            /* Certificate is self-signed and we are configured to accept them. */
            if (issuer_certificate == current_certificate)
            {
                /* Check for self-signed certificate in trusted store. */
                status = _nx_secure_x509_store_certificate_find(store, &current_certificate -> nx_secure_x509_distinguished_name, 0, &issuer_certificate, &issuer_location);
                
                if(status == NX_SECURE_X509_SUCCESS && issuer_location == NX_SECURE_X509_CERT_LOCATION_TRUSTED)
                {
                    return(NX_SECURE_X509_SUCCESS);
                }
                /* Self-signed certificate is not trusted. */
                break;
            }
#endif
        }

        /* Advance our working pointer to the next entry in the list. */
        current_certificate = issuer_certificate;
        depth++;
    } /* End while. */

    /* Certificate is invalid. */
    return(NX_SECURE_X509_CHAIN_VERIFY_FAILURE);
}

