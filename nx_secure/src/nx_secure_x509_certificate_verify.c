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
#include "nx_crypto_rsa.h"

static UCHAR generated_hash[64];       /* We need to be able to hold the entire generated hash - SHA-512 = 64 bytes. */
static UCHAR decrypted_signature[512]; /* This needs to hold the entire decrypted data - RSA 2048-bit key = 256 bytes. */
static UCHAR pss_scratch[512];         /* PSS verify: db[emLen - hLen - 1] + h_prime[hLen] = emLen - 1, so 512 covers RSA-4096. */



/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_certificate_verify                  PORTABLE C      */
/*                                                           6.1.11       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function verifies a certificate by checking its signature      */
/*    against its issuer's public key.                                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    store                                 Pointer to certificate store  */
/*    certificate                           Pointer to certificate        */
/*    issuer_certificate                    Pointer to issuer certificate */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    [nx_crypto_init]                      Crypto initialization         */
/*    [nx_crypto_operation]                 Crypto operation              */
/*    _nx_secure_x509_pkcs7_decode          Decode the PKCS#7 signature   */
/*    _nx_secure_x509_find_certificate_methods                            */
/*                                          Find certificate methods      */
/*    _nx_secure_x509_find_curve_method     Find named curve used         */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_certificate_chain_verify                            */
/*                                          Verify cert against stores    */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_certificate_verify(NX_SECURE_X509_CERTIFICATE_STORE *store,
                                        NX_SECURE_X509_CERT *certificate,
                                        NX_SECURE_X509_CERT *issuer_certificate)
{
UINT                    status;
UINT                    oid_length;
const UCHAR            *oid;
UINT                    decrypted_hash_length;
const UCHAR            *decrypted_hash;
const UCHAR            *certificate_verify_data;
UINT                    verify_data_length;
const UCHAR            *signature_data;
UINT                    signature_length;
UINT                    compare_result;
UINT                    hash_length;
UINT                    signature_algorithm;
UINT                    is_pss;
const NX_CRYPTO_METHOD *hash_method;
const NX_CRYPTO_METHOD *public_cipher_method;
NX_SECURE_X509_CRYPTO  *crypto_methods;
VOID                   *handler = NX_CRYPTO_NULL;
#ifndef NX_SECURE_X509_DISABLE_KEY_USAGE_CHECK
USHORT                  key_usage_bitfield = 0;
#endif
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
NX_SECURE_EC_PUBLIC_KEY *ec_pubkey;
const NX_CRYPTO_METHOD  *curve_method;
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */

    NX_CRYPTO_PARAMETER_NOT_USED(store);

#ifndef NX_SECURE_X509_DISABLE_KEY_USAGE_CHECK
    /* Before we do any crypto verification, we need to check the KeyUsage extension. */
    status = _nx_secure_x509_key_usage_extension_parse(issuer_certificate, &key_usage_bitfield);

    /* If extension is not present, we don't need to verify per RFC 5280. */
    if(NX_SECURE_X509_SUCCESS == status)
    {
        /* The issuer cert has a KeyUsage extension - check the KeyCertSign bit. */
        if(!(key_usage_bitfield & NX_SECURE_X509_KEY_USAGE_KEY_CERT_SIGN))
        {
            return(NX_SECURE_X509_KEY_USAGE_ERROR);
        }
    }
#endif

    /* Get working pointers to relevant data. */
    certificate_verify_data = certificate -> nx_secure_x509_certificate_data;
    verify_data_length = certificate -> nx_secure_x509_certificate_data_length;
    signature_data = certificate -> nx_secure_x509_signature_data;
    signature_length = certificate -> nx_secure_x509_signature_data_length;

    /*
     * RSASSA-PSS and PKCS#1 v1.5 use the same RSA operation and the same
     * digest; they differ only in how the recovered block is checked.  So a
     * PSS certificate is looked up under the PKCS#1 row for its digest and the
     * difference is carried in is_pss, rather than by adding three rows to
     * every X.509 cipher table in the tree.
     *
     * That matters beyond tidiness: _nx_secure_tls_send_clienthello_extensions
     * walks the same table to build signature_algorithms, so a row here is
     * also a code point on the wire, and PSS rows carrying the same method
     * pair as the PKCS#1 rows would have put each of rsa_pss_rsae_sha256/384/
     * 512 into every ClientHello twice.
     */
    signature_algorithm = certificate -> nx_secure_x509_signature_algorithm;
    is_pss              = NX_CRYPTO_FALSE;

    switch (signature_algorithm)
    {
    case NX_SECURE_TLS_X509_TYPE_RSA_PSS_SHA_256:
        signature_algorithm = NX_SECURE_TLS_X509_TYPE_RSA_SHA_256;
        is_pss = NX_CRYPTO_TRUE;
        break;

    case NX_SECURE_TLS_X509_TYPE_RSA_PSS_SHA_384:
        signature_algorithm = NX_SECURE_TLS_X509_TYPE_RSA_SHA_384;
        is_pss = NX_CRYPTO_TRUE;
        break;

    case NX_SECURE_TLS_X509_TYPE_RSA_PSS_SHA_512:
        signature_algorithm = NX_SECURE_TLS_X509_TYPE_RSA_SHA_512;
        is_pss = NX_CRYPTO_TRUE;
        break;

    default:
        break;
    }

    /* An id-RSASSA-PSS SubjectPublicKeyInfo certifies this modulus only for
       PSS. If its parameters are present, RFC 4055 3.3 also requires the
       signature hash/MGF/trailer to match and its salt to be at least the
       key's minimum. The parser has already required MGF1 with the same hash
       and trailer field 1 for both parameter sets. */
    if (issuer_certificate -> nx_secure_x509_public_key_identifier ==
            NX_SECURE_TLS_X509_TYPE_RSA_PSS)
    {
        if (is_pss == NX_CRYPTO_FALSE)
        {
            return(NX_SECURE_X509_WRONG_SIGNATURE_METHOD);
        }

        if (issuer_certificate -> nx_secure_x509_public_key_pss_algorithm !=
                NX_SECURE_TLS_X509_TYPE_UNKNOWN &&
            (issuer_certificate -> nx_secure_x509_public_key_pss_algorithm !=
                 certificate -> nx_secure_x509_signature_algorithm ||
             certificate -> nx_secure_x509_signature_salt_length <
                 issuer_certificate -> nx_secure_x509_public_key_pss_salt_length))
        {
            return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
        }
    }

    /* Find certificate crypto methods for this certificate. */
    status = _nx_secure_x509_find_certificate_methods(certificate, (USHORT)signature_algorithm, &crypto_methods);
    if (status != NX_SECURE_X509_SUCCESS)
    {
        return(status);
    }

    /* Assign local pointers for the crypto methods. */
    hash_method = crypto_methods -> nx_secure_x509_hash_method;
    public_cipher_method = crypto_methods -> nx_secure_x509_public_cipher_method;

    NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
    NX_SECURE_MEMSET(decrypted_signature, 0, sizeof(decrypted_signature));

    if (hash_method -> nx_crypto_init)
    {
        status = hash_method -> nx_crypto_init((NX_CRYPTO_METHOD*)hash_method,
                                      NX_CRYPTO_NULL,
                                      0,
                                      &handler,
                                      certificate -> nx_secure_x509_hash_metadata_area,
                                      certificate -> nx_secure_x509_hash_metadata_size);

        if(status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }                                                     
    }

    /* We need to generate a hash of this certificate in order to verify it against our trusted store. */
    if (hash_method -> nx_crypto_operation != NX_CRYPTO_NULL)
    {
        status = hash_method -> nx_crypto_operation(NX_CRYPTO_VERIFY,
                                           handler,
                                           (NX_CRYPTO_METHOD*)hash_method,
                                           NX_CRYPTO_NULL,
                                           0,
                                           (UCHAR *)certificate_verify_data,
                                           verify_data_length,
                                           NX_CRYPTO_NULL,
                                           generated_hash,
                                           sizeof(generated_hash),
                                           certificate -> nx_secure_x509_hash_metadata_area,
                                           certificate -> nx_secure_x509_hash_metadata_size,
                                           NX_CRYPTO_NULL, NX_CRYPTO_NULL);

        if(status != NX_CRYPTO_SUCCESS)
        {
            return(status);
        }                                                     
    }

    if (hash_method -> nx_crypto_cleanup)
    {
        status = hash_method -> nx_crypto_cleanup(certificate -> nx_secure_x509_hash_metadata_area);

        if(status != NX_CRYPTO_SUCCESS)
        {
#ifdef NX_SECURE_KEY_CLEAR
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */
            return(status);
        }                                                     
    }

    hash_length = (hash_method -> nx_crypto_ICV_size_in_bits >> 3);

    /* Perform a public-key decryption operation on the extracted signature from the certificate.
     * In this case, the operation is doing a "reverse decryption", using the public key to decrypt, rather
     * than the private. This allows us to tie a trusted root certificate to a signature of a certificate
     * signed by that root CA's private key. when combined with a hash method, this is the basic digital
     * signature operation. */
    if (public_cipher_method -> nx_crypto_algorithm == NX_CRYPTO_KEY_EXCHANGE_RSA ||
        public_cipher_method -> nx_crypto_algorithm == NX_CRYPTO_DIGITAL_SIGNATURE_RSA)
    {
        /* Make sure the public algorithm of the issuer certificate is RSA. */
        if (issuer_certificate -> nx_secure_x509_public_algorithm != NX_SECURE_TLS_X509_TYPE_RSA)
        {
#ifdef NX_SECURE_KEY_CLEAR
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

            return(NX_SECURE_X509_WRONG_SIGNATURE_METHOD);
        }

        if (public_cipher_method -> nx_crypto_init != NX_CRYPTO_NULL)
        {
            /* Initialize the crypto method with public key. */
            status = public_cipher_method -> nx_crypto_init((NX_CRYPTO_METHOD*)public_cipher_method,
                                                   (UCHAR *)issuer_certificate -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus,
                                                   (NX_CRYPTO_KEY_SIZE)(issuer_certificate -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length << 3),
                                                   &handler,
                                                   certificate -> nx_secure_x509_public_cipher_metadata_area,
                                                   certificate -> nx_secure_x509_public_cipher_metadata_size);

            if(status != NX_CRYPTO_SUCCESS)
            {
#ifdef NX_SECURE_KEY_CLEAR
                NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

                return(status);
            }
        }

        if (public_cipher_method -> nx_crypto_operation != NX_CRYPTO_NULL)
        {
            status = public_cipher_method -> nx_crypto_operation(NX_CRYPTO_DECRYPT,
                                                        handler,
                                                        (NX_CRYPTO_METHOD*)public_cipher_method,
                                                        (UCHAR *)issuer_certificate -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent,
                                                        (NX_CRYPTO_KEY_SIZE)(issuer_certificate -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent_length << 3),
                                                        (UCHAR *)signature_data,
                                                        signature_length,
                                                        NX_CRYPTO_NULL,
                                                        decrypted_signature,
                                                        sizeof(decrypted_signature),
                                                        certificate -> nx_secure_x509_public_cipher_metadata_area,
                                                        certificate -> nx_secure_x509_public_cipher_metadata_size,
                                                        NX_CRYPTO_NULL, NX_CRYPTO_NULL);

            if(status != NX_CRYPTO_SUCCESS)
            {
#ifdef NX_SECURE_KEY_CLEAR
                NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

                return(status);
            }
        }

        if (public_cipher_method -> nx_crypto_cleanup)
        {
            status = public_cipher_method -> nx_crypto_cleanup(certificate -> nx_secure_x509_public_cipher_metadata_area);

            if(status != NX_CRYPTO_SUCCESS)
            {
#ifdef NX_SECURE_KEY_CLEAR
                NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
                NX_SECURE_MEMSET(decrypted_signature, 0, sizeof(decrypted_signature));
#endif /* NX_SECURE_KEY_CLEAR  */

                return(status);
            }
        }

        if (is_pss)
        {
            /*
             * RFC 8017 9.1.2.  The RSA operation above recovered the encoded
             * message; the salt length comes out of the certificate's own
             * RSASSA-PSS-params, which is compared against the copy inside
             * the signed body before it gets here.
             *
             * emBits is modBits - 1, and modBits is the issuer modulus in
             * bits.  Every RSA modulus in use is a whole number of bytes, so
             * the signature length stands in for it, the same way the TLS 1.3
             * CertificateVerify path does it.
             */
            status = _nx_crypto_rsa_pss_verify(generated_hash, hash_length,
                                               decrypted_signature,
                                               (signature_length << 3) - 1u,
                                               hash_method,
                                               certificate -> nx_secure_x509_hash_metadata_area,
                                               certificate -> nx_secure_x509_hash_metadata_size,
                                               certificate -> nx_secure_x509_signature_salt_length,
                                               pss_scratch, sizeof(pss_scratch));

#ifdef NX_SECURE_KEY_CLEAR
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
            NX_SECURE_MEMSET(decrypted_signature, 0, sizeof(decrypted_signature));
            NX_SECURE_MEMSET(pss_scratch, 0, sizeof(pss_scratch));
#endif /* NX_SECURE_KEY_CLEAR  */

            if (status == NX_CRYPTO_SUCCESS)
            {
                return(NX_SECURE_X509_SUCCESS);
            }

            return(NX_SECURE_X509_CERTIFICATE_SIG_CHECK_FAILED);
        }

        /* Decode the decrypted signature, which should be in PKCS#7 format. */
        status = _nx_secure_x509_pkcs7_decode(decrypted_signature, signature_length, &oid, &oid_length,
                                              &decrypted_hash, &decrypted_hash_length);

#ifdef NX_SECURE_KEY_CLEAR
        if(status != NX_SECURE_X509_SUCCESS || decrypted_hash_length != hash_length)
        {
            /* Clear secrets state on errors. */
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
            NX_SECURE_MEMSET(decrypted_signature, 0, sizeof(decrypted_signature));
        }
#endif /* NX_SECURE_KEY_CLEAR  */

        if (status != NX_SECURE_X509_SUCCESS)
        {
            return(status);
        }

        if (decrypted_hash_length != hash_length)
        {
            return(NX_SECURE_X509_WRONG_SIGNATURE_METHOD);
        }

        /* Compare generated hash with decrypted hash. */
        compare_result = (UINT)NX_SECURE_MEMCMP(generated_hash, decrypted_hash, decrypted_hash_length);

#ifdef NX_SECURE_KEY_CLEAR
        NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
        NX_SECURE_MEMSET(decrypted_signature, 0, sizeof(decrypted_signature));
#endif /* NX_SECURE_KEY_CLEAR  */

        /* If the comparision worked, return success. */
        if (compare_result == 0)
        {
            return(NX_SECURE_X509_SUCCESS);
        }
    }
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    else if (public_cipher_method -> nx_crypto_algorithm == NX_CRYPTO_DIGITAL_SIGNATURE_ECDSA)
    {
        /* Make sure the public algorithm of the issuer certificate is EC. */
        if (issuer_certificate -> nx_secure_x509_public_algorithm != NX_SECURE_TLS_X509_TYPE_EC)
        {
            return(NX_SECURE_X509_WRONG_SIGNATURE_METHOD);
        }

        /* Verify the ECDSA signature. */

        ec_pubkey = &issuer_certificate -> nx_secure_x509_public_key.ec_public_key;

        /* Find out which named curve the remote certificate is using. */
        status = _nx_secure_x509_find_curve_method((USHORT)(ec_pubkey -> nx_secure_ec_named_curve), &curve_method);

#ifdef NX_SECURE_KEY_CLEAR
        if(status != NX_SECURE_X509_SUCCESS || curve_method == NX_CRYPTO_NULL)
        {
            /* Clear secrets on errors. */
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
        }
#endif /* NX_SECURE_KEY_CLEAR  */


        if(status != NX_SECURE_X509_SUCCESS)
        {
            return(status);
        }

        if (public_cipher_method -> nx_crypto_init != NX_CRYPTO_NULL)
        {
            status = public_cipher_method -> nx_crypto_init((NX_CRYPTO_METHOD*)public_cipher_method,
                                                            (UCHAR *)ec_pubkey -> nx_secure_ec_public_key,
                                                            (NX_CRYPTO_KEY_SIZE)(ec_pubkey -> nx_secure_ec_public_key_length << 3),
                                                            &handler,
                                                            certificate -> nx_secure_x509_public_cipher_metadata_area,
                                                            certificate -> nx_secure_x509_public_cipher_metadata_size);
            if (status != NX_CRYPTO_SUCCESS)
            {
#ifdef NX_SECURE_KEY_CLEAR
                NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

                return(status);
            }
        }
        if (public_cipher_method -> nx_crypto_operation == NX_CRYPTO_NULL)
        {
#ifdef NX_SECURE_KEY_CLEAR
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

            return(NX_SECURE_X509_MISSING_CRYPTO_ROUTINE);
        }

        status = public_cipher_method -> nx_crypto_operation(NX_CRYPTO_EC_CURVE_SET, handler,
                                                             (NX_CRYPTO_METHOD*)public_cipher_method, NX_CRYPTO_NULL, 0,
                                                             (UCHAR *)curve_method, sizeof(NX_CRYPTO_METHOD *), NX_CRYPTO_NULL,
                                                             NX_CRYPTO_NULL, 0,
                                                             certificate -> nx_secure_x509_public_cipher_metadata_area,
                                                             certificate -> nx_secure_x509_public_cipher_metadata_size,
                                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
        if (status != NX_CRYPTO_SUCCESS)
        {
#ifdef NX_SECURE_KEY_CLEAR
            NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

            return(status);
        }

        status = public_cipher_method -> nx_crypto_operation(NX_CRYPTO_VERIFY, handler,
                                                             (NX_CRYPTO_METHOD*)public_cipher_method,
                                                             (UCHAR *)ec_pubkey -> nx_secure_ec_public_key,
                                                             (NX_CRYPTO_KEY_SIZE)(ec_pubkey -> nx_secure_ec_public_key_length << 3),
                                                             generated_hash,
                                                             hash_method -> nx_crypto_ICV_size_in_bits >> 3,
                                                             NX_CRYPTO_NULL,
                                                             (UCHAR *)signature_data,
                                                             signature_length,
                                                             certificate -> nx_secure_x509_public_cipher_metadata_area,
                                                             certificate -> nx_secure_x509_public_cipher_metadata_size,
                                                             NX_CRYPTO_NULL, NX_CRYPTO_NULL);
#ifdef NX_SECURE_KEY_CLEAR
        NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

        if (status == NX_CRYPTO_SUCCESS)
        {
            return(NX_SECURE_X509_SUCCESS);
        }
    }
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */
    else
    {
        return(NX_SECURE_X509_UNSUPPORTED_PUBLIC_CIPHER);
    }

#ifdef NX_SECURE_KEY_CLEAR
        NX_SECURE_MEMSET(generated_hash, 0, sizeof(generated_hash));
#endif /* NX_SECURE_KEY_CLEAR  */

    /* Comparison failed, return error. */
    return(NX_SECURE_X509_CERTIFICATE_SIG_CHECK_FAILED);
}
