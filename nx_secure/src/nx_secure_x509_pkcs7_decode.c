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
/**    X.509 Digital Certificates - PKCS#7 parsing                        */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SECURE_SOURCE_CODE


#include "nx_secure_x509.h"

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_pkcs7_decode                        PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function decodes a PKCS#7 (RFC 5652) certificate signature     */
/*    and returns a pointer to the encapsulated hash for signature        */
/*    verification by the caller. Also returned is the OID for the        */
/*    signature algorithm.                                                */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    signature_pointer                     Pointer to PCKS#7 signature   */
/*    signature_length                      Length of entire signagure    */
/*    signature_oid                         Pointer to signature OID      */
/*    signature_oid_length                  Return length of OID          */
/*    hash_data                             Pointer to hash data          */
/*    hash_length                           Return length of hash         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Signature validity status     */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_certificate_verify    Verify a certificate          */
/*    _nx_secure_x509_crl_verify            Verify revocation list        */
/*    _nx_secure_tls_process_server_key_exchange                          */
/*                                          Process ServerKeyExchange     */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_pkcs7_decode(const UCHAR *signature_pointer, UINT signature_length,
                                  const UCHAR **signature_oid, UINT *signature_oid_length,
                                  const UCHAR **hash_data, UINT *hash_length)
{
UINT         i;
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data = NX_CRYPTO_NULL;
ULONG        header_length;
ULONG        seq_length;
UINT         status;
const UCHAR *signature_data = NX_CRYPTO_NULL;
ULONG        remaining_length;

    /* The buffer is a whole RSA block, and EMSA-PKCS1-v1_5 (RFC 8017 9.2) fixes
     * every byte of it:
     *    0x00
     *    0x01                        block type; 2 is encryption, 0 is ambiguous
     *    0xFF ... 0xFF               at least eight of them
     *    0x00                        terminator
     *    DigestInfo, DER, filling the block exactly
     *       SEQUENCE
     *           AlgorithmIdentifier SEQUENCE
     *              digest algorithm OID
     *              NULL parameters
     *           OCTET STRING of the hash value
     *
     * The encoding is checked, not skimmed.  A verifier that takes the first
     * 0x00 as the terminator and ignores what follows the DigestInfo lets a
     * forger with e=3 pick the low bytes freely, and a perfect cube then passes
     * with no knowledge of the private key at all -- Bleichenbacher, 2006.
     */

    signature_data = signature_pointer;
    remaining_length = signature_length;

    /* 0x00 0x01, eight padding bytes, 0x00, and a DigestInfo is the shortest
       this can be; anything under that cannot hold one. */
    if (signature_length < 11)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    if (signature_data[0] != 0x00 || signature_data[1] != 0x01)
    {
        /* Invalid PKCS#1 encoding or decryption failure. */
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    /* Every byte up to the terminator is 0xFF, and there are at least eight. */
    i = 2;
    while (i < signature_length && signature_data[i] == 0xFF)
    {
        i++;
    }

    if ((i - 2) < 8 || i >= signature_length || signature_data[i] != 0x00)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    /* Skip over the padding terminator. */
    i++;

    /* Advance our working pointer. */
    signature_data = &signature_data[i];
    remaining_length -= i;

    /* Now we have our ASN.1-encoded signature. */
    status = _nx_secure_x509_asn1_tlv_block_parse(signature_data, &remaining_length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed a proper ASN.1 sequence. */
    if (status != 0 || tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    /* The DigestInfo has to reach the end of the block.  Room after it is the
       other half of the forgery above: the padding is then no longer pinned to
       the modulus size and the low bytes are the forger's to choose. */
    if (remaining_length != 0)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    /* Advance our working pointer and adjust remaining length. */
    signature_data = tlv_data;
    remaining_length = tlv_length;

    /* Next up is the OID sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(signature_data, &remaining_length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed a proper ASN.1 sequence. */
    if (status != 0 || tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }
    signature_data = tlv_data;
    seq_length = tlv_length;

    /* Next we parse the OID(s). */
    do
    {
        /* Parse at least 1 OID. */
        status = _nx_secure_x509_asn1_tlv_block_parse(signature_data, &seq_length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

        /*  Make sure we parsed a proper ASN.1 sequence. */
        if (status != 0 || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
        {
            return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
        }

        /* Adjust our buffer pointer. */
        signature_data = &signature_data[tlv_length + header_length];

        /* If we see a NULL tag, we are at the end of the list. */
        if (tlv_type == NX_SECURE_ASN_TAG_NULL)
        {
            break;
        }

        /* Save off the OID. */
        *signature_oid = tlv_data;
        *signature_oid_length = tlv_length;
    } while (tlv_type == NX_SECURE_ASN_TAG_OID);

    /* Finally, we should be at the signature hash itself. */
    status = _nx_secure_x509_asn1_tlv_block_parse(signature_data, &remaining_length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed a proper ASN.1 sequence. */
    if (status != 0 || tlv_type != NX_SECURE_ASN_TAG_OCTET_STRING || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    /* The hash is the last field of the DigestInfo, so nothing follows it. */
    if (remaining_length != 0)
    {
        return(NX_SECURE_X509_PKCS7_PARSING_FAILED);
    }

    /* Return pointer to hash data and its length. */
    *hash_data = tlv_data;
    *hash_length = tlv_length;

    /* Signature is valid. */
    return(NX_SECURE_X509_SUCCESS);
}

