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

static UINT _nx_secure_x509_parse_cert_data(const UCHAR *buffer, ULONG length,
                                            UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_version(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                          NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_serial_num(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_signature_algorithm(const UCHAR *buffer, ULONG length,
                                                      UINT *bytes_processed,
                                                      NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_pss_parameters(const UCHAR *buffer, ULONG length,
                                                 UINT *algorithm, USHORT *salt_length);
static UINT _nx_secure_x509_parse_issuer(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                         NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_validity(const UCHAR *buffer, ULONG length,
                                           UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_subject(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                          NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_public_key(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_unique_ids(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_extensions(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_parse_signature_data(const UCHAR *buffer, ULONG length,
                                                 UINT *bytes_processed, NX_SECURE_X509_CERT *cert);
static UINT _nx_secure_x509_extract_oid_data(const UCHAR *buffer, UINT oid, UINT oid_param, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert);

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_certificate_parse                   PORTABLE C      */
/*                                                           6.1.11       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses a DER-encoded X509 digital certificate and     */
/*    up pointers in the NX_SECURE_X509_CERT structure to the various     */
/*    fields needed by applications such as TLS. Note that to save memory */
/*    the data is left in-place and not copied out into separate buffers. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Length of data in buffer      */
/*    bytes_processed                       Return bytes processed        */
/*    cert                                  Return X509 structure         */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*    _nx_secure_x509_parse_signature_algorithm                           */
/*                                          Parse signature algorithm in  */
/*                                            certificate                 */
/*    _nx_secure_x509_parse_signature_data  Parse signature data in       */
/*                                            certificate                 */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_tls_process_remote_certificate                           */
/*                                          Process server certificate    */
/*    _nx_secure_x509_certificate_initialize                              */
/*                                          Initialize certificate        */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_certificate_parse(const UCHAR *buffer, UINT length, UINT *bytes_processed,
                                       NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
UINT         bytes;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;
UINT         signature_algorithm;
USHORT       signature_salt;

    /* X509 Certificate structure:
     * ASN.1 sequence: Certificate
     *     Sequence: Certificate data
     *         Version (e.g. X509v3)
     *         Serial Number
     *         Sequence: Signature algorithm
     *             Signature Algorithms (e.g. RSA_SHA-256)
     *             NULL
     *         Sequence: Issuer
     *             Set: Issuer information (multiple sets here - one per OID)
     *                 Sequence: Information (multiple sequences here?)
     *                     ASN.1 OID    (e.g. Country/Region)
     *                     ASN.1 String (e.g. "US")
     *             ...
     *         Sequence: Validity Period
     *             UTC Time: Not before (ASN.1 time value)
     *             UTC Time: Not After
     *         Sequence: Subject info (Common Name, etc. for this certificate)
     *             Set: Subject information (multiple sets here - one per OID)
     *                 Sequence: Information (multiple sequences here?)
     *                     ASN.1 OID    (e.g. Country/Region)
     *                     ASN.1 String (e.g. "US")
     *             ...
     *         Sequence: Public Key
     *             Sequence: Public key data
     *                 ASN.1 OID (e.g. RSA)
     *                 NULL
     *             ASN.1 Bit string - contains embedded key data in ASN.1 format:
     *                {
     *                  1 byte: padding (always 0?)
     *                  ASN.1 Key information - sequence of 2 integers for RSA:
     *                  Public Modulus followed by Public Exponent
     *                }
     *          ASN.1 Bit String: Extensions
     *              {
     *                  ASN.1-encoded data for extensions
     *              }
     *    Sequence: Signature algorithm data
     *        ASN.1 OID (E.g RSA_SHA256)
     *        NULL
     *    ASN.1 Bit string: Signature data
     *
     * Parsing of this structure is as follows:
     *    - Each sequence is parsed by it's own function
     *    - The structure of each recursive sequence/set is encapsulated in the function that parses it
     *    - Some functions may be used in multiple places (e.g. subject info parsing)
     *    - At the lowest level, all parsing will be done by the ASN.1 TLV block parser.
     */


    if (cert == NX_CRYPTO_NULL)
    {
        return(NX_CRYPTO_PTR_ERROR);
    }

    /*  Parse a TLV block and get information to continue parsing. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, (ULONG *)&length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_INVALID_CERTIFICATE_SEQUENCE);
    }

    *bytes_processed = header_length;
    length = tlv_length;

    /* Next block should be the certificate data. */
    status = _nx_secure_x509_parse_cert_data(tlv_data, tlv_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    *bytes_processed += bytes;

    /*  Following the certificate data is the signature algorithm data.
     *
     *  The identifier appears twice: once inside the tbsCertificate, where it
     *  is covered by the signature, and once outside it, where it is not.  Both
     *  calls write nx_secure_x509_signature_algorithm and the outer one lands
     *  second, so verification picks its hash and its public-key operation from
     *  the copy an attacker can rewrite in flight.  RFC 5280 4.1.1.2 requires
     *  the two to be identical; comparing them is what makes the field the
     *  signer's rather than the sender's.
     */
    signature_algorithm = cert -> nx_secure_x509_signature_algorithm;
    signature_salt      = cert -> nx_secure_x509_signature_salt_length;

    tlv_data = &tlv_data[bytes];
    length -= bytes;
    status = _nx_secure_x509_parse_signature_algorithm(tlv_data, length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    if (cert -> nx_secure_x509_signature_algorithm != signature_algorithm ||
        cert -> nx_secure_x509_signature_salt_length != signature_salt)
    {
        return(NX_SECURE_X509_SIGNATURE_ALGORITHM_MISMATCH);
    }

    *bytes_processed += bytes;

    /* Finally, the signature itself is at the end of the certificate. */
    tlv_data = &tlv_data[bytes];
    length -= bytes;
    status = _nx_secure_x509_parse_signature_data(tlv_data, length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Return the number of bytes we processed. */
    *bytes_processed += bytes;

    if (cert -> nx_secure_x509_public_algorithm != NX_SECURE_TLS_X509_TYPE_RSA
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
        && cert -> nx_secure_x509_public_algorithm != NX_SECURE_TLS_X509_TYPE_EC
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */
        )
    {
        return(NX_SECURE_X509_UNSUPPORTED_PUBLIC_CIPHER);
    }

    /* Successfully parsed an X509 certificate. */
    return(NX_SECURE_X509_SUCCESS);
}


/* --- Helper functions. --- */

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_extract_oid_data                    PORTABLE C      */
/*                                                           6.1.11       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function extracts data from the certificate buffer associated   */
/*   with an OID, but not part of a Distinguished Name Field or           */
/*   extensions. This generally includes public keys and algorithm        */
/*   identifiers.                                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    oid                                   Data type in OID              */
/*    oid_param                             Public key parameter OID      */
/*    length                                Length of data in buffer      */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_public_key      Parse public key in           */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_extract_oid_data(const UCHAR *buffer, UINT oid, UINT oid_param, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
const UCHAR *sequence_data;
ULONG        header_length;
UINT         status;
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
NX_SECURE_EC_PUBLIC_KEY *ec_pubkey;
#else
    NX_CRYPTO_PARAMETER_NOT_USED(oid_param);
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */


    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);
    if (status != 0)
    {
        *bytes_processed = 0;

        return(status);
    }

    *bytes_processed = (header_length + tlv_length);

    /* The RSA OID represents an ASN.1 structure rather than a simple field so handle it differently. */
    if (oid == NX_SECURE_TLS_X509_TYPE_RSA)
    {
        /*  RSA public key. ASN.1 formatted string with a leading 0 byte. */

        if (tlv_length < 1)
        {
            return(NX_SECURE_X509_ASN1_LENGTH_TOO_LONG);
        }

        /*  Parse the RSA bitstring - it is preceeded by a byte indicating the number of padding bytes
         *  added. Should always be 0. */
        if (tlv_data[0] != 0)
        {
            return(NX_SECURE_X509_FOUND_NON_ZERO_PADDING);
        }

        length = tlv_length - 1;

        /* First is a sequence. */
        status = _nx_secure_x509_asn1_tlv_block_parse(&tlv_data[1], &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

        if (status || tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
        {
            return(NX_SECURE_X509_MISSING_PUBLIC_KEY);
        }

        sequence_data = tlv_data;
        length = tlv_length;

        /* Inside is the public modulus. */
        status = _nx_secure_x509_asn1_tlv_block_parse(sequence_data, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

        if (status || tlv_type != NX_SECURE_ASN_TAG_INTEGER || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
        {
            return(NX_SECURE_X509_INVALID_PUBLIC_KEY);
        }

        /* The modulus has a 0 byte at the front we need to skip.
         * This is due to the modulus being encoded as an ASN.1 bit string, which may
         * require padding bits to get to a multiple of 8 for byte alignment. The byte
         * represents the number of padding bits, but in X509 it should always be 0.
         *
         * That byte has to be there and has to be zero: an RSA modulus has its
         * top bit set, so DER always writes it, and skipping a byte that is
         * something else reads the modulus one byte out of place. A zero-length
         * INTEGER would also take the length below through zero. */
        if (tlv_length < 2 || tlv_data[0] != 0x00)
        {
            return(NX_SECURE_X509_INVALID_PUBLIC_KEY);
        }

        cert -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus = tlv_data + 1;
        cert -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = (USHORT)(tlv_length - 1);

        /* A modulus small enough to factor is not a key. 512 bits has been
           within reach of ordinary hardware for years, and 768 was factored in
           2009. The floor here is 1024 rather than the 2048 a public CA has
           issued since 2013, because a self-signed device certificate on
           somebody's own network may still be 1024 and refusing it would break
           a connection that works today. */
        if (cert -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length <
            NX_SECURE_X509_MIN_RSA_MODULUS_SIZE)
        {
            return(NX_SECURE_X509_INVALID_PUBLIC_KEY);
        }

        /* Finally the public exponent. */
        status = _nx_secure_x509_asn1_tlv_block_parse(&sequence_data[header_length + tlv_length], &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

        if (status || tlv_type != NX_SECURE_ASN_TAG_INTEGER || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
        {
            return(NX_SECURE_X509_INVALID_PUBLIC_KEY);
        }

        /* Extract a pointer to the public exponent. */
        cert -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent = tlv_data;
        cert -> nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent_length = (USHORT)tlv_length;
    }
#ifdef NX_SECURE_ENABLE_ECC_CIPHERSUITE
    else if (oid == NX_SECURE_TLS_X509_TYPE_EC)
    {
        /*  EC public key. */

        /*  Parse the EC bitstring - it is preceeded by a byte indicating the number of padding bytes
         *  added. Should always be 0. */
        if (tlv_data[0] != 0)
        {
            return(NX_SECURE_X509_FOUND_NON_ZERO_PADDING);
        }

        ec_pubkey = &cert -> nx_secure_x509_public_key.ec_public_key;
        ec_pubkey -> nx_secure_ec_public_key = &tlv_data[1];
        ec_pubkey -> nx_secure_ec_public_key_length = (USHORT)(tlv_length - 1);
        ec_pubkey -> nx_secure_ec_named_curve = oid_param;
    }
#endif /* NX_SECURE_ENABLE_ECC_CIPHERSUITE */

    /* Any additional special-case handling should go here. */
    switch (oid)
    {
    case NX_SECURE_TLS_X509_TYPE_RSA_MD5:
    case NX_SECURE_TLS_X509_TYPE_RSA_SHA_1:
    case NX_SECURE_TLS_X509_TYPE_RSA_SHA_256:
    case NX_SECURE_TLS_X509_TYPE_RSA_SHA_384:
    case NX_SECURE_TLS_X509_TYPE_RSA_SHA_512:
    case NX_SECURE_TLS_X509_TYPE_DSS_SHA_1:
    case NX_SECURE_TLS_X509_TYPE_DH:
    case NX_SECURE_TLS_X509_TYPE_RSA:
        /*Public keys require additional parsing, handled above. */
    default:
        break;
    }

    /* We have successfully extracted our data based on the OID. */
    return(NX_SECURE_X509_SUCCESS);
}


/* Parse the sequence that contains all the certificate data (e.g. Common Name and public key). */
/*         Version (e.g. X509v3)
 *         Serial Number
 *         Sequence: Signature algorithm (NULL-terminated)
 *         Sequence: Issuer
 *         Sequence: Validity Period
 *         Sequence: Subject info (Common Name, etc. for this certificate)
 *         Sequence: Public Key
 *         ASN.1 Bit String: Extensions
 */
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data                     PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the ASN.1 sequence in an X.509 certificate that */
/*   contains the identity information for the certificate. This is the   */
/*   high-level container for all the certificate information.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*    _nx_secure_x509_parse_extensions      Parse extension in certificate*/
/*    _nx_secure_x509_parse_issuer          Parse issuer in certificate   */
/*    _nx_secure_x509_parse_public_key      Parse public key in           */
/*                                            certificate                 */
/*    _nx_secure_x509_parse_serial_num      Parse serial number in        */
/*                                            certificate                 */
/*    _nx_secure_x509_parse_signature_algorithm                           */
/*                                          Parse signature algorithm in  */
/*                                            certificate                 */
/*    _nx_secure_x509_parse_subject         Parse subject in certificate  */
/*    _nx_secure_x509_parse_unique_ids      Parse unique IDs in           */
/*                                            certificate                 */
/*    _nx_secure_x509_parse_validity        Parse validity in certificate */
/*    _nx_secure_x509_parse_version         Parse version in certificate  */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_certificate_parse     Extract public key data       */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_cert_data(const UCHAR *buffer, ULONG length,
                                            UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
UINT         bytes;
UINT         cur_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    /*  Parse a TLV block and get information to continue parsing. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    /* Buffer should contain the certificate data sequence. */
    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_INVALID_CERTIFICATE_DATA);
    }

    /* We need to save off a pointer to the certificate data and its length for
       signature generation and verification later on. The certificate data
       for verification includes the encapsulating ASN.1 sequence header.  */
    cert -> nx_secure_x509_certificate_data = buffer;
    cert -> nx_secure_x509_certificate_data_length = tlv_length + header_length;

    *bytes_processed = header_length;

    /*  First up is the version data. */
    status = _nx_secure_x509_parse_version(tlv_data, tlv_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    cur_length = tlv_length;

    /*  Next is the serial number. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;
    status = _nx_secure_x509_parse_serial_num(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Signature algorithm (embedded in the certificate information). */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;
    status = _nx_secure_x509_parse_signature_algorithm(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Issuer data. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;
    status = _nx_secure_x509_parse_issuer(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Validity period. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;
    status = _nx_secure_x509_parse_validity(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Subject information. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;
    status = _nx_secure_x509_parse_subject(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Public key. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;
    status = _nx_secure_x509_parse_public_key(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    /* Optional Issuer and Subject Unique IDs. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;

    /* The following fields are all optional, so stop parsing with success if
       they were not included. */
    if (cur_length == 0)
    {
        return(NX_SECURE_X509_SUCCESS);
    }


    status = _nx_secure_x509_parse_unique_ids(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    *bytes_processed += bytes;


    /* Parse extensions. */
    tlv_data = &tlv_data[bytes];
    cur_length -= bytes;
    *bytes_processed += bytes;


    /* The following fields are all optional, so stop parsing with success if
       they were not included. */
    if (cur_length == 0)
    {
        return(NX_SECURE_X509_SUCCESS);
    }

    status = _nx_secure_x509_parse_extensions(tlv_data, cur_length, &bytes, cert);

    if (status != 0)
    {
        return(status);
    }

    *bytes_processed += bytes;

    /* Parsed X509 certificate data successfully. */
    return(NX_SECURE_X509_SUCCESS);
}

/* X509 certificate version parsing. NOTE: X509v1 certificates do NOT have a version field! */
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_version                       PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the optional version field in an X.509          */
/*   certificate. If the field is omitted, the certificate must be a      */
/*   version 1 X.509 certificate.                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_version(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                          NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    NX_CRYPTO_PARAMETER_NOT_USED(cert);

    /*  Parse a TLV block and get information to continue parsing. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    /* Check to see if version exists. If the version is present it will have a type
     * of NX_SECURE_ASN_TAG_BER. Otherwise it is an X509v1 certificate or invalid
     * (determined higher up the call stack). */
    if (tlv_type == NX_SECURE_ASN_TAG_BER && tlv_type_class == NX_SECURE_ASN_TAG_CLASS_CONTEXT)
    {
        /* Version is the payload byte. */
        cert -> nx_secure_x509_version = (USHORT)tlv_data[0];

        /* Return the number of bytes we processed. */
        *bytes_processed = header_length + tlv_length;
    }
    else
    {
        /* No Version field found, assume X509v1. */
        cert -> nx_secure_x509_version = NX_SECURE_X509_VERSION_1;

        /* No bytes processed since the field was omitted. */
        *bytes_processed = 0;
    }

    /* Always return success - this field is optional. */
    return(NX_SECURE_X509_SUCCESS);
}

/* X509 certificate serial number parsing. */
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_serial_num                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the serial number field of an X.509             */
/*   certificate.                                                         */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_serial_num(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    NX_CRYPTO_PARAMETER_NOT_USED(cert);

    /*  Parse a TLV block and get information to continue parsing. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    /* Check to see if version exists. If the version is present it will have a type
     * of NX_SECURE_ASN_TAG_BER. Otherwise it is an X509v1 certificate or invalid
     * (determined higher up the call stack). */
    if (tlv_type != NX_SECURE_ASN_TAG_INTEGER || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Save off the serial number in case someone wants it. */
    cert -> nx_secure_x509_serial_number = tlv_data;
    cert -> nx_secure_x509_serial_number_length = (USHORT)tlv_length;

    /* Return the number of bytes we processed. */
    *bytes_processed = header_length + tlv_length;

    return(NX_SECURE_X509_SUCCESS);
}

/* X509 certificate signature algorithm parsing. Used at both the top level and in the certificate sequence. */
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_signature_algorithm           PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the signature algorithm field in an X.509       */
/*   certificate. The signature algorithm is found both in certificate    */
/*   data sequence and with the public key information.                   */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*    _nx_secure_x509_oid_parse             Parse OID in certificate      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*    _nx_secure_x509_certificate_parse     Extract public key data       */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_signature_algorithm(const UCHAR *buffer, ULONG length,
                                                      UINT *bytes_processed,
                                                      NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
UINT         oid;
ULONG        header_length;
UINT         status;
UCHAR        oid_found = NX_CRYPTO_FALSE;

    /* The signature algorithm is an OID and has optionally associated parameters. */
    *bytes_processed = 0;

    /*  First, parse the sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /*  Limit the length to the sequence length. */
    length = tlv_length;

    /*  While the tag is not NULL and we don't run out of buffer, keep parsing OIDs. */
    *bytes_processed += header_length;
    while (length > 0)
    {
        status = _nx_secure_x509_asn1_tlv_block_parse(tlv_data, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);
        if (status != 0)
        {
            return status;
        }

        /*  Update bytes processed. */
        *bytes_processed += (header_length + tlv_length);

        /* Now check out what we got. */
        if (tlv_type == NX_SECURE_ASN_TAG_OID)
        {
            _nx_secure_x509_oid_parse(tlv_data, tlv_length, &oid);

            cert -> nx_secure_x509_signature_algorithm = oid;
            cert -> nx_secure_x509_signature_salt_length = 0;

            oid_found = NX_CRYPTO_TRUE;
        }
        else if (tlv_type == NX_SECURE_ASN_TAG_SEQUENCE &&
                 tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL &&
                 oid_found == NX_CRYPTO_TRUE &&
                 cert -> nx_secure_x509_signature_algorithm == NX_SECURE_TLS_X509_TYPE_RSA_PSS)
        {
            /* id-RSASSA-PSS is the one signature OID whose parameters are not
               NULL: the digest, the mask generation function and the salt
               length live in a SEQUENCE beside it (RFC 4055 3.1).  Reading
               them is what turns the bare OID into an algorithm anything
               downstream can act on, and every branch below this call is a
               refusal, so an unreadable parameter set fails the certificate
               rather than silently picking a digest. */
            status = _nx_secure_x509_parse_pss_parameters(
                tlv_data, tlv_length,
                &cert -> nx_secure_x509_signature_algorithm,
                &cert -> nx_secure_x509_signature_salt_length);

            if (status != NX_SECURE_X509_SUCCESS)
            {
                return(status);
            }

            break;
        }
        else if (tlv_type == NX_SECURE_ASN_TAG_NULL)
        {
            break;
        }
        else
        {
            return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
        }

        /* Advance the data pointer. */
        tlv_data = &tlv_data[tlv_length];
    }

    /* A bare id-RSASSA-PSS with no parameters means the RFC 4055 defaults,
       which are SHA-1 throughout.  This stack does not accept a SHA-1
       signature from any other table either. */
    if (cert -> nx_secure_x509_signature_algorithm == NX_SECURE_TLS_X509_TYPE_RSA_PSS)
    {
        return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
    }

    if (oid_found == NX_CRYPTO_TRUE)
    {
        return(NX_SECURE_X509_SUCCESS);
    }

    /* We were expecting a signature algorithm OID but didn't find one. */
    return(NX_SECURE_X509_MISSING_SIGNATURE_ALGORITHM);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_algorithm_id                  PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Parses one AlgorithmIdentifier and returns the internal constant for */
/*    its OID, plus a pointer to whatever parameters follow the OID inside */
/*    the same SEQUENCE.  MGF1 nests one of these inside another, which is */
/*    why the parameters come back rather than being skipped.             */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                AlgorithmIdentifier to parse  */
/*    length                                Bytes available at buffer     */
/*    oid_value                             Return the OID constant       */
/*    params                                Return parameters pointer     */
/*    params_length                         Return parameters length      */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_pss_parameters  Parse RSASSA-PSS-params       */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_algorithm_id(const UCHAR *buffer, ULONG length,
                                               UINT *oid_value,
                                               const UCHAR **params, ULONG *params_length)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
ULONG        sequence_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    *oid_value     = NX_SECURE_TLS_X509_TYPE_UNKNOWN;
    *params        = NX_CRYPTO_NULL;
    *params_length = 0;

    /* AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL } */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class,
                                                  &tlv_length, &tlv_data, &header_length);

    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE ||
        tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    sequence_length = tlv_length;
    length          = tlv_length;

    status = _nx_secure_x509_asn1_tlv_block_parse(tlv_data, &length, &tlv_type, &tlv_type_class,
                                                  &tlv_length, &tlv_data, &header_length);

    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_OID ||
        tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    if ((header_length + tlv_length) > sequence_length)
    {
        return(NX_SECURE_X509_ASN1_LENGTH_TOO_LONG);
    }

    _nx_secure_x509_oid_parse(tlv_data, tlv_length, oid_value);

    *params        = &tlv_data[tlv_length];
    *params_length = sequence_length - header_length - tlv_length;

    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_pss_parameters                PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Parses RSASSA-PSS-params (RFC 4055 3.1) and refines the certificate's */
/*    signature algorithm from the bare id-RSASSA-PSS into the RSA_PSS row  */
/*    for the digest actually named, recording the salt length beside it.   */
/*                                                                        */
/*    Every one of the four fields is DEFAULTed, and every default is       */
/*    SHA-1: an absent digest is SHA-1, an absent mask generation function  */
/*    is MGF1-SHA-1.  This stack removed SHA-1 from the X.509 table on      */
/*    purpose, so an omitted field is refused rather than defaulted.  The   */
/*    salt length is the exception: its default of 20 is a length and not   */
/*    an algorithm, and a signature made with it verifies or does not.      */
/*                                                                        */
/*    The mask generation digest must equal the message digest.  RFC 4055   */
/*    permits them to differ; no certificate issued anywhere does, and the  */
/*    verify path below takes one hash method, so a split pair is refused   */
/*    rather than silently verified against the wrong one.                  */
/*                                                                        */
/*  INPUT                                                                  */
/*                                                                        */
/*    buffer                                RSASSA-PSS-params contents    */
/*    length                                Bytes available at buffer     */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                 */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLED BY                                                              */
/*                                                                        */
/*    _nx_secure_x509_parse_signature_algorithm                            */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_pss_parameters(const UCHAR *buffer, ULONG length,
                                                 UINT *algorithm, USHORT *parsed_salt_length)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
USHORT       int_type;
USHORT       int_class;
ULONG        tlv_length;
ULONG        int_length;
ULONG        available;
ULONG        remaining;
ULONG        field_total;
ULONG        header_length;
ULONG        int_header;
const UCHAR *tlv_data;
const UCHAR *int_data;
const UCHAR *params;
ULONG        params_length;
UINT         status;
UINT         mgf_oid;
UINT         hash_oid     = NX_SECURE_TLS_X509_TYPE_UNKNOWN;
UINT         mgf_hash_oid = NX_SECURE_TLS_X509_TYPE_UNKNOWN;
ULONG        salt_length  = 20; /* RFC 4055 3.1 DEFAULT saltLength. */
ULONG        trailer      = 1;  /* RFC 4055 3.1 DEFAULT trailerFieldBC. */
ULONG        value;
ULONG        i;

    remaining = length;

    while (remaining > 0)
    {
        available = remaining;

        status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &available, &tlv_type, &tlv_type_class,
                                                      &tlv_length, &tlv_data, &header_length);

        if (status != 0)
        {
            return(status);
        }

        /* The bound the ASN.1 helper keeps is its own header, not the value it
           just described, so the value has to be checked against what is left
           here or a length field decides how far past the buffer to read. */
        if ((header_length + tlv_length) > remaining)
        {
            return(NX_SECURE_X509_ASN1_LENGTH_TOO_LONG);
        }

        field_total = header_length + tlv_length;

        /* Every field is [n] EXPLICIT, so anything else here is not this
           structure. */
        if (tlv_type_class != NX_SECURE_ASN_TAG_CLASS_CONTEXT)
        {
            return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
        }

        switch (tlv_type)
        {
        case 0: /* hashAlgorithm */
            status = _nx_secure_x509_parse_algorithm_id(tlv_data, tlv_length, &hash_oid,
                                                        &params, &params_length);
            break;

        case 1: /* maskGenAlgorithm: MGF1, whose own parameter is the digest. */
            status = _nx_secure_x509_parse_algorithm_id(tlv_data, tlv_length, &mgf_oid,
                                                        &params, &params_length);

            if (status == NX_SECURE_X509_SUCCESS)
            {
                if (mgf_oid != NX_SECURE_TLS_X509_TYPE_MGF1)
                {
                    return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
                }

                status = _nx_secure_x509_parse_algorithm_id(params, params_length, &mgf_hash_oid,
                                                            &params, &params_length);
            }
            break;

        case 2: /* saltLength */
        case 3: /* trailerField */
            available = tlv_length;

            status = _nx_secure_x509_asn1_tlv_block_parse(tlv_data, &available, &int_type,
                                                          &int_class, &int_length,
                                                          &int_data, &int_header);

            if (status != 0)
            {
                return(status);
            }

            if (int_type != NX_SECURE_ASN_TAG_INTEGER ||
                int_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL ||
                (int_header + int_length) > tlv_length)
            {
                return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
            }

            /* A DER INTEGER is big-endian and may carry a leading zero; four
               bytes is far more than either of these fields can need. */
            if (int_length == 0 || int_length > 4)
            {
                return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
            }

            value = 0;
            for (i = 0; i < int_length; ++i)
            {
                value = (value << 8) | int_data[i];
            }

            if (tlv_type == 2)
            {
                salt_length = value;
            }
            else
            {
                trailer = value;
            }
            break;

        default:
            return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
        }

        if (status != NX_SECURE_X509_SUCCESS)
        {
            return(status);
        }

        remaining -= field_total;
        buffer     = &buffer[field_total];
    }

    if (trailer != 1)
    {
        return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
    }

    /* An RSA-2048 signature leaves 256 bytes of encoded message, and the salt
       has to fit inside it beside the hash.  The verify would refuse a larger
       one anyway; refusing it here keeps the value inside the USHORT it is
       stored in. */
    if (salt_length > 512)
    {
        return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
    }

    if (hash_oid != mgf_hash_oid)
    {
        return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
    }

    switch (hash_oid)
    {
    case NX_SECURE_TLS_X509_TYPE_HASH_SHA_256:
        *algorithm = NX_SECURE_TLS_X509_TYPE_RSA_PSS_SHA_256;
        break;

    case NX_SECURE_TLS_X509_TYPE_HASH_SHA_384:
        *algorithm = NX_SECURE_TLS_X509_TYPE_RSA_PSS_SHA_384;
        break;

    case NX_SECURE_TLS_X509_TYPE_HASH_SHA_512:
        *algorithm = NX_SECURE_TLS_X509_TYPE_RSA_PSS_SHA_512;
        break;

    default:
        return(NX_SECURE_X509_UNSUPPORTED_SIGNATURE_PARAMETERS);
    }

    *parsed_salt_length = (USHORT)salt_length;

    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_issuer                        PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the issuer distinguished name in an X.509       */
/*   certificate. The issuer distinguished name is used to link the       */
/*   certificate to the CA certificate that signed it.                    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*    _nx_secure_x509_distinguished_name_parse                            */
/*                                          Parse Distinguished Name      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_issuer(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                         NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
UINT         bytes;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    /*  First, parse the sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Now, pass the issuer certificate to populate it with the id info. Note that
     * even if the issuer cert is NULL, we still need to parse the information -
     * the parse_id function handles NULL appropriately. */
    status = _nx_secure_x509_distinguished_name_parse(tlv_data, tlv_length, &bytes, &cert -> nx_secure_x509_issuer);

    /* Return the number of bytes we processed. */
    *bytes_processed = bytes + header_length;

    return status;
}

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_validity                      PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the validity period fields in an X.509          */
/*   certificate. The fields "Not Before" and "Not After" define an       */
/*   explicit time period during which the certificate is valid. The the  */
/*   current date and time fall outside that period, the certificate is   */
/*   considered invalid and should not be trusted.                        */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_validity(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                           NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;
const UCHAR *current_buffer;

    NX_CRYPTO_PARAMETER_NOT_USED(cert);

    /*  First, parse the sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Return the number of bytes we processed. */
    *bytes_processed = header_length + tlv_length;
    length = tlv_length;

    /* Advance to our next item. */
    current_buffer = &buffer[0] + header_length;

    /* Parse the "not before" field. */
    status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if ((tlv_type != NX_SECURE_ASN_TAG_UTC_TIME && tlv_type != NX_SECURE_ASN_TAG_GENERALIZED_TIME) || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    cert -> nx_secure_x509_not_before_validity_format = tlv_type;
    cert -> nx_secure_x509_not_before = tlv_data;
    cert -> nx_secure_x509_not_before_length = (USHORT)tlv_length;

    /* Advance to our next item. */
    current_buffer = current_buffer + (tlv_length + header_length);

    /* Parse the "not after" field. */
    status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if ((tlv_type != NX_SECURE_ASN_TAG_UTC_TIME && tlv_type != NX_SECURE_ASN_TAG_GENERALIZED_TIME) || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    cert -> nx_secure_x509_not_after_validity_format = tlv_type;
    cert -> nx_secure_x509_not_after = tlv_data;
    cert -> nx_secure_x509_not_after_length = (USHORT)tlv_length;

    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_subject                       PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the subject field of an X.509 certificate. This */
/*   field consists of an X.509 Distinguished Name that provides the      */
/*   identity information for the certificate.                            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*    _nx_secure_x509_distinguished_name_parse                            */
/*                                          Parse Distinguished Name      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_subject(const UCHAR *buffer, ULONG length, UINT *bytes_processed,
                                          NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
UINT         bytes;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    /*  First, parse the sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Now, pass the issuer certificate to populate it with the id info. Note that
     * even if the issuer cert is NULL, we still need to parse the information -
     * the parse_id function handles NULL appropriately. */
    status = _nx_secure_x509_distinguished_name_parse(tlv_data, tlv_length, &bytes, &cert -> nx_secure_x509_distinguished_name);

    /* Return the number of bytes we processed. */
    *bytes_processed = bytes + header_length;

    return status;
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_public_key                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the public key field of an X.509 certificate.   */
/*   The field consists of an OID indicating the algorithm (e.g. RSA) and */
/*   an ASN.1 bit string containing a DER-encoded public key, the format  */
/*   of which varies with the algorithm.                                  */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*    _nx_secure_x509_extract_oid_data      Extract OID data              */
/*    _nx_secure_x509_oid_parse             Parse OID in certificate      */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_public_key(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
UINT         bytes = 0;
const UCHAR *tlv_data;
const UCHAR *bitstring_ptr;
ULONG        bitstring_len;
ULONG        header_length;
ULONG        parameter_length;
UINT         oid;
UINT         oid_parameter;
UINT         status;

    /* Extract public key information, encoded as ASN.1 in an ASN.1 bitstring, and populate the certificate. */
    /*         Sequence: Public Key
     *             Sequence: Public key data
     *                 ASN.1 OID (e.g. RSA)
     *                 NULL or parameters
     *             ASN.1 Bit string - contains embedded key data in ASN.1 format:
     *                {
     *                  1 byte: padding (always 0?)
     *                  ASN.1 Key information - sequence of 2 integers for RSA:
     *                  Public Modulus followed by Public Exponent
     *                }
     */

    /* The public key is a sequence of OIDs that is terminated by a NULL ASN.1 tag. */
    *bytes_processed = 0;

    /*  First, parse the outermost sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Save off a pointer into our sequence - we will need it to jump to the public key data,
     * which follows the public key id in the outermost sequence. */
    bitstring_ptr = tlv_data;
    *bytes_processed += header_length;
    length = tlv_length;

    /* Next, parse the OID sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(tlv_data, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Update byte count. */
    *bytes_processed += header_length;

    /* Advance sequence pointer to the next item in the outermost sequence (following the id sequence) */
    bitstring_ptr = &bitstring_ptr[(header_length + tlv_length)];

    /* The length we use to parse the bitstring should be equal to the length of the entire buffer
     * minus the length of the OID sequence. */
    bitstring_len = length;
    length = tlv_length;

    /* Next in the buffer should be an OID to id the public key algorithm. */
    status = _nx_secure_x509_asn1_tlv_block_parse(tlv_data, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);
    if (status != 0)
    {
        return status;
    }

    /*  Update bytes processed. */
    *bytes_processed += (header_length + tlv_length);


    /* Now check out what we got. Should be an OID... */
    if (tlv_type == NX_SECURE_ASN_TAG_OID)
    {
        /* The OID is in the data we extracted. */
        _nx_secure_x509_oid_parse(tlv_data, tlv_length, &oid);
        cert -> nx_secure_x509_public_key_identifier = oid;
        cert -> nx_secure_x509_public_algorithm = oid;

        /* id-RSASSA-PSS carries the same RSAPublicKey bit string as
           rsaEncryption, but certifies it for PSS signatures only. Preserve
           that policy in public_key_identifier and normalize the operation
           type so the existing RSA primitive and key union remain usable. */
        if (oid == NX_SECURE_TLS_X509_TYPE_RSA_PSS)
        {
            cert -> nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_RSA;
            cert -> nx_secure_x509_public_key_pss_algorithm = NX_SECURE_TLS_X509_TYPE_UNKNOWN;
            cert -> nx_secure_x509_public_key_pss_salt_length = 0;
        }

        /* The OID is followed by NULL, a parameter OID, PSS parameters, or
           nothing (the latter is valid only for an id-RSASSA-PSS SPKI). */
        tlv_data = &tlv_data[tlv_length];
        oid_parameter = 0;

        if (length == 0 && oid != NX_SECURE_TLS_X509_TYPE_RSA_PSS)
        {
            return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
        }

        if (length > 0)
        {
            parameter_length = length;
            status = _nx_secure_x509_asn1_tlv_block_parse(tlv_data, &length, &tlv_type,
                                                          &tlv_type_class, &tlv_length,
                                                          &tlv_data, &header_length);
            if (status != 0)
            {
                return status;
            }

            if (oid == NX_SECURE_TLS_X509_TYPE_RSA_PSS)
            {
                /* RFC 4055 permits absent PSS SPKI parameters, but if a
                   value is present it must be RSASSA-PSS-params, never NULL
                   or an unrelated AlgorithmIdentifier. */
                if (tlv_type != NX_SECURE_ASN_TAG_SEQUENCE ||
                    tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
                {
                    return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
                }

                status = _nx_secure_x509_parse_pss_parameters(
                    tlv_data, tlv_length,
                    &cert -> nx_secure_x509_public_key_pss_algorithm,
                    &cert -> nx_secure_x509_public_key_pss_salt_length);
                if (status != NX_SECURE_X509_SUCCESS)
                {
                    return(status);
                }
            }
            else if (tlv_type == NX_SECURE_ASN_TAG_OID)
            {
                _nx_secure_x509_oid_parse(tlv_data, tlv_length, &oid_parameter);
            }
            else if (tlv_type != NX_SECURE_ASN_TAG_NULL ||
                     tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
            {
                return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
            }

            /* AlgorithmIdentifier contains exactly one parameters value. */
            if ((header_length + tlv_length) != parameter_length)
            {
                return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
            }

            *bytes_processed += (header_length + tlv_length);
        }

        /* Extract the data in the block following the OID sequence. Use the calculated remaining
         * length for the length of the data going in. */
        status = _nx_secure_x509_extract_oid_data(bitstring_ptr,
                                                  (oid == NX_SECURE_TLS_X509_TYPE_RSA_PSS) ?
                                                      NX_SECURE_TLS_X509_TYPE_RSA : oid,
                                                  oid_parameter, bitstring_len, &bytes, cert);
        if (status != 0)
        {
            return status;
        }

        /* Update the processed byte count with the extracted OID data. */
        *bytes_processed += (bytes);
    }
    else
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* All good! */
    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_unique_ids                    PORTABLE C      */
/*                                                           6.1.11       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the optional isserUniqueID and subjectUniqueID  */
/*   bit strings in an X.509 certificate.                                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_unique_ids(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;
const UCHAR *current_buffer;
UINT         processed_id;

    NX_CRYPTO_PARAMETER_NOT_USED(cert);

    /* Extract unique identifiers for issuer and subject, if present. */
    /*          issuerUniqueID   ::= ASN.1 Bit String OPTIONAL
     *          subjectUniqueID  ::= ASN.1 Bit String OPTIONAL
     */

    /*  First, parse the next item which may be an ID or the item following the IDs in the X.509 spec if they were omitted. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    *bytes_processed = 0;
    current_buffer = buffer;

    /* If we process either ID, then we need to do a version check (v2 or v3 only). If neither is
       encountered skip the version check. */
    processed_id = NX_CRYPTO_FALSE;

    /* Check for the OPTIONAL issuer unique ID. */
    if (tlv_type_class == NX_SECURE_ASN_TAG_CLASS_CONTEXT && tlv_type == NX_SECURE_X509_TAG_ISSUER_UNIQUE_ID)
    {

        /* We processed an ID, mark for version check. */
        processed_id = NX_CRYPTO_TRUE;

        /* The field is an IMPLICIT bit string, so the data just follows the context-specific tag. */

        /* Save off a pointer to the issuer unique identifier data and its length. */
        cert -> nx_secure_x509_issuer_identifier = tlv_data + 1;
        cert -> nx_secure_x509_issuer_identifier_length = (USHORT)(tlv_length - 1);

        /* Return the number of bytes we processed. */
        *bytes_processed += (header_length + tlv_length);

        /* Advance to our next item. */
        current_buffer = &current_buffer[header_length + tlv_length];

        /* Padding data? */
        if (length > 0)
        {
            /*  Parse the next item which might be another ID or perhaps the extensions. */
            status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

            /*  Make sure we parsed the block alright. */
            if (status != 0)
            {
                return(status);
            }
        }
    }

    /* Check for the OPTIONAL subject unique id field. */
    if (tlv_type_class == NX_SECURE_ASN_TAG_CLASS_CONTEXT && tlv_type == NX_SECURE_X509_TAG_SUBJECT_UNIQUE_ID)
    {

        /* We processed an ID, mark for version check. */
        processed_id = NX_CRYPTO_TRUE;

        /* The field is an IMPLICIT bit string, so the data just follows the context-specific tag. */

        /* Save off a pointer to the issuer unique identifier data and its length. */
        cert -> nx_secure_x509_subject_identifier = tlv_data + 1;
        cert -> nx_secure_x509_subject_identifier_length = (USHORT)(tlv_length - 1);

        /* Return the number of bytes we processed. */
        *bytes_processed += (header_length + tlv_length);
    }

    /* If we processed either field, make sure this is version 2 or 3. */
    if(processed_id)
    {
        if (cert -> nx_secure_x509_version != NX_SECURE_X509_VERSION_2 && cert -> nx_secure_x509_version != NX_SECURE_X509_VERSION_3)
        {
            return(NX_SECURE_X509_INVALID_VERSION);
        }
    }

    /* If neither ID field was parsed, bytes_processed should be 0. */
    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_extensions                    PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the extensions sequence in an X.509             */
/*   certificate. The extensions themselves are not parsed here, but a    */
/*   pointer to the beginning of the DER-encoded sequence is saved in     */
/*   the certificate structure so that the extension-specific helper      */
/*   functions can easily find and parse the extensions later.            */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_parse_cert_data       Parse certificate             */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_extensions(const UCHAR *buffer, ULONG length,
                                             UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
const UCHAR *current_buffer;
ULONG        header_length;
UINT         status;

    /* Extract any extension information present in the certificate buffer and populate the certificate structure.
     * Extensions are encoded as ASN.1 in a sequence, so extract and parse that separately. */
    /*          ASN.1 Sequence: Extensions
     *              {
     *                  ASN.1-encoded data for extensions
     *              }
     */

    /*  First, parse the context-specific tag (if it exists). */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    /* If the next item up is not a sequence, then it isn't an extensions block. */
    if (!(tlv_type_class == NX_SECURE_ASN_TAG_CLASS_CONTEXT && tlv_type == NX_SECURE_X509_TAG_EXTENSIONS))
    {
        /* No extensions block is OK because it is non-existent in v1 and v2, and
           OPTIONAL in v3. */
        return(NX_SECURE_X509_SUCCESS);
    }

    /* We have an extensions sequence, this MUST be a version 3 certificate,
       or we have an error. */
    if (cert -> nx_secure_x509_version != NX_SECURE_X509_VERSION_3)
    {
        return(NX_SECURE_X509_INVALID_VERSION);
    }

    *bytes_processed = header_length + tlv_length;
    current_buffer = tlv_data;
    length = tlv_length;

    /*  Next, parse the extensions sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    /* If the next item up is not a sequence, then it isn't an extensions block. */
    if (!(tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL && tlv_type == NX_SECURE_ASN_TAG_SEQUENCE))
    {
        /* No extensions block is OK because it is non-existent in v1 and v2, and
           OPTIONAL in v3. */
        return(NX_SECURE_X509_SUCCESS);
    }

    /* Save off the start of the extensions sequence so we can parse it later when needed. */
    cert -> nx_secure_x509_extensions_data = tlv_data;
    cert -> nx_secure_x509_extensions_data_length = tlv_length;

    /* We have saved off the extensions data successfully. */
    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_parse_signature_data                PORTABLE C      */
/*                                                           6.1.11       */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*   This function parses the certificate signature field in an X.509     */
/*   certificate. The signature data consists of a hash of the            */
/*   certificate data that is encrypted using the issuer's private key.   */
/*   Decrypting the hash with the issuer's public key and checking the    */
/*   result against a locally-computed hash cryptographically ties a      */
/*   certificate to its issuer.                                           */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    buffer                                Pointer data to be parsed     */
/*    length                                Return bytes processed        */
/*    bytes_processed                       Number of bytes being         */
/*                                            consumed by the oid         */
/*    cert                                  The certificate               */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_certificate_parse     Extract public key data       */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_parse_signature_data(const UCHAR *buffer, ULONG length,
                                                 UINT *bytes_processed, NX_SECURE_X509_CERT *cert)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
ULONG        header_length;
UINT         status;

    /* Extract the signature data, which is a hash of the certificate data which is then encrypted using the issuer's
     * private key. This function extracts the encrypted hash but decryption/authentication is done elsewhere. */
    /*    ASN.1 Bit string: Signature data */

    /*  First, parse the sequence. */
    status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class, &tlv_length, &tlv_data, &header_length);

    /*  Make sure we parsed the block alright. */
    if (status != 0)
    {
        return(status);
    }

    if (tlv_type != NX_SECURE_ASN_TAG_BIT_STRING || tlv_type_class != NX_SECURE_ASN_TAG_CLASS_UNIVERSAL)
    {
        return(NX_SECURE_X509_UNEXPECTED_ASN1_TAG);
    }

    /* Save off a pointer to the signature data and its length. */
    /* Signature has a 0 byte at the front we need to skip.
     * This is due to the data being encoded as an ASN.1 bit string, which may
     * require padding bits to get to a multiple of 8 for byte alignment. The byte
     * represents the number of padding bits, but in X509 it should always be 0. */
    cert -> nx_secure_x509_signature_data = tlv_data + 1;
    cert -> nx_secure_x509_signature_data_length = tlv_length - 1;

    /* Return the number of bytes we processed. */
    *bytes_processed = header_length + tlv_length;

    return(NX_SECURE_X509_SUCCESS);
}
