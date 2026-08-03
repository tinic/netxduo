/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
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
/*    _nx_secure_x509_basic_constraints_extension_parse   PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Tinic Uro                                                           */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function parses the basicConstraints extension of an X.509     */
/*    certificate, returning the cA boolean and the pathLenConstraint.    */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    certificate                           Pointer to X.509 certificate  */
/*    is_ca                                 Return cA boolean             */
/*    path_length                           Return pathLenConstraint, or  */
/*                                            -1 when it is absent        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Completion status             */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_extension_find        Find extension in certificate */
/*    _nx_secure_x509_asn1_tlv_block_parse  Parse ASN.1 block             */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_secure_x509_certificate_chain_verify                            */
/*                                          Verify a certificate chain    */
/*    Application Code                                                    */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_basic_constraints_extension_parse(NX_SECURE_X509_CERT *certificate,
                                                       UINT *is_ca, INT *path_length)
{
USHORT                   tlv_type;
USHORT                   tlv_type_class;
ULONG                    tlv_length;
const UCHAR             *tlv_data;
const UCHAR             *current_buffer;
ULONG                    length;
ULONG                    remaining;
ULONG                    header_length;
UINT                     status;
ULONG                    i;
ULONG                    value;
NX_SECURE_X509_EXTENSION basic_constraints_extension;

    /* basicConstraints ASN.1 format:

       id-ce-basicConstraints OBJECT IDENTIFIER ::=  { id-ce 19 }

       BasicConstraints ::= SEQUENCE {
           cA                      BOOLEAN DEFAULT FALSE,
           pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */

    *is_ca = NX_CRYPTO_FALSE;
    *path_length = -1;

    /* Find the BasicConstraints extension in the certificate. */
    status = _nx_secure_x509_extension_find(certificate, &basic_constraints_extension,
                                            NX_SECURE_TLS_X509_TYPE_BASIC_CONSTRAINTS);

    /* Absence is reported to the caller, which decides what it means. */
    if (status != NX_SECURE_X509_SUCCESS)
    {
        return(status);
    }

    current_buffer = basic_constraints_extension.nx_secure_x509_extension_data;
    length = basic_constraints_extension.nx_secure_x509_extension_data_length;

    /* The extension data is a single SEQUENCE. */
    status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class,
                                                  &tlv_length, &tlv_data, &header_length);

    if (status != 0)
    {
        return(status);
    }

    if (!(tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL && tlv_type == NX_SECURE_ASN_TAG_SEQUENCE))
    {
        return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
    }

    /* An empty sequence is legal: both members have a default or are optional. */
    remaining = tlv_length;

    if (remaining == 0)
    {
        return(NX_SECURE_X509_SUCCESS);
    }

    current_buffer = tlv_data;

    /* Each parse is handed what is left of the sequence, and the block parser
       refuses a block whose header and value do not fit in it -- so the
       subtraction below cannot go negative and no read leaves the extension.

       cA, if present.  DER forbids encoding a DEFAULT at its default value, so
       an absent boolean means FALSE and the first member is the
       pathLenConstraint -- itself only meaningful with cA TRUE, but parsing it
       is harmless. */
    length = remaining;
    status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class,
                                                  &tlv_length, &tlv_data, &header_length);

    if (status != 0)
    {
        return(status);
    }

    if (tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL && tlv_type == NX_SECURE_ASN_TAG_BOOLEAN)
    {
        if (tlv_length != 1)
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }

        /* ASN.1 TRUE is any non-zero octet; DER requires 0xFF. */
        *is_ca = (tlv_data[0] != 0);

        remaining -= header_length + tlv_length;
        current_buffer += header_length + tlv_length;

        if (remaining == 0)
        {
            return(NX_SECURE_X509_SUCCESS);
        }

        length = remaining;
        status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class,
                                                      &tlv_length, &tlv_data, &header_length);

        if (status != 0)
        {
            return(status);
        }
    }

    /* pathLenConstraint, if present. */
    if (tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL && tlv_type == NX_SECURE_ASN_TAG_INTEGER)
    {
        /* It is a non-negative INTEGER, so a leading zero octet is padding and
           anything wider than that is beyond any chain this can be asked about.
           Clamp rather than fail: an unreadably large limit constrains nothing. */
        value = 0;

        for (i = 0; i < tlv_length; i++)
        {
            if (value > (0x7FFFFFFFuL >> 8))
            {
                value = 0x7FFFFFFFuL;
                break;
            }

            value = (value << 8) + tlv_data[i];
        }

        *path_length = (INT)value;
    }

    return(NX_SECURE_X509_SUCCESS);
}
