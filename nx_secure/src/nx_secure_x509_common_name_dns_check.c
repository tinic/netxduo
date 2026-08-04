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
/*    _nx_secure_x509_common_name_dns_check               PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Timothy Stapko, Microsoft Corporation                               */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function checks a certificate's Common Name against a Top      */
/*    Level Domain name (TLD) provided by the caller for the purposes of  */
/*    DNS validation of a remote host. This utility function is intended  */
/*    to be called from within a certificate validation callback routine  */
/*    provided by the application. The TLD name should be the top part of */
/*    the URL used to access the remote host (the "."-separated string    */
/*    before the first slash).                                            */
/*                                                                        */
/*    NOTE 1: If the Common Name does not match the provided string, the  */
/*            "subject alt name" field is compared as well.               */
/*                                                                        */
/*    NOTE 2: It is important to understand the format of the common name */
/*            (and subject alt name) in expected certificates. For        */
/*            example, some certificates may use a raw IP address or a    */
/*            wild card. The DNS TLD string must be formatted such that   */
/*            it will match the expected values in received certificates. */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    certificate                           Pointer to certificate        */
/*    dns_tld                               Top-level domain name         */
/*    dns_tls_length                        Length of TLS in bytes        */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    status                                Validity of certificate       */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    _nx_secure_x509_extension_find        Find extension in certificate */
/*    _nx_secure_x509_subject_alt_names_find                              */
/*                                          Find subject alt names        */
/*    _nx_secure_x509_wildcard_compare      Wildcard compare for names    */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    Application code                                                    */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_common_name_dns_check(NX_SECURE_X509_CERT *certificate, const UCHAR *dns_tld,
                                           UINT dns_tld_length)
{
INT                      compare_value;
UINT                     status;
const UCHAR             *common_name;
USHORT                   common_name_len;
NX_SECURE_X509_EXTENSION alt_name_extension;
UINT                     dns_names_present = NX_FALSE;

    /* The subjectAltName comes first, and when it carries dNSNames it is the
       only thing consulted.  RFC 6125 section 6.4.4: the Common Name is to be
       used only when the certificate presents no name of the type being
       matched, and RFC 9525 section 6.3 removes even that.  Testing it first
       and returning on a match, as this function used to, let a certificate
       whose subjectAltName covers one set of hosts be accepted for a
       different host named in its CN -- the CA signed the names in the
       extension, and the CN was never the authority on where the certificate
       may be used.  */
    status = _nx_secure_x509_extension_find(certificate, &alt_name_extension, NX_SECURE_TLS_X509_TYPE_SUBJECT_ALT_NAME);

    /* See if extension present - it is OK if not present! */
    if (status == NX_SECURE_X509_SUCCESS)
    {
        /* Extract the subject alt name string from the parsed extension. */
        status = _nx_secure_x509_subject_alt_names_find_ex(&alt_name_extension, dns_tld, dns_tld_length,
                                                           NX_SECURE_X509_SUB_ALT_NAME_TAG_DNSNAME,
                                                           &dns_names_present);

        if (status == NX_SECURE_X509_SUCCESS)
        {
            return(NX_SECURE_X509_SUCCESS);
        }

        /* Names of this type were offered and none of them matched.  That is
           the answer; the Common Name does not get a second vote.  */
        if (dns_names_present == NX_TRUE)
        {
            return(NX_SECURE_X509_CERTIFICATE_DNS_MISMATCH);
        }
    }

    /* No dNSName to go on, so fall back to the Common Name.  */
    common_name = certificate -> nx_secure_x509_distinguished_name.nx_secure_x509_common_name;
    common_name_len = certificate -> nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length;

    /* Compare the given string against the common name. */
    compare_value = _nx_secure_x509_wildcard_compare(dns_tld, dns_tld_length, common_name, common_name_len);

    if (compare_value == 0)
    {
        return(NX_SECURE_X509_SUCCESS);
    }

    /* If we get here, none of the strings matched. */
    return(NX_SECURE_X509_CERTIFICATE_DNS_MISMATCH);
}

