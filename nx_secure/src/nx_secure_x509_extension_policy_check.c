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
/**    X.509 Digital Certificates                                         */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SECURE_SOURCE_CODE

#include "nx_secure_x509.h"

/* The three checks RFC 5280 asks of a relying party and nx_secure did not make:
   an extendedKeyUsage that permits server authentication, the nameConstraints
   a CA placed on everything below it, and a critical extension nobody
   understood.

   They are one file because they are one property.  The critical bit is the
   certificate's own statement that a relying party which does not understand
   this extension must not use the certificate; honouring that bit while
   treating nameConstraints as understood-and-ignored produces a verifier that
   reports "critical extensions enforced" and lets a constrained CA issue for
   anything, which is worse than not looking at the bit at all.  So the known
   set below is the set this file actually acts on, and nothing is added to it
   without adding the code that acts on it.

   Known-critical is deliberately four entries.  It is not "everything we can
   parse": authorityKeyIdentifier, subjectKeyIdentifier, CRL distribution
   points and certificate policies all parse and none of them is enforced
   here, so a certificate that marks one critical is refused.  That is the
   correct answer under RFC 5280 4.2 and it costs nothing in practice, because
   marking those critical is a misissuance.

   extendedKeyUsage is in the set because Let's Encrypt marks it critical on
   its intermediates.  Leaving it out rejects most of the web.  */

/* The extensions this file enforces, and therefore the only ones a
   certificate may mark critical.  nameConstraints is absent on purpose: it is
   accepted only on the certificate where _nx_secure_x509_name_constraints_check
   has just enforced it, which the caller states. */
static const USHORT _nx_secure_x509_known_critical[] =
{
    NX_SECURE_TLS_X509_TYPE_BASIC_CONSTRAINTS,
    NX_SECURE_TLS_X509_TYPE_KEY_USAGE,
    NX_SECURE_TLS_X509_TYPE_SUBJECT_ALT_NAME,
    NX_SECURE_TLS_X509_TYPE_EXTENDED_KEY_USAGE
};

#define NX_SECURE_X509_KNOWN_CRITICAL_COUNT \
    (sizeof(_nx_secure_x509_known_critical) / sizeof(_nx_secure_x509_known_critical[0]))

/* GeneralName context tags, RFC 5280 4.2.1.6.  Only dNSName is evaluated
   here; see _nx_secure_x509_name_constraints_check for what happens to the
   others. */
#define NX_SECURE_X509_GENERAL_NAME_DNS     (2)


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_dns_name_constrained                PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Does a dNSName fall inside a nameConstraints dNSName subtree?        */
/*    RFC 5280 4.2.1.10: the subtree matches the name itself and any name  */
/*    with additional labels to the left.  "example.com" therefore covers  */
/*    "example.com" and "a.example.com" but not "notexample.com", and the  */
/*    boundary test is what separates those two.  A leading dot in the     */
/*    constraint is tolerated because certificates carry it, and an empty  */
/*    constraint matches everything.                                       */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_dns_name_constrained(const UCHAR *name, UINT name_length,
                                                 const UCHAR *constraint, UINT constraint_length)
{
UINT i;
UCHAR a;
UCHAR b;

    /* Strip a leading dot from the constraint: ".example.com" and
       "example.com" are written interchangeably and mean the same subtree. */
    if ((constraint_length > 0) && (constraint[0] == '.'))
    {
        constraint++;
        constraint_length--;
    }

    /* An empty subtree is every name. */
    if (constraint_length == 0)
    {
        return(NX_CRYPTO_TRUE);
    }

    if (name_length < constraint_length)
    {
        return(NX_CRYPTO_FALSE);
    }

    /* The name has to end with the constraint, case-insensitively. */
    for (i = 0; i < constraint_length; i++)
    {
        a = name[(name_length - constraint_length) + i];
        b = constraint[i];

        if ((a >= 'A') && (a <= 'Z'))
        {
            a = (UCHAR)(a + ('a' - 'A'));
        }
        if ((b >= 'A') && (b <= 'Z'))
        {
            b = (UCHAR)(b + ('a' - 'A'));
        }

        if (a != b)
        {
            return(NX_CRYPTO_FALSE);
        }
    }

    /* Exact match, or the character before the suffix is a label boundary.
       Without this test "notexample.com" is inside "example.com". */
    if (name_length == constraint_length)
    {
        return(NX_CRYPTO_TRUE);
    }

    if (name[(name_length - constraint_length) - 1] == '.')
    {
        return(NX_CRYPTO_TRUE);
    }

    return(NX_CRYPTO_FALSE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_leaf_dns_constrained                PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Does any DNS identity the leaf presents fall inside one subtree?     */
/*    The names are enumerated here rather than through                    */
/*    _nx_secure_x509_subject_alt_names_find, which answers the opposite   */
/*    question -- it takes a name and looks for it, with a wildcard        */
/*    compare that belongs to hostname matching and not to this one.       */
/*                                                                        */
/*    A leaf with no dNSName falls back to its common name, because that   */
/*    is the identity _nx_secure_x509_common_name_dns_check would then     */
/*    accept, and a constraint has to bind the same string the hostname    */
/*    check does.                                                          */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_leaf_dns_constrained(NX_SECURE_X509_CERT *leaf,
                                                 const UCHAR *constraint, UINT constraint_length)
{
NX_SECURE_X509_EXTENSION alt_name;
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
const UCHAR *current_buffer;
ULONG        length;
ULONG        header_length;
UINT         status;
UINT         dns_seen = NX_CRYPTO_FALSE;

    status = _nx_secure_x509_extension_find(leaf, &alt_name, NX_SECURE_TLS_X509_TYPE_SUBJECT_ALT_NAME);

    if (status == NX_SECURE_X509_SUCCESS)
    {
        current_buffer = alt_name.nx_secure_x509_extension_data;
        length = alt_name.nx_secure_x509_extension_data_length;

        status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class,
                                                      &tlv_length, &tlv_data, &header_length);

        if ((status == 0) &&
            (tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL) &&
            (tlv_type == NX_SECURE_ASN_TAG_SEQUENCE))
        {
            current_buffer = tlv_data;
            length = tlv_length;

            while (length > 0)
            {
                status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type,
                                                              &tlv_type_class, &tlv_length, &tlv_data,
                                                              &header_length);
                if (status != 0)
                {
                    break;
                }

                if (tlv_type_class != NX_SECURE_ASN_TAG_CLASS_CONTEXT)
                {
                    break;
                }

                /* Header and value both, or a name of another type ahead of a
                   dNSName leaves the pointer and the counter out of step. */
                current_buffer += header_length + tlv_length;

                if (tlv_type != NX_SECURE_X509_GENERAL_NAME_DNS)
                {
                    continue;
                }

                dns_seen = NX_CRYPTO_TRUE;

                if (_nx_secure_x509_dns_name_constrained(tlv_data, (UINT)tlv_length,
                                                         constraint, constraint_length) == NX_CRYPTO_TRUE)
                {
                    return(NX_CRYPTO_TRUE);
                }
            }
        }
    }

    if (dns_seen == NX_CRYPTO_TRUE)
    {
        return(NX_CRYPTO_FALSE);
    }

    if (leaf -> nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length > 0)
    {
        return(_nx_secure_x509_dns_name_constrained(leaf -> nx_secure_x509_distinguished_name.nx_secure_x509_common_name,
                                                    leaf -> nx_secure_x509_distinguished_name.nx_secure_x509_common_name_length,
                                                    constraint, constraint_length));
    }

    return(NX_CRYPTO_FALSE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_subtree_walk                        PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Walk one GeneralSubtrees and test the leaf against every dNSName     */
/*    entry.  Reports separately whether any dNSName subtree was present   */
/*    and whether one of them matched, because "permitted" needs both: a   */
/*    permittedSubtrees with no dNSName entry does not constrain DNS names */
/*    at all, while one that has entries and matches none rejects.         */
/*                                                                        */
/*    A subtree naming any other GeneralName form is a constraint this     */
/*    code cannot evaluate, and a constraint that is not evaluated is not  */
/*    a constraint.  It returns an error rather than skipping the entry.   */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_subtree_walk(const UCHAR *buffer, ULONG length,
                                         NX_SECURE_X509_CERT *leaf,
                                         UINT *dns_present, UINT *dns_matched)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
const UCHAR *tlv_data;
ULONG        header_length;
ULONG        subtree_length;
const UCHAR *subtree_buffer;
UINT         status;

    *dns_present = NX_CRYPTO_FALSE;
    *dns_matched = NX_CRYPTO_FALSE;

    while (length > 0)
    {
        /* GeneralSubtree ::= SEQUENCE { base GeneralName, minimum, maximum } */
        status = _nx_secure_x509_asn1_tlv_block_parse(buffer, &length, &tlv_type, &tlv_type_class,
                                                      &tlv_length, &tlv_data, &header_length);
        if (status != 0)
        {
            return(status);
        }

        if (!(tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL &&
              tlv_type == NX_SECURE_ASN_TAG_SEQUENCE))
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }

        buffer += header_length + tlv_length;

        /* The base GeneralName is the first element of the subtree. */
        subtree_buffer = tlv_data;
        subtree_length = tlv_length;

        status = _nx_secure_x509_asn1_tlv_block_parse(subtree_buffer, &subtree_length, &tlv_type,
                                                      &tlv_type_class, &tlv_length, &tlv_data,
                                                      &header_length);
        if (status != 0)
        {
            return(status);
        }

        if (tlv_type_class != NX_SECURE_ASN_TAG_CLASS_CONTEXT)
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }

        if (tlv_type != NX_SECURE_X509_GENERAL_NAME_DNS)
        {
            /* An iPAddress, directoryName, rfc822Name or URI subtree.  This
               code does not evaluate those, and a CA that carries one placed
               it there to be obeyed, so the chain does not verify. */
            return(NX_SECURE_X509_NAME_CONSTRAINT_UNSUPPORTED);
        }

        *dns_present = NX_CRYPTO_TRUE;

        if (_nx_secure_x509_leaf_dns_constrained(leaf, tlv_data, (UINT)tlv_length) == NX_CRYPTO_TRUE)
        {
            *dns_matched = NX_CRYPTO_TRUE;
        }
    }

    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_name_constraints_check              PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Apply the nameConstraints a CA carries to the leaf being verified.   */
/*    RFC 5280 4.2.1.10.  Returns NX_SECURE_X509_EXTENSION_NOT_FOUND when  */
/*    the CA has no constraints, which is not an error and is how the      */
/*    caller learns whether the extension was there to be enforced.        */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_name_constraints_check(NX_SECURE_X509_CERT *ca_certificate,
                                            NX_SECURE_X509_CERT *leaf_certificate)
{
NX_SECURE_X509_EXTENSION constraints;
USHORT                   tlv_type;
USHORT                   tlv_type_class;
ULONG                    tlv_length;
const UCHAR             *tlv_data;
const UCHAR             *current_buffer;
ULONG                    length;
ULONG                    header_length;
UINT                     status;
UINT                     dns_present;
UINT                     dns_matched;
UINT                     permitted_present = NX_CRYPTO_FALSE;
UINT                     permitted_matched = NX_CRYPTO_FALSE;

    status = _nx_secure_x509_extension_find(ca_certificate, &constraints,
                                            NX_SECURE_TLS_X509_TYPE_NAME_CONSTRAINTS);

    if (status != NX_SECURE_X509_SUCCESS)
    {
        /* No constraints, or an extensions blob that would not parse.  Either
           way it is the caller's to interpret. */
        return(status);
    }

    /* NameConstraints ::= SEQUENCE { permittedSubtrees [0] OPTIONAL,
                                      excludedSubtrees  [1] OPTIONAL } */
    current_buffer = constraints.nx_secure_x509_extension_data;
    length = constraints.nx_secure_x509_extension_data_length;

    status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class,
                                                  &tlv_length, &tlv_data, &header_length);
    if (status != 0)
    {
        return(status);
    }

    if (!(tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL &&
          tlv_type == NX_SECURE_ASN_TAG_SEQUENCE))
    {
        return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
    }

    current_buffer = tlv_data;
    length = tlv_length;

    while (length > 0)
    {
        status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &length, &tlv_type, &tlv_type_class,
                                                      &tlv_length, &tlv_data, &header_length);
        if (status != 0)
        {
            return(status);
        }

        if (tlv_type_class != NX_SECURE_ASN_TAG_CLASS_CONTEXT)
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }

        current_buffer += header_length + tlv_length;

        status = _nx_secure_x509_subtree_walk(tlv_data, tlv_length, leaf_certificate,
                                              &dns_present, &dns_matched);
        if (status != NX_SECURE_X509_SUCCESS)
        {
            return(status);
        }

        if (tlv_type == 0)
        {
            /* permittedSubtrees.  Only binding if it names DNS at all. */
            if (dns_present == NX_CRYPTO_TRUE)
            {
                permitted_present = NX_CRYPTO_TRUE;

                if (dns_matched == NX_CRYPTO_TRUE)
                {
                    permitted_matched = NX_CRYPTO_TRUE;
                }
            }
        }
        else if (tlv_type == 1)
        {
            /* excludedSubtrees.  One match is a rejection. */
            if (dns_matched == NX_CRYPTO_TRUE)
            {
                return(NX_SECURE_X509_NAME_CONSTRAINT_VIOLATION);
            }
        }
        else
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }
    }

    if ((permitted_present == NX_CRYPTO_TRUE) && (permitted_matched != NX_CRYPTO_TRUE))
    {
        return(NX_SECURE_X509_NAME_CONSTRAINT_VIOLATION);
    }

    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_extended_key_usage_check            PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    An extendedKeyUsage that does not permit the requested authentication*/
/*    purpose is a statement by the issuer that this key is not for that   */
/*    TLS endpoint role.  RFC                                              */
/*    5280 4.2.1.12: the extension absent means unconstrained, present     */
/*    means the list is exhaustive, and anyExtendedKeyUsage re-opens it.   */
/*                                                                        */
/*    Applied to CA certificates as well as the leaf.  A CA that carries   */
/*    an EKU is constrained by it for everything it issues, which is the   */
/*    rule browsers call EKU chaining and the reason a code-signing        */
/*    sub-CA cannot mint a web server certificate.                         */
/*                                                                        */
/**************************************************************************/
static UINT _nx_secure_x509_extended_key_usage_check(NX_SECURE_X509_CERT *certificate,
                                                      USHORT required_key_usage)
{
UINT status;

    status = _nx_secure_x509_extended_key_usage_extension_parse(certificate,
                                                                required_key_usage);

    if (status == NX_SECURE_X509_SUCCESS)
    {
        return(NX_SECURE_X509_SUCCESS);
    }

    if (status == NX_SECURE_X509_EXTENSION_NOT_FOUND)
    {
        /* No extendedKeyUsage at all: unconstrained. */
        return(NX_SECURE_X509_SUCCESS);
    }

    if (status != NX_SECURE_X509_EXT_KEY_USAGE_NOT_FOUND)
    {
        /* The extension is there and did not parse. */
        return(status);
    }

    /* Present, and serverAuth is not in it.  anyExtendedKeyUsage is the one
       remaining way for it to be permitted. */
    status = _nx_secure_x509_extended_key_usage_extension_parse(certificate,
                                                                NX_SECURE_TLS_X509_TYPE_ANY_EXTENDED_KEY_USAGE);

    if (status == NX_SECURE_X509_SUCCESS)
    {
        return(NX_SECURE_X509_SUCCESS);
    }

    return(NX_SECURE_X509_EXT_KEY_USAGE_NOT_FOUND);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_extended_key_usage_chain_check      PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Enforce one TLS authentication purpose on the leaf and every         */
/*    intermediate certificate in its verified chain.  Certificate-chain  */
/*    verification itself is purpose-neutral: it is also used for CRLs and */
/*    may be supplied as an application callback, so it cannot assume that */
/*    every chain belongs to a TLS server.                                 */
/*                                                                        */
/*    The TLS session calls this after the cryptographic chain verification*/
/*    has succeeded.  This walk deliberately follows the same store lookup */
/*    rules and, like the verifier, does not apply certificate extensions  */
/*    from the trust anchor itself.                                        */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_extended_key_usage_chain_check(NX_SECURE_X509_CERTIFICATE_STORE *store,
                                                     NX_SECURE_X509_CERT *certificate,
                                                     USHORT required_key_usage)
{
NX_SECURE_X509_CERT *current_certificate;
NX_SECURE_X509_CERT *issuer_certificate;
UINT                 issuer_location;
UINT                 status;
UINT                 depth;
INT                  compare_result;

    current_certificate = certificate;
    depth = 0;

    while (current_certificate != NX_CRYPTO_NULL)
    {
        if (depth > NX_SECURE_X509_MAX_VERIFY_DEPTH)
        {
            return(NX_SECURE_X509_CHAIN_TOO_LONG);
        }

        status = _nx_secure_x509_extended_key_usage_check(current_certificate,
                                                           required_key_usage);
        if (status != NX_SECURE_X509_SUCCESS)
        {
            return(status);
        }

        compare_result = _nx_secure_x509_distinguished_name_compare(
            &current_certificate -> nx_secure_x509_distinguished_name,
            &current_certificate -> nx_secure_x509_issuer,
            NX_SECURE_X509_NAME_ALL_FIELDS);

        if (compare_result == 0)
        {
            /* A successful chain verification can reach this case only when
               self-signed certificates are enabled and the certificate is a
               configured trust anchor.  Its endpoint EKU was checked above. */
            return(NX_SECURE_X509_SUCCESS);
        }

        issuer_location = NX_SECURE_X509_CERT_LOCATION_NONE;
        status = _nx_secure_x509_store_certificate_find(store,
                                                         &current_certificate -> nx_secure_x509_issuer,
                                                         0,
                                                         &issuer_certificate,
                                                         &issuer_location);
        if (status != NX_SECURE_X509_SUCCESS)
        {
            return(NX_SECURE_X509_ISSUER_CERTIFICATE_NOT_FOUND);
        }

        if (issuer_location == NX_SECURE_X509_CERT_LOCATION_TRUSTED)
        {
            return(NX_SECURE_X509_SUCCESS);
        }

        current_certificate = issuer_certificate;
        depth++;
    }

    return(NX_SECURE_X509_CHAIN_VERIFY_FAILURE);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_critical_extensions_check           PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    Walk every extension in a certificate and refuse the certificate if  */
/*    one is marked critical and is not in the known set above.  RFC 5280  */
/*    4.2.  _nx_secure_x509_extension_find stops at the first OID that     */
/*    matches, so nothing before this walked the whole list, and the       */
/*    critical boolean it parses was written to the structure and never    */
/*    read by anything -- see nx_secure_x509_extension_find.c:191.         */
/*                                                                        */
/*    name_constraints_enforced says the caller has just run               */
/*    _nx_secure_x509_name_constraints_check over this certificate, which  */
/*    is the only thing that makes a critical nameConstraints acceptable.  */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_critical_extensions_check(NX_SECURE_X509_CERT *certificate,
                                               UINT name_constraints_enforced)
{
USHORT       tlv_type;
USHORT       tlv_type_class;
ULONG        tlv_length;
ULONG        extensions_sequence_length;
ULONG        seq_length;
UINT         extension_oid = 0;
const UCHAR *tlv_data;
const UCHAR *current_buffer;
const UCHAR *sequence_buffer;
ULONG        header_length;
UINT         status;
UINT         critical;
UINT         i;
UINT         known;

    current_buffer = certificate -> nx_secure_x509_extensions_data;
    extensions_sequence_length = certificate -> nx_secure_x509_extensions_data_length;

    while (extensions_sequence_length > 0)
    {
        status = _nx_secure_x509_asn1_tlv_block_parse(current_buffer, &extensions_sequence_length,
                                                      &tlv_type, &tlv_type_class, &tlv_length,
                                                      &tlv_data, &header_length);
        if (status != 0)
        {
            return(status);
        }

        if (!(tlv_type_class == NX_SECURE_ASN_TAG_CLASS_UNIVERSAL &&
              tlv_type == NX_SECURE_ASN_TAG_SEQUENCE))
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }

        current_buffer += header_length + tlv_length;

        sequence_buffer = tlv_data;
        seq_length = tlv_length;

        /* Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
                                    extnValue OCTET STRING } */
        status = _nx_secure_x509_asn1_tlv_block_parse(sequence_buffer, &seq_length, &tlv_type,
                                                      &tlv_type_class, &tlv_length, &tlv_data,
                                                      &header_length);
        if (status != 0)
        {
            return(status);
        }

        if (tlv_type != NX_SECURE_ASN_TAG_OID)
        {
            return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
        }

        _nx_secure_x509_oid_parse(tlv_data, tlv_length, &extension_oid);

        sequence_buffer = tlv_data + tlv_length;

        status = _nx_secure_x509_asn1_tlv_block_parse(sequence_buffer, &seq_length, &tlv_type,
                                                      &tlv_type_class, &tlv_length, &tlv_data,
                                                      &header_length);
        if (status != 0)
        {
            return(status);
        }

        critical = NX_CRYPTO_FALSE;

        if (tlv_type == NX_SECURE_ASN_TAG_BOOLEAN)
        {
            if (tlv_length == 0)
            {
                return(NX_SECURE_X509_INVALID_EXTENSION_SEQUENCE);
            }

            critical = (tlv_data[0] != 0);
        }

        if (critical != NX_CRYPTO_TRUE)
        {
            continue;
        }

        known = NX_CRYPTO_FALSE;

        for (i = 0; i < NX_SECURE_X509_KNOWN_CRITICAL_COUNT; i++)
        {
            if (extension_oid == (UINT)_nx_secure_x509_known_critical[i])
            {
                known = NX_CRYPTO_TRUE;
                break;
            }
        }

        if ((known != NX_CRYPTO_TRUE) &&
            (extension_oid == NX_SECURE_TLS_X509_TYPE_NAME_CONSTRAINTS) &&
            (name_constraints_enforced == NX_CRYPTO_TRUE))
        {
            known = NX_CRYPTO_TRUE;
        }

        if (known != NX_CRYPTO_TRUE)
        {
            return(NX_SECURE_X509_UNSUPPORTED_CRITICAL_EXTENSION);
        }
    }

    return(NX_SECURE_X509_SUCCESS);
}


/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_secure_x509_extension_policy_check              PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    The two purpose-neutral checks in the order they have to run:         */
/*    nameConstraints, then the critical sweep, because the sweep           */
/*    needs to know whether the constraints were enforced.                 */
/*                                                                        */
/*    depth is the chain walk's own depth, 0 for the leaf.  A leaf is not  */
/*    a CA and RFC 5280 4.2.1.10 says nameConstraints appears in CA        */
/*    certificates only, so on the leaf its presence is the defect and     */
/*    there is nothing to enforce it against.                              */
/*                                                                        */
/**************************************************************************/
UINT _nx_secure_x509_extension_policy_check(NX_SECURE_X509_CERT *certificate,
                                            NX_SECURE_X509_CERT *leaf_certificate,
                                            UINT depth)
{
UINT status;
UINT name_constraints_enforced = NX_CRYPTO_FALSE;

    status = _nx_secure_x509_name_constraints_check(certificate, leaf_certificate);

    if (status == NX_SECURE_X509_SUCCESS)
    {
        if (depth == 0)
        {
            /* An end-entity certificate constraining names below it.  There is
               nothing below it. */
            return(NX_SECURE_X509_NAME_CONSTRAINT_UNSUPPORTED);
        }

        name_constraints_enforced = NX_CRYPTO_TRUE;
    }
    else if (status != NX_SECURE_X509_EXTENSION_NOT_FOUND)
    {
        return(status);
    }

    return(_nx_secure_x509_critical_extensions_check(certificate, name_constraints_enforced));
}
