#!/usr/bin/env python3
##############################################################################
# Copyright (c) 2026 Eclipse ThreadX contributors
#
# This program and the accompanying materials are made available under the
# terms of the MIT License which is available at
# https://opensource.org/licenses/MIT.
#
# SPDX-License-Identifier: MIT
##############################################################################
"""Write nx_secure_tls_hash_clone_test_certs.c, the credential family that
nx_secure_tls_hash_clone_test uses in place of tls_two_test_certs.c and
test_ca.crl.der.c.

The server there presents "certificate_with_policies", whose only (critical)
extendedKeyUsage is timeStamping, so a TLS client refuses it (RFC 5280
4.2.1.12).  Its issuer's private key is not in the tree, so this family has
its own intermediate, on the key in certificates/nx_secure_hash_clone_test_ica.key
(created if absent), issued by "NetX Secure Test CA" (certificates/
nx_secure_test_ca.key).  From tls_two_test_certs.c and test_ca.crl.der.c:
  - the intermediate: subject CN "NX Secure Hash Clone Test Intermediate CA",
    otherwise the old one's subject, serial, notBefore and extensions
    (basicConstraints critical CA:TRUE), notAfter twenty years later, the
    key identifiers for the new keys;
  - test_server_cert_der and test_device_cert_der: the same subject, serial,
    public key, validity and extensions, issued by that intermediate, with
    the authority key identifier for it; test_device_cert_der's
    extendedKeyUsage is timeStamping, serverAuth, clientAuth, still critical;
  - the private keys: copied unchanged;
  - test_ca_crl_der: the same dates, entries and extensions, issued and signed
    by that intermediate.
The shared files are not changed.  With both keys committed the output is the
same on every run.

  make_hash_clone_test_certs.py

Needs python3-cryptography.
"""
import datetime, os, re, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID, NameOID

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_KEY = os.path.join(HERE, 'certificates', 'nx_secure_test_ca.key')
ICA_KEY = os.path.join(HERE, 'certificates', 'nx_secure_hash_clone_test_ica.key')
OUT = os.path.join(HERE, 'nx_secure_tls_hash_clone_test_certs.c')
ICA_CN = 'NX Secure Hash Clone Test Intermediate CA'
VALIDITY = datetime.timedelta(days=7305)
ARRAY = re.compile(r'((?:static\s+)?unsigned\s+char\s+(\w+)\s*\[\s*\]\s*=\s*\{)(.*?)(\};)', re.S)


def arrays(name):
    src = open(os.path.join(HERE, name), encoding='latin-1').read()
    return {m.group(2): bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3))) for m in ARRAY.finditer(src)}


def key(path):
    if not os.path.exists(path):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        open(path, 'wb').write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    return serialization.load_pem_private_key(open(path, 'rb').read(), None)


def ski(k):
    return x509.SubjectKeyIdentifier.from_public_key(k.public_key())


def aki(issuer_ski):
    return x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(issuer_ski)


def c_array(storage, name, data):
    lines = ['0x%02x' % b for b in data]
    body = ',\n'.join('    ' + ', '.join(lines[i:i + 12]) for i in range(0, len(lines), 12))
    return '%sunsigned char %s[] = {\n%s\n};\n%sunsigned int %s_len = %d;\n' % (storage, name, body, storage, name, len(data))


def main():
    two = arrays('tls_two_test_certs.c')
    root = x509.load_der_x509_certificate(arrays('test_ca_cert.c')['test_ca_cert_der'])
    crl = x509.load_der_x509_crl(arrays('test_ca.crl.der.c')['test_ca_crl_der'])
    old_ica = x509.load_der_x509_certificate(two['ica_cert_der'])
    root_key = key(ROOT_KEY)
    ica_key = key(ICA_KEY)
    if root_key.public_key().public_numbers() != root.public_key().public_numbers():
        raise SystemExit('certificates/nx_secure_test_ca.key is not the key of test_ca_cert_der')
    root_ski = root.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value

    ica_subject = x509.Name([x509.NameAttribute(a.oid, ICA_CN if a.oid == NameOID.COMMON_NAME else a.value)
                             for a in old_ica.subject])
    b = (x509.CertificateBuilder().subject_name(ica_subject).issuer_name(root.subject)
         .public_key(ica_key.public_key()).serial_number(old_ica.serial_number)
         .not_valid_before(old_ica.not_valid_before_utc).not_valid_after(old_ica.not_valid_before_utc + VALIDITY))
    for e in old_ica.extensions:
        if e.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            b = b.add_extension(ski(ica_key), critical=e.critical)
        elif e.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            b = b.add_extension(aki(root_ski), critical=e.critical)
        else:
            b = b.add_extension(e.value, critical=e.critical)
    ica = b.sign(root_key, old_ica.signature_hash_algorithm)
    if not ica.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca:
        raise SystemExit('intermediate is not CA:TRUE')

    leaves = {}
    for name in ('test_server_cert_der', 'test_device_cert_der'):
        c = x509.load_der_x509_certificate(two[name])
        k = serialization.load_der_private_key(two[name.replace('_der', '_key_der')], None)
        if k.public_key().public_numbers() != c.public_key().public_numbers():
            raise SystemExit('%s: key does not match' % name)
        b = (x509.CertificateBuilder().subject_name(c.subject).issuer_name(ica.subject)
             .public_key(c.public_key()).serial_number(c.serial_number)
             .not_valid_before(c.not_valid_before_utc).not_valid_after(c.not_valid_after_utc))
        for e in c.extensions:
            if e.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                b = b.add_extension(aki(ski(ica_key)), critical=e.critical)
            elif e.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                usages = list(e.value)
                for u in (ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH):
                    if u not in usages:
                        usages.append(u)
                b = b.add_extension(x509.ExtendedKeyUsage(usages), critical=e.critical)
            else:
                b = b.add_extension(e.value, critical=e.critical)
        leaves[name] = b.sign(ica_key, c.signature_hash_algorithm)

    b = (x509.CertificateRevocationListBuilder().issuer_name(ica.subject)
         .last_update(crl.last_update_utc).next_update(crl.next_update_utc))
    for r in crl:
        rb = x509.RevokedCertificateBuilder().serial_number(r.serial_number).revocation_date(r.revocation_date_utc)
        for e in r.extensions:
            rb = rb.add_extension(e.value, critical=e.critical)
        b = b.add_revoked_certificate(rb.build())
    for e in crl.extensions:
        b = b.add_extension(e.value, critical=e.critical)
    new_crl = b.sign(ica_key, crl.signature_hash_algorithm)

    # Every signature checks out under its issuer.
    for c, issuer in ((ica, root), (leaves['test_server_cert_der'], ica), (leaves['test_device_cert_der'], ica)):
        issuer.public_key().verify(c.signature, c.tbs_certificate_bytes, padding.PKCS1v15(), c.signature_hash_algorithm)
    ica.public_key().verify(new_crl.signature, new_crl.tbs_certlist_bytes, padding.PKCS1v15(), new_crl.signature_hash_algorithm)

    der = lambda c: c.public_bytes(serialization.Encoding.DER)
    out = open(os.path.join(HERE, 'tls_two_test_certs.c'), encoding='latin-1').read()
    header = out[:out.index('unsigned char ica_cert_der[]')]
    body = (c_array('', 'ica_cert_der', der(ica)) + '\n\n' +
            c_array('', 'test_server_cert_der', der(leaves['test_server_cert_der'])) + '\n' +
            c_array('', 'test_server_cert_key_der', two['test_server_cert_key_der']) + '\n\n' +
            c_array('', 'test_device_cert_der', der(leaves['test_device_cert_der'])) + '\n' +
            c_array('', 'test_device_cert_key_der', two['test_device_cert_key_der']) + '\n\n' +
            c_array('static ', 'test_ca_crl_der', der(new_crl)))
    note = ('/* Written by make_hash_clone_test_certs.py: tls_two_test_certs.c and\n'
            '   test_ca.crl.der.c reissued under a dedicated intermediate, with\n'
            '   serverAuth and clientAuth added to test_device_cert_der.  */\n\n')
    open(OUT, 'w', encoding='latin-1').write(header + note + body)

    for name, old, new in (('ica_cert_der', two['ica_cert_der'], der(ica)),
                           ('test_server_cert_der', two['test_server_cert_der'], der(leaves['test_server_cert_der'])),
                           ('test_device_cert_der', two['test_device_cert_der'], der(leaves['test_device_cert_der'])),
                           ('test_ca_crl_der', arrays('test_ca.crl.der.c')['test_ca_crl_der'], der(new_crl))):
        print('%-22s %4d -> %4d bytes' % (name, len(old), len(new)))
    print('wrote', os.path.relpath(OUT, HERE))


if __name__ == '__main__':
    main()
