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
"""Renew the "NetX Secure Test CA" RSA family embedded in the regression tests.

The root's original private key is not in the tree, so the root is reissued on
the key in certificates/nx_secure_test_ca.key (created if absent) with the same
subject and serial, and every certificate it issued is re-signed by it with the
same subject, serial, public key, extensions and notBefore, except:
  - the authority key identifier, recomputed for the new root key;
  - an issuer among them (it issues other certificates in the tree) gets
    basicConstraints critical CA:TRUE, as RFC 5280 6.1.4 (k) requires;
  - notAfter, twenty years after notBefore.
notBefore is kept because tests pin the clock (2017, 2018) and verify these
certificates against it.  Run it on the tree before the renewal; with the
committed root key the output is the same on every run.
Every C byte array in the test tree whose bytes equal an old certificate is
rewritten with the new one, with its _len.  Certificates further down (issued
by such an intermediate) are unchanged: the intermediate keeps its key.

  renew_nx_secure_test_ca.py [--write]

Without --write, reports what it would change and any other occurrence of the
old root's public key, key identifier or fingerprints in the sources.
Needs python3-cryptography.
"""
import datetime, glob, os, re, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID

HERE = os.path.dirname(os.path.abspath(__file__))
TREE = os.path.dirname(HERE)
KEY_FILE = os.path.join(HERE, 'certificates', 'nx_secure_test_ca.key')
ROOT_CN = 'NetX Secure Test CA'
VALIDITY = datetime.timedelta(days=7305)
ARRAY = re.compile(r'(\b(\w+)\s*\[\s*\d*\s*\]\s*=\s*\{)(.*?)(\};)', re.S)


def arrays():
    for f in sorted(glob.glob(os.path.join(TREE, '**', '*.[ch]'), recursive=True)):
        if '/build/' in f:
            continue
        src = open(f, encoding='latin-1').read()
        for m in ARRAY.finditer(src):
            data = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3)))
            if len(data) > 100 and data[0] == 0x30:
                yield f, m.group(2), data


def cert(data):
    try:
        return x509.load_der_x509_certificate(data)
    except Exception:
        return None


def cn(name):
    v = name.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    return v[0].value if v else ''


def main():
    write = '--write' in sys.argv
    found = {}
    for f, var, data in arrays():
        c = cert(data)
        if c is not None:
            found.setdefault(data, []).append((f, var, c))

    roots = {d: v for d, v in found.items() if cn(v[0][2].subject) == ROOT_CN and v[0][2].subject == v[0][2].issuer}
    children = {d: v for d, v in found.items() if cn(v[0][2].issuer) == ROOT_CN and v[0][2].subject != v[0][2].issuer}
    if len(roots) != 1:
        raise SystemExit('expected one distinct root, found %d' % len(roots))
    old_root_der, root_copies = next(iter(roots.items()))
    old_root = root_copies[0][2]
    issuers = {c.subject for v in found.values() for _, _, c in v}

    print('root: %d copies' % len(root_copies))
    for _, (f, var, _) in enumerate(root_copies):
        print('   ', os.path.relpath(f, TREE), var)
    for d, v in children.items():
        c = v[0][2]
        role = 'issuer -> CA:TRUE' if any(o[0][2].issuer == c.subject for o in found.values() if o[0][2].subject != c.subject) else 'leaf'
        print('child %-40s %-18s %d copies' % (cn(c.subject)[:40], role, len(v)))

    # Anything else that pins the old root: its SPKI, key identifier or fingerprints.
    spki = old_root.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ski = old_root.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest
    pins = {'spki': spki, 'ski': ski,
            'sha1': old_root.fingerprint(hashes.SHA1()), 'sha256': old_root.fingerprint(hashes.SHA256())}
    for f in sorted(glob.glob(os.path.join(TREE, '**', '*.[ch]'), recursive=True)):
        if '/build/' in f:
            continue
        src = open(f, encoding='latin-1').read()
        blob = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', src))
        text = src.lower()
        for k, p in pins.items():
            if k in ('spki', 'ski'):
                # inside a certificate copy these are expected; count non-certificate hits below
                pass
            if p.hex() in text.replace(' ', '').replace(':', ''):
                print('PIN as hex string:', k, os.path.relpath(f, TREE))
        for m in ARRAY.finditer(src):
            data = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3)))
            if data in found:
                continue
            for k, p in pins.items():
                if p in data:
                    print('PIN in non-certificate array:', k, os.path.relpath(f, TREE), m.group(2))

    if not write:
        return

    if os.path.exists(KEY_FILE):
        key = serialization.load_pem_private_key(open(KEY_FILE, 'rb').read(), None)
    else:
        os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        open(KEY_FILE, 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                     serialization.NoEncryption()))
    ski_new = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    root_builder = (x509.CertificateBuilder().subject_name(old_root.subject).issuer_name(old_root.subject)
                    .public_key(key.public_key()).serial_number(old_root.serial_number)
                    .not_valid_before(old_root.not_valid_before_utc)
                    .not_valid_after(old_root.not_valid_before_utc + VALIDITY))
    # The old root's own extensions, in its order, with the new key's identifiers.
    for e in old_root.extensions:
        if e.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
            root_builder = root_builder.add_extension(ski_new, critical=e.critical)
        elif e.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
            root_builder = root_builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_new), critical=e.critical)
        else:
            root_builder = root_builder.add_extension(e.value, critical=e.critical)
    root = root_builder.sign(key, old_root.signature_hash_algorithm)
    new = {old_root_der: root.public_bytes(serialization.Encoding.DER)}
    for d, v in children.items():
        c = v[0][2]
        is_issuer = any(o[0][2].issuer == c.subject for o in found.values() if o[0][2].subject != c.subject)
        b = (x509.CertificateBuilder().subject_name(c.subject).issuer_name(root.subject)
             .public_key(c.public_key()).serial_number(c.serial_number)
             .not_valid_before(c.not_valid_before_utc).not_valid_after(c.not_valid_before_utc + VALIDITY))
        for e in c.extensions:
            if e.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski_new), critical=False)
            elif e.oid == ExtensionOID.BASIC_CONSTRAINTS and is_issuer:
                b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            else:
                b = b.add_extension(e.value, critical=e.critical)
        if is_issuer and ExtensionOID.BASIC_CONSTRAINTS not in [e.oid for e in c.extensions]:
            b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        algorithm = c.signature_hash_algorithm or hashes.SHA256()
        new[d] = b.sign(key, algorithm).public_bytes(serialization.Encoding.DER)

    patch_captures(new, found)

    for f in sorted({f for d in new for f, _, _ in found[d]}):
        src = open(f, encoding='latin-1').read()

        def sub(m):
            data = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3)))
            if data not in new:
                return m.group(0)
            nd = new[data]
            lines = ['0x%02x' % x for x in nd]
            body = '\n' + ',\n'.join('    ' + ', '.join(lines[i:i + 12]) for i in range(0, len(lines), 12)) + '\n'
            sub.lens[m.group(2)] = (len(data), len(nd))
            return m.group(1) + body + m.group(4)
        sub.lens = {}
        src = ARRAY.sub(sub, src)
        for var, (old_len, new_len) in sub.lens.items():
            src, n = re.subn(r'(\b%s_len\s*=\s*)%d\b' % (var, old_len), r'\g<1>%d' % new_len, src)
            if n == 0 and re.search(r'\b%s_len\b' % var, src):
                raise SystemExit('cannot update %s_len in %s' % (var, f))
        open(f, 'w', encoding='latin-1').write(src)
        print('wrote', os.path.relpath(f, TREE), ' '.join(sub.lens))


def _len3(b, i):
    return (b[i] << 16) | (b[i + 1] << 8) | b[i + 2]


def _rebuild_records(data, new):
    """data is a run of TLS records; rebuild every Certificate handshake message with
    the new certificates, fixing the certificate, list, handshake and record lengths."""
    out = bytearray()
    i = 0
    while i < len(data):
        if i + 5 > len(data):
            return None
        rtype, rlen = data[i], (data[i + 3] << 8) | data[i + 4]
        frag = data[i + 5:i + 5 + rlen]
        if len(frag) != rlen:
            return None
        if rtype == 0x16:
            hs = bytearray()
            j = 0
            while j < len(frag):
                htype, hlen = frag[j], _len3(frag, j + 1)
                body = frag[j + 4:j + 4 + hlen]
                if len(body) != hlen:
                    return None
                if htype == 11:
                    llen = _len3(body, 0)
                    k, certs = 3, bytearray()
                    while k < 3 + llen:
                        clen = _len3(body, k)
                        c = body[k + 3:k + 3 + clen]
                        c = new.get(bytes(c), c)
                        certs += len(c).to_bytes(3, 'big') + c
                        k += 3 + clen
                    body = len(certs).to_bytes(3, 'big') + certs + body[3 + llen:]
                hs += bytes([htype]) + len(body).to_bytes(3, 'big') + body
                j += 4 + hlen
            frag = bytes(hs)
        out += data[i:i + 3] + len(frag).to_bytes(2, 'big') + frag
        i += 5 + rlen
    return bytes(out)


def patch_captures(new, found):
    """Captured TLS records that carry an old certificate."""
    for f in sorted(glob.glob(os.path.join(TREE, '**', '*.[ch]'), recursive=True)):
        if '/build/' in f:
            continue
        src = open(f, encoding='latin-1').read()
        changed = []

        def sub(m):
            data = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(3)))
            if data in found or not any(d in data for d in new):
                return m.group(0)
            nd = data
            if all(len(d) == len(new[d]) for d in new if d in data):
                for d in new:
                    nd = nd.replace(d, new[d])
            else:
                nd = _rebuild_records(data, new)
                if nd is None or any(d in nd for d in new):
                    raise SystemExit('cannot rebuild the TLS records in %s %s' % (f, m.group(2)))
            changed.append((m.group(2), len(data), len(nd)))
            lines = ['0x%02x' % x for x in nd]
            body = '\n' + ',\n'.join('    ' + ', '.join(lines[i:i + 12]) for i in range(0, len(lines), 12)) + '\n'
            return m.group(1) + body + m.group(4)
        src = ARRAY.sub(sub, src)
        for var, old_len, new_len in changed:
            if old_len != new_len and re.search(r'\b%d\b' % old_len, src):
                print('NOTE: %s %s length %d -> %d; check sizeof/explicit lengths' % (os.path.relpath(f, TREE), var, old_len, new_len))
        if changed:
            open(f, 'w', encoding='latin-1').write(src)
            print('patched capture', os.path.relpath(f, TREE), changed)


if __name__ == '__main__':
    main()
