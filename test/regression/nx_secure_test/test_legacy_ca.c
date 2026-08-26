/* Some legacy regression trust anchors carry basicConstraints CA:FALSE.
   State the test's trust-anchor role explicitly without altering the DER;
   production verification must continue to reject the same certificate when
   a peer sends it as an intermediate issuer. */
static const UCHAR test_legacy_ca_basic_constraints[] =
{
    0x30, 0x0c,
    0x06, 0x03, 0x55, 0x1d, 0x13,
    0x04, 0x05,
    0x30, 0x03, 0x01, 0x01, 0xff
};

static VOID test_legacy_certificate_mark_ca(NX_SECURE_X509_CERT *certificate)
{
    certificate -> nx_secure_x509_extensions_data =
        (UCHAR *)test_legacy_ca_basic_constraints;
    certificate -> nx_secure_x509_extensions_data_length =
        sizeof(test_legacy_ca_basic_constraints);
}
