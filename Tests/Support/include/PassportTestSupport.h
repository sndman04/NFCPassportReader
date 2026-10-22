#ifndef PassportTestSupport_h
#define PassportTestSupport_h
#include <stddef.h>
#include <OpenSSL/OpenSSL.h>
// Test-only deterministic entropy import. Caller owns the returned key.
EVP_PKEY *NFCPRTestImportKey(EVP_PKEY *parameters,
    const unsigned char *privateBytes, size_t privateLength,
    const unsigned char *publicBytes, size_t publicLength, int isDH);
#endif
