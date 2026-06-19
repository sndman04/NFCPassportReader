#ifndef OpenSSLCompat_h
#define OpenSSLCompat_h

#include <stddef.h>
#include <OpenSSL/OpenSSL.h>

EVP_PKEY *NFCPRCreateDHMappedParameters(
    EVP_PKEY *mappingKey,
    const unsigned char *passportPublicKey,
    size_t passportPublicKeyLength,
    const BIGNUM *nonce
);

EVP_PKEY *NFCPRCreateECDHMappedParameters(
    EVP_PKEY *mappingKey,
    const unsigned char *passportPublicKey,
    size_t passportPublicKeyLength,
    const BIGNUM *nonce
);

#endif
