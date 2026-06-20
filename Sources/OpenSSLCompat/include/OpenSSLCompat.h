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

EVP_PKEY *NFCPRCreateDHIntegratedMappedParameters(
    EVP_PKEY *domainKey,
    const unsigned char *fieldElement,
    size_t fieldElementLength
);

EVP_PKEY *NFCPRCreateECDHIntegratedMappedParameters(
    EVP_PKEY *domainKey,
    const unsigned char *fieldElement,
    size_t fieldElementLength
);

int NFCPRVerifyDHGenerator(
    EVP_PKEY *parameters,
    const unsigned char *expectedGenerator,
    size_t expectedGeneratorLength
);

int NFCPRVerifyECGenerator(
    EVP_PKEY *parameters,
    const unsigned char *expectedGenerator,
    size_t expectedGeneratorLength
);

int NFCPRCalculateECDHCAMPublicKey(
    EVP_PKEY *staticPublicKey,
    const unsigned char *chipAuthenticationData,
    size_t chipAuthenticationDataLength,
    unsigned char *output,
    size_t *outputLength
);

int NFCPRVerifyECDHCAMPublicKey(
    EVP_PKEY *staticPublicKey,
    const unsigned char *mappingPublicKey,
    size_t mappingPublicKeyLength,
    const unsigned char *chipAuthenticationData,
    size_t chipAuthenticationDataLength
);

#endif
