#ifndef OpenSSLCompat_h
#define OpenSSLCompat_h

#include <stddef.h>
#include <OpenSSL/OpenSSL.h>

/* Owned stack and owned X509 references, in SignerInfos order. NULL on ambiguity/missing SID. */
STACK_OF(X509) *NFCPRCopyCMSSignerCertificates(const unsigned char *der, size_t length);
/* Returns an ICAO Table 12 parameter ID, or -1. Never adopts unknown chip parameters. */
int NFCPRMatchKnownPACEParameters(const unsigned char *der, size_t length, int ellipticCurve);
int NFCPRNormalizeAARecovery(EVP_PKEY *key, unsigned char *block, size_t length);
int NFCPRIsPrimeCurveKey(EVP_PKEY *key);
/* 1 clear, 2 revoked, 3 no matching authenticated CRL, 4 invalid profile, 5 stale, 6 future. */
int NFCPRCheckRevocation(const unsigned char *data, size_t length, X509 *signer, X509 *issuer);

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
