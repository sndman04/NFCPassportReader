#include "OpenSSLCompat.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

EVP_PKEY *NFCPRCreateDHMappedParameters(
    EVP_PKEY *mappingKey,
    const unsigned char *passportPublicKey,
    size_t passportPublicKeyLength,
    const BIGNUM *nonce
) {
    DH *dhMappingKey = EVP_PKEY_get1_DH(mappingKey);
    if (dhMappingKey == NULL) {
        return NULL;
    }

    BIGNUM *passportPublicBN = BN_bin2bn(passportPublicKey, (int)passportPublicKeyLength, NULL);
    if (passportPublicBN == NULL) {
        DH_free(dhMappingKey);
        return NULL;
    }

    unsigned char *secret = OPENSSL_malloc((size_t)DH_size(dhMappingKey));
    if (secret == NULL) {
        BN_free(passportPublicBN);
        DH_free(dhMappingKey);
        return NULL;
    }

    int secretLength = DH_compute_key(secret, passportPublicBN, dhMappingKey);
    BN_free(passportPublicBN);
    if (secretLength <= 0) {
        OPENSSL_free(secret);
        DH_free(dhMappingKey);
        return NULL;
    }

    BIGNUM *sharedSecretBN = BN_bin2bn(secret, secretLength, NULL);
    OPENSSL_clear_free(secret, (size_t)DH_size(dhMappingKey));
    if (sharedSecretBN == NULL) {
        DH_free(dhMappingKey);
        return NULL;
    }

    DH *ephemeralDH = DHparams_dup(dhMappingKey);
    if (ephemeralDH == NULL) {
        BN_clear_free(sharedSecretBN);
        DH_free(dhMappingKey);
        return NULL;
    }

    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *g = NULL;
    DH_get0_pqg(dhMappingKey, &p, &q, &g);
    if (p == NULL || g == NULL) {
        DH_free(ephemeralDH);
        BN_clear_free(sharedSecretBN);
        DH_free(dhMappingKey);
        return NULL;
    }

    BN_CTX *bnContext = BN_CTX_new();
    BIGNUM *poweredGenerator = BN_new();
    BIGNUM *mappedGenerator = BN_new();
    if (bnContext == NULL || poweredGenerator == NULL || mappedGenerator == NULL) {
        BN_free(mappedGenerator);
        BN_free(poweredGenerator);
        BN_CTX_free(bnContext);
        DH_free(ephemeralDH);
        BN_clear_free(sharedSecretBN);
        DH_free(dhMappingKey);
        return NULL;
    }

    int ok = BN_mod_exp(poweredGenerator, g, nonce, p, bnContext) == 1
        && BN_mod_mul(mappedGenerator, poweredGenerator, sharedSecretBN, p, bnContext) == 1
        && DH_set0_pqg(ephemeralDH, BN_dup(p), q != NULL ? BN_dup(q) : NULL, BN_dup(mappedGenerator)) == 1;

    BN_free(mappedGenerator);
    BN_free(poweredGenerator);
    BN_CTX_free(bnContext);
    BN_clear_free(sharedSecretBN);
    DH_free(dhMappingKey);

    if (!ok) {
        DH_free(ephemeralDH);
        return NULL;
    }

    EVP_PKEY *ephemeralParameters = EVP_PKEY_new();
    if (ephemeralParameters == NULL || EVP_PKEY_set1_DH(ephemeralParameters, ephemeralDH) != 1) {
        EVP_PKEY_free(ephemeralParameters);
        DH_free(ephemeralDH);
        return NULL;
    }

    DH_free(ephemeralDH);
    return ephemeralParameters;
}

static EC_POINT *NFCPRComputeECDHMappingPoint(
    EVP_PKEY *privateKey,
    const unsigned char *passportPublicKey,
    size_t passportPublicKeyLength,
    EC_GROUP **outGroup
) {
    EC_KEY *ecdh = EVP_PKEY_get1_EC_KEY(privateKey);
    if (ecdh == NULL) {
        return NULL;
    }

    const BIGNUM *privateECKey = EC_KEY_get0_private_key(ecdh);
    const EC_GROUP *group = EC_KEY_get0_group(ecdh);
    if (privateECKey == NULL || group == NULL) {
        EC_KEY_free(ecdh);
        return NULL;
    }

    EC_GROUP *groupCopy = EC_GROUP_dup(group);
    EC_POINT *passportPoint = EC_POINT_new(group);
    EC_POINT *output = EC_POINT_new(group);
    if (groupCopy == NULL || passportPoint == NULL || output == NULL) {
        EC_POINT_free(output);
        EC_POINT_free(passportPoint);
        EC_GROUP_free(groupCopy);
        EC_KEY_free(ecdh);
        return NULL;
    }

    int ok = EC_POINT_oct2point(group, passportPoint, passportPublicKey, passportPublicKeyLength, NULL) == 1
        && EC_POINT_mul(group, output, NULL, passportPoint, privateECKey, NULL) == 1;

    EC_POINT_free(passportPoint);
    if (!ok) {
        EC_POINT_free(output);
        EC_GROUP_free(groupCopy);
        EC_KEY_free(ecdh);
        return NULL;
    }

    size_t outputLength = EC_POINT_point2oct(
        group,
        output,
        POINT_CONVERSION_UNCOMPRESSED,
        NULL,
        0,
        NULL
    );
    unsigned char *outputBytes = outputLength > 0 ? OPENSSL_malloc(outputLength) : NULL;
    EC_POINT *groupCopyOutput = EC_POINT_new(groupCopy);
    ok = outputBytes != NULL
        && groupCopyOutput != NULL
        && EC_POINT_point2oct(
            group,
            output,
            POINT_CONVERSION_UNCOMPRESSED,
            outputBytes,
            outputLength,
            NULL
        ) == outputLength
        && EC_POINT_oct2point(groupCopy, groupCopyOutput, outputBytes, outputLength, NULL) == 1;

    OPENSSL_free(outputBytes);
    EC_POINT_free(output);
    if (!ok) {
        EC_POINT_free(groupCopyOutput);
        EC_GROUP_free(groupCopy);
        EC_KEY_free(ecdh);
        return NULL;
    }

    *outGroup = groupCopy;
    EC_KEY_free(ecdh);
    return groupCopyOutput;
}

EVP_PKEY *NFCPRCreateECDHMappedParameters(
    EVP_PKEY *mappingKey,
    const unsigned char *passportPublicKey,
    size_t passportPublicKeyLength,
    const BIGNUM *nonce
) {
    EC_GROUP *group = NULL;
    EC_POINT *sharedSecretMappingPoint = NFCPRComputeECDHMappingPoint(
        mappingKey,
        passportPublicKey,
        passportPublicKeyLength,
        &group
    );
    if (sharedSecretMappingPoint == NULL || group == NULL) {
        return NULL;
    }

    EC_POINT *mappedGenerator = EC_POINT_new(group);
    BIGNUM *order = BN_new();
    BIGNUM *cofactor = BN_new();
    if (mappedGenerator == NULL || order == NULL || cofactor == NULL) {
        BN_free(cofactor);
        BN_free(order);
        EC_POINT_free(mappedGenerator);
        EC_GROUP_free(group);
        EC_POINT_free(sharedSecretMappingPoint);
        return NULL;
    }

    int ok = EC_GROUP_get_order(group, order, NULL) == 1
        && EC_GROUP_get_cofactor(group, cofactor, NULL) == 1
        && EC_POINT_mul(group, mappedGenerator, nonce, sharedSecretMappingPoint, BN_value_one(), NULL) == 1
        && EC_GROUP_set_generator(group, mappedGenerator, order, cofactor) == 1
        && EC_GROUP_check(group, NULL) == 1;

    EC_POINT_free(sharedSecretMappingPoint);
    EC_POINT_free(mappedGenerator);
    BN_free(order);
    BN_free(cofactor);
    if (!ok) {
        EC_GROUP_free(group);
        return NULL;
    }

    EC_KEY *ephemeralEC = EC_KEY_new();
    EVP_PKEY *ephemeralParameters = EVP_PKEY_new();
    if (ephemeralEC == NULL
        || ephemeralParameters == NULL
        || EC_KEY_set_group(ephemeralEC, group) != 1
        || EVP_PKEY_set1_EC_KEY(ephemeralParameters, ephemeralEC) != 1) {
        EVP_PKEY_free(ephemeralParameters);
        EC_KEY_free(ephemeralEC);
        EC_GROUP_free(group);
        return NULL;
    }

    EC_KEY_free(ephemeralEC);
    EC_GROUP_free(group);
    return ephemeralParameters;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
