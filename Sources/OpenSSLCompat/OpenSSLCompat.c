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

EVP_PKEY *NFCPRCreateDHIntegratedMappedParameters(
    EVP_PKEY *domainKey,
    const unsigned char *fieldElement,
    size_t fieldElementLength
) {
    DH *domainDH = EVP_PKEY_get1_DH(domainKey);
    if (domainDH == NULL || fieldElement == NULL || fieldElementLength == 0) {
        DH_free(domainDH);
        return NULL;
    }

    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *g = NULL;
    DH_get0_pqg(domainDH, &p, &q, &g);
    if (p == NULL || q == NULL) {
        DH_free(domainDH);
        return NULL;
    }

    BN_CTX *bnContext = BN_CTX_new();
    BIGNUM *x = BN_bin2bn(fieldElement, (int)fieldElementLength, NULL);
    BIGNUM *cofactor = BN_new();
    BIGNUM *mappedGenerator = BN_new();
    BIGNUM *one = BN_new();
    if (bnContext == NULL || x == NULL || cofactor == NULL || mappedGenerator == NULL || one == NULL) {
        BN_free(one);
        BN_free(mappedGenerator);
        BN_free(cofactor);
        BN_clear_free(x);
        BN_CTX_free(bnContext);
        DH_free(domainDH);
        return NULL;
    }

    int ok = BN_one(one) == 1
        && BN_mod(x, x, p, bnContext) == 1
        && BN_sub(cofactor, p, BN_value_one()) == 1
        && BN_div(cofactor, NULL, cofactor, q, bnContext) == 1
        && BN_mod_exp(mappedGenerator, x, cofactor, p, bnContext) == 1
        && BN_cmp(mappedGenerator, one) != 0;

    DH *mappedDH = NULL;
    EVP_PKEY *mappedParameters = NULL;
    if (ok) {
        mappedDH = DHparams_dup(domainDH);
        ok = mappedDH != NULL
            && DH_set0_pqg(mappedDH, BN_dup(p), BN_dup(q), BN_dup(mappedGenerator)) == 1;
    }

    if (ok) {
        mappedParameters = EVP_PKEY_new();
        ok = mappedParameters != NULL && EVP_PKEY_set1_DH(mappedParameters, mappedDH) == 1;
    }

    if (!ok) {
        EVP_PKEY_free(mappedParameters);
        mappedParameters = NULL;
    }

    DH_free(mappedDH);
    BN_free(one);
    BN_free(mappedGenerator);
    BN_free(cofactor);
    BN_clear_free(x);
    BN_CTX_free(bnContext);
    DH_free(domainDH);

    return mappedParameters;
}

EVP_PKEY *NFCPRCreateECDHIntegratedMappedParameters(
    EVP_PKEY *domainKey,
    const unsigned char *fieldElement,
    size_t fieldElementLength
) {
    EC_KEY *domainEC = EVP_PKEY_get1_EC_KEY(domainKey);
    if (domainEC == NULL || fieldElement == NULL || fieldElementLength == 0) {
        EC_KEY_free(domainEC);
        return NULL;
    }

    const EC_GROUP *domainGroup = EC_KEY_get0_group(domainEC);
    EC_GROUP *group = domainGroup != NULL ? EC_GROUP_dup(domainGroup) : NULL;
    BN_CTX *bnContext = BN_CTX_new();
    if (group == NULL || bnContext == NULL) {
        BN_CTX_free(bnContext);
        EC_GROUP_free(group);
        EC_KEY_free(domainEC);
        return NULL;
    }

    BN_CTX_start(bnContext);
    BIGNUM *a = BN_CTX_get(bnContext);
    BIGNUM *b = BN_CTX_get(bnContext);
    BIGNUM *p = BN_CTX_get(bnContext);
    BIGNUM *t = BN_CTX_get(bnContext);
    BIGNUM *alpha = BN_CTX_get(bnContext);
    BIGNUM *alphaSquared = BN_CTX_get(bnContext);
    BIGNUM *denominator = BN_CTX_get(bnContext);
    BIGNUM *denominatorInverse = BN_CTX_get(bnContext);
    BIGNUM *x2 = BN_CTX_get(bnContext);
    BIGNUM *x3 = BN_CTX_get(bnContext);
    BIGNUM *h2 = BN_CTX_get(bnContext);
    BIGNUM *h3 = BN_CTX_get(bnContext);
    BIGNUM *u = BN_CTX_get(bnContext);
    BIGNUM *sqrtCandidate = BN_CTX_get(bnContext);
    BIGNUM *exponent = BN_CTX_get(bnContext);
    BIGNUM *tmp = BN_CTX_get(bnContext);
    BIGNUM *tmp2 = BN_CTX_get(bnContext);
    BIGNUM *x = BN_CTX_get(bnContext);
    BIGNUM *y = BN_CTX_get(bnContext);
    BIGNUM *order = BN_CTX_get(bnContext);
    BIGNUM *cofactor = BN_CTX_get(bnContext);
    if (cofactor == NULL) {
        BN_CTX_end(bnContext);
        BN_CTX_free(bnContext);
        EC_GROUP_free(group);
        EC_KEY_free(domainEC);
        return NULL;
    }

    int ok = EC_GROUP_get_curve_GFp(group, p, a, b, bnContext) == 1
        && EC_GROUP_get_order(group, order, bnContext) == 1
        && EC_GROUP_get_cofactor(group, cofactor, bnContext) == 1
        && BN_bin2bn(fieldElement, (int)fieldElementLength, t) != NULL
        && BN_mod(t, t, p, bnContext) == 1
        && !BN_is_zero(t);

    BIGNUM *four = BN_new();
    ok = ok
        && four != NULL
        && BN_set_word(four, 4) == 1
        && BN_mod(tmp, p, four, bnContext) == 1
        && BN_is_word(tmp, 3);
    BN_free(four);

    ok = ok
        && BN_mod_sqr(alpha, t, p, bnContext) == 1
        && BN_mod_sub(alpha, BN_value_one(), alpha, p, bnContext) == 1
        && BN_mod_sub(alpha, alpha, BN_value_one(), p, bnContext) == 1
        && BN_mod_sqr(alphaSquared, alpha, p, bnContext) == 1
        && BN_mod_add(denominator, alpha, alphaSquared, p, bnContext) == 1
        && BN_mod_add(tmp, denominator, BN_value_one(), p, bnContext) == 1
        && BN_mod_mul(denominator, a, denominator, p, bnContext) == 1
        && BN_mod_inverse(denominatorInverse, denominator, p, bnContext) != NULL
        && BN_mod_mul(x2, b, tmp, p, bnContext) == 1
        && BN_mod_sub(x2, BN_value_one(), x2, p, bnContext) == 1
        && BN_mod_sub(x2, x2, BN_value_one(), p, bnContext) == 1
        && BN_mod_mul(x2, x2, denominatorInverse, p, bnContext) == 1
        && BN_mod_mul(x3, alpha, x2, p, bnContext) == 1;

    ok = ok
        && BN_mod_sqr(tmp, x2, p, bnContext) == 1
        && BN_mod_mul(h2, tmp, x2, p, bnContext) == 1
        && BN_mod_mul(tmp, a, x2, p, bnContext) == 1
        && BN_mod_add(h2, h2, tmp, p, bnContext) == 1
        && BN_mod_add(h2, h2, b, p, bnContext) == 1
        && BN_mod_sqr(tmp, x3, p, bnContext) == 1
        && BN_mod_mul(h3, tmp, x3, p, bnContext) == 1
        && BN_mod_mul(tmp, a, x3, p, bnContext) == 1
        && BN_mod_add(h3, h3, tmp, p, bnContext) == 1
        && BN_mod_add(h3, h3, b, p, bnContext) == 1;

    ok = ok
        && BN_mod_sqr(tmp, t, p, bnContext) == 1
        && BN_mod_mul(tmp, tmp, t, p, bnContext) == 1
        && BN_mod_mul(u, tmp, h2, p, bnContext) == 1
        && BN_copy(exponent, p) != NULL
        && BN_sub(exponent, exponent, BN_value_one()) == 1
        && BN_copy(tmp, p) != NULL
        && BN_add(tmp, tmp, BN_value_one()) == 1
        && BN_rshift(tmp, tmp, 2) == 1
        && BN_sub(exponent, exponent, tmp) == 1
        && BN_mod_exp(sqrtCandidate, h2, exponent, p, bnContext) == 1
        && BN_mod_sqr(tmp, sqrtCandidate, p, bnContext) == 1
        && BN_mod_mul(tmp, tmp, h2, p, bnContext) == 1;

    if (ok && BN_is_one(tmp)) {
        ok = BN_copy(x, x2) != NULL
            && BN_mod_mul(y, sqrtCandidate, h2, p, bnContext) == 1;
    } else if (ok) {
        ok = BN_copy(x, x3) != NULL
            && BN_mod_mul(y, sqrtCandidate, u, p, bnContext) == 1;
    }

    EC_POINT *generator = ok ? EC_POINT_new(group) : NULL;
    EC_POINT *cofactoredGenerator = ok ? EC_POINT_new(group) : NULL;
    ok = ok
        && generator != NULL
        && cofactoredGenerator != NULL
        && EC_POINT_set_affine_coordinates_GFp(group, generator, x, y, bnContext) == 1
        && EC_POINT_mul(group, cofactoredGenerator, NULL, generator, cofactor, bnContext) == 1
        && EC_GROUP_set_generator(group, cofactoredGenerator, order, cofactor) == 1
        && EC_GROUP_check(group, bnContext) == 1;

    EC_KEY *mappedEC = NULL;
    EVP_PKEY *mappedParameters = NULL;
    if (ok) {
        mappedEC = EC_KEY_new();
        mappedParameters = EVP_PKEY_new();
        ok = mappedEC != NULL
            && mappedParameters != NULL
            && EC_KEY_set_group(mappedEC, group) == 1
            && EVP_PKEY_set1_EC_KEY(mappedParameters, mappedEC) == 1;
    }

    if (!ok) {
        EVP_PKEY_free(mappedParameters);
        mappedParameters = NULL;
    }

    EC_KEY_free(mappedEC);
    EC_POINT_free(cofactoredGenerator);
    EC_POINT_free(generator);
    BN_CTX_end(bnContext);
    BN_CTX_free(bnContext);
    EC_GROUP_free(group);
    EC_KEY_free(domainEC);

    return mappedParameters;
}

int NFCPRVerifyDHGenerator(
    EVP_PKEY *parameters,
    const unsigned char *expectedGenerator,
    size_t expectedGeneratorLength
) {
    DH *dh = EVP_PKEY_get1_DH(parameters);
    if (dh == NULL || expectedGenerator == NULL || expectedGeneratorLength == 0) {
        DH_free(dh);
        return 0;
    }

    const BIGNUM *p = NULL;
    const BIGNUM *q = NULL;
    const BIGNUM *g = NULL;
    DH_get0_pqg(dh, &p, &q, &g);
    BIGNUM *expected = BN_bin2bn(expectedGenerator, (int)expectedGeneratorLength, NULL);
    int result = expected != NULL && g != NULL && BN_cmp(g, expected) == 0;
    BN_free(expected);
    DH_free(dh);
    return result;
}

int NFCPRVerifyECGenerator(
    EVP_PKEY *parameters,
    const unsigned char *expectedGenerator,
    size_t expectedGeneratorLength
) {
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(parameters);
    if (ec == NULL || expectedGenerator == NULL || expectedGeneratorLength == 0) {
        EC_KEY_free(ec);
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *generator = group != NULL ? EC_GROUP_get0_generator(group) : NULL;
    EC_POINT *expected = group != NULL ? EC_POINT_new(group) : NULL;
    int result = expected != NULL
        && generator != NULL
        && EC_POINT_oct2point(group, expected, expectedGenerator, expectedGeneratorLength, NULL) == 1
        && EC_POINT_cmp(group, generator, expected, NULL) == 0;

    EC_POINT_free(expected);
    EC_KEY_free(ec);
    return result;
}

int NFCPRCalculateECDHCAMPublicKey(
    EVP_PKEY *staticPublicKey,
    const unsigned char *chipAuthenticationData,
    size_t chipAuthenticationDataLength,
    unsigned char *output,
    size_t *outputLength
) {
    if (staticPublicKey == NULL || chipAuthenticationData == NULL || chipAuthenticationDataLength == 0 || outputLength == NULL) {
        return 0;
    }

    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(staticPublicKey);
    if (ecKey == NULL) {
        return 0;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ecKey);
    const EC_POINT *staticPublicPoint = EC_KEY_get0_public_key(ecKey);
    BIGNUM *chipAuthenticationScalar = BN_bin2bn(chipAuthenticationData, (int)chipAuthenticationDataLength, NULL);
    EC_POINT *calculatedPoint = group != NULL ? EC_POINT_new(group) : NULL;
    if (group == NULL || staticPublicPoint == NULL || chipAuthenticationScalar == NULL || calculatedPoint == NULL) {
        EC_POINT_free(calculatedPoint);
        BN_clear_free(chipAuthenticationScalar);
        EC_KEY_free(ecKey);
        return 0;
    }

    int ok = EC_POINT_mul(group, calculatedPoint, NULL, staticPublicPoint, chipAuthenticationScalar, NULL) == 1;
    BN_clear_free(chipAuthenticationScalar);
    if (!ok) {
        EC_POINT_free(calculatedPoint);
        EC_KEY_free(ecKey);
        return 0;
    }

    size_t requiredLength = EC_POINT_point2oct(
        group,
        calculatedPoint,
        POINT_CONVERSION_UNCOMPRESSED,
        NULL,
        0,
        NULL
    );
    if (requiredLength == 0) {
        EC_POINT_free(calculatedPoint);
        EC_KEY_free(ecKey);
        return 0;
    }

    if (output == NULL || *outputLength < requiredLength) {
        *outputLength = requiredLength;
        EC_POINT_free(calculatedPoint);
        EC_KEY_free(ecKey);
        return output == NULL ? 1 : 0;
    }

    ok = EC_POINT_point2oct(
        group,
        calculatedPoint,
        POINT_CONVERSION_UNCOMPRESSED,
        output,
        *outputLength,
        NULL
    ) == requiredLength;
    *outputLength = requiredLength;

    EC_POINT_free(calculatedPoint);
    EC_KEY_free(ecKey);
    return ok ? 1 : 0;
}

int NFCPRVerifyECDHCAMPublicKey(
    EVP_PKEY *staticPublicKey,
    const unsigned char *mappingPublicKey,
    size_t mappingPublicKeyLength,
    const unsigned char *chipAuthenticationData,
    size_t chipAuthenticationDataLength
) {
    if (mappingPublicKey == NULL || mappingPublicKeyLength == 0) {
        return 0;
    }

    size_t calculatedLength = 0;
    if (NFCPRCalculateECDHCAMPublicKey(
        staticPublicKey,
        chipAuthenticationData,
        chipAuthenticationDataLength,
        NULL,
        &calculatedLength
    ) != 1 || calculatedLength == 0) {
        return 0;
    }

    unsigned char *calculated = OPENSSL_malloc(calculatedLength);
    if (calculated == NULL) {
        return 0;
    }

    int ok = NFCPRCalculateECDHCAMPublicKey(
        staticPublicKey,
        chipAuthenticationData,
        chipAuthenticationDataLength,
        calculated,
        &calculatedLength
    ) == 1
        && calculatedLength == mappingPublicKeyLength
        && CRYPTO_memcmp(calculated, mappingPublicKey, mappingPublicKeyLength) == 0;

    OPENSSL_clear_free(calculated, calculatedLength);
    return ok ? 1 : 0;
}

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
