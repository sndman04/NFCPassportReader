#include "OpenSSLCompat.h"

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

STACK_OF(X509) *NFCPRCopyCMSSignerCertificates(const unsigned char *der, size_t length) {
    if (der == NULL || length == 0 || length > 2 * 1024 * 1024) return NULL;
    const unsigned char *cursor = der;
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)length);
    if (cms == NULL || cursor != der + length) { CMS_ContentInfo_free(cms); return NULL; }
    STACK_OF(CMS_SignerInfo) *signers = CMS_get0_SignerInfos(cms);
    STACK_OF(X509) *certificates = CMS_get1_certs(cms);
    STACK_OF(X509) *result = sk_X509_new_null();
    int count = signers != NULL ? sk_CMS_SignerInfo_num(signers) : 0;
    int ok = result != NULL && certificates != NULL && count > 0 && count <= 16;
    for (int i = 0; ok && i < count; ++i) {
        CMS_SignerInfo *signer = sk_CMS_SignerInfo_value(signers, i);
        X509 *match = NULL;
        for (int j = 0; j < sk_X509_num(certificates); ++j) {
            X509 *candidate = sk_X509_value(certificates, j);
            if (CMS_SignerInfo_cert_cmp(signer, candidate) != 0) continue;
            if (match != NULL && X509_cmp(match, candidate) != 0) { ok = 0; break; }
            match = candidate;
        }
        if (!ok || match == NULL || X509_up_ref(match) != 1) { ok = 0; break; }
        if (sk_X509_push(result, match) == 0) { X509_free(match); ok = 0; }
    }
    sk_X509_pop_free(certificates, X509_free);
    CMS_ContentInfo_free(cms);
    if (!ok) { sk_X509_pop_free(result, X509_free); return NULL; }
    return result;
}

int NFCPRMatchKnownPACEParameters(const unsigned char *der, size_t length, int ellipticCurve) {
    if (der == NULL || length == 0 || length > 4096) return -1;
    const unsigned char *cursor = der;
    int result = -1;
    if (ellipticCurve) {
        EC_GROUP *group = d2i_ECPKParameters(NULL, &cursor, (long)length);
        if (group == NULL || cursor != der + length) { EC_GROUP_free(group); return -1; }
        const int curves[] = {NID_X9_62_prime192v1, NID_brainpoolP192r1, NID_secp224r1,
            NID_brainpoolP224r1, NID_X9_62_prime256v1, NID_brainpoolP256r1,
            NID_brainpoolP320r1, NID_secp384r1, NID_brainpoolP384r1,
            NID_brainpoolP512r1, NID_secp521r1};
        for (int i = 0; i < 11; ++i) {
            EC_GROUP *known = EC_GROUP_new_by_curve_name(curves[i]);
            if (known != NULL && EC_GROUP_cmp(group, known, NULL) == 0) result = i + 8;
            EC_GROUP_free(known);
            if (result >= 0) break;
        }
        EC_GROUP_free(group);
    } else {
        DH *group = d2i_DHxparams(NULL, &cursor, (long)length);
        if (group == NULL || cursor != der + length) { DH_free(group); return -1; }
        const BIGNUM *p = NULL, *q = NULL, *g = NULL;
        DH_get0_pqg(group, &p, &q, &g);
        for (int i = 0; i < 3 && p != NULL && q != NULL && g != NULL; ++i) {
            DH *known = i == 0 ? DH_get_1024_160() : (i == 1 ? DH_get_2048_224() : DH_get_2048_256());
            const BIGNUM *kp = NULL, *kq = NULL, *kg = NULL;
            if (known != NULL) {
                DH_get0_pqg(known, &kp, &kq, &kg);
                if (BN_cmp(p, kp) == 0 && BN_cmp(q, kq) == 0 && BN_cmp(g, kg) == 0) result = i;
            }
            DH_free(known);
            if (result >= 0) break;
        }
        DH_free(group);
    }
    return result;
}

int NFCPRIsPrimeCurveKey(EVP_PKEY *key) {
    EC_KEY *ec = key != NULL ? EVP_PKEY_get1_EC_KEY(key) : NULL;
    const EC_GROUP *group = ec != NULL ? EC_KEY_get0_group(ec) : NULL;
    int prime = group != NULL && EC_GROUP_get_field_type(group) == NID_X9_62_prime_field;
    EC_KEY_free(ec);
    return prime;
}

int NFCPRNormalizeAARecovery(EVP_PKEY *key, unsigned char *block, size_t length) {
    if (key == NULL || block == NULL || length == 0 || length > 8192
        || length != (size_t)EVP_PKEY_get_size(key)) return 0;
    if ((block[length - 1] & 15) == 12) return 1;
    BIGNUM *modulus = NULL;
    BIGNUM *value = BN_bin2bn(block, (int)length, NULL);
    int ok = value != NULL && EVP_PKEY_get_bn_param(key, "n", &modulus) == 1
        && BN_cmp(modulus, value) > 0 && BN_sub(value, modulus, value) == 1
        && BN_bn2binpad(value, block, (int)length) == (int)length
        && (block[length - 1] & 15) == 12;
    BN_free(modulus);
    BN_clear_free(value);
    return ok;
}

static int NFCPRCRLMatchesIssuer(X509_CRL *crl, X509 *issuer) {
    AUTHORITY_KEYID *authority = X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, NULL, NULL);
    const ASN1_OCTET_STRING *subject = X509_get0_subject_key_id(issuer);
    int matches = authority != NULL && authority->keyid != NULL && subject != NULL
        && ASN1_OCTET_STRING_cmp(authority->keyid, subject) == 0;
    AUTHORITY_KEYID_free(authority);
    if (!matches) return 0;
    ASN1_BIT_STRING *usage = X509_get_ext_d2i(issuer, NID_key_usage, NULL, NULL);
    int authorized = usage != NULL && ASN1_BIT_STRING_get_bit(usage, 6) == 1;
    ASN1_BIT_STRING_free(usage);
    if (!authorized) return -1;
    EVP_PKEY *key = X509_get_pubkey(issuer);
    int verified = key != NULL && X509_CRL_verify(crl, key) == 1;
    EVP_PKEY_free(key);
    return verified ? 1 : -1;
}

/* Only complete, direct ICAO CRLs are supported. Validate every matching
 * authenticated CRL before selecting by number; invalid replacements cannot
 * disappear behind an older valid list in the same supplied bundle. */
static int NFCPRCompareRevokedSerials(const X509_REVOKED *const *a, const X509_REVOKED *const *b) {
    return ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(*a), X509_REVOKED_get0_serialNumber(*b));
}

static int NFCPRUniqueRevokedSerials(const STACK_OF(X509_REVOKED) *entries) {
    if (entries == NULL || sk_X509_REVOKED_num(entries) < 2) return 1;
    // Sort a shallow copy of the container, not the authenticated CRL's entries.
    // O(n log n), without rewriting signed TBS bytes or taking entry ownership.
    STACK_OF(X509_REVOKED) *sorted = sk_X509_REVOKED_dup(entries);
    if (sorted == NULL) return 0;
    sk_X509_REVOKED_set_cmp_func(sorted, NFCPRCompareRevokedSerials);
    sk_X509_REVOKED_sort(sorted);
    int unique = 1;
    for (int i = 1; i < sk_X509_REVOKED_num(sorted); ++i) {
        if (ASN1_INTEGER_cmp(X509_REVOKED_get0_serialNumber(sk_X509_REVOKED_value(sorted, i - 1)),
                             X509_REVOKED_get0_serialNumber(sk_X509_REVOKED_value(sorted, i))) == 0) {
            unique = 0; break;
        }
    }
    sk_X509_REVOKED_free(sorted);
    return unique;
}

static int NFCPRValidCRLProfile(X509_CRL *crl) {
    const ASN1_TIME *thisUpdate = X509_CRL_get0_lastUpdate(crl);
    const ASN1_TIME *nextUpdate = X509_CRL_get0_nextUpdate(crl);
    if (thisUpdate == NULL || nextUpdate == NULL || ASN1_TIME_check(thisUpdate) != 1
        || ASN1_TIME_check(nextUpdate) != 1 || ASN1_TIME_compare(thisUpdate, nextUpdate) >= 0) return 0;
    if (X509_CRL_get_version(crl) != 1
        || X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0
        || X509_CRL_get_ext_by_NID(crl, NID_issuing_distribution_point, -1) >= 0) return 0;
    ASN1_INTEGER *number = X509_CRL_get_ext_d2i(crl, NID_crl_number, NULL, NULL);
    BIGNUM *value = number != NULL ? ASN1_INTEGER_to_BN(number, NULL) : NULL;
    int valid = value != NULL && !BN_is_negative(value) && BN_num_bytes(value) <= 20;
    BN_free(value); ASN1_INTEGER_free(number);
    if (!valid || X509_CRL_get_ext_count(crl) > 64) return 0;
    for (int i = 0; i < X509_CRL_get_ext_count(crl); ++i) {
        X509_EXTENSION *extension = X509_CRL_get_ext(crl, i);
        if (X509_EXTENSION_get_critical(extension)) return 0;
        for (int j = 0; j < i; ++j) {
            if (OBJ_cmp(X509_EXTENSION_get_object(extension),
                        X509_EXTENSION_get_object(X509_CRL_get_ext(crl, j))) == 0) return 0;
        }
    }
    STACK_OF(X509_REVOKED) *entries = X509_CRL_get_REVOKED(crl);
    if (!NFCPRUniqueRevokedSerials(entries)) return 0;
    for (int i = 0; entries != NULL && i < sk_X509_REVOKED_num(entries); ++i) {
        X509_REVOKED *entry = sk_X509_REVOKED_value(entries, i);
        if (X509_REVOKED_get_ext_count(entry) > 32
            || X509_REVOKED_get_ext_by_NID(entry, NID_certificate_issuer, -1) >= 0) return 0;
        for (int j = 0; j < X509_REVOKED_get_ext_count(entry); ++j) {
            X509_EXTENSION *extension = X509_REVOKED_get_ext(entry, j);
            if (X509_EXTENSION_get_critical(extension)) return 0;
            for (int k = 0; k < j; ++k) {
                if (OBJ_cmp(X509_EXTENSION_get_object(extension),
                            X509_EXTENSION_get_object(X509_REVOKED_get_ext(entry, k))) == 0) return 0;
            }
        }
        if (X509_REVOKED_get_ext_by_NID(entry, NID_crl_reason, -1) >= 0) {
            ASN1_ENUMERATED *reason = X509_REVOKED_get_ext_d2i(entry, NID_crl_reason, NULL, NULL);
            long code = reason != NULL ? ASN1_ENUMERATED_get(reason) : -1;
            ASN1_ENUMERATED_free(reason);
            /* RFC 5280 5.3.1: removeFromCRL (8) belongs only to delta CRLs. */
            if (!((code >= 0 && code <= 6) || code == 9 || code == 10)) return 0;
        }
    }
    return 1;
}

static int NFCPRCompareCRLNumber(X509_CRL *candidate, X509_CRL *current) {
    ASN1_INTEGER *a = X509_CRL_get_ext_d2i(candidate, NID_crl_number, NULL, NULL);
    ASN1_INTEGER *b = X509_CRL_get_ext_d2i(current, NID_crl_number, NULL, NULL);
    // A second decode can still fail under allocation pressure.
    int order = a != NULL && b != NULL ? ASN1_INTEGER_cmp(a, b) : 0;
    int result = a == NULL || b == NULL ? 2 : (order < 0 ? -1 : (order > 0 ? 1 : 0));
    ASN1_INTEGER_free(a); ASN1_INTEGER_free(b);
    return result;
}

static int NFCPRSameCRLContent(X509_CRL *a, X509_CRL *b) {
    unsigned char *first = NULL, *second = NULL;
    int firstLength = i2d_re_X509_CRL_tbs(a, &first);
    int secondLength = i2d_re_X509_CRL_tbs(b, &second);
    int same = firstLength > 0 && firstLength == secondLength && memcmp(first, second, (size_t)firstLength) == 0;
    OPENSSL_free(first); OPENSSL_free(second);
    return same;
}

/* Validate the entire local bundle; PEM_read alone can silently skip garbage or
 * stop after a valid older CRL followed by a truncated replacement. */
static int NFCPRPEMCRLCount(const unsigned char *data, size_t length) {
    const char begin[] = "-----BEGIN X509 CRL-----", end[] = "-----END X509 CRL-----";
    size_t offset = 0;
    int count = 0;
    while (offset < length) {
        while (offset < length && (data[offset] == ' ' || data[offset] == '\t'
            || data[offset] == '\r' || data[offset] == '\n')) ++offset;
        if (offset == length) break;
        if (length - offset < sizeof(begin) - 1 || memcmp(data + offset, begin, sizeof(begin) - 1) != 0) return -1;
        offset += sizeof(begin) - 1;
        while (length - offset >= sizeof(end) - 1 && memcmp(data + offset, end, sizeof(end) - 1) != 0) ++offset;
        if (length - offset < sizeof(end) - 1) return -1;
        offset += sizeof(end) - 1;
        if (++count > 1024) return -1;
    }
    return count;
}

int NFCPRCheckRevocation(const unsigned char *data, size_t length, X509 *signer, X509 *issuer) {
    if (data == NULL || length == 0 || length > 16 * 1024 * 1024 || signer == NULL || issuer == NULL) return 4;
    int expectedCount = data[0] == 0x30 ? 0 : NFCPRPEMCRLCount(data, length);
    if (expectedCount < 0) return 4;
    BIO *input = BIO_new_mem_buf(data, (int)length);
    if (input == NULL) return 4;
    X509_CRL *latest = NULL;
    int count = 0, invalidSignature = 0;
    for (;;) {
        X509_CRL *crl = PEM_read_bio_X509_CRL(input, NULL, NULL, NULL);
        if (crl == NULL) break;
        if (++count > 1024) { X509_CRL_free(crl); X509_CRL_free(latest); BIO_free(input); return 4; }
        int matches = NFCPRCRLMatchesIssuer(crl, issuer);
        if (matches < 0 || (matches == 1 && !NFCPRValidCRLProfile(crl))) {
            X509_CRL_free(crl); X509_CRL_free(latest); BIO_free(input); return 4;
        }
        int order = matches == 1 && latest != NULL ? NFCPRCompareCRLNumber(crl, latest) : 1;
        if (order == 2 || (matches == 1 && latest != NULL && order == 0 && !NFCPRSameCRLContent(crl, latest))) {
            X509_CRL_free(crl); X509_CRL_free(latest); BIO_free(input); return 4;
        }
        if (matches == 1 && (latest == NULL || order > 0)) {
            X509_CRL_free(latest); latest = crl;
        } else { X509_CRL_free(crl); }
    }
    BIO_free(input);
    ERR_clear_error();
    if (count != expectedCount) { X509_CRL_free(latest); return 4; }
    if (count == 0) {
        const unsigned char *cursor = data;
        X509_CRL *crl = d2i_X509_CRL(NULL, &cursor, (long)length);
        int matches = crl != NULL && cursor == data + length ? NFCPRCRLMatchesIssuer(crl, issuer) : -1;
        if (matches == 1) latest = crl;
        else { if (matches < 0) invalidSignature = 1; X509_CRL_free(crl); }
    }
    if (latest == NULL) return invalidSignature ? 4 : 3;
    int result = NFCPRValidCRLProfile(latest) ? 1 : 4;
    if (result == 1) {
        int before = X509_cmp_current_time(X509_CRL_get0_lastUpdate(latest));
        const ASN1_TIME *next = X509_CRL_get0_nextUpdate(latest);
        int after = next != NULL ? X509_cmp_current_time(next) : 0;
        if (before == 0 || after == 0) result = 4;
        else if (before > 0) result = 6;
        else if (after < 0) result = 5;
    }
    if (result == 1) {
        X509_REVOKED *revoked = NULL;
        if (X509_CRL_get0_by_serial(latest, &revoked, X509_get0_serialNumber(signer)) == 1) result = 2;
    }
    X509_CRL_free(latest);
    return result;
}

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
