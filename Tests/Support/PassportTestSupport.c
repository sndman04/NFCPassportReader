// This target is a dependency of the test bundle only. Legacy accessors preserve
// the exact mapped group, as in OpenSSLCompat, instead of importing its old name.
#define OPENSSL_SUPPRESS_DEPRECATED
#include "PassportTestSupport.h"
#include <string.h>
#include <stdlib.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
EVP_PKEY *NFCPRTestImportKey(EVP_PKEY *parameters,
    const unsigned char *privateBytes, size_t privateLength,
    const unsigned char *publicBytes, size_t publicLength, int isDH) {
    BIGNUM *secret = BN_bin2bn(privateBytes, (int)privateLength, NULL);
    EVP_PKEY *result = EVP_PKEY_new();
    int ok = 0;
    if (secret == NULL || result == NULL) goto done;
    if (isDH) {
        DH *source = EVP_PKEY_get1_DH(parameters);
        DH *key = source != NULL ? DHparams_dup(source) : NULL;
        DH_free(source);
        BIGNUM *pub = BN_bin2bn(publicBytes, (int)publicLength, NULL);
        BIGNUM *computed = BN_new();
        BN_CTX *ctx = BN_CTX_new();
        const BIGNUM *p = NULL, *g = NULL;
        if (key != NULL) DH_get0_pqg(key, &p, NULL, &g);
        if (p != NULL && g != NULL && pub != NULL && computed != NULL && ctx != NULL &&
            BN_mod_exp(computed, g, secret, p, ctx) == 1 && BN_cmp(computed, pub) == 0 &&
            DH_set0_key(key, pub, secret) == 1) {
            pub = NULL; secret = NULL;
            ok = EVP_PKEY_set1_DH(result, key) == 1;
        }
        BN_free(pub); BN_free(computed); BN_CTX_free(ctx); DH_free(key);
    } else {
        EC_KEY *source = EVP_PKEY_get1_EC_KEY(parameters);
        EC_KEY *key = EC_KEY_new();
        EC_GROUP *group = source != NULL ? EC_GROUP_dup(EC_KEY_get0_group(source)) : NULL;
        if (group != NULL) EC_GROUP_set_curve_name(group, NID_undef);
        if (key != NULL) EC_KEY_set_conv_form(key, POINT_CONVERSION_UNCOMPRESSED);
        EC_POINT *pub = group != NULL ? EC_POINT_new(group) : NULL;
        ok = key != NULL && group != NULL && pub != NULL &&
            EC_POINT_oct2point(group, pub, publicBytes, publicLength, NULL) == 1 &&
            EC_KEY_set_group(key, group) == 1 && EC_KEY_set_private_key(key, secret) == 1 &&
            EC_KEY_set_public_key(key, pub) == 1 && EC_KEY_check_key(key) == 1 &&
            EVP_PKEY_set1_EC_KEY(result, key) == 1;
        EC_POINT_free(pub); EC_GROUP_free(group); EC_KEY_free(key); EC_KEY_free(source);
    }
done:
    BN_clear_free(secret);
    if (!ok) { EVP_PKEY_free(result); return NULL; }
    // Production key generation uses provider keys. Import the exact explicit
    // parameters so the test entropy replacement has the same representation.
    OSSL_PARAM *params = NULL;
    EVP_PKEY *providerKey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, isDH ? "DHX" : "EC", NULL);
    if (EVP_PKEY_todata(result, EVP_PKEY_KEYPAIR, &params) != 1 || ctx == NULL) {
        EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(result); OSSL_PARAM_free(params); return NULL;
    }
    // A mapped EC key can retain its original group name. Explicit p/a/b/g/n
    // must take precedence. Do not let the provider restore the original group.
    for (OSSL_PARAM *param = params; param->key != NULL; ++param) {
        if (strcmp(param->key, OSSL_PKEY_PARAM_GROUP_NAME) == 0) {
            param->key = "unused-test-group-name";
        }
    }
    ok = EVP_PKEY_fromdata_init(ctx) == 1 &&
         EVP_PKEY_fromdata(ctx, &providerKey, EVP_PKEY_KEYPAIR, params) == 1;
    EVP_PKEY_CTX_free(ctx); OSSL_PARAM_free(params); EVP_PKEY_free(result);
    if (!ok) { EVP_PKEY_free(providerKey); return NULL; }
    return providerKey;
}

#pragma clang diagnostic pop
