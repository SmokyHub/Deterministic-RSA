#include <string.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/evp.h>
#include "../include/rsagen.h"

void rsa_key_pair_init(RSA_KEY_PAIR *key_pair) {
    key_pair->n = BN_new();
    key_pair->e = BN_new();
    key_pair->d = BN_new();
    key_pair->p = BN_new();
    key_pair->q = BN_new();
    key_pair->dp = BN_new();
    key_pair->dq = BN_new();
    key_pair->qinv = BN_new();

    if (!key_pair->n || !key_pair->e || !key_pair->d || !key_pair->p || 
        !key_pair->q || !key_pair->dp || !key_pair->dq || !key_pair->qinv) {
        rsa_key_pair_free(key_pair);
    }
}

void rsa_key_pair_free(RSA_KEY_PAIR *key_pair) {
    if (key_pair->n) BN_free(key_pair->n);
    if (key_pair->e) BN_free(key_pair->e);
    if (key_pair->d) BN_free(key_pair->d);
    if (key_pair->p) BN_free(key_pair->p);
    if (key_pair->q) BN_free(key_pair->q);
    if (key_pair->dp) BN_free(key_pair->dp);
    if (key_pair->dq) BN_free(key_pair->dq);
    if (key_pair->qinv) BN_free(key_pair->qinv);

    // Zero out the pointers after freeing
    key_pair->n = NULL;
    key_pair->e = NULL;
    key_pair->d = NULL;
    key_pair->p = NULL;
    key_pair->q = NULL;
    key_pair->dp = NULL;
    key_pair->dq = NULL;
    key_pair->qinv = NULL;
}

static int generate_prime_from_seed(BIGNUM *prime, const uint8_t *seed, 
                                  size_t seed_len, int bits, BN_CTX *ctx) {
    BIGNUM *temp = BN_new();
    if (!temp) return 0;

    // Convert seed to BIGNUM and ensure it's the right size
    if (!BN_bin2bn(seed, seed_len, temp)) {
        BN_free(temp);
        return 0;
    }

    // Set the top bit to ensure proper size
    BN_set_bit(temp, bits - 1);
    
    // Set LSB to 1 to ensure it's odd
    BN_set_bit(temp, 0);

    // Test for primality with modern OpenSSL API
    int is_prime = BN_check_prime(temp, ctx, NULL);
    
    if (is_prime) {
        BN_copy(prime, temp);
        BN_free(temp);
        return 1;
    }

    // If not prime, find next prime
    int tries = 0;
    while (tries < 1000) { // Limit attempts
        BN_add_word(temp, 2);
        if (BN_check_prime(temp, ctx, NULL)) {
            BN_copy(prime, temp);
            BN_free(temp);
            return 1;
        }
        tries++;
    }

    BN_free(temp);
    return 0;
}

static int check_prime_difference(const BIGNUM *p, const BIGNUM *q) {
    BIGNUM *diff = BN_new();
    BIGNUM *abs_diff = BN_new();
    if (!diff || !abs_diff) {
        BN_free(diff);
        BN_free(abs_diff);
        return 0;
    }

    // Calculate |p - q|
    BN_sub(diff, p, q);
    // If diff is negative, multiply by -1
    if (BN_is_negative(diff)) {
        BN_copy(abs_diff, diff);
        BN_set_negative(abs_diff, 0);
    } else {
        BN_copy(abs_diff, diff);
    }
    
    int bit_diff = BN_num_bits(abs_diff);
    
    BN_free(diff);
    BN_free(abs_diff);
    
    return bit_diff >= MIN_PRIME_DIFFERENCE_BITS;
}

int rsagen(const uint8_t *bytes, RSA_KEY_PAIR *key_pair) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return 0;

    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *phi = BN_new();
    if (!p_minus_1 || !q_minus_1 || !phi) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    // Set e to F4 (65537)
    if (!BN_set_word(key_pair->e, 65537)) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    // Generate p and q from different parts of the input bytes
    if (!generate_prime_from_seed(key_pair->p, bytes, RSA_BYTE_KEYPAIR_SIZE/2, 
                                RSA_KEY_SIZE/2, ctx) ||
        !generate_prime_from_seed(key_pair->q, 
                                bytes + RSA_BYTE_KEYPAIR_SIZE/2, 
                                RSA_BYTE_KEYPAIR_SIZE/2, 
                                RSA_KEY_SIZE/2, ctx)) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    // Verify p and q are sufficiently different
    if (!check_prime_difference(key_pair->p, key_pair->q)) {
        // If too close, regenerate q with modified seed
        uint8_t modified_seed[RSA_BYTE_KEYPAIR_SIZE/2];
        memcpy(modified_seed, bytes + RSA_BYTE_KEYPAIR_SIZE/2, 
               RSA_BYTE_KEYPAIR_SIZE/2);
        modified_seed[0] ^= 0xFF; // Modify seed to get different prime
        
        if (!generate_prime_from_seed(key_pair->q, modified_seed, 
                                    RSA_BYTE_KEYPAIR_SIZE/2, 
                                    RSA_KEY_SIZE/2, ctx)) {
            BN_CTX_free(ctx);
            BN_free(p_minus_1);
            BN_free(q_minus_1);
            BN_free(phi);
            return 0;
        }
    }

    // Calculate n = p * q
    if (!BN_mul(key_pair->n, key_pair->p, key_pair->q, ctx)) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    // Calculate phi = (p-1)(q-1)
    if (!BN_copy(p_minus_1, key_pair->p) ||
        !BN_copy(q_minus_1, key_pair->q) ||
        !BN_sub_word(p_minus_1, 1) ||
        !BN_sub_word(q_minus_1, 1) ||
        !BN_mul(phi, p_minus_1, q_minus_1, ctx)) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    // Calculate d = e^(-1) mod phi
    if (!BN_mod_inverse(key_pair->d, key_pair->e, phi, ctx)) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    // Calculate CRT parameters
    if (!BN_mod(key_pair->dp, key_pair->d, p_minus_1, ctx) ||
        !BN_mod(key_pair->dq, key_pair->d, q_minus_1, ctx) ||
        !BN_mod_inverse(key_pair->qinv, key_pair->q, key_pair->p, ctx)) {
        BN_CTX_free(ctx);
        BN_free(p_minus_1);
        BN_free(q_minus_1);
        BN_free(phi);
        return 0;
    }

    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(phi);
    BN_CTX_free(ctx);
    return 1;
}

int store_keys_pem(const RSA_KEY_PAIR *key_pair, 
                  const char *private_key_path, 
                  const char *public_key_path) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (!ctx) return 0;

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Build parameters for the key
    if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, key_pair->n) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, key_pair->e) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, key_pair->d) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, key_pair->p) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, key_pair->q) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, key_pair->dp) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, key_pair->dq) ||
        !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, key_pair->qinv)) {
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) {
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PRIVATE_KEY, params) <= 0) {
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    // Write private key
    FILE *private_fp = fopen(private_key_path, "w");
    if (!private_fp) {
        EVP_PKEY_free(pkey);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (!PEM_write_PrivateKey(private_fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(private_fp);
        EVP_PKEY_free(pkey);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    fclose(private_fp);

    // Write public key
    FILE *public_fp = fopen(public_key_path, "w");
    if (!public_fp) {
        EVP_PKEY_free(pkey);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (!PEM_write_PUBKEY(public_fp, pkey)) {
        fclose(public_fp);
        EVP_PKEY_free(pkey);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    fclose(public_fp);

    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(ctx);
    return 1;
}