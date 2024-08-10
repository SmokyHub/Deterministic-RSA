#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "../include/utils.h"

int generate_pbkdf2(const char *password, const char *salt, int iterations,
                   uint8_t *output, size_t output_len) {
    return PKCS5_PBKDF2_HMAC(password, strlen(password),
                            (const unsigned char *)salt, strlen(salt),
                            iterations,
                            EVP_sha256(),
                            output_len, output);
}

int find_pattern(const uint8_t *pattern, size_t pattern_len,
                const uint8_t *stream, size_t stream_len) {
    // Input validation
    if (!pattern || !stream || pattern_len > stream_len || pattern_len == 0) {
        return 0;
    }

    // Fixed sliding window search
    for (size_t i = 0; i <= stream_len - pattern_len; i++) {
        if (memcmp(stream + i, pattern, pattern_len) == 0) {
            return 1;
        }
    }
    return 0;
}

void secure_zero(void *ptr, size_t len) {
    OPENSSL_cleanse(ptr, len);
}

void cleanup_cipher_ctx(EVP_CIPHER_CTX *ctx) {
    if (ctx) {
        EVP_CIPHER_CTX_cleanup(ctx);
        EVP_CIPHER_CTX_free(ctx);
    }
}

void init_openssl(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

void cleanup_openssl(void) {
    EVP_cleanup();
    ERR_free_strings();
}