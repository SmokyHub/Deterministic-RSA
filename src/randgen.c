#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "../include/randgen.h"
#include "../include/utils.h"

void prng_cleanup(PRNG_STATE *state) {
    if (!state) return;
    
    if (state->ctx) {
        cleanup_cipher_ctx(state->ctx);
        state->ctx = NULL;
    }
    
    secure_zero(state->seed, SEED_SIZE);
    state->generated_bytes = 0;
}

int prng_init(PRNG_STATE *state, const uint8_t *seed) {
    if (!state || !seed) {
        return 0;
    }

    // Clean up any existing state
    prng_cleanup(state);

    state->ctx = EVP_CIPHER_CTX_new();
    if (!state->ctx) {
        return 0;
    }

    uint8_t key[CHACHA20_KEY_SIZE];
    uint8_t nonce[CHACHA20_NONCE_SIZE] = {0};
    
    memcpy(key, seed, CHACHA20_KEY_SIZE);
    memcpy(state->seed, seed, SEED_SIZE);
    
    const EVP_CIPHER *cipher = EVP_chacha20();
    if (!cipher) {
        cleanup_cipher_ctx(state->ctx);
        state->ctx = NULL;
        secure_zero(key, sizeof(key));
        return 0;
    }

    if (!EVP_EncryptInit_ex(state->ctx, cipher, NULL, key, nonce)) {
        cleanup_cipher_ctx(state->ctx);
        state->ctx = NULL;
        secure_zero(key, sizeof(key));
        return 0;
    }

    secure_zero(key, sizeof(key));
    state->generated_bytes = 0;
    
    return 1;
}

int prng_generate(PRNG_STATE *state, uint8_t *output, size_t length) {
    if (!state || !state->ctx || !output || length == 0) {
        return 0;
    }

    uint8_t *zeros = OPENSSL_zalloc(length);
    if (!zeros) {
        return 0;
    }

    int outlen;
    int success = EVP_EncryptUpdate(state->ctx, output, &outlen, zeros, length);
    
    OPENSSL_clear_free(zeros, length);

    if (!success || (size_t)outlen != length) {
        secure_zero(output, length);
        return 0;
    }

    state->generated_bytes += length;
    return 1;
}

int randgen(size_t size, const char *password, const char *confusion_string, 
            int iterations, uint8_t *output) {


    // Use shorter pattern length for better probability
    size_t pattern_len = 3;
    
    // Generate initial seed using PBKDF2
    uint8_t initial_seed[SEED_SIZE];
    secure_zero(initial_seed, SEED_SIZE);

    EVP_cleanup();  // Cleanup any leftover EVP state

    if (!generate_pbkdf2(password, confusion_string, 
                        PBKDF2_ITERATIONS_BASE * iterations,
                        initial_seed, SEED_SIZE)) {
        secure_zero(initial_seed, SEED_SIZE);
        return 0;
    }

    // Generate confusion pattern
    uint8_t *confusion_pattern = OPENSSL_malloc(pattern_len);
    if (!confusion_pattern) {
        secure_zero(initial_seed, SEED_SIZE);
        return 0;
    }

    if (!generate_pbkdf2(confusion_string, password, 
                        PBKDF2_ITERATIONS_BASE * iterations,
                        confusion_pattern, pattern_len)) {
        secure_zero(initial_seed, SEED_SIZE);
        OPENSSL_clear_free(confusion_pattern, pattern_len);
        return 0;
    }

    PRNG_STATE state = {0};  // Zero-initialize
    if (!prng_init(&state, initial_seed)) {
        secure_zero(initial_seed, SEED_SIZE);
        OPENSSL_clear_free(confusion_pattern, pattern_len);
        return 0;
    }

    uint8_t *temp_buffer = OPENSSL_malloc(size);
    if (!temp_buffer) {
        secure_zero(initial_seed, SEED_SIZE);
        OPENSSL_clear_free(confusion_pattern, pattern_len);
        prng_cleanup(&state);
        return 0;
    }

    // Main generation loop
    int found_pattern = 0;
    int current_iteration = 0;
    
    // Increased attempts for better probability
    const int MAX_ATTEMPTS = 1 << 20;  // ~1 million attempts

    while (current_iteration < iterations) {
        int attempts = 0;
        
        do {
            if (!prng_generate(&state, temp_buffer, size)) {
                goto cleanup;
            }
            
            found_pattern = find_pattern(confusion_pattern, pattern_len,
                                      temp_buffer, size);
            attempts++;
            
            if (attempts >= MAX_ATTEMPTS) {
                goto cleanup;
            }
        } while (!found_pattern);

        // Re-initialize with new seed
        if (!prng_init(&state, temp_buffer + size - SEED_SIZE)) {
            goto cleanup;
        }

        current_iteration++;
    }

    // Final copy
    memcpy(output, temp_buffer, size);
    
    // Cleanup
    secure_zero(temp_buffer, size);
    secure_zero(confusion_pattern, pattern_len);
    secure_zero(initial_seed, SEED_SIZE);
    
    OPENSSL_clear_free(temp_buffer, size);
    OPENSSL_clear_free(confusion_pattern, pattern_len);
    prng_cleanup(&state);
    EVP_cleanup();  // Final EVP cleanup
    return 1;

cleanup:
    secure_zero(temp_buffer, size);
    secure_zero(confusion_pattern, pattern_len);
    secure_zero(initial_seed, SEED_SIZE);
    OPENSSL_clear_free(temp_buffer, size);
    OPENSSL_clear_free(confusion_pattern, pattern_len);
    prng_cleanup(&state);
    EVP_cleanup();  // Final EVP cleanup
    return 0;
}