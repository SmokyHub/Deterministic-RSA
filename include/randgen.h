#ifndef RANDGEN_H
#define RANDGEN_H

#include <stdint.h>
#include <openssl/evp.h>

#define SEED_SIZE 32
#define BUFFER_SIZE 4096
#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 16
#define PBKDF2_ITERATIONS_BASE 10000

// Structure to hold PRNG state
typedef struct {
    EVP_CIPHER_CTX *ctx;
    uint8_t seed[SEED_SIZE];
    size_t generated_bytes;
} PRNG_STATE;

/**
 * @brief Initialize the PRNG state
 * @param state PRNG state to initialize
 * @param seed Initial seed
 * @return 1 on success, 0 on failure
 */
int prng_init(PRNG_STATE *state, const uint8_t *seed);

/**
 * @brief Generate random bytes using ChaCha20
 * @param state PRNG state
 * @param output Buffer to store generated bytes
 * @param length Number of bytes to generate
 * @return 1 on success, 0 on failure
 */
int prng_generate(PRNG_STATE *state, uint8_t *output, size_t length);

/**
 * @brief Generate deterministic random bytes using password and confusion string
 * @param size Size of output buffer
 * @param password Password for seeding
 * @param confusion_string String used for pattern matching
 * @param iterations Number of iterations
 * @param output Output buffer
 * @return 1 on success, 0 on failure
 */
int randgen(size_t size, const char *password, const char *confusion_string, 
            int iterations, uint8_t *output);

/**
 * @brief Clean up PRNG state
 * @param state PRNG state to clean
 */
void prng_cleanup(PRNG_STATE *state);

#endif // RANDGEN_H