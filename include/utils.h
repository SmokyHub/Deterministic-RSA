#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <openssl/evp.h>

/**
 * @brief Generate key derivation using PBKDF2-HMAC-SHA256
 * @param password Password input
 * @param salt Salt input
 * @param iterations Number of iterations
 * @param output Output buffer
 * @param output_len Desired output length
 * @return 1 on success, 0 on failure
 */
int generate_pbkdf2(const char *password, const char *salt, int iterations,
                   uint8_t *output, size_t output_len);

/**
 * @brief Find pattern in byte stream
 * @param pattern Pattern to search for
 * @param pattern_len Pattern length
 * @param stream Stream to search in
 * @param stream_len Stream length
 * @return 1 if pattern found, 0 otherwise
 */
int find_pattern(const uint8_t *pattern, size_t pattern_len,
                const uint8_t *stream, size_t stream_len);

/**
 * @brief Secure memory wiping function
 */
void secure_zero(void *ptr, size_t len);

// 
/**
 * @brief Helper function to properly cleanup EVP cipher context
 */
void cleanup_cipher_ctx(EVP_CIPHER_CTX *ctx);

/**
 * @brief Initialize OpenSSL
 */
void init_openssl(void);

/**
 * @brief Cleanup OpenSSL
 */
void cleanup_openssl(void);

#endif // UTILS_H