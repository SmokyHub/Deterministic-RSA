#ifndef RSAGEN_H
#define RSAGEN_H

#include <openssl/bn.h>

#define RSA_KEY_SIZE 2048
#define RSA_BYTE_KEYPAIR_SIZE (RSA_KEY_SIZE / 8) // Size in bytes for p and q combined
#define MR_ROUNDS 64 // Number of Miller-Rabin rounds for prime testing
#define MIN_PRIME_DIFFERENCE_BITS 100 // Minimum difference between p and q in bits

typedef struct {
    BIGNUM *n;  // modulus
    BIGNUM *e;  // public exponent
    BIGNUM *d;  // private exponent
    BIGNUM *p;  // first prime factor
    BIGNUM *q;  // second prime factor
    BIGNUM *dp; // d mod (p-1)
    BIGNUM *dq; // d mod (q-1)
    BIGNUM *qinv; // q^(-1) mod p
} RSA_KEY_PAIR;

/**
 * @brief Generate RSA key pair from random bytes
 * @param bytes Random bytes for prime generation
 * @param key_pair Pointer to store generated key pair
 * @return 1 on success, 0 on failure
 */
int rsagen(const uint8_t *bytes, RSA_KEY_PAIR *key_pair);

/**
 * @brief Initialize RSA key pair structure
 * @param key_pair Pointer to key pair structure
 */
void rsa_key_pair_init(RSA_KEY_PAIR *key_pair);

/**
 * @brief Free RSA key pair structure
 * @param key_pair Pointer to key pair structure
 */
void rsa_key_pair_free(RSA_KEY_PAIR *key_pair);

/**
 * @brief Store RSA key pair in PEM format
 * @param key_pair Key pair to store
 * @param private_key_path Path to store private key
 * @param public_key_path Path to store public key
 * @return 1 on success, 0 on failure
 */
int store_keys_pem(const RSA_KEY_PAIR *key_pair, 
                  const char *private_key_path, 
                  const char *public_key_path);

#endif // RSAGEN_H