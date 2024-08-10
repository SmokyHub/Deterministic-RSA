#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/rsagen.h"
#include "../include/utils.h"

#define DEFAULT_PRIVATE_KEY "private_key.pem"
#define DEFAULT_PUBLIC_KEY "public_key.pem"

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [private_key_file public_key_file]\n", program_name);
    fprintf(stderr, "Reads random bytes from stdin to generate RSA key pair\n");
    fprintf(stderr, "Default output files: %s, %s\n", 
            DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY);
}

int main(int argc, char *argv[]) {
    const char *private_key_path = DEFAULT_PRIVATE_KEY;
    const char *public_key_path = DEFAULT_PUBLIC_KEY;

    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        print_usage(argv[0]);
        return 0;
    }

    if (argc == 3) {
        private_key_path = argv[1];
        public_key_path = argv[2];
    } else if (argc != 1) {
        print_usage(argv[0]);
        return 1;
    }

    init_openssl();

    uint8_t *random_bytes = malloc(RSA_BYTE_KEYPAIR_SIZE);
    if (!random_bytes) {
        fprintf(stderr, "Error: memory allocation failed\n");
        cleanup_openssl();
        return 1;
    }

    // Read random bytes from stdin
    size_t bytes_read = fread(random_bytes, 1, RSA_BYTE_KEYPAIR_SIZE, stdin);
    if (bytes_read != RSA_BYTE_KEYPAIR_SIZE) {
        fprintf(stderr, "Error: failed to read %d bytes from stdin\n", 
                RSA_BYTE_KEYPAIR_SIZE);
        free(random_bytes);
        cleanup_openssl();
        return 1;
    }

    RSA_KEY_PAIR key_pair;
    rsa_key_pair_init(&key_pair);

    if (!rsagen(random_bytes, &key_pair)) {
        fprintf(stderr, "Error: RSA key generation failed\n");
        free(random_bytes);
        rsa_key_pair_free(&key_pair);
        cleanup_openssl();
        return 1;
    }

    if (!store_keys_pem(&key_pair, private_key_path, public_key_path)) {
        fprintf(stderr, "Error: Failed to store keys\n");
        free(random_bytes);
        rsa_key_pair_free(&key_pair);
        cleanup_openssl();
        return 1;
    }

    printf("Successfully generated RSA key pair:\n");
    printf("  Private key: %s\n", private_key_path);
    printf("  Public key: %s\n", public_key_path);

    free(random_bytes);
    rsa_key_pair_free(&key_pair);
    cleanup_openssl();
    return 0;
}