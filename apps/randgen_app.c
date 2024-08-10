#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../include/randgen.h"
#include "../include/utils.h"

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s [-t] <password> <confusion_string> <iterations>\n", program_name);
    fprintf(stderr, "  -t: Test mode - measure time instead of generating output\n");
}

int main(int argc, char *argv[]) {
    int test_mode = 0;
    int arg_offset = 0;

    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-t") == 0) {
        test_mode = 1;
        arg_offset = 1;
        if (argc < 5) {
            print_usage(argv[0]);
            return 1;
        }
    }

    const char *password = argv[1 + arg_offset];
    const char *confusion_string = argv[2 + arg_offset];
    int iterations = atoi(argv[3 + arg_offset]);

    if (iterations <= 0) {
        fprintf(stderr, "Error: iterations must be positive\n");
        return 1;
    }

    init_openssl();

    uint8_t *output = malloc(BUFFER_SIZE);
    if (!output) {
        fprintf(stderr, "Error: memory allocation failed\n");
        cleanup_openssl();
        return 1;
    }

    clock_t start = clock();
    
    if (!randgen(BUFFER_SIZE, password, confusion_string, iterations, output)) {
        fprintf(stderr, "Error: random generation failed\n");
        free(output);
        cleanup_openssl();
        return 1;
    }

    clock_t end = clock();
    
    if (test_mode) {
        double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
        printf("Time taken: %.3f seconds\n", time_spent);
        printf("Parameters:\n");
        printf("  Password length: %zu bytes\n", strlen(password));
        printf("  Confusion string length: %zu bytes\n", strlen(confusion_string));
        printf("  Iterations: %d\n", iterations);
        printf("  Output size: %d bytes\n", BUFFER_SIZE);
    } else {
        fwrite(output, 1, BUFFER_SIZE, stdout);
    }

    free(output);
    cleanup_openssl();
    return 0;
}