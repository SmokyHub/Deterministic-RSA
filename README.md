# Deterministic RSA (D-RSA)

Traditional RSA key generation relies on randomness, making keys irreproducible and requiring secure storage. Deterministic approaches, like those in Trusted Platform Modules (TPMs), derive keys from secrets but depend on hardware-bound security (e.g., a TPM’s internal secret). This project explores an alternative: time-based computational complexity as a substitute for hardware secrets, enabling deterministic RSA key generation in software.

## Core Components

1. **ChaCha20 PRNG**: Implements the ChaCha20 stream cipher for cryptographically secure random number generation
2. **Computational Complexity Engine**: Uses a pattern-based iteration scheme to enforce computational intensity
3. **RSA Key Generation**: Produces 2048-bit RSA keys with complete Chinese Remainder Theorem (CRT) parameters

## Cryptographic Foundation

- ChaCha20 stream cipher for secure byte generation
- PBKDF2-HMAC-SHA256 for robust key derivation
- Pattern-based computational complexity enforcement
- Strong prime generation with enforced minimum bit-difference
- Full CRT parameter computation for RSA private key operations
- Standard OpenSSL PEM format for key storage

## Building the System

Requires OpenSSL development libraries (libssl-dev).

```bash
make all
```

Produces two executables in `bin/`:
- `randgen`: ChaCha20-based PRNG with pattern matching
- `rsagen`: RSA key pair generator with CRT parameters

## Pseudo-Random Number Generator (randgen)

The PRNG utilizes ChaCha20 with a pattern-matching complexity scheme for deterministic byte generation.

### Command Interface

```bash
# Performance analysis mode
./bin/randgen -t <password> <confusion_string> <iterations>

# Byte generation mode
./bin/randgen <password> <confusion_string> <iterations> > output.bin
```

### Cryptographic Parameters

- `password`: Entropy source for PBKDF2 key derivation
- `confusion_string`: Pattern matching complexity parameter
- `iterations`: Pattern-finding iteration count
- `-t`: Performance analysis flag

### Performance Characteristics

The computational complexity scales with:

1. **Pattern Length**: 
   - 3 bytes for all input sizes
   - Pattern length exponentially impacts search complexity

2. **Iteration Depth**: 
   - Linear scaling with iteration count
   - Each iteration requires pattern detection
   - Maximum pattern search attempts: 2^20

3. **PBKDF2 Operations**:
   - Base iteration count: 10000
   - Effective iterations = 10000 * user_iterations

## RSA Key Generator (rsagen)

Generates 2048-bit RSA key pairs with full CRT parameter computation.

### Command Interface

```bash
# Standard output (private_key.pem, public_key.pem)
./bin/rsagen

# Custom key paths
./bin/rsagen <private_key_file> <public_key_file>
```

### Cryptographic Properties

- 2048-bit modulus
- Fixed public exponent: 65537 (F4)
- Minimum prime difference: 100 bits
- Full CRT parameter set

### Deterministic Key Generation

Generate deterministic RSA keys by chaining randgen output to rsagen:

```bash
./bin/randgen "entropy_password" "complexity_string" 10 | ./bin/rsagen priv.pem pub.pem
```

## System Architecture

```
├── include/
│   ├── randgen.h    # PRNG interface definitions
│   ├── rsagen.h     # RSA generation parameters
│   └── utils.h      # Cryptographic utilities
├── src/
│   ├── randgen.c    # ChaCha20 PRNG implementation
│   ├── rsagen.c     # RSA key generation logic
│   └── utils.c      # Common cryptographic operations
└── apps/
    ├── randgen_app.c # PRNG command interface 
    └── rsagen_app.c  # RSA generator interface
```

## Cryptographic Considerations

1. **Password Entropy**:
   - Employ high-entropy passwords
   - Maximize password length
   - Avoid structured patterns

2. **Complexity Parameters**:
   - Pattern length affects search complexity
   - Longer patterns increase computational intensity
   - Balance security requirements with performance

3. **Iteration Depth**:
   - Higher counts increase computational complexity
   - Each iteration enforces pattern detection
   - Scale based on security requirements

4. **Key Management**:
   - Implement proper file access controls
   - Secure private key storage
   - Consider HSM integration

## Implementation Details

### PRNG Architecture
- ChaCha20 stream cipher integration
- Computational complexity through pattern matching
- PBKDF2 for initial entropy expansion
- Secure memory operations

### RSA Implementation
- 2048-bit modulus generation
- Strong prime number generation
- Complete OpenSSL cryptographic integration

## Build Requirements

```bash
# Library dependencies (Ubuntu/Debian)
sudo apt-get install build-essential libssl-dev

# System compilation
make all

# Build cleanup
make clean
```

## Performance Analysis

Analyze PRNG computational characteristics:

```bash
# Basic analysis
./bin/randgen -t "entropy_source" "complexity" 10

# Extended analysis
./bin/randgen -t "high_entropy_source" "extended_complexity" 10
```

Performance analysis mode provides detailed computational metrics and parameter impact data.