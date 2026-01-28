# QuantumVault Go SDK

<p align="center">
  <strong>A Product of <a href="https://allsecurex.com">AllSecureX</a></strong><br>
  Enterprise-Grade Post-Quantum Cryptography
</p>

<p align="center">
  <a href="https://github.com/AllSecureX-Quantum/quantumvault-go/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://pkg.go.dev/github.com/AllSecureX-Quantum/quantumvault-go"><img src="https://pkg.go.dev/badge/github.com/AllSecureX-Quantum/quantumvault-go.svg" alt="Go Reference"></a>
</p>

---

**Post-quantum cryptography for Go applications - FIPS 203/204/205 compliant.**

This package provides quantum-safe cryptographic primitives for Go, implementing NIST-standardized post-quantum algorithms:
- **ML-KEM** (Kyber) for key encapsulation (FIPS 203)
- **ML-DSA** (Dilithium) for digital signatures (FIPS 204)
- **SLH-DSA** (SPHINCS+) for hash-based signatures (FIPS 205)

## Installation

```bash
go get github.com/AllSecureX-Quantum/quantumvault-go
```

## Quick Start

```go
package main

import (
    "fmt"
    qv "github.com/AllSecureX-Quantum/quantumvault-go"
)

func main() {
    // Generate ML-KEM key pair (recommended: MLKEM768)
    pub, priv, err := qv.GenerateMLKEMKeyPair(qv.MLKEM768)
    if err != nil {
        panic(err)
    }

    // Encapsulate - generates ciphertext and shared secret
    ciphertext, sharedSecret1, err := qv.Encapsulate(pub)
    if err != nil {
        panic(err)
    }

    // Decapsulate - recovers the same shared secret
    sharedSecret2, err := qv.Decapsulate(priv, ciphertext)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Shared secrets match: %v\n", string(sharedSecret1) == string(sharedSecret2))
}
```

## ML-KEM (Key Encapsulation)

```go
// Security levels
qv.MLKEM512  // NIST Level 1 - fastest
qv.MLKEM768  // NIST Level 3 - recommended
qv.MLKEM1024 // NIST Level 5 - highest security

// Generate key pair
pub, priv, err := qv.GenerateMLKEMKeyPair(qv.MLKEM768)

// Encapsulate (sender)
ciphertext, sharedSecret, err := qv.Encapsulate(pub)

// Decapsulate (receiver)
sharedSecret, err := qv.Decapsulate(priv, ciphertext)
```

## ML-DSA (Digital Signatures)

```go
// Security levels
qv.MLDSA44 // NIST Level 2 - fastest
qv.MLDSA65 // NIST Level 3 - recommended
qv.MLDSA87 // NIST Level 5 - highest security

// Generate key pair
pub, priv, err := qv.GenerateMLDSAKeyPair(qv.MLDSA65)

// Sign message
message := []byte("Hello, Quantum World!")
signature, err := qv.Sign(priv, message)

// Verify signature
valid, err := qv.Verify(pub, message, signature)
```

## Configuration

```go
// Configure QuantumVault API (optional - for analytics)
qv.Configure(qv.Config{
    APIEndpoint: "https://api.quantumvault.io",
    APIKey:      os.Getenv("QUANTUMVAULT_API_KEY"),
    HybridMode:  true,
})
```

## Algorithm Comparison

| Algorithm | Type | Security Level | Key Size | Signature/Ciphertext |
|-----------|------|----------------|----------|---------------------|
| ML-KEM-512 | KEM | Level 1 | 800 B | 768 B |
| ML-KEM-768 | KEM | Level 3 | 1184 B | 1088 B |
| ML-KEM-1024 | KEM | Level 5 | 1568 B | 1568 B |
| ML-DSA-44 | Sign | Level 2 | 1312 B | 2420 B |
| ML-DSA-65 | Sign | Level 3 | 1952 B | 3309 B |
| ML-DSA-87 | Sign | Level 5 | 2592 B | 4627 B |

## crypto.Signer Interface

ML-DSA private keys implement the `crypto.Signer` interface:

```go
priv, _ := qv.GenerateMLDSAKeyPair(qv.MLDSA65)

// Use with crypto.Signer interface
var signer crypto.Signer = priv
signature, err := signer.Sign(rand.Reader, digest, nil)
```

## Requirements

- Go 1.21 or later

## License

Apache License 2.0

## Support

- Documentation: https://docs.quantumvault.io
- Issues: https://github.com/AllSecureX-Quantum/quantumvault-go/issues
- Email: support@allsecurex.com

## About AllSecureX

AllSecureX provides enterprise-grade post-quantum cryptography solutions. QuantumVault is our flagship product for NIST-standardized quantum-resistant algorithms (FIPS 203, 204, 205).

- Website: https://allsecurex.com
- GitHub: https://github.com/AllSecureX-Quantum
