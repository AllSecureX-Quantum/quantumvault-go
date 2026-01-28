module github.com/AllSecureX-Quantum/quantumvault-go

go 1.21

require (
	golang.org/x/crypto v0.18.0
)

// QuantumVault Go SDK - Post-Quantum Cryptography
// https://github.com/AllSecureX-Quantum/quantumvault-go
//
// Implements FIPS 203/204/205 compliant algorithms:
// - ML-KEM (Kyber) for key encapsulation
// - ML-DSA (Dilithium) for digital signatures
// - SLH-DSA (SPHINCS+) for hash-based signatures
