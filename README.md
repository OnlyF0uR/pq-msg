# pq-msg

[![Crates.io](https://img.shields.io/crates/v/pq-msg.svg)](https://crates.io/crates/pq-msg)
[![Documentation](https://docs.rs/pq-msg/badge.svg)](https://docs.rs/pq-msg)
[![License](https://img.shields.io/crates/l/pq-msg.svg)](LICENSE)

## 🔒 Overview

A Rust crate that combines multiple post-quantum cryptographic techniques to facilitate quantum-resistant end-to-end encrypted messaging. `pq-msg` serves as an abstraction layer over various cryptographic schemes to provide a comprehensive solution for secure communication in a post-quantum world.

## 🛠️ Cryptographic Foundation

| Component | Implementation | Purpose |
|-----------|---------------|---------|
| **Key Exchange** | ML-KEM (FIPS 203) | Quantum-resistant key establishment |
| **Symmetric Encryption** | XChaCha20Poly1305 | Fast and secure data encryption |
| **Message Authentication** | Falcon (FN-DSA, FIPS 206) | Quantum-resistant digital signatures |

## ⚙️ Usage

```rust
// Basic usage example coming soon
```

## ⚠️ Important Notice

**This library is currently in development and should be considered experimental.**

Some of the cryptographic packages used have not been independently audited, and certain components are awaiting final standardization by NIST. Please refrain from using this in production environments and consider it for educational and research purposes until further notice.

## 📚 Documentation

For full documentation and examples, please visit [docs.rs/pq-msg](https://docs.rs/pq-msg).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the [MIT/Apache-2.0 dual license](LICENSE).