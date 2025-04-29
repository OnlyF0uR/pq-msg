# pq-msg

This crate combines multiple post-quantum cryptographic techniques in order to facilitate E2EE messaging that is quantum-resistant. It serves as an abstraction on top of the underlying functionality of these different cryptographic schemes aimed at providing all that is neccessary for safe and optimal exchange of encrypted communications.

### Contents
The following schemes are used:
 - ML-KEM (FIPS 203): for key exchange
 - XChaCha20Poly1305: for symmetric encryption
 - Falcon (FN-DSA when standardised, FIPS 206): for message authenticity

### Attention
Some of the used packages have not been audited independently, nor have been appropriately standardised by NIST. Please refrain from using this in any production-ready application and consider this for educational purposes for the time being.