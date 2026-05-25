# AegisCrypt Engine - Professional Enterprise File Security Tool

AegisCrypt Engine is a high-security, professional desktop workstation utility for encrypting and decrypting sensitive local records securely using modern python paradigms.

## Security Controls Specifications Matrix

* **Encryption Core Primitive Architecture:** AES-256-GCM (Authenticated Encryption with Associated Data).
* **Key Derivation Model Architecture:** PBKDF2-HMAC-SHA256 accompanied with 600,000 computation passes loops and salted configurations.
* **Integrity Validation Layer:** GCM Tag Authentication Mode built-in to catch corruption or malicious alterations directly before decoding file blocks.
* **Brute-Force Throttling Mitigation Matrix:** Automatically throttles interaction attempts linearly when authorization challenges hit consecutive threshold limits.
* **Storage Disposal (Shredding):** Includes choices allowing users to write pseudorandom block segments over their data prior to removing original system registry tracking nodes.

## Setup Requirements and Installation Steps

1. Install system requirements securely using your package management solutions toolchain:
   ```bash
   pip install -r requirements.txt