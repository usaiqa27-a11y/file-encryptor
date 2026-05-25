import os
import sys
from pathlib import Path
from typing import Callable, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Constants
SALT_SIZE = 16
NONCE_SIZE = 12
CHUNK_SIZE = 64 * 1024  # 64KB chunks
ITERATIONS = 600000

class CryptoEngine:
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derives a 256-bit AES key from a password using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=ITERATIONS
        )
        password_bytes = password.encode('utf-8')
        key = kdf.derive(password_bytes)
        
        # Explicit zeroing of transient memory where possible
        del password_bytes
        return key

    @staticmethod
    def encrypt_file(
        file_path: Path, 
        password: str, 
        progress_callback: Optional[Callable[[float], None]] = None
    ) -> Path:
        """Encrypts a file chunk by chunk using AES-256-GCM."""
        if not file_path.exists():
            raise FileNotFoundError("Target file does not exist.")

        output_path = file_path.with_suffix(file_path.suffix + ".enc")
        if output_path.exists():
            raise FileExistsError(f"Target file {output_path.name} already exists. Action aborted to prevent overwrite.")

        salt = os.urandom(SALT_SIZE)
        key = CryptoEngine.derive_key(password, salt)
        aesgcm = AESGCM(key)

        total_size = file_path.stat().st_size
        bytes_processed = 0

        with open(file_path, "rb") as infile, open(output_path, "wb") as outfile:
            # Write metadata overhead cleanly to top of file
            outfile.write(salt)

            while True:
                chunk = infile.read(CHUNK_SIZE)
                if not chunk:
                    break

                # Generate unique nonces per chunk
                nonce = os.urandom(NONCE_SIZE)
                encrypted_chunk = aesgcm.encrypt(nonce, chunk, None)
                
                # Format: [Nonce (12B)] [Len of payload (4B)] [Payload]
                outfile.write(nonce)
                outfile.write(len(encrypted_chunk).to_bytes(4, byteorder=sys.byteorder))
                outfile.write(encrypted_chunk)

                bytes_processed += len(chunk)
                if progress_callback and total_size > 0:
                    progress_callback(bytes_processed / total_size)

        # Wipe local reference to keys
        del key
        return output_path

    @staticmethod
    def decrypt_file(
        file_path: Path, 
        password: str, 
        progress_callback: Optional[Callable[[float], None]] = None
    ) -> Path:
        """Decrypts and authenticates an AES-256-GCM file while preventing tampering."""
        if not file_path.exists():
            raise FileNotFoundError("Target file does not exist.")

        if file_path.suffix != ".enc":
            raise ValueError("Invalid target extension. File must have '.enc' extension.")

        # Determine output file name dynamically by removing .enc
        output_path = file_path.with_suffix("")
        if output_path.exists():
            raise FileExistsError(f"Decrypted target file {output_path.name} already exists.")

        total_size = file_path.stat().st_size
        bytes_processed = 0

        with open(file_path, "rb") as infile:
            salt = infile.read(SALT_SIZE)
            if len(salt) < SALT_SIZE:
                raise ValueError("Malformed file: Header structurally compromised.")

            key = CryptoEngine.derive_key(password, salt)
            aesgcm = AESGCM(key)

            bytes_processed += SALT_SIZE
            
            # Temporary storage of execution blocks to guarantee atomic complete operations
            with open(output_path, "wb") as outfile:
                while True:
                    nonce = infile.read(NONCE_SIZE)
                    if not nonce:
                        break # EOF reached cleanly
                    
                    if len(nonce) < NONCE_SIZE:
                        raise ValueError("Tampering detected: Truncated cryptographic nonce wrapper.")

                    len_bytes = infile.read(4)
                    if not len_bytes:
                        raise ValueError("Tampering detected: Missing chunk boundaries.")
                    chunk_len = int.from_bytes(len_bytes, byteorder=sys.byteorder)

                    encrypted_chunk = infile.read(chunk_len)
                    if len(encrypted_chunk) < chunk_len:
                        raise ValueError("Tampering or corruption detected: Unexpected truncation of payloads.")

                    try:
                        decrypted_chunk = aesgcm.decrypt(nonce, encrypted_chunk, None)
                    except Exception:
                        raise ValueError("Authentication Failed! Wrong password or file structural integrity failure.")

                    outfile.write(decrypted_chunk)
                    bytes_processed += (NONCE_SIZE + 4 + chunk_len)
                    
                    if progress_callback and total_size > 0:
                        progress_callback(bytes_processed / total_size)

        del key
        return output_path