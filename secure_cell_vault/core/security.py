from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from base64 import b64encode, b64decode
from typing import Optional
import os

class CellEncryption:
    def __init__(self, cell_id: str, master_key: bytes):
        self.cell_id = cell_id
        self.master_key = master_key
        self._init_encryption()

    def _init_encryption(self):
        """Initialize the encryption context for this cell"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.cell_id.encode(),
            iterations=100000,
        )
        self.cell_key = kdf.derive(self.master_key)
        self.aesgcm = AESGCM(self.cell_key)

    def encrypt(self, data: str) -> str:
        """Encrypt data using AES-GCM with a unique nonce"""
        nonce = os.urandom(12)
        data_bytes = data.encode()
        ct = self.aesgcm.encrypt(nonce, data_bytes, None)
        return b64encode(nonce + ct).decode('utf-8')

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data using AES-GCM"""
        decoded = b64decode(encrypted_data.encode('utf-8'))
        nonce = decoded[:12]
        ct = decoded[12:]
        plaintext = self.aesgcm.decrypt(nonce, ct, None)
        return plaintext.decode('utf-8')

class KeyRotation:
    def __init__(self, cell_id: str):
        self.cell_id = cell_id
        self.current_key_version = 1
        self.keys = {}

    def rotate_key(self) -> int:
        """Generate a new key version and store it"""
        self.current_key_version += 1
        self.keys[self.current_key_version] = os.urandom(32)
        return self.current_key_version

    def get_current_key(self) -> bytes:
        """Get the current active key"""
        return self.keys[self.current_key_version]

    def get_key_by_version(self, version: int) -> Optional[bytes]:
        """Get a specific key version"""
        return self.keys.get(version)

class HSMIntegration:
    """Hardware Security Module integration for key management"""
    def __init__(self, provider: str, config: dict):
        self.provider = provider
        self.config = config
        self._init_hsm()

    def _init_hsm(self):
        """Initialize HSM connection based on provider"""
        if self.provider == "aws":
            # AWS KMS integration
            pass
        elif self.provider == "azure":
            # Azure Key Vault integration
            pass
        elif self.provider == "gcp":
            # Google Cloud KMS integration
            pass
        else:
            raise ValueError(f"Unsupported HSM provider: {self.provider}")

    def generate_key(self) -> bytes:
        """Generate a new key in the HSM"""
        raise NotImplementedError()

    def encrypt(self, key_id: str, data: bytes) -> bytes:
        """Encrypt data using a key in the HSM"""
        raise NotImplementedError()

    def decrypt(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using a key in the HSM"""
        raise NotImplementedError()

class MasterKeyManager:
    """Manages the master key used for deriving cell keys"""
    def __init__(self, hsm: Optional[HSMIntegration] = None):
        self.hsm = hsm
        self._master_key = None

    def initialize(self):
        """Initialize or load the master key"""
        if self.hsm:
            self._master_key = self.hsm.generate_key()
        else:
            self._master_key = os.urandom(32)

    @property
    def master_key(self) -> bytes:
        """Get the current master key"""
        if not self._master_key:
            raise RuntimeError("Master key not initialized")
        return self._master_key

class TransitEncryption:
    """Handles encryption of data in transit"""
    def __init__(self, key: bytes):
        self.key = key
        self.fernet = Fernet(key)

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data for transit"""
        return self.fernet.encrypt(data)

    def decrypt(self, token: bytes) -> bytes:
        """Decrypt data from transit"""
        return self.fernet.decrypt(token)