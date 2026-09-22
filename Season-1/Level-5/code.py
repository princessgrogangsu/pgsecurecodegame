import binascii
import hashlib
import os
import secrets

class Random_generator:
    def __init__(self):
        pass

    def generate_token(self, length=8):
        return secrets.token_hex(length)

    def generate_salt(self, length=16):
        return secrets.token_hex(length)

class SHA256_hasher:
    def __init__(self):
        pass

    def password_hash(self, password, salt):
        password_bytes = password.encode('utf-8')
        salt_bytes = salt.encode('utf-8')
        return salt + hashlib.sha256(salt_bytes + password_bytes).hexdigest()

    def password_verification(self, password, password_hash):
        # Extract the 32-char hex salt (16 bytes = 32 hex chars) from the front
        salt = password_hash[:32]
        expected_hash = self.password_hash(password, salt)
        return secrets.compare_digest(expected_hash, password_hash)

class MD5_hasher:
    def __init__(self):
        pass

    def password_hash(self, password):
        return hashlib.md5(password.encode('utf-8')).hexdigest()

    def password_verification(self, password, password_hash):
        return secrets.compare_digest(self.password_hash(password), password_hash)
