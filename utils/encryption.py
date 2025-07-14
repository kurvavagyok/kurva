# JADE Ultimate - Encryption Utilities
# Comprehensive encryption and decryption utilities

import os
import base64
import hashlib
import secrets
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
import structlog

from config import Config

logger = structlog.get_logger()

class EncryptionService:
    """
    Comprehensive encryption service for JADE Ultimate
    """
    
    def __init__(self):
        self.encryption_key = Config.ENCRYPTION_KEY.encode()
        self.jwt_secret = Config.JWT_SECRET_KEY
        self.fernet = Fernet(self._derive_key(self.encryption_key))
    
    def _derive_key(self, password: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        """
        salt = b'jade_ultimate_salt'  # In production, use random salt per encryption
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def encrypt_data(self, data: str) -> str:
        """
        Encrypt sensitive data using Fernet symmetric encryption
        """
        try:
            if not data:
                return ""
            
            encrypted_data = self.fernet.encrypt(data.encode())
            return base64.urlsafe_b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error("Data encryption failed", error=str(e))
            raise
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """
        Decrypt data using Fernet symmetric encryption
        """
        try:
            if not encrypted_data:
                return ""
            
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception as e:
            logger.error("Data decryption failed", error=str(e))
            raise
    
    def encrypt_json(self, data: Dict[str, Any]) -> str:
        """
        Encrypt JSON data
        """
        try:
            import json
            json_str = json.dumps(data)
            return self.encrypt_data(json_str)
        except Exception as e:
            logger.error("JSON encryption failed", error=str(e))
            raise
    
    def decrypt_json(self, encrypted_json: str) -> Dict[str, Any]:
        """
        Decrypt JSON data
        """
        try:
            import json
            decrypted_str = self.decrypt_data(encrypted_json)
            return json.loads(decrypted_str)
        except Exception as e:
            logger.error("JSON decryption failed", error=str(e))
            raise
    
    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt
        """
        try:
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        except Exception as e:
            logger.error("Password hashing failed", error=str(e))
            raise
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Verify password against hash
        """
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            logger.error("Password verification failed", error=str(e))
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure random token
        """
        try:
            return secrets.token_urlsafe(length)
        except Exception as e:
            logger.error("Token generation failed", error=str(e))
            raise
    
    def generate_api_key(self, user_id: int, permissions: list = None) -> str:
        """
        Generate API key for user
        """
        try:
            payload = {
                'user_id': user_id,
                'permissions': permissions or [],
                'type': 'api_key',
                'created_at': datetime.now(timezone.utc).isoformat(),
                'expires_at': (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
            }
            
            api_key = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
            return api_key
        except Exception as e:
            logger.error("API key generation failed", error=str(e))
            raise
    
    def verify_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode API key
        """
        try:
            payload = jwt.decode(api_key, self.jwt_secret, algorithms=['HS256'])
            
            # Check if token is expired
            expires_at = datetime.fromisoformat(payload.get('expires_at', ''))
            if expires_at < datetime.now(timezone.utc):
                return None
            
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("API key expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid API key")
            return None
        except Exception as e:
            logger.error("API key verification failed", error=str(e))
            return None
    
    def create_jwt_token(self, user_id: int, user_data: Dict[str, Any], expires_in: int = 3600) -> str:
        """
        Create JWT token for user authentication
        """
        try:
            payload = {
                'user_id': user_id,
                'user_data': user_data,
                'type': 'access_token',
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(seconds=expires_in)
            }
            
            token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
            return token
        except Exception as e:
            logger.error("JWT token creation failed", error=str(e))
            raise
    
    def verify_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid JWT token")
            return None
        except Exception as e:
            logger.error("JWT token verification failed", error=str(e))
            return None
    
    def create_refresh_token(self, user_id: int) -> str:
        """
        Create refresh token for user
        """
        try:
            payload = {
                'user_id': user_id,
                'type': 'refresh_token',
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(days=7)
            }
            
            token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')
            return token
        except Exception as e:
            logger.error("Refresh token creation failed", error=str(e))
            raise
    
    def encrypt_file(self, file_path: str, output_path: str) -> bool:
        """
        Encrypt file using AES encryption
        """
        try:
            # Generate random key and IV
            key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(16)   # 128-bit IV
            
            # Create cipher
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Read and encrypt file
            with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write IV at the beginning of the file
                outfile.write(iv)
                
                while True:
                    chunk = infile.read(8192)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        # Pad the chunk to 16 bytes
                        chunk += b' ' * (16 - len(chunk) % 16)
                    
                    outfile.write(encryptor.update(chunk))
                
                outfile.write(encryptor.finalize())
            
            # Store key securely (encrypted with master key)
            encrypted_key = self.encrypt_data(base64.b64encode(key).decode())
            
            # Save encrypted key to a separate file
            key_file = f"{output_path}.key"
            with open(key_file, 'w') as f:
                f.write(encrypted_key)
            
            return True
        except Exception as e:
            logger.error("File encryption failed", file_path=file_path, error=str(e))
            return False
    
    def decrypt_file(self, encrypted_file_path: str, key_file_path: str, output_path: str) -> bool:
        """
        Decrypt file using AES decryption
        """
        try:
            # Read and decrypt the key
            with open(key_file_path, 'r') as f:
                encrypted_key = f.read()
            
            decrypted_key = self.decrypt_data(encrypted_key)
            key = base64.b64decode(decrypted_key)
            
            # Read encrypted file
            with open(encrypted_file_path, 'rb') as infile:
                iv = infile.read(16)  # Read IV from beginning
                
                # Create cipher
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                
                # Decrypt file
                with open(output_path, 'wb') as outfile:
                    while True:
                        chunk = infile.read(8192)
                        if len(chunk) == 0:
                            break
                        outfile.write(decryptor.update(chunk))
                    
                    outfile.write(decryptor.finalize())
            
            return True
        except Exception as e:
            logger.error("File decryption failed", file_path=encrypted_file_path, error=str(e))
            return False
    
    def calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of file
        """
        try:
            if algorithm == 'sha256':
                hash_algo = hashlib.sha256()
            elif algorithm == 'md5':
                hash_algo = hashlib.md5()
            elif algorithm == 'sha1':
                hash_algo = hashlib.sha1()
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    hash_algo.update(chunk)
            
            return hash_algo.hexdigest()
        except Exception as e:
            logger.error("File hash calculation failed", file_path=file_path, error=str(e))
            raise
    
    def generate_certificate_fingerprint(self, cert_data: bytes) -> str:
        """
        Generate certificate fingerprint
        """
        try:
            sha256_hash = hashlib.sha256(cert_data).hexdigest()
            # Format as colon-separated groups
            return ':'.join(sha256_hash[i:i+2] for i in range(0, len(sha256_hash), 2))
        except Exception as e:
            logger.error("Certificate fingerprint generation failed", error=str(e))
            raise
    
    def secure_compare(self, a: str, b: str) -> bool:
        """
        Secure string comparison to prevent timing attacks
        """
        try:
            return secrets.compare_digest(a.encode(), b.encode())
        except Exception as e:
            logger.error("Secure comparison failed", error=str(e))
            return False
    
    def generate_otp(self, secret: str, counter: int = None) -> str:
        """
        Generate One-Time Password (OTP)
        """
        try:
            import pyotp
            
            if counter is not None:
                # HOTP (Counter-based)
                hotp = pyotp.HOTP(secret)
                return hotp.at(counter)
            else:
                # TOTP (Time-based)
                totp = pyotp.TOTP(secret)
                return totp.now()
        except Exception as e:
            logger.error("OTP generation failed", error=str(e))
            raise
    
    def verify_otp(self, secret: str, token: str, counter: int = None) -> bool:
        """
        Verify One-Time Password (OTP)
        """
        try:
            import pyotp
            
            if counter is not None:
                # HOTP verification
                hotp = pyotp.HOTP(secret)
                return hotp.verify(token, counter)
            else:
                # TOTP verification
                totp = pyotp.TOTP(secret)
                return totp.verify(token)
        except Exception as e:
            logger.error("OTP verification failed", error=str(e))
            return False
    
    def generate_2fa_secret(self) -> str:
        """
        Generate 2FA secret for user
        """
        try:
            import pyotp
            return pyotp.random_base32()
        except Exception as e:
            logger.error("2FA secret generation failed", error=str(e))
            raise
    
    def generate_qr_code_url(self, secret: str, user_email: str, issuer_name: str = "JADE Ultimate") -> str:
        """
        Generate QR code URL for 2FA setup
        """
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.provisioning_uri(
                name=user_email,
                issuer_name=issuer_name
            )
        except Exception as e:
            logger.error("QR code URL generation failed", error=str(e))
            raise

# Global encryption service instance
encryption_service = EncryptionService()

# Convenience functions
def encrypt_data(data: str) -> str:
    """Encrypt data using the global encryption service"""
    return encryption_service.encrypt_data(data)

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data using the global encryption service"""
    return encryption_service.decrypt_data(encrypted_data)

def hash_password(password: str) -> str:
    """Hash password using the global encryption service"""
    return encryption_service.hash_password(password)

def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password using the global encryption service"""
    return encryption_service.verify_password(password, hashed_password)

def generate_secure_token(length: int = 32) -> str:
    """Generate secure token using the global encryption service"""
    return encryption_service.generate_secure_token(length)

def create_jwt_token(user_id: int, user_data: Dict[str, Any], expires_in: int = 3600) -> str:
    """Create JWT token using the global encryption service"""
    return encryption_service.create_jwt_token(user_id, user_data, expires_in)

def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify JWT token using the global encryption service"""
    return encryption_service.verify_jwt_token(token)
