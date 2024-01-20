from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from typing import Optional, Union, Tuple
from Utils.logger import Logger


class Encryptor:

    def __init__(self, debug_mode: bool) -> None:
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def generate_bytes_stream(self, size: Optional[int] = 16) -> bytes:
        return get_random_bytes(size)

    def hash_password(self, password: Union[str, bytes]) -> bytes:
        if isinstance(password, str):
            password = password.encode()
        return SHA256.new(password).digest()

    def encrypt_aes_key(self, key: bytes, password_hash: bytes, iv_size: Optional[int] = 16) -> Tuple[bytes, bytes]:
        iv = self.generate_bytes_stream(iv_size)
        cipher = AES.new(key=password_hash, mode=AES.MODE_CBC, iv=iv)
        encrypted_key = cipher.encrypt(key)
        return iv, encrypted_key

