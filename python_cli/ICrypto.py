from abc import ABC, abstractmethod
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import x25519
import hashlib

class ICrypto(ABC):
    def __init__(self):
        self.__private_key = get_random_bytes(32)
        self.cl_public_key = x25519.scalar_base_mult(self.__private_key)
        self.shared_key = None
        self.iv = None
    
    @staticmethod
    def getRandomByteArray(length):
        """
        Generates a random byte array of the specified length.

        Args:
            length (int): The length of the byte array to generate.

        Returns:
            bytes: A byte array containing random bytes.
        """
        return get_random_bytes(length)
    
    @staticmethod
    def PBKDF2(data, salt):
        if isinstance(salt, str):
            salt = bytes.fromhex(salt)
        dk = hashlib.pbkdf2_hmac('sha256', data, salt, 100000)
        return "".join("{:02x}".format(x) for x in dk), "".join("{:02x}".format(x) for x in salt)

    def setSharedKey(self, key):
        self.shared_key = x25519.scalar_mult(self.__private_key, key)
        print("Shared key: ", self.shared_key)

    @abstractmethod
    def encrypt(self, data):
        """
        Encrypts the given data.

        Args:
            data (str): The data to be encrypted.

        Returns:
            str: The encrypted data.
        """
        pass

    @abstractmethod
    def decrypt(self, data):
        """
        Decrypts the provided data.

        Args:
            data (bytes): The encrypted data to be decrypted.

        Returns:
            bytes: The decrypted data.
        """
        pass