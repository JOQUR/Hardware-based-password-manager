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
        self.__iv = None
        self.__tag = None

    @property
    def tag(self):
        return self.__tag
    
    @tag.setter
    def tag(self, value):
        self.__tag = value

    @property
    def iv(self):
        return self.__iv
    
    @iv.setter
    def iv(self, value):
        self.__iv = value

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
    def encrypt(self, data, tag=None, aad=None):
        """
        Encrypts the given data.

        Args:
            data (bytes): The data to be encrypted.
            tag (bytes, optional): The tag to be used for encryption. Defaults to None.
            aad (bytes, optional): Additional authenticated data. Defaults to None.

        Returns:
            bytes: The encrypted data.
        """
        pass

    @abstractmethod
    def decrypt(self, data, tag=None, aad=None):
        """
        Decrypts the provided data.

        Args:
            data (bytes): The encrypted data to be decrypted.
            tag (bytes, optional): The authentication tag used for verifying the integrity of the data. Default is None.
            aad (bytes, optional): Additional authenticated data that was used during encryption. Default is None.

        Returns:
            bytes: The decrypted data.

        Raises:
            ValueError: If the decryption fails due to invalid data or tag.
        """
        pass