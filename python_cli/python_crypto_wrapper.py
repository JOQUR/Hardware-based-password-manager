from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import x25519
import os



class CryptoPython:
    def __init__(self) -> None:
        self.__client_private_key = get_random_bytes(32)
        self.__client_public_key = self.generate_public_key()
        self.__shared_secret = None
        self.__iv = None
        self.__cipher = None

    # TODO: Make it private member
    def generate_public_key(self) -> bytearray:
        return(
            x25519.scalar_base_mult(self.__client_private_key)
        )
    
    def generate_shared_secret(self, server_public_key: bytearray):
        shared_secret = x25519.scalar_mult(self.__client_private_key, server_public_key)
        self.__shared_secret = shared_secret
    
    @staticmethod
    def generate_random_buffer(len: int):
        return get_random_bytes(len)

    @property
    def client_public_key(self):
        return self.__client_public_key
    
    @property
    def shared_secret(self):
        return self.__shared_secret
    
    def set_iv(self, iv: bytearray):
        self.__iv = iv

    def encrypt_data(self, data):
        pass
    
    def init_aes(self):
        assert self.__iv != "" and self.__shared_secret != ""
        self.__cipher = AES.new(self.__shared_secret, AES.MODE_CBC, iv=self.__iv)