from Crypto.Cipher import AES
from ICrypto import ICrypto
from Crypto.Util.Padding import unpad, pad


class AesCBCCrypto(ICrypto):
    def __init__(self):
        super().__init__()

    @property
    def clPublicKey(self):
        return self.cl_public_key
    
    def encrypt(self, data):
        """
        Encrypts the given data using AES in CBC mode.

        Args:
            data (str): The data to be encrypted.

        Returns:
            bytes: The encrypted data.
        """
        cipher = AES.new(self.shared_key, AES.MODE_CBC, self.iv)
        padded_data = pad(data.encode(), AES.block_size)
        return cipher.encrypt(padded_data)
    
    def decrypt(self, encrypted_data):
        """
        Decrypts the provided data using AES in CBC mode.

        Args:
            encrypted_data (bytes): The encrypted data to be decrypted.

        Returns:
            str: The decrypted data.
        """
        cipher = AES.new(self.shared_key, AES.MODE_CBC, self.iv)
        decrypted_data = cipher.decrypt(bytes(encrypted_data))
        return decrypted_data