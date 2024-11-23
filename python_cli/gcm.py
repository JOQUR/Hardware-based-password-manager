from Crypto.Cipher import AES
from ICrypto import ICrypto
from Crypto.Util.Padding import unpad, pad


class GCM(ICrypto):
    def __init__(self):
        super().__init__()

    @property
    def clPublicKey(self):
        return self.cl_public_key
    
    def encrypt(self, data, tag=None, aad=None):
        cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=self.iv)
        cipher.update(aad)
        cipher, calc_tag = cipher.encrypt_and_digest(data)
        return cipher, calc_tag
    
    def decrypt(self, data, tag=None, aad=None):
        cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=self.iv)
        if aad is not None:
            cipher.update(aad)
        return cipher.decrypt_and_verify(data, tag)