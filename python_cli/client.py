import os
import bitproto
import socket
import gowno
from binascii import hexlify
import x25519
import json
from Cryptodome.Cipher import AES


HOST =  "127.0.0.1"
PORT = 8070

private_key = b'a' * 32

public_key = x25519.scalar_base_mult(private_key)
print(f"client pubKey {hexlify(public_key)}")

priv = b'1' * 32

sec = x25519.scalar_mult(public_key, priv)


p = gowno.PublicKeyExchange(pub_key=public_key)
pk_exchange = p.encode()

p = gowno.Msg(msg=gowno.PUBLIC_KEY_ECHANGE)

key_exchange = p.encode()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        data = s.recv(1024)
        if not data:
            break
        decoded_data = gowno.Msg()
        decoded_data.decode(data)


        if decoded_data.msg == 0:
            s.sendall(pk_exchange)
        data = s.recv(1024)
        if not data:
            break
        decoded_data = gowno.PublicKeyExchange()
        decoded_data.decode(data)
        
        public_ex = json.loads(decoded_data.to_json())
        public_ex = bytes(public_ex.get("pub_key"))
        print(f"srv pubKey {hexlify(public_ex)}")
        
        shared_secret = x25519.scalar_mult(private_key, public_ex)
        iv = b'\x00\x01\x02\x03\x04\x05\x06\07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
        cipher = AES.new(shared_secret, AES.MODE_CBC, iv=iv)
        data = s.recv(16)
        if not data:
            break
        plaintext = cipher.decrypt(data)
        print(f"secret {hexlify(shared_secret)}")
        print(f"data {hexlify(plaintext)}")
        

