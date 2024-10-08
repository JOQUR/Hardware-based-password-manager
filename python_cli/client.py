import os
import bitproto
from socket import socket, AF_INET, SOCK_STREAM
import messaging_bp
import json
import random
from python_crypto_wrapper import CryptoPython
from messanger import Messanger, ChannelStatus
HOST =  "127.0.0.1"
PORT = 8070


class Client:
    def __init__(self) -> None:
        self.crypto_context = CryptoPython()
        self.__messanger = Messanger()
        with socket(AF_INET, SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # Init Comm
            hello_msg = self.__messanger.hello_msg(self.crypto_context.client_public_key)
            assert self.__messanger.channel_status == ChannelStatus.ESTABLISHING
            s.send(hello_msg)

            # Init Comm Rsp
            rcv = s.recv(1024)
            self.handle_init(rcv)

            # Challange
            # challange_buffer = CryptoPython.generate_random_buffer(16)
            # challange_msg = self.__messanger.challange_msg(challange_buffer)
            s.send(self.send_challange_msg())

            # Challange Rsp
            rcv = s.recv(1024)
            self.process_challange(rcv)

            self.send_and_process_fin_hs(s=s)

    def handle_init(self, rcv_bytes):
        assert rcv_bytes is not None
        received = messaging_bp.Responses()
        received.decode(rcv_bytes)
        self.crypto_context.set_iv(bytes(received.init_comm.initialization_vector))
        print(received.to_json())

    def send_challange_msg(self):
        challange = [random.randint(0, 64) for _ in range(0, 16)]
        print(f"Challange: {challange}")
        encode_challange = messaging_bp.Challange(challange)
        msg_struct = messaging_bp.Messages(id=messaging_bp.CHALLANGE, challange=encode_challange)
        return msg_struct.encode()

    def process_challange(self, rcv_bytes):
        assert rcv_bytes is not None
        received = messaging_bp.Responses()
        received.decode(rcv_bytes)
        print(f"decoded challange: {received.to_json()}")

    def send_and_process_fin_hs(self, s: socket):
        fin_handshake = messaging_bp.HandshakeFinished(True)
        msg_struct = messaging_bp.Messages(id=messaging_bp.HANDSHAKE_FINISHED, handshake_finished=fin_handshake)
        msg_buff = msg_struct.encode()
        s.send(msg_buff)
        rcv = s.recv(1024)
        assert rcv is not None
        received = messaging_bp.Responses()
        received.decode(rcv)
        print(received.to_json())
        assert received.handshake_finished.ack == True




if __name__ == "__main__":
    Client()