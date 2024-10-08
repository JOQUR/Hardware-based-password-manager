import bitproto
import messaging_bp
from enum import Enum

class ChannelStatus(Enum):
    TERMINATED = 0,
    ESTABLISHING = 1,
    ESTABLISHED = 2,
    ERROR = 3

class Messanger:
    def __init__(self) -> None:
        self.__message = None
        self.__response = messaging_bp.Responses()
        self.__channel_status = ChannelStatus.TERMINATED

    def process_message(self, rcv_bytes: bytes):
        self.__response.decode(rcv_bytes)
        
        if self.__response._get_id() == messaging_bp.MessageId.INITIALIZE_COMM:
            pass

        return self.__response.encode()

    def hello_msg(self, client_pub_key: bytearray) -> bytearray:
        init_comm = messaging_bp.InitializeComm(list(client_pub_key))
        self.__message = messaging_bp.Messages(id=messaging_bp.INITIALIZE_COMM, init_comm=init_comm)
        self.__channel_status = ChannelStatus.ESTABLISHING
        return self.__message.encode()
    
    def challange_msg(self, challange_buffer: bytearray):
        challange = messaging_bp.Challange(list(challange_buffer))
        self.__message = messaging_bp.Messages(id=messaging_bp.CHALLANGE, challange=challange)
        return self.__message.encode()

    
    @property
    def channel_status(self):
        return self.__channel_status
    
