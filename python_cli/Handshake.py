from IStage import IStage
from AesCBCCrypto import AesCBCCrypto
import ICrypto
from messaging_bp import *
from State import State

class ChallangeFailedException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class HandshakeFailedException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class Handshake(IStage):
    def __init__(self, crypto: ICrypto):
        """
        Initializes the Handshake object with the given crypto instance.

        Args:
            crypto (ICrypto): An instance of a class that implements the ICrypto interface.
        """
        super().__init__(crypto)
        self.__state = State.HELLO

    @property
    def state(self):
        return self.__state
    
    def prepareHello(self):
        """
        Prepares a hello message for initializing communication.

        This method creates an `InitializeComm` object using the public key from the 
        `crypto` attribute, then wraps it in a `Messages` object with the 
        `INITIALIZE_COMM` identifier. The resulting message is encoded and returned.

        Returns:
            str: The encoded initialization message.
        """
        init_comm = InitializeComm(self.crypto.clPublicKey)
        message = Messages(id=INITIALIZE_COMM, init_comm=init_comm)
        return message.encode()      
    
    def prepareChallange(self):
        """
        Prepares a challenge message for the handshake process.

        This method generates a random 32-byte challenge message using the ICrypto library.
        It then creates a Challange object with the generated challenge message and
        wraps it in a Messages object with the CHALLANGE identifier. The encoded message
        is then returned.

        Returns:
            bytes: The encoded challenge message.
        """
        self.challange_message = ICrypto.get_random_bytes(32)
        challenge = Challange(challange_buffer=self.challange_message)
        message = Messages(id=CHALLANGE, challange=challenge)
        return message.encode()
    
    def prepareHandshakeFinish(self):
        """
        Prepares and encodes a handshake finish message.

        This method creates a `Messages` object with the `HANDSHAKE_FINISHED` id and a 
        `HandshakeFinished` object indicating acknowledgment. It then encodes the message 
        and returns the encoded result.

        Returns:
            bytes: The encoded handshake finish message.
        """
        msg = Messages(id=HANDSHAKE_FINISHED, handshake_finished=HandshakeFinished(ack=True))
        return msg.encode()
    
    def prepareStartApp(self):
        """
        Prepares the application to start by setting the internal state to APP_START
        and returning an encoded message indicating the start of the application.

        Returns:
            bytes: An encoded message indicating the application start.
        """
        self.__state = State.APP_START
        return Messages(id=START_APP, start_app=True).encode()

    def processMessage(self, bytes_rcv: bytearray):
        """
        Processes the received message and updates the state of the handshake process.

        Args:
            bytes_rcv (bytearray): The received message in bytes.

        Raises:
            ChallangeFailedException: If the challenge response does not match the expected challenge message.
            HandshakeFailedException: If the handshake acknowledgment is not received.

        The function decodes the received message and performs actions based on the message ID:
        - INITIALIZE_COMM: Sets the shared key and initialization vector for the cryptographic operations.
        - CHALLANGE: Decrypts the challenge buffer and verifies the response against the expected challenge message.
        - HANDSHAKE_FINISHED: Checks the acknowledgment and updates the state to authenticated if successful.
        """
        assert bytes_rcv is not None
        message_rsp = Responses()
        message_rsp.decode(bytes_rcv)
        if message_rsp.id == INITIALIZE_COMM:
            init_comm_rsp = message_rsp.init_comm
            self.crypto.setSharedKey(bytes(init_comm_rsp.public_key))
            self.crypto.iv = bytes(init_comm_rsp.initialization_vector)
        elif message_rsp.id == CHALLANGE:
            challenge_rsp = message_rsp.challange
            response = self.crypto.decrypt(challenge_rsp.challange_buffer)
            if response == self.challange_message:
                self.__state = State.CHALLANGE
            else:
                raise ChallangeFailedException("Challange failed!")
        elif message_rsp.id == HANDSHAKE_FINISHED:
            handshake_finished_rsp = message_rsp.handshake_finished
            if handshake_finished_rsp.ack:
                self.__state = State.AUTHENTICATED
            else:
                raise HandshakeFailedException("Handshake failed!")
            

