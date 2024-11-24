from IStage import IStage
from ICrypto import ICrypto
from gcm import GCM
from messaging_bp import *
from binascii import hexlify


class Application(IStage):
    def __init__(self, crypto: ICrypto):
        """
        Initializes the Application object with the given crypto instance.

        Args:
            crypto (ICrypto): An instance of a class that implements the ICrypto interface.
        """
        super().__init__(crypto)

    def prepareGenerate(self) -> bytearray:
        """
        Prepares and generates a password.
        This method creates an instance of the `Generate` class with a `True` parameter,
        then uses it to create an `App` instance with the `node_id` set to the `Generate` class
        and the `generate` parameter set to the `Generate` instance. Finally, it encodes
        the `App` instance and returns the resulting bytearray.
        Returns:
            bytearray: The encoded `App` instance.
        """
        
        generatePass = Generate(True)
        return App(node_id=GENERATE, generate=generatePass).encode()
    
    def processGenerate(self, message: bytearray):
        """
        Processes the generate response message.

        This method decodes the given message, verifies the node ID and acknowledgment,
        decrypts the generated password, and prints the decrypted password.

        Args:
            message (bytearray): The response message to process.

        Raises:
            AssertionError: If the node ID is not GENERATE or if the acknowledgment is not False.
        """
        rsp = AppRsp()
        rsp.decode(message)
        assert rsp.node_id == GENERATE, "Node ID is not GENERATE_RSP."
        assert rsp.new_entry.ack == False, "Ack is not False."
        decrypted = self.crypto.decrypt(bytes(rsp.generate.generated_password), bytes(rsp.generate.initialization_vector), bytes(rsp.generate.tag))
        print("Decrypted password: ", hexlify(decrypted))
