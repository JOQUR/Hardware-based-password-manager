from Handshake import Handshake
from Application import Application
from User import User
from messaging_bp import *
from AesCBCCrypto import AesCBCCrypto
from State import *


class Client:
    def __init__(self, login, password):
        self.__user = User(login, password)
        self.__state = State.HELLO
        self.__crypto = AesCBCCrypto()
        self.__stage = Handshake(self.__crypto)

    @property
    def stage(self):
        """
        Returns the current stage of the client.

        :return: The current stage.
        :rtype: str
        """
        return self.__stage
    
    @stage.setter
    def stage(self, value):
        """
        Sets the stage value.

        Args:
            value: The value to set for the stage.
        """
        self.__stage = value
    
    @property
    def crypto(self):
        """
        Returns the cryptographic module instance used by the client.

        Returns:
            CryptoModule: The cryptographic module instance.
        """
        return self.__crypto

if __name__ == "__main__":
    client = Client("admin", "admin")
    print("Client created successfully.")
    print("User logged in successfully.")
    print("Handshake stage created successfully.")
    print("Application stage")