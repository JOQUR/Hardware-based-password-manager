from IStage import IStage
from ICrypto import ICrypto
from gcm import GCM
from messaging_bp import *
from binascii import *
from json_reader import JSONReader
import json

class Application(IStage):
    def __init__(self, crypto: ICrypto):
        """
        Initializes the Application object with the given crypto instance.

        Args:
            crypto (ICrypto): An instance of a class that implements the ICrypto interface.
        """
        super().__init__(crypto)

    def processMessage(self, rcv: bytearray):
        """
        Processes the received message and runs the correct node.

        This method decodes the given message and runs the correct node
        based on the node ID.

        Args:
            rcv (bytearray): The received message to process.
        """
        app = AppRsp()
        app.decode(rcv)
        if app.node_id == GENERATE:
            self.processGenerate(rcv)
        elif app.node_id == ADD_ENTRY:
            self.processAddEntry(rcv)
        elif app.node_id == DEL_ENTRY:
            self.processDeleteEntry(rcv)
        else:
            print("Unknown node ID.")

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
        decrypted = self.crypto.decrypt(bytes(rsp.generate.generated_password), bytes(rsp.generate.initialization_vector), bytes(rsp.generate.tag))
        print("Decrypted password: ", hexlify(decrypted))

    def prepareAddEntry(self, info: bytes, password: bytes) -> bytearray:
        """
        Prepares and adds a new entry with the provided information and password.
        Args:
            info (bytes): The information to be added.
            password (bytes): The password to be encrypted and added.
        Returns:
            bytearray: The encoded application data containing the new entry.
        Raises:
            JSONDecodeError: If there is an error reading the JSON configuration.
            EncryptionError: If there is an error during the encryption process.
        """
        newEntry = AddEntry()
        for i in range(len(info)):
            newEntry.info[i] = info[i]
        kek = JSONReader.read_json()["users"][0]["kek"]
        
        kek = bytearray.fromhex(kek)
        for i in range(len(kek)):
            newEntry.kek[i] = kek[i]
        iv = ICrypto.getRandomByteArray(12)
        wrapped_password, tag_pass = self.crypto.encrypt(password, iv)
        kek, tag_kek = self.crypto.encrypt(kek, iv)

        for i in range(len(wrapped_password)):
            newEntry.wrapped_password[i] = wrapped_password[i]

        for i in range(len(tag_pass)):
            newEntry.tag_pass[i] = tag_pass[i]

        for i in range(len(kek)):
            newEntry.kek[i] = kek[i]

        for i in range(len(tag_kek)):
            newEntry.tag_kek[i] = tag_kek[i]

        for i in range(len(iv)):
            newEntry.initialization_vector[i] = iv[i]

        newEntry.password_length = len(password)
        app = App(node_id=ADD_ENTRY, new_entry=newEntry)
        print(app.to_json())
        return app.encode()
    
    def processAddEntry(self, message: bytearray):
        """
        Processes the add entry response message.

        This method decodes the given message, verifies the node ID and acknowledgment,
        and prints the acknowledgment.

        Args:
            message (bytearray): The response message to process.

        Raises:
            AssertionError: If the node ID is not ADD_ENTRY or if the acknowledgment is not True.
        """
        rsp = AppRsp()
        rsp.decode(message)
        assert rsp.node_id == ADD_ENTRY, "Node ID is not ADD_ENTRY_RSP."
        print(f"Entry added successfully with index: {rsp.new_entry.index}.")
        self.__append_to_json(rsp.new_entry.info, rsp.new_entry.index)

    def prepareDeleteEntry(self, index: int) -> bytearray:
        """
        Prepares and deletes an entry with the provided index.
        Args:
            index (int): The index of the entry to delete.
        Returns:
            bytearray: The encoded application data containing the entry to delete.
        """
        deleteEntry = DelEntry(index=index)
        return App(node_id=DEL_ENTRY, del_entry=deleteEntry).encode()
    
    def processDeleteEntry(self, message: bytearray):
        """
        Processes the delete entry response message.

        This method decodes the given message, verifies the node ID and acknowledgment,
        and prints the acknowledgment.

        Args:
            message (bytearray): The response message to process.

        Raises:
            AssertionError: If the node ID is not DEL_ENTRY or if the acknowledgment is not True.
        """
        rsp = AppRsp()
        rsp.decode(message)
        assert rsp.node_id == DEL_ENTRY, "Node ID is not DEL_ENTRY_RSP."
        print(f"Entry deleted successfully!")
        

    def __append_to_json(self, info: bytes, index: int):
        """
        Appends the given information to the JSON data structure and writes it back to the file.

        Args:
            info (bytes): The information to append, in bytes format.
            index (int): The index associated with the information.

        Raises:
            FileNotFoundError: If the JSON file to read or write does not exist.
            JSONDecodeError: If the JSON file contains invalid JSON.
        """
        data = JSONReader.read_json()
        str_info = "".join("{:02x}".format(x) for x in info)
        str_info = bytearray.fromhex(str_info).decode()
        for user in data['users']:
            user['passwords']['list'].append({"info": str_info, "index": index})
        with open("userdata.json", "w") as file:
            json.dump(data, file, indent=4)
