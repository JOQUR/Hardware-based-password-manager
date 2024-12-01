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
        if rcv is None:
            raise ValueError("Received message is None.")
        app = AppRsp()
        app.decode(rcv)
        if app.node_id == GENERATE:
            self.processGenerate(rcv)
        elif app.node_id == ADD_ENTRY:
            self.processAddEntry(rcv)
        elif app.node_id == DEL_ENTRY:
            self.processDeleteEntry(rcv)
        elif app.node_id == MODIFY:
            self.processModifyEntry(rcv)
        elif app.node_id == READ_ENTRY:
            self.processReadEntry(rcv)
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
        self.__delete_element_json(index)
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
        assert rsp.del_entry.ack == True, "Entry deletion failed."
        print(f"Entry deleted successfully!")

    def prepareModifyEntry(self, index: int, info: bytes, password: bytes) -> bytearray:
        """
        Prepares a message to modify an entry in the hardware-based password manager.

        Args:
            index (int): The index of the entry to be modified.
            info (bytes): The new information to be stored in the entry.
            password (bytes): The password associated with the entry.

        Returns:
            bytearray: The encoded message ready to be sent to the hardware.
        """
        mod = Modify(index=index)
        iv = ICrypto.getRandomByteArray(12)
        wrapped_password, tag_pass = self.crypto.encrypt(password, iv)

        for i in range(len(tag_pass)):
            mod.tag_pass[i] = tag_pass[i]

        for i in range(len(info)):
            mod.info[i] = info[i]

        for i in range(len(wrapped_password)):
            mod.new_password[i] = wrapped_password[i]
        
        
        for i in range(len(iv)):
            mod.initialization_vector[i] = iv[i]
        
        mod.password_length = len(password)

        self.__modify_json(index, info)
        msg = App(node_id=MODIFY, modify=mod)
        return msg.encode()

    def processModifyEntry(self, message: bytearray):
        """
        Processes the modify entry response message.

        This method decodes the given message, verifies the node ID and acknowledgment,
        and prints the acknowledgment.

        Args:
            message (bytearray): The response message to process.

        Raises:
            AssertionError: If the node ID is not MODIFY or if the acknowledgment is not True.
        """
        rsp = AppRsp()
        rsp.decode(message)
        assert rsp.modify.ack == True, "Entry modification failed."

    def prepareReadEntry(self, index: int) -> bytearray:
        """
        Prepares a message to read an entry from the hardware-based password manager.

        Args:
            index (int): The index of the entry to be read.

        Returns:
            bytearray: The encoded message ready to be sent to the hardware.
        """
        kek = JSONReader.read_json()["users"][0]["kek"]
        read = ReadEntry(index=index)
        
        kek = bytearray.fromhex(kek)
        for i in range(len(kek)):
            read.kek[i] = kek[i]
        return App(node_id=READ_ENTRY, read=read).encode()
    
    def processReadEntry(self, message: bytearray):
        """
        Processes the read entry response message.

        This method decodes the given message, verifies the node ID and acknowledgment,
        decrypts the password, and prints the decrypted password.

        Args:
            message (bytearray): The response message to process.

        Raises:
            AssertionError: If the node ID is not READ_ENTRY or if the acknowledgment is not True.
        """
        rsp = AppRsp()
        rsp.decode(message)
        assert rsp.node_id == READ_ENTRY, "Node ID is not READ_ENTRY."
        decrypted = self.crypto.decrypt(bytes(rsp.read.wrapped_password), bytes(rsp.read.initialization_vector), bytes(rsp.read.tag))
        print("Decrypted password: ", str(decrypted).replace("b'", "").replace("'", "").strip('\x00'))

    def __modify_json(self, index: int, info: bytes):
        data = JSONReader.read_json()
        str_info = "".join("{:02x}".format(x) for x in info)
        str_info = bytearray.fromhex(str_info).decode()
        for user in data['users']:
            for password in user['passwords']['list']:
                if password['index'] == index:
                    password['info'] = str_info
        with open("userdata.json", "w") as file:
            json.dump(data, file, indent=4)
        
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
            user['passwords']['list'].append({"info": "", "index": index})
            user['passwords']['list'][index]['info'] = str_info
        with open("userdata.json", "w") as file:
            json.dump(data, file, indent=4)

    def __delete_element_json(self, index: int):
        """
        Deletes an element from the JSON data based on the provided index.

        Args:
            index (int): The index of the password to be deleted.

        Raises:
            FileNotFoundError: If the JSON file does not exist.
            JSONDecodeError: If the JSON file is not properly formatted.
        """
        data = JSONReader.read_json()
        for user in data['users']:
            for password in user['passwords']['list']:
                if password['index'] == index:
                    user['passwords']['list'].remove(password)
        with open("userdata.json", "w") as file:
            json.dump(data, file, indent=4)
