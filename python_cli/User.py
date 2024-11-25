import json
from ICrypto import ICrypto

class FailedToLoginException(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return self.message

class User:
    def __init__(self, username, password):
        isCreated = self.__isUserCreated()
        if self.__salt == "" and isCreated == False:
            self.__salt = ICrypto.getRandomByteArray(16)
        password, self.__salt = ICrypto.PBKDF2(password.encode() + username.encode(), self.__salt)
        self.__kek = None
        if isCreated == False:
            self.__createUser(username, password, self.__salt)
        else:
            self.username = username
            self.password = password
            if self.__verifyUser() == False:
                raise FailedToLoginException("Failed to login. Please check your username and password.")

    def __verifyUser(self) -> bool:
        json_file = self.__read_json("userdata.json")
        userName = json_file["users"][0]["login"]
        passHash = json_file["users"][0]["password_hash"]
        self.__kek = json_file["users"][0]["kek"]
        if self.__isUserCreated():
            if userName == self.username and passHash == self.password:
                return True
            else:
                return False
        else:
            return False

    def __isUserCreated(self):
        json_file = self.__read_json("userdata.json")
        userName = json_file["users"][0]["login"]
        passHash = json_file["users"][0]["password_hash"]
        self.__salt = json_file["users"][0]["salt"]
        if userName == "" or passHash == "":
            return False
        
        return True
    
    def __createUser(self, username, password, salt):
        kek = ICrypto.getRandomByteArray(16)
        json_file = self.__read_json("userdata.json")
        json_file["users"][0]["login"] = username
        json_file["users"][0]["password_hash"] = password
        json_file["users"][0]["salt"] = salt
        json_file["users"][0]["kek"] = "".join("{:02x}".format(x) for x in kek)
        with open("userdata.json", "w") as file:
            json.dump(json_file, file, indent=4)
        


    def __read_json(self, file_name):
        with open(file_name, "r") as file:
            return json.load(file)
        
    @property
    def kek(self):
        self.__kek = self.__read_json("userdata.json")["users"][0]["kek"]
        assert self.__kek is not None, "kek is not initialized."
        return self.__kek
        
if __name__ == "__main__":
    user = User("admin", "admin")
    print("User created successfully.")