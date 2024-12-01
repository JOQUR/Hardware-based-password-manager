import os
from Application import Application
import getpass

class cli_tool:
    def __init__(self, application: Application):
        self.application = application

    def run(self):
        self.__print_menu()
        user_input = input()
        self.__clear_terminal()
        return self.__parse_input(user_input)
    
    def __print_menu(self):
        print("Choose an option: ")
        print("1. Generate password for me.")
        print("2. Add new Entry.")
        print("3. Delete Entry.")
        print("4. Modify Entry.")
        print("5. Read Entry.")
        print("0. Exit.")

    def __parse_input(self, usr_input: str):
        user_input = int(usr_input)

        if user_input == 1:
            print("Generating password...")
            return self.application.prepareGenerate()
        elif user_input == 2:
            print("Adding new entry...")
            info = input("Enter the info: ")
            password = getpass.getpass("Enter the password: ")
            return self.application.prepareAddEntry(info.encode(), password.encode())
        elif user_input == 3:
            print("Deleting entry...")
            info = input("Enter the info: ")
            print("Deleting entry with info: ", int(info))
            return self.application.prepareDeleteEntry(int(info))
        elif user_input == 4: 
            print("Modifying entry...")
            index = int(input("Enter the index: "))
            info = input("Enter the info: ")
            password = getpass.getpass("Enter the password: ")
            return self.application.prepareModifyEntry(index, info.encode(), password.encode())
        elif user_input == 5:
            print("Reading entry...")
            index = int(input("Enter the index: "))
            return self.application.prepareReadEntry(index)
        elif user_input == 0:
            print("Exiting...")
            exit(0)
    
    def __clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')