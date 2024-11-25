from socket import *
import os
from Client import Client
from State import State
from Application import Application
from cli_tool import cli_tool
import getpass

class ConnectionHandler:
    def __init__(self, client: Client, port):
        self.__client = client
        self.__port = port
        self.__server_socket = socket(AF_INET, SOCK_STREAM)
        self.cli_tool = None
    
    def __start_app(self):
            self.__client.stage = Application(self.__client.stage.crypto)
            self.cli_tool = cli_tool(self.__client.stage)
        
    def start(self):
        self.__server_socket.connect(("localhost", self.__port))
        with self.__server_socket as server_socket:

            '''
            Establishing connection with the server.
            '''
            server_socket.sendall(self.__client.stage.prepareHello())
            rcv = server_socket.recv(1024)
            self.__client.stage.processMessage(rcv)
            server_socket.sendall(self.__client.stage.prepareChallange())
            rcv = server_socket.recv(1024)
            self.__client.stage.processMessage(rcv)
            server_socket.sendall(self.__client.stage.prepareHandshakeFinish())
            rcv = server_socket.recv(1024)
            self.__client.stage.processMessage(rcv)
            

            '''
            Connection established.
            '''

            assert self.__client.stage.state == State.AUTHENTICATED

            '''
            Starting the application.
            '''
            server_socket.sendall(self.__client.stage.prepareStartApp())
            assert self.__client.stage.state == State.APP_START, "Application did not start successfully."
            self.__start_app()

            while True:
                server_socket.sendall(self.cli_tool.run())
                rcv = server_socket.recv(1024)
                self.__client.stage.processMessage(rcv)
            

if __name__ == "__main__":
    client = Client(input("Enter the login: "), getpass.getpass("Enter the password: "))
    connection_handler = ConnectionHandler(client, 8070)
    connection_handler.start()
    print("Connection established successfully.")