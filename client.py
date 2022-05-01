import socket
import sys
import threading
from rsa_coding import RSAKeyGen

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.keys = RSAKeyGen()

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())
        # exchanged public keys and converted server keys
        server_keys = self.s.recv(1024).decode().split(',')
        server_keys = [int(keypart) for keypart in server_keys]
        print(server_keys)
        self.s.send(','.join([str(key) for key in self.keys.public]).encode())
        # receive the encrypted secret key
        msg = [int(block) for block in self.s.recv(1024).decode().split(',')]
        print(msg)
        input()

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        input()
        while True:
            message = self.s.recv(1024).decode()

            # decrypt message with the secrete key

            # ...


            print(message)

    def write_handler(self):
        input()
        while True:
            message = input()

            # encrypt message with the secrete key

            # ...

            self.s.send(message.encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
