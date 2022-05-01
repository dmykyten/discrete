import socket
import threading
from rsa_coding import RSAKeyGen, rsa

class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.server_public = None
        self.server_private = None
        self.keys = RSAKeyGen()
        print(f"self keys is: {self.keys.public, self.keys.private}")

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
        self.server_public = tuple(
            int(keypart) for keypart in server_keys
        )
        print(f"server keys is: {server_keys}")
        self.s.send(','.join([str(key) for key in self.keys.public]).encode())
        # receive the encrypted secret key
        secret_hash = self.s.recv(1024)
        secret = self.s.recv(1024).decode()
        secret = [
            int(keypart) for keypart in secret.split(',')
        ]
        if rsa.check_hash(secret_hash, str(secret)):
            secret = int(self.keys.decrypt_msg(self.keys.private, secret))
            self.server_private = self.server_public[0], secret

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()


    def read_handler(self):
        while True:
            message_hash = self.s.recv(1024)
            message = self.s.recv(1024).decode()
            message = self.keys.decrypt_msg(self.server_private, message)
            if rsa.verify_integrity(message_hash, message):
                print(message)
            else:
                self.s.close()

    def write_handler(self):
        while True:
            message = input()
            message_hash = rsa.get_hash(message)
            message = self.keys.encrypt_msg(self.server_public, message)
            self.s.send(message_hash)
            self.s.send(','.join([str(value) for value in message]).encode())

if __name__ == "__main__":
    cl = Client("127.0.0.1", 9001, "b_g")
    cl.init_connection()
