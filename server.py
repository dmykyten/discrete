import socket
import threading
from rsa_coding import RSAKeyGen
from msg_integrity import HasgMsg
import string
from itertools import count


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # generating keys
        self.keys = RSAKeyGen()
        self.clients_keys = dict()

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"{username} tries to connect")
            self.broadcast(f'new person has joined: {username}')
            self.username_lookup[c] = username
            self.clients.append(c)

            # send public key to the client
            c.send(','.join([str(key) for key in self.keys.public]).encode())
            c_keys = [int(keypart) for keypart in c.recv(1024).decode().split(',')]
            self.clients_keys[c] = c_keys
            print(c_keys)
            # encrypt the secret with the clients public key
            secret = 'cdeomeo'
            encrypted = self.keys.encrypt_msg(c_keys, secret)
            print(encrypted)
            c.send(','.join([str(block) for block in encrypted]).encode())
            input()
            # send the encrypted secret to a client

            # ...

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            # encrypt the message

            # ...

            client.send(msg.encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg = c.recv(1024)

            for client in self.clients:
                if client != c:
                    client.send(msg)


if __name__ == "__main__":
    s = Server(9001)
    s.start()
