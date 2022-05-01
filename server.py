import socket
import threading
from rsa_coding import RSAKeyGen, rsa


class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # generating keys
        self.keys = RSAKeyGen()
        print(f"self keys is: {self.keys.public, self.keys.private}")
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
            c_keys = tuple(int(keypart) for keypart in c.recv(1024).decode().split(','))
            self.clients_keys[c] = c_keys
            print(f"client keys is: {c_keys}")
            # encrypt the secret with the clients public key
            secret = self.keys.encrypt_msg(
                c_keys, str(self.keys.private[1])
            )
            # send the encrypted secret to a client
            secret_hash = rsa.get_hash(str(secret))
            secret = ','.join([str(value) for value in secret]).encode()
            c.send(secret_hash)
            c.send(secret)

            threading.Thread(target=self.handle_client, args=(c, addr,)).start()

    def broadcast(self, msg: str):
        for client in self.clients:
            client.send(msg.encode())

    def handle_client(self, c: socket, addr):
        while True:
            msg_hash = c.recv(1024)
            oldmsg = c.recv(1024).decode()
            msg = [int(keypart) for keypart in oldmsg.split(',')]
            msg = self.keys.decrypt_msg(self.keys.private, msg)
            print(msg)
            if rsa.verify_integrity(msg_hash, msg):
                for client in self.clients:
                    if client != c:
                        client.send(msg_hash)
                        client.send(oldmsg)


if __name__ == "__main__":
    s = Server(9001)
    s.start()
