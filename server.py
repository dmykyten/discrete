import socket
import threading
from rsa_coding import RSAKeyGen
import string

class Server:

    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.keys = RSAKeyGen()
        self.clients = []
        self.username_lookup = {}
        self.clients_keys = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

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
            c.send(bytes(self.keys.public[0]))
            c.send(bytes(self.keys.public[1]))
            c_public = c.recv(1024).decode(), c.recv(1024).decode()
            print(c_public)
            self.clients_keys[c] = c_public
            # encrypt the secret with the clients public key
            encrypted_msg = self.encrypt_msg(c, self.keys.public)
            # send the encrypted secret to a client 
            #self.s.send(encrypted_msg)
            # ...

            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def encrypt_msg(self, client, msg):        # should encrypt msg(english only at moment)
        public_key = self.clients_keys[client] # (n, e)
        encrypted = ''
        for letter in msg:
            letter_code = str(string.ascii_letters.find(letter))
            if letter.isupper():
                letter_code -= 25
            if int(letter_code) < 10:
                letter_code += letter_code
            encrypted += letter_code


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
