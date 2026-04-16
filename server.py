import socket
import threading
import hashlib

def encrypt_msg(msg, key):
    xored = [ord(c) ^ ord(key[i % len(key)]) for i, c in enumerate(msg)]
    return bytes(xored).hex()

class Server:
    def __init__(self, port: int) -> None:
        self.host = '127.0.0.1'
        self.port = port
        self.clients = []
        self.username_lookup = {}
        self.s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.secret_key = "i_love_diskret_math"

    def start(self):
        self.s.bind((self.host, self.port))
        self.s.listen(100)
        print(f"Server is listening on port {self.port}...")

        while True:
            c, addr = self.s.accept()

            # get user's name
            username = c.recv(1024).decode()
            c.send(b'ack')
            print(f"{username} tries to connect")

            # receive public key from the user
            pub_key_str = c.recv(1024).decode()
            e, n = map(int, pub_key_str.split(','))

            # encrypt the secret with the user's public key (RSA)
            enc_secret = [pow(ord(char), e, n) for char in self.secret_key]
            enc_secret_str = ",".join(map(str, enc_secret))

            # send the encrypted secret to a user
            c.send(enc_secret_str.encode())
            self.username_lookup[c] = username
            self.clients.append(c)
            self.broadcast(f'new person has joined: {username}')
            threading.Thread(target=self.handle_client,args=(c,addr,)).start()

    def broadcast(self, msg: str):
        # encrypt the message and message integrity
        enc_msg = encrypt_msg(msg, self.secret_key)
        h = hashlib.sha256(msg.encode()).hexdigest()
        payload = f"{h}|{enc_msg}"

        for client in self.clients:
            try:
                client.send(payload.encode())
            except:
                pass

    def handle_client(self, c: socket, addr):
        username = self.username_lookup.get(c, "Unknown")

        while True:
            try:
                msg = c.recv(1024)
                if not msg:
                    break

                for client in self.clients:
                    if client != c:
                        client.send(msg)
            except:
                # exit cycle if user left
                break

        if c in self.clients:
            self.clients.remove(c)
        if c in self.username_lookup:
            del self.username_lookup[c]

        c.close()

        print(f"{username} disconnected")
        self.broadcast(f'--- {username} has left the chat ---')

if __name__ == "__main__":
    s = Server(9001)
    s.start()
