import socket
import threading
import random
import hashlib

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y

def mod_inverse(e, phi):
    _, x, _ = extended_gcd(e, phi)
    return (x % phi + phi) % phi

def is_prime(num):
    if num < 2: return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0: return False
    return True

def generate_prime(min_val, max_val):
    prime = random.randint(min_val, max_val)
    while not is_prime(prime):
        prime = random.randint(min_val, max_val)
    return prime

def generate_keypair():
    p = generate_prime(100, 1000)
    q = generate_prime(100, 1000)
    while p == q: q = generate_prime(100, 1000)
    n = p * q
    phi = (p-1) * (q-1)
    e = random.randrange(2, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt_msg(msg, key):
    xored = [ord(c) ^ ord(key[i % len(key)]) for i, c in enumerate(msg)]
    return bytes(xored).hex()

def decrypt_msg(hex_str, key):
    xored = bytes.fromhex(hex_str)
    return "".join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(xored))


class Client:
    def __init__(self, server_ip: str, port: int, username: str) -> None:
        self.server_ip = server_ip
        self.port = port
        self.username = username
        self.secret_key = None

    def init_connection(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server_ip, self.port))
        except Exception as e:
            print("[client]: could not connect to server: ", e)
            return

        self.s.send(self.username.encode())
        self.s.recv(1024)

        # create key pairs (RSA)
        public_key, private_key = generate_keypair()

        # exchange public keys
        pub_key_str = f"{public_key[0]},{public_key[1]}"
        self.s.send(pub_key_str.encode())

        # receive the encrypted secret key
        enc_secret_str = self.s.recv(1024).decode()
        enc_secret_list = [int(x) for x in enc_secret_str.split(',')]

        # decrypt the secret key using private key
        d, n = private_key
        self.secret_key = "".join([chr(pow(c, d, n)) for c in enc_secret_list])

        message_handler = threading.Thread(target=self.read_handler,args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.write_handler,args=())
        input_handler.start()

    def read_handler(self):
        while True:
            try:
                payload = self.s.recv(1024).decode()
                if not payload:
                    break

                if '|' in payload:
                    # separate hash and encrypted message
                    h_recv, enc_msg = payload.split('|', 1)

                    # decrypt message with the secret key
                    message = decrypt_msg(enc_msg, self.secret_key)

                    # message integrity
                    h_calc = hashlib.sha256(message.encode()).hexdigest()
                    if h_calc == h_recv:
                        print(message)
                    else:
                        print("[Error] Message integrity is compromised")
            except Exception as e:
                break

    def write_handler(self):
        while True:
            try:
                raw_msg = input()

                message = f"[{self.username}]: {raw_msg}"

                enc_msg = encrypt_msg(message, self.secret_key)
                h = hashlib.sha256(message.encode()).hexdigest()
                payload = f"{h}|{enc_msg}"

                self.s.send(payload.encode())
            except Exception as e:
                break

if __name__ == "__main__":
    user_name = input("Enter your username: ") or "user"
    cl = Client("127.0.0.1", 9001, user_name)
    cl.init_connection()
