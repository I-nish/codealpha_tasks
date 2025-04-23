import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from getmac import get_mac_address as gma
import logging

logging.basicConfig(filename="audit_log_sender.txt", level=logging.INFO, format='%(asctime)s - %(message)s')

def log_event(message):
    logging.info(f"{gma()} - " + message )

# === Setup ===
key = b"thequickbrownfox"  # 16 bytes
nonce = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX, nonce)

sucess = False
# === File Read and Encrypt ===

while sucess is not True:
    file_path = input("Enter the full name of the file: ")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        sucess = True
    except:
        print("❌ Error occured while reading file or wrong file name.")
        log_event("Error while reading file.")
ciphertext, tag = cipher.encrypt_and_digest(data)
log_event("Data encrypted and digested sucessfully.")

file_name = os.path.basename(file_path)
file_size = len(ciphertext)

# === Connect and Send ===
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 5555))
log_event("Connected to Receiver.")

# Send nonce (first)
client.sendall(nonce)

# Send header (file name + size)
header = f"{file_name}<SEP>{file_size}<END_HEADER>".encode()
client.sendall(header)

# Send encrypted data
client.sendall(ciphertext)

# Send tag
client.sendall(tag)

# Send end marker
client.sendall(b"<END>")

print("✅ File sent successfully.")
log_event("Sucessful file transfer")
client.close()