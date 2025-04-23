import socket
import tqdm
from Crypto.Cipher import AES
from getmac import get_mac_address as gma
import logging

logging.basicConfig(filename="audit_log_receiver.txt", level=logging.INFO, format='%(asctime)s - %(message)s')

def log_event(message):
    logging.info(f"{gma()} - " + message )

# === Setup ===
key = b"thequickbrownfox"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 5555))
server.listen()

print("📡 Waiting for sender...")
client, addr = server.accept()
log_event("Server Created and connected to " + f" {addr}")
print("📥 Connected to", addr)

# === Receive nonce ===
nonce = client.recv(16)
log_event("Nonce key has been sent.")
cipher = AES.new(key, AES.MODE_EAX, nonce)

# === Receive header ===
header = b""
while b"<END_HEADER>" not in header:
    header += client.recv(1024)
log_event("File metadata sent.")

# Find the position of <END_HEADER>
header_end_index = header.index(b"<END_HEADER>") + len(b"<END_HEADER>")
header_data = header[:header_end_index]
file_bytes = header[header_end_index:]  # leftover = beginning of ciphertext

# Decode only the header portion
header_str = header_data.decode()
file_name, file_size = header_str.replace("<END_HEADER>", "").split("<SEP>")
file_size = int(file_size)


# Start collecting any remaining part of encrypted file already in buffer
file_bytes = header.split(b"<END_HEADER>")[1]

print("📄 Receiving:", file_name)
print("📦 File size:", file_size)

#To work in the local host for the same name of file
file_name = file_name.split(".")
extention = file_name[1]
file_name = file_name[0]
file_name = file_name + "1." + extention

# === Receive encrypted file + tag + <END> ===
progress = tqdm.tqdm(unit="B", unit_scale=True, unit_divisor=1000, total=file_size)

while True:
    chunk = client.recv(1024)
    file_bytes += chunk
    progress.update(len(chunk))
    if file_bytes[-5:] == b"<END>":
        break

# === Remove END marker ===
file_bytes = file_bytes[:-5]

# Extract tag (last 16 bytes)
tag = file_bytes[-16:]
ciphertext = file_bytes[:-16]

# === Decrypt and Save ===
try:
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(file_name, "wb") as f:
        f.write(decrypted_data)
    print("✅ File decrypted and saved successfully.")
    log_event("File decrypted and saved sucessfully.")
except ValueError:
    print("❌ Decryption failed. Tag mismatch or data corrupted.")
    log_event("Error occured while decrypting data, ",ValueError)

client.close()
server.close()