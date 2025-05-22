import time
import random
import logging

# Setup logging
logging.basicConfig(filename='rfid_logger.txt', level=logging.INFO, format='%(asctime)s - %(message)s')


# Simulated list of authorized RFID tags
authorized_tags = ["TAG111", "TAG555", "TAG000"]


# Function to simulate scanning an RFID tag
def scan_rfid():
    simulated_tags = ["TAG111", "TAG222", "TAG555", "TAG999", "TAG888", "TAG000"]  # Including unauthorized tags
    scanned_tag = random.choice(simulated_tags)
    return scanned_tag


# Function to check if the scanned tag is authorized
def is_authorized(tag):
    return tag in authorized_tags


# Function to log unauthorized scans
def log_unauthorized_scan(tag):
    logging.warning(f"Unauthorized RFID scan detected: {tag}")


# Function to notify user of unauthorized scan (simulated with print statement)
def notify_user(tag):
    print(f"Alert! Unauthorized RFID scan detected: {tag}")


# Main function to run the RFID blocking simulation
def rfid_blocking_system(num_scans):
    for _ in range(num_scans):
        scanned_tag = scan_rfid()
        print(f"Scanned RFID Tag: {scanned_tag}")
        
        if not is_authorized(scanned_tag):
            log_unauthorized_scan(scanned_tag)
            notify_user(scanned_tag)
        
        # Wait for a short period before the next scan
        time.sleep(2)  # Adjust as needed


# Run the RFID blocking system simulation
if __name__ == "__main__":
    print("Starting RFID blocking system simulation...")
    rfid_blocking_system(num_scans=5)  # Number of scans to perform