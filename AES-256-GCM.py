from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import os

FILE_SIZE = 2 * 1024 * 1024 * 1024 # The max file size of a file that can be encrypted / decrypted is set to 2GB to prevent memory issues. (You can adjust this value as needed)

def encrypt(file_path):

    if os.path.getsize(file_path) > FILE_SIZE:
        print(f"File is too large to encrypt: {file_path}. \n")
        return

    temp_file_path = file_path + ".tmp" # Create a temporary file path for encryption.

    try:
        with open(file_path, "rb") as file:
            Data = file.read()

        # Generate a random nonce.
        Nonce = os.urandom(12)

        # Encrypt the data using AES-GCM. The nonce is included in the output to allow for decryption later.
        EncryptedData = aesgcm.encrypt(Nonce, Data, None)

        # Write to the temporary file first to ensure that the original file is not corrupted in case of an error during encryption.
        with open(temp_file_path, "wb") as file:
            file.write(Nonce + EncryptedData)
        
        os.replace(temp_file_path, file_path) # Replace the original file with the temporary file after successful encryption.

        print(f"File encrypted: {file_path}. \n")

    # Remove the temporary file if an error occurs during encryption.
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        print(f"Error encrypting {file_path}: {e}. \n")

def decrypt(file_path):

    if os.path.getsize(file_path) > FILE_SIZE:
        print(f"File is too large to decrypt: {file_path}. \n")
        return

    temp_file_path = file_path + ".tmp" # Create a temporary file path for decryption.

    try:
        with open(file_path, "rb") as file:
            Data = file.read()

        Nonce = Data[:12] # Extract the nonce from the data.
        
        EncryptedData = Data[12:] # Extract the encrypted data from the rest of the data.

        DecryptedData = aesgcm.decrypt(Nonce, EncryptedData, None) # Decrypt the data using AES-GCM.

        # Write decrypted data to temp file first to ensure that the original file is not corrupted in case of an error during decryption.
        with open(temp_file_path, "wb") as file:
            file.write(DecryptedData)

        os.replace(temp_file_path, file_path) # Replace the original file with the temporary file after successful decryption.
        
        print(f"File decrypted: {file_path}. \n")
    
    except InvalidTag:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        print(f"Error decrypting {file_path}: Invalid authentication tag. \n")  

    # Remove the temporary file if an error occurs during decryption.
    except Exception as e:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        print(f"Error decrypting {file_path}: {e}. \n")  

def encrypt_folder(folder_path):

    # Walk through all files in the folder and its subfolders.
    for root_dir, _, files in os.walk(folder_path):
        for file in files:

            if file.endswith(".key"): # Skip the key file to prevent it from being encrypted.
                print(f"Skipping the key file: {file}. \n")
                continue

            if file == "AES-256-GCM.py": # Skip the script itself to prevent it from being encrypted.
                print(f"Skipping the script file: {file}. \n")
                continue

            file_path = os.path.join(root_dir, file)
            encrypt(file_path) # Encrypt each file using the encrypt function.

def decrypt_folder(folder_path):

    # Walk through all files in the folder and its subfolders.
    for root_dir, _, files in os.walk(folder_path):
        for file in files:

            if file.endswith(".key"): # Skip the key file to prevent it from being decrypted.
                print(f"Skipping the key file: {file}. \n")
                continue

            if file == "AES-256-GCM.py": # Skip the script itself to prevent it from being decrypted.
                print(f"Skipping the script file: {file}. \n")
                continue

            file_path = os.path.join(root_dir, file)
            decrypt(file_path) # Decrypt each file using the decrypt function.

if __name__ == "__main__":
    Mode = input("Encryption or Decryption? (e/d): ").strip().lower()
    Folder = input("Enter the path of the folder: ").strip()

    # Check if the specified folder exists before proceeding with encryption or decryption.
    if not os.path.exists(Folder):
        print("The specified folder does not exist. \n")
        exit()

    # Perform encryption if the user selects 'e'.
    if Mode == "e":

        # If the AES key file exists, load the key from the file.
        if os.path.exists("AES-256-GCM.key"):
            with open("AES-256-GCM.key", "rb") as file:
                Key = file.read()
            print("The key was found and loaded successfully. \n")
        
        # If the AES key file does not exist, generate a new key and save it to the file.
        else:
            Key = AESGCM.generate_key(bit_length = 256) # Generate a new AES-256 key.

            with open("AES-256-GCM.key", "wb") as file:
                file.write(Key)
            print("A new key was generated and saved successfully. \n")
        
        aesgcm = AESGCM(Key) # Create an AES-GCM cipher instance.

        encrypt_folder(Folder) # Encrypt all files in the specified folder.
        print("Encryption completed successfully. \n")

    # Perform decryption if the user selects 'd'.
    elif Mode == "d":

        # If the AES key file exists, load the key from the file.
        if os.path.exists("AES-256-GCM.key"):
            with open("AES-256-GCM.key", "rb") as file:
                Key = file.read()
            print("The key was found and loaded successfully. \n")
        else:
            print("The key file does not exist. \n")
            exit()

        aesgcm = AESGCM(Key) # Create an AES-GCM cipher instance.

        decrypt_folder(Folder) # Decrypt all files in the specified folder.
        print("Decryption completed successfully. \n")

    # Handle invalid mode selection.
    else:
        print("Invalid mode selected. Please choose 'e' for encryption or 'd' for decryption. \n")
        exit()
