import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# This function will encrypt the given plaintext using AES-GCM.
def encrypt(file_path):
    try:
        with open(file_path, "rb") as file: # Read the file input.
            Data = file.read()

        Nonce = os.urandom(12) # Generate a random nonce.
        EncryptedData = aesgcm.encrypt(Nonce, Data, None)
        
        # Overwrite the original file.
        with open(file_path, "wb") as file:
            file.write(Nonce + EncryptedData) # Write the nonce and the encrypted data to the file.
        print(f"File encrypted: {file_path}. \n")
    
    except Exception as e:
        print(f"Error encrypting {file_path}: {e}. \n")

# This function will decrypt the given ciphertext using AES-GCM.
def decrypt(file_path):
    try:
        with open(file_path, "rb") as file: # Read the file input.
            Data = file.read()

        Nonce = Data[:12] # Extract the nonce from the data.
        EncryptedData = Data[12:] # Extract the encrypted data from the rest of the data.
        DecryptedData = aesgcm.decrypt(Nonce, EncryptedData, None) # Decrypt the data using AES-GCM.
        
        with open(file_path, "wb") as file:
            file.write(DecryptedData) # Write the decrypted data back to the file.
        print(f"File decrypted: {file_path}. \n")
    
    except InvalidTag:
        print(f"Decryption failed for {file_path}. \n")
    
    except Exception as e:
        print(f"Error decrypting {file_path}: {e}. \n")

# This function encrypts all files in the specified folder and its subfolders.
def encrypt_folder(folder_path):

    # Walk through all files in the folder and its subfolders.
    for root_dir, _, files in os.walk(folder_path):
        for file in files:

            if file == "AES-256-GCM.key": # Skip the key to prevent it from being encrypted.
                continue

            file_path = os.path.join(root_dir, file)
            encrypt(file_path) # Encrypt each file using the encrypt function.

# This function decrypts all files in the specified folder and its subfolders.
def decrypt_folder(folder_path):

    # Walk through all files in the folder and its subfolders.
    for root_dir, _, files in os.walk(folder_path):
        for file in files:

            if file == "AES-256-GCM.key": # Skip the key.
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
        print("All files in the folder have been encrypted successfully. \n")

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
        print("All files in the folder have been decrypted successfully. \n")

    # Handle invalid mode selection.
    else:
        print("Invalid mode selected. Please choose 'e' for encryption or 'd' for decryption. \n")
        exit()