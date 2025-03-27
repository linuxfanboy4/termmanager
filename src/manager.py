import os
import hashlib
import base64
import argparse
import json
import re
import random
import string
import pyotp
import time
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from getpass import getpass
from datetime import datetime, timedelta

class PasswordManager:
    def __init__(self):
        self.salt = os.urandom(16)
        self.password_file = "passwords.json"
        self.auth_file = "auth.json"
        self.master_key = None
        self.authenticated = False
        self.totp = None

    def _derive_key(self, master_password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=200000,
            backend=default_backend()
        )
        return kdf.derive(master_password.encode())

    def _encrypt(self, plaintext, password):
        self.master_key = self._derive_key(password)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_data = plaintext + (16 - len(plaintext) % 16) * ' '
        ciphertext = encryptor.update(padded_data.encode()) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    def _decrypt(self, encrypted_text, password):
        self.master_key = self._derive_key(password)
        encrypted_data = base64.b64decode(encrypted_text)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data.decode().rstrip()

    def _authenticate(self):
        if not os.path.exists(self.auth_file):
            self._setup_auth()
        with open(self.auth_file, 'r') as f:
            auth_data = json.load(f)
        stored_hash = auth_data["password_hash"]
        attempts = 3
        while attempts > 0:
            master_password = getpass("Enter Master Password: ")
            hashed_attempt = hashlib.sha256(master_password.encode()).hexdigest()
            if hashed_attempt == stored_hash:
                totp = pyotp.TOTP(auth_data["totp_secret"])
                code = input("Enter 2FA Code: ")
                if totp.verify(code):
                    self.authenticated = True
                    print("Authentication successful.")
                    return master_password
                else:
                    print("Invalid 2FA Code.")
            else:
                print("Invalid Password.")
            attempts -= 1
        print("Too many failed attempts.")
        exit()

    def _setup_auth(self):
        master_password = getpass("Set Master Password: ")
        confirm_password = getpass("Confirm Master Password: ")
        if master_password != confirm_password:
            print("Passwords do not match.")
            exit()
        password_hash = hashlib.sha256(master_password.encode()).hexdigest()
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)
        print("Scan this QR code with your 2FA app:")
        print(totp.provisioning_uri("PasswordManager", issuer_name="SecureVault"))
        auth_data = {"password_hash": password_hash, "totp_secret": totp_secret}
        with open(self.auth_file, 'w') as f:
            json.dump(auth_data, f)
        print("Authentication setup complete.")

    def add_password(self, account, password, master_password, expiry_days=365):
        if not self.authenticated:
            print("Access denied.")
            return
        encrypted_password = self._encrypt(password, master_password)
        expiry_date = (datetime.now() + timedelta(days=expiry_days)).isoformat()
        data = {"account": account, "password": encrypted_password, "expiry_date": expiry_date}
        self._store_password(data)
        
    def get_password(self, account, master_password):
        if not self.authenticated:
            print("Access denied.")
            return
        passwords = self._load_passwords()
        for entry in passwords:
            if entry["account"] == account:
                if datetime.fromisoformat(entry["expiry_date"]) > datetime.now():
                    return self._decrypt(entry["password"], master_password)
                else:
                    print("Password expired.")
                    return None
        return None

    def _store_password(self, data):
        passwords = self._load_passwords()
        passwords.append(data)
        with open(self.password_file, 'w') as f:
            json.dump(passwords, f)

    def _load_passwords(self):
        if not os.path.exists(self.password_file):
            return []
        with open(self.password_file, 'r') as f:
            return json.load(f)

    def delete_password(self, account):
        if not self.authenticated:
            print("Access denied.")
            return
        passwords = self._load_passwords()
        for entry in passwords:
            if entry["account"] == account:
                passwords.remove(entry)
                with open(self.password_file, 'w') as f:
                    json.dump(passwords, f)
                print(f"{account} password deleted.")
                return
        print("Account not found.")

    def update_password(self, account, new_password, master_password):
        if not self.authenticated:
            print("Access denied.")
            return
        passwords = self._load_passwords()
        for entry in passwords:
            if entry["account"] == account:
                encrypted_password = self._encrypt(new_password, master_password)
                entry["password"] = encrypted_password
                with open(self.password_file, 'w') as f:
                    json.dump(passwords, f)
                print(f"{account} password updated.")
                return
        print("Account not found.")

    def generate_password(self, length=16):
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

    def export_data(self, master_password):
        if not self.authenticated:
            print("Access denied.")
            return
        passwords = self._load_passwords()
        for entry in passwords:
            entry["password"] = self._decrypt(entry["password"], master_password)
        with open('exported_data.json', 'w') as f:
            json.dump(passwords, f)
        print("Data exported.")

    def import_data(self, master_password):
        if not self.authenticated:
            print("Access denied.")
            return
        with open('imported_data.json', 'r') as f:
            passwords = json.load(f)
        for entry in passwords:
            encrypted_password = self._encrypt(entry["password"], master_password)
            entry["password"] = encrypted_password
            self._store_password(entry)
        print("Data imported.")

def main():
    parser = argparse.ArgumentParser(description="Advanced Secure Password Manager")
    parser.add_argument('action', choices=['add', 'get', 'delete', 'update', 'generate', 'export', 'import'], help='Action to perform')
    parser.add_argument('--account', help='Account name')
    parser.add_argument('--password', help='Password for account')
    parser.add_argument('--new_password', help='New password for account')
    parser.add_argument('--master_password', help='Master password to encrypt/decrypt passwords', required=True)
    args = parser.parse_args()

    manager = PasswordManager()
    master_password = manager._authenticate()

    if args.action == 'add':
        if args.account and args.password:
            manager.add_password(args.account, args.password, master_password)
        else:
            print('Account and password required.')

    elif args.action == 'get':
        if args.account:
            password = manager.get_password(args.account, master_password)
            print(f'Password: {password}' if password else "Not found.")
    
    elif args.action == 'delete':
        if args.account:
            manager.delete_password(args.account)

    elif args.action == 'update':
        if args.account and args.new_password:
            manager.update_password(args.account, args.new_password, master_password)

    elif args.action == 'generate':
        print('Generated password:', manager.generate_password())

    elif args.action == 'export':
        manager.export_data(master_password)

    elif args.action == 'import':
        manager.import_data(master_password)

if __name__ == "__main__":
    main()
