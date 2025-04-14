from cryptography.fernet import Fernet

# Generate a key (save this securely; do not regenerate every time)
key = Fernet.generate_key()
with open("secret.key", "wb") as key_file:
    key_file.write(key)

# Encrypt the password
f = Fernet(key)
encrypted_password = f.encrypt(b"YOUREMAILPASSWORDHERE")

# Save encrypted password
with open("encrypted_password.bin", "wb") as file:
    file.write(encrypted_password)

print("Password encrypted and saved.")
