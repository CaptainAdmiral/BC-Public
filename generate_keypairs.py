import csv
import keyboard
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_64 = base64.b64encode(public_der).decode('utf-8')
    private_key_64 = base64.b64encode(private_der).decode('utf-8')

    return public_key_64, private_key_64


with open('keypairs.csv', mode='a', newline='') as file:
    writer = csv.writer(file)
    
    i = 0
    while True:
        public_key, private_key = generate_rsa_keypair()
        writer.writerow([public_key, private_key])
        i += 1
        print(f"{i} new keypairs", end='\r') 
        if keyboard.is_pressed('q'):
            break
