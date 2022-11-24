import argparse
import base64
from cryptography.fernet import Fernet

def Vig_generateKey(string, key):
    key = list(key)
    if len(string) == len(key):
        return(key)
    else:
      for i in range(len(string) -len(key)):
          key.append(key[i % len(key)])
          return("" . join(key))

def Vig_encryption(string, key):
    encrypt_text = []
    for i in range(len(string)):
        x = (ord(string[i]) +ord(key[i])) % 26
        x += ord('A')
        encrypt_text.append(chr(x))
    return("" . join(encrypt_text))

def Vig_decryption(encrypt_text, key):
    orig_text = []
    for i in range(len(encrypt_text)):
        x = (ord(encrypt_text[i]) -ord(key[i]) + 26) % 26
        x += ord('A')
        orig_text.append(chr(x))
    return("" . join(orig_text))

key = Fernet.generate_key()

with open('filekey.key', 'wb') as filekey:
    filekey.write(key)


parser = argparse.ArgumentParser()
subparser = parser.add_subparsers(dest='command')
encrypt = subparser.add_parser('encrypt')
decrypt = subparser.add_parser('decrypt')

encrypt.add_argument('-file', type=str,required=True)
encrypt.add_argument('-type', type=str,required=True)

decrypt.add_argument('-file', type=str,required=True)
decrypt.add_argument('-type', type=str,required=True)
args = parser.parse_args()

with open(args.file, 'r+') as file:
    original = file.read()
tmpkey = Fernet.generate_key()
tmpkey = str(tmpkey)
VigKey = Vig_generateKey(original, original[0:5])
if args.command == 'encrypt':
    if args.type == 'b64':
        with open(args.file, 'r+') as file:
            original = file.read()
            original_bytes = original.encode('ascii')
            encrypted_bytes = base64.b64encode(original_bytes)

        with open(args.file, 'w+') as encrypted_file:
            encrypted = encrypted_bytes.decode('ascii')
            encrypted_file.write(encrypted)

    elif args.type == 'vig':
        with open(args.file, 'r+') as file:
            original = file.read()

        encrypted = Vig_encryption(original,VigKey)

        with open(args.file, 'w+') as encrypted_file:
            encrypted_file.write(encrypted)

    elif args.type == 'fernet':
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()
        fernet = Fernet(key)

        with open(args.file, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(args.file, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

elif args.command == 'decrypt':
    if args.type == 'b64':
        with open(args.file, 'r+') as encrypted_file:
            encrypted = encrypted_file.read()
            encrypted_bytes = encrypted.encode('ascii')
            decrypted_bytes = base64.b64decode(encrypted_bytes)

        with open(args.file, 'w+') as decrypted_file:
            decrypted = decrypted_bytes.decode('ascii')
            decrypted_file.write(decrypted)

    elif args.type == 'vig':
        with open(args.file, 'r+') as encrypted_file:
            encrypted = encrypted_file.read()

        decrypted = Vig_decryption(encrypted,VigKey)

        with open(args.file, 'w+') as decrypted_file:
            decrypted_file.write(decrypted)

    elif args.type == '' or 'fernet':
        with open('filekey.key', 'rb') as filekey:
            key = filekey.read()
        fernet = Fernet(key)

        with open(args.file,'rb') as enc_file:
            encrypted = enc_file.read();

        decrypted = fernet.decrypt(encrypted)

        with open(args.file, 'wb') as dec_file:
            dec_file.write(decrypted)
