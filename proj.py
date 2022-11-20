import argparse
from cryptography.fernet import Fernet

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

if args.command == 'encrypt':
    if args.type == '' or 'fernet':

        with open('filekey.key', 'rb') as filekey:
            filekey.read()
        fernet = Fernet(key)

        with open(args.file, 'rb') as file:
            original = file.read()

        encrypted = fernet.encrypt(original)

        with open(args.file, 'wb') as encrypted_file:
            encrypted_file.write(encrypted)

if args.command == 'decrypt':
    if args.type == '' or 'fernet':
        with open('filekey.key', 'rb') as filekey:
            filekey.read()
        fernet = Fernet(key)

        with open(args.file,'rb') as enc_file:
            encrypted = enc_file.read();

        decrypted = fernet.decrypt(encrypted)

        with open(args.file, 'wb') as dec_file:
            dec_file.write(decrypted)
