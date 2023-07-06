#!/usr/bin/env python3

import hashlib
import base64
from Cryptodome.Cipher import AES
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt mRemoteNG passwords.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-f", "--file", help="name of file containing mRemoteNG password")
    group.add_argument(
        "-s", "--string", help="base64 string of mRemoteNG password")
    parser.add_argument("-p", "--password",
                        help="Custom password", default="mR3m")
    parser.add_argument("-w", "--wordlist",
                        help="wordlist file for brute-forcing")

    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    encrypted_data = ""
    if args.file is not None:
        with open(args.file) as f:
            encrypted_data = f.read()
            encrypted_data = encrypted_data.strip()
            encrypted_data = base64.b64decode(encrypted_data)

    elif args.string is not None:
        encrypted_data = args.string
        encrypted_data = base64.b64decode(encrypted_data)

    else:
        print("Please use either the file (-f, --file) or string (-s, --string) flag")
        sys.exit(1)

    salt = encrypted_data[:16]
    associated_data = encrypted_data[:16]
    nonce = encrypted_data[16:32]
    ciphertext = encrypted_data[32:-16]
    tag = encrypted_data[-16:]

    if args.wordlist is not None:
        with open(args.wordlist) as wordlist_file:
            for line in wordlist_file:
                password = line.strip()
                key = hashlib.pbkdf2_hmac(
                    "sha1", password.encode(), salt, 1000, dklen=32)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                cipher.update(associated_data)
                try:
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    print("Password found: {}".format(password))
                    sys.exit(0)
                except ValueError:
                    continue

        print("Password not found in the wordlist.")
        sys.exit(1)

    key = hashlib.pbkdf2_hmac(
        "sha1", args.password.encode(), salt, 1000, dklen=32)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(associated_data)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        print("Password: {}".format(plaintext.decode("utf-8")))
    except ValueError:
        print("Incorrect password.")


if __name__ == "__main__":
    main()
