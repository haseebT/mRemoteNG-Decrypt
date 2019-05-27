#!/usr/bin/env python3

import hashlib
import base64
from Cryptodome.Cipher import AES
import argparse
import sys

def main():
  parser = argparse.ArgumentParser(description="Decrypt mRemoteNG passwords.")
  group = parser.add_mutually_exclusive_group()
  group.add_argument("-f", "--file", help="name of file containing mRemoteNG password")
  group.add_argument("-s", "--string", help="base64 string of mRemoteNG password")
  parser.add_argument("-p", "--password", help="Custom password", default="mR3m")

  if len(sys.argv) < 2:
    parser.print_help(sys.stderr)
    sys.exit(1)

  args = parser.parse_args()
  encrypted_data = ""
  if args.file != None:
    with open(args.file) as f:
      encrypted_data = f.read()
      encrypted_data = encrypted_data.strip()
      encrypted_data = base64.b64decode(encrypted_data)

  elif args.string != None:
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
  key = hashlib.pbkdf2_hmac("sha1", args.password.encode(), salt, 1000, dklen=32)

  cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
  cipher.update(associated_data)
  plaintext = cipher.decrypt_and_verify(ciphertext, tag)
  print("Password: {}".format(plaintext.decode("utf-8")))

if __name__ == "__main__":
  main()
