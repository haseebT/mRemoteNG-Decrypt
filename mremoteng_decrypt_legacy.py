#!/usr/bin/env python3
#
# Version < 1.74 
# https://www.errno.fr/mRemoteNG.html

import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
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

  initial_vector = encrypted_data[:16]
  ciphertext = encrypted_data[16:]
  key = hashlib.md5(args.password.encode()).digest()

  cipher = AES.new(key, AES.MODE_CBC, initial_vector)
  plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
  print("Password: {}".format(plaintext.decode("utf-8")))

if __name__ == "__main__":
  main()
