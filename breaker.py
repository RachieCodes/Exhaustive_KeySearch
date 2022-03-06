import json
from base64 import b64encode, b64decode
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import time
import argparse
from random import randint
from utils_demo import *
import ftfy

parser = argparse.ArgumentParser(description='Bruteforce attack against randomized AES-128-CTR.')
parser.add_argument('-n', type=int,
                    help='Effective key length in bytes.', default=3)
parser.add_argument('-c1', type=str,
                    help='Ciphertext1 file input name.', default="files/c1.bin")
parser.add_argument('-c2', type=str,
                    help='Ciphertext2 file input name.', default="files/c2.bin")
parser.add_argument('-c3', type=str,
                    help='Ciphertext3 file input name.', default="files/c3.bin")

parser.add_argument('-n1', type=str,
                    help='Nonce1 file input name.', default="files/nonce1.bin")
parser.add_argument('-n2', type=str,
                    help='Nonce2 file input name.', default="files/nonce2.bin")
parser.add_argument('-n3', type=str,
                    help='Nonce3 file input name.', default="files/nonce3.bin")

parser.add_argument('-m1', type=str,
                    help='Plaintext1 file input name.', default="files/m1.txt")
parser.add_argument('-m2', type=str,
                    help='Plaintext2 file input name.', default="files/m2.txt")
parser.add_argument('-m3', type=str,
                    help='Plaintext3 file input name.', default="files/m3.txt")

args = parser.parse_args()
#The input value for brute force attack in bits. 16 bits is equal to 2 bytes.
length_postfix = args.n * 8

#Reading ciphertexts from files. 
ciphertext1 = read_bytes(fn = args.c1)
ciphertext2 = read_bytes(fn = args.c2)
ciphertext3 = read_bytes(fn = args.c3)

#Reading nonces from files
nonce1 = read_bytes(fn = args.n1)
nonce2 = read_bytes(fn = args.n2)
nonce3 = read_bytes(fn = args.n3)

#Reading plaintexts from files. 
plaintext1 = ftfy.fix_text(read_file(fn = args.m1))
plaintext2 = ftfy.fix_text(read_file(fn = args.m2))
plaintext3 = ftfy.fix_text(read_file(fn = args.m3))

max_key_value = 2**24 - 1	#The max value the last 3 bytes can have
base_key = 2**127	#128 bit key, 1 in the first spot means 2^127

#Iterate through all possible key endings
for i in range(max_key_value):
	#Evaluate key
	key = base_key | i
	key = key.to_bytes(16, 'big')

	#Attempt to decode with this key
	#This might fail with incorrect keys because of UTF-8 encoding
	try:
		p1_attempt = ftfy.fix_text(decryptor_CTR(ciphertext1, nonce1, key).decode())

		print(str(p1_attempt) + " ?= " + str(plaintext1))

		#Compare all decrypted plaintexts to actual plaintexts
		if p1_attempt == plaintext1:
			p2_attempt = ftfy.fix_text(decryptor_CTR(ciphertext2, nonce2, key).decode())
			p3_attempt = ftfy.fix_text(decryptor_CTR(ciphertext3, nonce3, key).decode())

			print(str(p2_attempt) + " ?= " + str(plaintext2))
			print(str(p3_attempt) + " ?= " + str(plaintext3))

			if p2_attempt == plaintext2 and p3_attempt == plaintext3:
				#If the key was found, output it and stop brute forcing
				print("Found key: " + str(key.hex()))
				break
	except:
		pass



