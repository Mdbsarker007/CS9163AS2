#!/usr/bin/python3
# Author : trustie_rity
import base64 as b64
from binascii import hexlify
from hashlib import sha256
from os import urandom 

SEED = b64.b64decode("2RUHYAyJWdDdXOicZfnTRw==")

def generate_salt(length, debug=True):
	import random
	random.seed(SEED)
	return hexlify(random.randint(0, 2 ** length - 1).to_bytes(length, byteorder='big'))


def hash_pword(salt, pword):
	assert (salt is not None and pword is not None)
	hasher = sha256()
	hasher.update(salt)
	#hasher.update(pword.encode())
	hasher.update(pword)
	return hasher.hexdigest()

def parse_salt_and_password(user):
	return user.split('$')

def check_password(user, password):
	salt, password_record = parse_salt_and_password("000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3")
	verify = hash_pword(salt.encode('utf-8'), password)
	#if verify in password_record:
	#	return True
	return verify
#print(check_password("admin" , "123"))

# 000000000000000000000000000078d2$18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3
##  salt . $ . password
#
with open("/usr/share/wordlists/rockyou.txt" , "rb") as f:
	for i in f.readlines():
		i = i.strip(b"\n")
		password = check_password("haha2" , i) 
		#print(password)
		if password == "18821d89de11ab18488fdc0a01f1ddf4d290e198b0f80cd4974fc031dc2615a3":
			print(f"\nThe password is : { i.decode() } ")
			break
		else:
			print(f"Trying to decode... { password }",end="\r" ,flush=True)
