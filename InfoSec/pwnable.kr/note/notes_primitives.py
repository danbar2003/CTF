class NotesPrimitievs:
    
    def __init__(self, io) -> None:
        self._io = io

    @property
    def conn(self):
        return self._io


    def _validate_prompt(self) -> bytes:
        return self._io.recvuntil(b'5. exit\n')
    

    def create_note(self) -> int:
        self._validate_prompt()
        
        self._io.sendline(b'1')

        data = self._io.recvuntil(b']')
        data = data[data.find(b'[') + 1 : -1]

        return int(data, base=16)

    def write_note(self, index: int, data: bytes):

        assert b'\n' not in data

        self._validate_prompt()

        self._io.sendline(b'2')
        self._io.sendline(str(index).encode())
        self._io.sendline(data)

    def hackers_secret(self, data: bytes):
        self._validate_prompt()
        self._io.sendline(str(0x31337).encode())
        self._io.sendline(data)
