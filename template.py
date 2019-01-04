#!/usr/bin/python
from pwn import *
import sys

arch = 'x86_64'
elf_file = '/bin/sh'
libc_file = '/libctf/{}/libc-2.23.so'.format(arch)
elf = change_ld(elf_file, '/libctf/{}/ld-2.23.so'.format(arch))
elf = change_libc(elf, '/libctf/{}/libc-2.23.so'.format(arch))
mode = sys.argv[1].upper() if len(sys.argv) >= 2 else 'LOCAL'

context(arch = arch, os='linux', terminal=['terminator', '--new-tab', '-x'])

sh = None
if mode == 'LOCAL':
	sh = elf.process()
elif mode == 'REMOTE':
	sh = remote('111.198.29.45', 30006)
elif mode == 'DEBUG':
	context.update(log_level='debug')
	sh = gdb.debug(elf.path, '''
		b system
		c
	''')
elif mode == 'ATTACH':
	context.update(log_level='debug')
	sh = elf.process()
	gdb.attach(sh, '''
		b system
		c
	''')
else:
	exit(1)

rop = ROP(elf)
libc = ELF(libc_file)


def main():
	global sh, elf, rop, libc
	sh.interactive()

def cycfind():
	global sh, elf, rop, libc
	sh.sendline(cyclic(200))
	print(cyclic_find(0x61616177))

if __name__ == '__main__':
	main()
