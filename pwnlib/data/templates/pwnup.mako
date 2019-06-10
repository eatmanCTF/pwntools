<%page args="binary, host=None, port=None, user=None, password=None, remote_path=None, quiet=False"/>\
<%
import os
import sys

from pwnlib.context import context as ctx
from pwnlib.elf.elf import ELF
from pwnlib.util.sh_string import sh_string
from elftools.common.exceptions import ELFError

argv = list(sys.argv)
argv[0] = os.path.basename(argv[0])

try:
    if binary:
       ctx.binary = ELF(binary, checksec=False)
except ELFError:
    pass

if not binary:
    binary = './path/to/binary'

elf = os.path.basename(binary)

ssh = user or password
if ssh and not port:
    port = 22
elif host and not port:
    port = 4141

remote_path = remote_path or elf 
password = password or 'secret1234'
binary_repr = repr(binary)
%>\
#!/usr/bin/env python2
# -*- coding: utf-8 -*-
%if not quiet:
# This exploit template was generated via:
# $ ${' '.join(map(sh_string, argv))}
%endif
from pwn import *
from roputils import ROP
import re
import os
import time
import numpy as np
%if not quiet:
# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
%if host or port or user:
# ./exploit.py GDB HOST=example.com PORT=4141
%endif
%endif
%if host:
host = args.HOST or ${repr(host)}
%endif
%if port:
port = int(args.PORT or ${port})
%endif
%if user:
user = args.USER or ${repr(user)}
password = args.PASSWORD or ${repr(password)}
%endif
%if ssh:
remote_path = ${repr(remote_path)}
%endif

%if ssh:
# Connect to the remote SSH server
shell = None
if not args.LOCAL:
    shell = ssh(user, host, port, password)
    shell.set_working_directory(symlink=True)
%endif

%if elf or remote_path:
%if not quiet:
# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
%endif
gdbscript = '''
'''.format(**locals())
%endif

%if not quiet:
# Set up pwntools for the correct architecture
%endif

def attack(ip=None, port=None, local_test=False):
    if local_test:
        context.terminal = ["tmux", "splitw", "-h", "-p", "60"]
        pwn = Pwn(${binary_repr}, 
            src='2.27', 
            libs=[], 
            host=host, port=port, gdbscript=gdbscript)
        elf = context.binary = pwn.elf
        libc = pwn.libc
        rop = ROP(elf.path)
        io = pwn.start()
    else:
        elf = ELF(${binary_repr})
        libc = elf.libc
        rop = ROP(elf.path)
        io = remote(ip, port)
    flag = exp(io, libc, rop, elf)
    io.close()
    return flag
%if ctx.binary:
<% binary_repr = 'elf.path' %>
%else:
context.update(arch='i386')
<% binary_repr = 'elf' %>
%endif
%if not quiet:
#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
%else:
# -- Exploit goes here --
%endif
%if ctx.binary and not quiet:
# ${'%-10s%s-%s-%s' % ('Arch:',
                       ctx.binary.arch,
                       ctx.binary.bits,
                       ctx.binary.endian)}
%for line in ctx.binary.checksec(color=False).splitlines():
# ${line}
%endfor
%endif
def exp(io, libc, rop, elf):
    io.interactive()

%if not quiet:
# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)
%endif

if __name__ == "__main__":
    attack(local_test=True)