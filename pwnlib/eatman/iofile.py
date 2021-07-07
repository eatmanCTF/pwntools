from __future__ import absolute_import

# from pwnlib.context import context
# from pwnlib import gdb
# from pwnlib.args import args
# from pwnlib.elf import ELF
# from pwnlib.asm import asm
# from pwnlib.log import Logger, getLogger
# from pwnlib.util.packing import u32, u64, p32, p64, make_packer

from ctypes import *

class IO_File(Structure):
    _pack_ = 4

    @staticmethod
    def init():
        return IO_File(flags=0xfbad2887)

IO_File._fields_ = [
    # High-order word is _IO_MAGIC; rest is flags.
    ('flags', c_uint32),

    # The following pointers correspond to the C++ streambuf protocol. */
    ('_IO_read_ptr', c_uint64),
    ('_IO_read_end', c_uint64),
    ('_IO_read_base', c_uint64),
    ('_IO_write_base', c_uint64),
    ('_IO_write_ptr', c_uint64),
    ('_IO_write_end', c_uint64),
    ('_IO_buf_base', c_uint64),
    ('_IO_buf_end', c_uint64),
    ('_IO_buf_end', c_uint64),
    ('_IO_buf_end', c_uint64),

    # The following fields are used to support backing up and undo.
    ('_IO_save_base', c_uint64),
    ('_IO_backup_base', c_uint64),
    ('_IO_save_end', c_uint64),

    #
    ('_markers', c_uint64),

    #
    ('_chain', c_uint64),

    #
    ('_fileno', c_uint32),
    ('_flags2', c_uint32),
    ('_oldoffset', c_uint64),

    # 1+column number of pbase(); 0 is unknown. */
    ('_cur_column', c_uint16),
    ('_vtable_offset', c_uint8),
    ('_shortbuf', c_uint8),
    
    # 
    ('_lock', c_uint64),

    #  Wide character stream stuff.
    ('_offset', c_uint64),
    ('_codecvt', c_uint64),
    ('_wide_data', c_uint64),
    ('_freeres_list', c_uint64),
    ('__pad5', c_uint64),
    ('_mode', c_uint32),
    ('_unused1', c_uint64),
    ('_unused2', c_uint64),
    ('_unused3', c_uint32),
    ('vtable', c_uint64),
]