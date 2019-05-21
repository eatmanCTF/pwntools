# -*- coding: utf-8 -*-
"""Normal bytes
"""
import string
from pwnlib.log import getLogger

log = getLogger(__name__)

class Bytes(object):
    '''
    Normal bytes
    '''

    def __init__(self, byts):
        self._bytes = byts

    def __str__(self):
        return self.hexdump

    def __getitem__(self, key):
        return Bytes(self._bytes[key])

    def __len__(self):
        return len(self._bytes)

    @property
    def bytes(self):
        return self._bytes

    @property
    def length(self):
        return len(self.bytes)

    @property
    def content(self):
        return ''.join(chr(d) for d in self.bytes)

    @property
    def inline(self):
        return self.to_inline(self.content)

    @property
    def printable(self):
        return self.to_printable(self.content)

    @property
    def hexdump(self):
        return self.to_hex(self.content)

    @staticmethod
    def to_inline(content):
        inline = ''
        for c in content:
            d = ord(c)
            if d == 34:
                inline += '\\"'
            elif d == 0x5c:
                inline += '\\\\'
            elif d >= 32 and d <= 126:
                inline += c
            elif d == 10 or d == 13:
                inline += '\\n'
            else:
                inline += '\\x' + hex(d)[2:].rjust(2, '0')
        return inline

    @staticmethod
    def to_printable(content):
        printable = ''
        for c in content:
            d = ord(c)
            if chr(d) in string.printable and d != 0xb and d != 0xc and d != 0x5c:
                printable += chr(d)
            elif d == 0x5c:
                printable += '\\\\'
            else:
                printable += '\\x' + hex(d)[2:].rjust(2, '0')
        return printable

    @staticmethod
    def to_hex(content):
        return ''.join(['\\x' + hex(ord(c))[2:].rjust(2, '0') for c in content])

    def get_inline(self, start=None, end=None):
        return self.to_inline(self.content[start:end])

    def get_printable(self, start=None, end=None):
        return self.to_printable(self.content[start:end])

