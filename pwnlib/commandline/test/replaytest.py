#!/usr/bin/python
import sys
import unittest
sys.path.append('../')
from replay import *
from pwn import *


class ReplayTest(unittest.TestCase):
    data64 = 0x7fe012345698
    data32 = 0xf7123456
    rust = 'aaaaaaa'

    def test_raw_amd64_little(self):
        context.update(arch='amd64', endian='little')
        payload = [
            p64(self.data64, endian='little') + self.rust,
            self.rust + p64(self.data64, endian='little'),
            self.rust + p64(self.data64, endian='little') + self.rust
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data64, 6, p.index('\x98'), 'raw'), msg='amd64, little, raw')
            self.assertIsNotNone(Address.parse(p, p.index('\x7f')))
    
    def test_raw_amd64_big(self):
        context.update(arch='amd64', endian='big')
        payload = [
            p64(self.data64, endian='big') + self.rust,
            self.rust + p64(self.data64, endian='big'),
            self.rust + p64(self.data64, endian='big') + self.rust
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data64, 6, p.index('\x7f'), 'raw'), msg='amd64, big, raw')
            self.assertIsNotNone(Address.parse(p, p.index('\x7f')))

    def test_raw_i386_little(self):
        context.update(arch='i386', endian='little')
        payload = [
            p32(self.data32, endian='little') + self.rust,
            self.rust + p32(self.data32, endian='little'),
            self.rust + p32(self.data32, endian='little') + self.rust,
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data32, 4, p.index('\x56'), 'raw'), msg='i386, little, raw')
            self.assertIsNotNone(Address.parse(p, p.index('\xf7')))

    def test_raw_i386_big(self):
        context.update(arch='i386', endian='big')
        payload = [
            p32(self.data32, endian='big') + self.rust,
            self.rust + p32(self.data32, endian='big'),
            self.rust + p32(self.data32, endian='big') + self.rust,
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data32, 4, p.index('\xf7'), 'raw'), msg='i386, big, raw')
            self.assertIsNotNone(Address.parse(p, p.index('\xf7')))

    def test_hex_amd64_little(self):
        context.update(arch='amd64', endian='little')
        payload = [
            '98563412e07f' + self.rust,
            self.rust + '98563412e07f',
            self.rust + '98563412e07f' + self.rust,
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data64, 12, p.index('9'), 'hex'), msg='amd64, little, hex')
            self.assertIsNotNone(Address.parse(p, p.index('f')))
  
    def test_hex_amd64_big(self):
        context.update(arch='amd64', endian='big')
        payload = [
            hex(self.data64)[2:] + self.rust,
            self.rust + hex(self.data64)[2:],
            self.rust + hex(self.data64)[2:] + self.rust,
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data64, 12, p.index('7'), 'hex'), msg='amd64, big, hex')
            self.assertIsNotNone(Address.parse(p, p.index('f')))

    def test_hex_i386_little(self):
        context.update(arch='i386', endian='little')
        payload = [
            '563412f7' + self.rust,
            self.rust + '563412f7',
            self.rust + '563412f7' + self.rust,
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data32, 8, p.index('5'), 'hex'), msg='i386, little, hex')
            self.assertIsNotNone(Address.parse(p, p.index('7')))

    def test_hex_i386_big(self):
        context.update(arch='i386', endian='big')
        payload = [
            hex(self.data32)[2:] + self.rust,
            self.rust + hex(self.data32)[2:],
            self.rust + hex(self.data32)[2:] + self.rust,
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data32, 8, p.index('f'), 'hex'), msg='i386, big, hex')
            self.assertIsNotNone(Address.parse(p, p.index('7')))

    def test_digital_amd64_payload(self):
        context.update(arch='amd64')
        payload = [
            str(self.data64) + self.rust,        
            self.rust + str(self.data64),
            str(self.data64) + self.rust,        
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data64, 15, p.index('1'), 'digital'), msg='amd64, digital')
            self.assertIsNotNone(Address.parse(p, p.rindex('4')))

    def test_digital_i386_payload(self):
        context.update(arch='i386')
        payload = [
            str(self.data32) + self.rust,        
            self.rust + str(self.data32),
            str(self.data32) + self.rust,        
        ]
        for p in payload:
            for i in range(len(p)):
                if Address.parse(p, i) is not None:
                    self.assertEqual(Address.parse(p, i), (self.data32, 10, p.index('4'), 'digital'), msg='i386, digital')
            self.assertIsNotNone(Address.parse(p, p.rindex('8')))
    
    def test_transformer(self):
        self.assertEqual(Address.transformAs(self.data64, 'amd64', 'little', 'raw'), (p64(self.data64, endian='little')))
        self.assertEqual(Address.transformAs(self.data64, 'amd64', 'big', 'raw'), (p64(self.data64, endian='big')))
        self.assertEqual(Address.transformAs(self.data32, 'i386', 'little', 'raw'), (p32(self.data32, endian='little')))
        self.assertEqual(Address.transformAs(self.data32, 'i386', 'big', 'raw'), (p32(self.data32, endian='big')))
        self.assertEqual(Address.transformAs(self.data64, 'amd64', 'little', 'hex'), '98563412e07f')
        self.assertEqual(Address.transformAs(self.data64, 'amd64', 'big', 'hex'), hex(self.data64)[2:])
        self.assertEqual(Address.transformAs(self.data32, 'amd64', 'little', 'hex'), '563412f7')
        self.assertEqual(Address.transformAs(self.data32, 'amd64', 'big', 'hex'), hex(self.data32)[2:])
        self.assertEqual(Address.transformAs(self.data32, 'amd64', 'little', 'digital'), str(data64))
        self.assertEqual(Address.transformAs(self.data32, 'i386', 'little', 'digital'), str(data32))

    # def test_1(self):
    #     context.update(arch='amd64', endian='little')
    #     print Address.parse('1 -173043456 115224226 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \n1.change num.\n2.get array.\n3.unique.\n4.exit.\n', 2)
    #     self.assertEqual(Address.parse('1 -173043456 115224226 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 \n1.change num.\n2.get array.\n3.unique.\n4.exit.\n', 2)[0], 0xf5af9100)


def main():
    unittest.main()

if __name__ == '__main__':
    main()