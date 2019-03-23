#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import string
import sys
import pwnlib
from pwnlib.term import text
import numpy as np
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common

DIRECTION_RECV = str(1)
DIRECTION_SEND = str(0)

def get_dir_files(path):
    fnames = []
    if os.path.isdir(path):
        for fname in os.listdir(path):
            abs_fname = os.path.join(path, fname)
            if os.path.isfile(abs_fname):
                fnames.append(abs_fname)
        return fnames
    else:
        log.critical('Given path:{} is not a valid path"'.format(path))
        sys.exit(1)

parser = common.parser_commands.add_parser(
    'replay',
    help = "Replay attack helper"
)

parser.add_argument(
    '--path',
    nargs='?',
    type=get_dir_files,
    help='Directory for storing data files'
)

parser.add_argument(
    '--host',
    nargs='?',
    type=str,
    help='Remote attack host address'
)

parser.add_argument(
    '--port',
    nargs='?',
    type=int,
    help='Remote attack port'
)

parser.add_argument(
    '--elf',
    nargs='?',
    type=argparse.FileType('r'),
    help='Elf file for local test'
)

parser.add_argument(
    '--timeout',
    nargs='?',
    type=int,
    help='Remote attack recieve timeout'
)

parser.add_argument(
    '--template',
    nargs='?',
    type=argparse.FileType('r'),
    help='Template for script generate, must be one of infiles'
)

parser.add_argument(
    '--no-comment',
    action = 'store_true',
    help = 'Do not display comments',
)

parser.add_argument(
    '--no-autofix',
    action = 'store_true',
    help = 'Do not do auto fix',
)

parser.add_argument(
    'infiles',
    nargs='*',
    type=argparse.FileType('r'),
    help='Wireshark c-array type data file'
)

parser.add_argument(
    '--recvuntil',
    action = 'store_true',
    default = False,
    help = 'Use recvuntil instead of recv',
)

parser.add_argument(
    '--endian',
    action = 'store',
    default = 'little',
    type = str,
    choices = ['little', 'big'],
    help = 'Received address is big endian',
)

parser.add_argument(
    '--test',
    action = 'store_true',
    default = False,
    help = 'Do all tests',
)


class Address(object):

    def __init__(self, peer, cdata, position, addr_type, val, length):
        self.id = 0
        self.peer = peer
        self.cdata = cdata
        self.position = position
        self.type = addr_type
        self.val = val
        self.length = length
        self.hex = hex(val)

    @staticmethod
    def get_handlers():
        # handlers['parser']
        # param1: cdata (chr mode)
        # param2: parse position
        # return: (val, length, real position)

        # handlers['transformer']
        # param1: value (int)
        # return: cdata (chr mode)
        return [
            {'type': 'raw', 'arch': 'amd64', 'endian': 'little', 'parser': Address.parse_raw_amd64_little, 'transformer': Address.trans_raw_amd64_little},
            {'type': 'raw', 'arch': 'amd64', 'endian': 'big', 'parser': Address.parse_raw_amd64_big, 'transformer': Address.trans_raw_amd64_big},
            {'type': 'raw', 'arch': 'i386', 'endian': 'little', 'parser': Address.parse_raw_i386_little, 'transformer': Address.trans_raw_i386_little},
            {'type': 'raw', 'arch': 'i386', 'endian': 'big', 'parser': Address.parse_raw_i386_big, 'transformer': Address.trans_raw_i386_big},
            {'type': 'hex', 'arch': 'amd64', 'endian': 'little', 'parser': Address.parse_hex_amd64_little, 'transformer': Address.trans_hex_amd64_little},
            {'type': 'hex', 'arch': 'amd64', 'endian': 'big', 'parser': Address.parse_hex_amd64_big, 'transformer': Address.trans_hex_amd64_big},
            {'type': 'hex', 'arch': 'i386', 'endian': 'little', 'parser': Address.parse_hex_i386_little, 'transformer': Address.trans_hex_i386_little},
            {'type': 'hex', 'arch': 'i386', 'endian': 'big', 'parser': Address.parse_hex_i386_big, 'transformer': Address.trans_hex_i386_big},
            {'type': 'digital', 'arch': 'amd64', 'endian': 'little', 'parser': Address.parse_digital_amd64, 'transformer': Address.trans_digital_amd64},
            {'type': 'digital', 'arch': 'amd64', 'endian': 'big', 'parser': Address.parse_digital_amd64, 'transformer': Address.trans_digital_amd64},
            {'type': 'digital', 'arch': 'i386', 'endian': 'little', 'parser': Address.parse_digital_i386, 'transformer': Address.trans_digital_i386},
            {'type': 'digital', 'arch': 'i386', 'endian': 'big', 'parser': Address.parse_digital_i386, 'transformer': Address.trans_digital_i386},
        ]


    @staticmethod
    def parse_raw_amd64_little(data, i):
        # parse 64-bit little-endian raw address to value. eg. '\x78\x56\x34\x12\xf0\x7f' ==> 0x7ff012345678
        if data[i] in [chr(0x7f)] and i >= 5:
            return u64(data[i-5:i+1].ljust(8, '\x00'), endian='little'), 6, i-5
        else:
            return None

    @staticmethod
    def trans_raw_amd64_little(value):
        # translate value to 64-bit little-endian raw address. eg. 0x7ff012345678 ==> '\x78\x56\x34\x12\xf0\x7f'
        try:
            res = p64(value, endian='little')
        except:
            return None
        return res

    @staticmethod
    def parse_raw_amd64_big(data, i):
        # parse 64-bit big-endian raw address to value. eg. 'x7f\xf0\x12\34\x56\x78' ==> 0x7ff012345678
        if data[i] in [chr(0x7f)] and len(data) - i >= 6:
            return u64(data[i:i+6].rjust(8, '\x00'), endian='big'), 6, i
        else:
            return None

    @staticmethod
    def trans_raw_amd64_big(value):
        # translate value to 64-bit big-endian raw address. eg. 0x7ff012345678 ==> 'x7f\xf0\x12\34\x56\x78'
        try:
            res = p64(value, endian='big')
        except:
            return None
        return res


    @staticmethod
    def parse_raw_i386_little(data, i):
        # parse 32-bit little-endian raw address to value. eg. 'x56\x34\x12\xf7' ==> 0xf7123456
        if data[i] in [chr(0xf7)] and i >= 3:
            return u32(data[i-3:i+1], endian='little'), 4, i-3
        else:
            return None

    @staticmethod
    def trans_raw_i386_little(value):
        # translate value to 32-bit little-endian raw address. eg. 0xf7123456 ==> 'x56\x34\x12\xf7'
        try:
            res = p32(value, endian='little')
        except:
            return None
        return res


    @staticmethod
    def parse_raw_i386_big(data, i):
        # parse 32-bit big-endian raw address to value. eg. '\xf7\x12\x34\x56' ==> 0xf7123456
        if data[i] in [chr(0xf7)] and len(data) - i >= 4:
            return u32(data[i:i+4], endian='big'), 4, i
        else:
            return None

    @staticmethod
    def trans_raw_i386_big(value):
        # translate value to 32-bit big-endian raw address. eg. 0xf7123456 ==> '\xf7\x12\x34\x56'
        try:
            res = p32(value, endian='big')
        except:
            return None
        return res


    @staticmethod
    def parse_hex_amd64_little(data, i):
        # parse 64-bit little-endian hex address to value. eg. '78563412f07f' ==> 0x7ff012345678
        if int(data[i-1:i+1], 16) in [0x7f] and i >= 11:
            value_list = [data[i-11+2*j:i-11+2*(j+1)] for j in range(len(data[i-11:i+1]) // 2)]
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return r, 12, i-11
        else:
            return None

    @staticmethod
    def trans_hex_amd64_little(value):
        return ""

    @staticmethod
    def parse_hex_amd64_big(data, i):
        # parse 64-bit big-endian hex address to value. eg. '7ff012345678' ==> 0x7ff012345678
        if int(data[i-1:i+1], 16) in [0x7f] and len(data) - i >= 11:
            value_list = [data[i-1+2*j:i-1+2*(j+1)] for j in range(len(data[i-1:i+11]) // 2)]
            value_list.reverse()
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return r, 12, i-1
        else:
            return None

    @staticmethod
    def trans_hex_amd64_big(value):
        return ""

    @staticmethod
    def parse_hex_i386_little(data, i):
        # parse 32-bit little-endian hex address to value. eg. '563412f7' ==> 0xf7123456
        if int(data[i-1:i+1], 16) in [0xf7] and i >= 7:
            value_list = [data[i-7+2*j:i-7+2*(j+1)] for j in range(len(data[i-7:i+1]) // 2)]
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return r, 8, i-7
        else:
            return None

    @staticmethod
    def trans_hex_i386_little(value):
        return ""

    @staticmethod
    def parse_hex_i386_big(data, i):
        # parse 32-bit big-endian hex address to value. eg. 'f7123456' ==> 0xf7123456
        if int(data[i-1:i+1], 16) in [0xf7] and len(data) - i >= 7:
            value_list = [data[i-1+2*j:i-1+2*(j+1)] for j in range(len(data[i-1:i+7]) // 2)]
            value_list.reverse()
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return r, 8, i-1
        else:
            return None

    @staticmethod
    def trans_hex_i386_big(value):
        return ""

    @staticmethod
    def parse_digital_amd64(data, i):
        # parse 64-bit digital address to value. eg. '140737488355327' ==> 0x7ff012345678
        digital = int(data[i-14:i+1])
        if digital >= 0x7effffffffff and digital <= 0x7fffffffffff:
            return digital, 15, i-14
        else:
            return None

    @staticmethod
    def trans_digital_amd64(value):
        return ""

    @staticmethod
    def parse_digital_i386(data, i):
        # parse 32-bit digital address to value. eg. '4160749567' ==> 0xf7123456
        digital = int(data[i-9:i+1])
        if digital >= 0xf6ffffff and digital <= 0xf7ffffff:
            return digital, 10, i-9
        else:
            return None

    @staticmethod
    def trans_digital_i386(value):
        return ""

    def transform(self):
        handlers = filter(lambda x: x['arch'] == context.arch and x['endian'] == context.endian and x['type'] == self.type, Address.get_handlers())
        if len(handlers) > 0:
            handler = handlers[0]
            res = handler['transformer'](self.val)
            if res is None:
                raise Exception('transform failed!')
            return res, len(res)

        else:
            raise Exception('unknow arch, endian or type')

    @staticmethod
    def transformAs(value, arch, endian, addr_type):
        handlers = filter(lambda x: x['arch'] == arch and x['endian'] == endian and x['type'] == addr_type, Address.get_handlers())
        if len(handlers) > 0:
            handler = handlers[0]
            res = handler['transformer'](value)
            if res is None:
                raise Exception('transform failed!')
            return res

        else:
            raise Exception('unknow arch, endian or type')

    @staticmethod
    def parse(data, i):
        for handler in filter(lambda x: x['arch'] == context.arch and x['endian'] == context.endian, Address.get_handlers()):
            try:
                res = handler['parser'](data, i)
                if  res is not None:
                    return res[0], res[1], res[2], handler['type']
            except:
                continue
        return None

    @staticmethod
    def parseAs(data, arch, endian, addr_type):
        handlers = filter(lambda x: x['arch'] == arch and x['endian'] == endian and x['type'] == addr_type, Address.get_handlers())
        res = None
        if len(handlers) > 0:
            handler = handlers[0]
            for i in range(len(data)):
                try:
                    res = handler['parser'](data, i)
                    if res is not None:
                        break
                except:
                    continue
            else:
                raise Exception('parse failed!')
            return res[0]
        else:
            raise Exception('unknow arch, endian or type')

class PeerBytes(object):

    def __init__(self, data, direction, idx):
        self.addr_list = []
        self.data = data
        self.direction = direction
        self.idx = idx
        self.walk()

    @property
    def length(self):
        return len(self.data)

    @property
    def cdata(self):
        return ''.join(self._cdata(d) for d in self.data)
    
    @property
    def inline_content(self):
        return ''.join(self._inline_content(d) for d in self.data)
    
    @property
    def readable_content(self):
        return ''.join(self._readable_content(d) for d in self.data)
    
    @property
    def hex_content(self):
        return ''.join(self._hex_content(d) for d in self.data)

    @staticmethod
    def _cdata(d):
        return chr(d)

    @staticmethod
    def _inline_content(d):
        if d >= 32 and d <= 126:
            return chr(d)
        elif d == 10 or d == 13:
            return '\\n'
        else:
            return '\\x' + hex(d)[2:].rjust(2, '0')

    @staticmethod
    def _readable_content(d):
        if d >= 32 and d <= 126:
            return chr(d)
        elif d == 10 or d == 13:
            return '\\n'
        else:
            return '\\x' + hex(d)[2:].rjust(2, '0')

    @staticmethod
    def _hex_content(d):
        return '\\x' + hex(d)[2:].rjust(2, '0')

    def get_inline_content(self, start=None, end=None):
        return ''.join(self._inline_content(d) for d in self.data[start:end])

    def walk(self):
        data = self.data
        cdata = self.cdata
        for i, v in enumerate(cdata):
            addr = Address.parse(cdata, i)
            if addr is not None:
                val, length, position, addr_type = addr
                self.addr_list.append(Address(self, cdata, position, addr_type, val, length))

class DataFile(object):

    def __init__(self, fd):
        self.name = fd.name
        self.peer_list = []
        self.addr_list = []
        self.offset_list = []
        self.weight = 0
        p = re.compile(r'char peer(?P<direction>\d+)_(?P<id>\d+)\[\] = { \/\* Packet \d+ \*\/(?P<data>[^\}]*)};')
        fdata = fd.read()
        addr_id = 0
        for m in re.finditer(p, fdata):
            data = [int(d[:4], 16) for d in m.group('data').split()]
            direction = m.group('direction')
            idx = m.group('id')
            peer = PeerBytes(data, direction, idx)
            self.peer_list.append(peer)
            for addr in peer.addr_list:
                addr.id = addr_id
                self.addr_list.append(addr)
                addr_id += 1
        self.find_offset()

    @property
    def recv_addr_list(self):
        return self._get_addr_list(DIRECTION_RECV)
    
    @property
    def send_addr_list(self):
        return self._get_addr_list(DIRECTION_SEND)


    def _get_addr_list(self, direction):
        return filter(lambda ad: ad.peer.direction == direction, self.addr_list)
    
    def find_offset(self):
        for raddr in self.recv_addr_list:
            for saddr in self.send_addr_list:
                # if recvived offset is coming before sent offset
                if raddr.id < saddr.id:
                    val = raddr.val-saddr.val
                    self.offset_list.append({'recv': raddr, 'send': saddr, 'val': val, 'hex': hex(val), 'weight': 0})

    @staticmethod
    def compare(df1, df2):
        for of1 in df1.offset_list:
            for of2 in df2.offset_list:
                # add weight if offset's value matches
                if of1['val'] == of2['val']:
                    of1['weight'] += 1
                    of2['weight'] += 1
                    df1.weight += 1
                    df2.weight += 1
                    # add weight if addr's last 12bits matches
                    if of1['recv'].val & 0xfff == of2['recv'].val & 0xfff:
                        of1['weight'] += 1
                        of2['weight'] += 1
                        df1.weight += 1
                        df2.weight += 1

class ReplayScript(object):
    alternate_colors = [
        text.red,
        text.green,
        text.blue,
        text.yellow,
        text.cyan
    ]

    content = [
        '#!/usr/bin/python',
        'from pwn import *',
        'from pwnlib.commandline.replay import Address',
        'context.terminal = ["terminator", "--new-tab", "-e"]',
        'if args.REMOTE:',
        '\tio = remote("{}", {})',
        'else:',
        '\tio = ELF("{}").process()',
        '\tif args.GDB:'
        '\t\tgdb.attach(io, "c")',
    ]

    def __init__(self, args):
        self.files = args.infiles or []
        self.host = args.host or '127.0.0.1'
        self.port = args.port or 9999
        if not args.elf:
            log.warn('You did not specify the ELF file, which will cause the local test to fail!')
        self.elf = ELF(args.elf.name) if args.elf is not None else ELF('/bin/sh')
        context.update(arch = self.elf.arch)
        context.update(endian = args.endian)
        self.df_list = []
        self.recv_timeout = args.timeout or 3
        self.no_comment = args.no_comment
        self.no_fix = args.no_autofix
        self.template = DataFile(args.template) if args.template is not None else None
        self._alternate_color_count = -1
        self.recvuntil = args.recvuntil
        self.analysis()

    def analysis(self):
        for f in self.files:
            if type(f) == str:
                if self.template and f == self.template.name:
                    continue
                with open(file_peer_map, 'rb') as fin:
                    self.df_list.append(DataFile(fin))
            elif type(f) == file:
                if self.template and f.name != self.template.name:
                    continue
                self.df_list.append(DataFile(f))

        if not self.template:
            for i in range(0, len(self.df_list)):
                for j in range(i+1, len(self.df_list)):
                    DataFile.compare(self.df_list[i], self.df_list[j])
            self.template = self.df_list[0]
            for df in self.df_list:
                if df.weight > self.template.weight:
                    self.template = df
        else:
            for df in self.df_list:
                if df.name != self.template.name:
                    DataFile.compare(self.template, df)

    def _output_comment(self, string, textcolor=None):
        if not textcolor:
            textcolor = text.magenta
        if not self.no_comment:
            sys.stdout.write(textcolor("# " + string))

    def _output(self, string, textcolor=None):
        if not textcolor:
            textcolor = str
        sys.stdout.write(textcolor(string))

    def get_alternate_color(self):
        self._alternate_color_count += 1
        return self.alternate_colors[self._alternate_color_count % len(self.alternate_colors)]

    def generate(self):
        df = self.template
        valid_offset_list = []
        for send_addr in df.send_addr_list:
            send_id = send_addr.id
            valid_offset = None
            for (i, offset) in enumerate(df.offset_list):
                if offset['send'].id == send_id:
                    if (not valid_offset) or (offset['weight'] > valid_offset['weight']):
                        valid_offset = offset
                        valid_offset['id'] = i
            if valid_offset:
                valid_offset_list.append(valid_offset)


        self._output('\n'.join(self.content).format(self.host, self.port, self.elf.file.name) + '\n')
        self._output_comment('Using template: {}\n'.format(self.template.name))

        for peer in df.peer_list:
            if peer.direction == DIRECTION_RECV:
                self._output_comment('Received peer{}_{}:\n'.format(peer.direction, peer.idx))
                # recvived peer may be repeated
                recvived = False
                for vof in valid_offset_list:
                    if peer is vof['recv'].peer:
                        raddr = vof['recv']
                        if 'color' not in vof:
                            vof['color'] = self.get_alternate_color() 
                        self._output_comment('[VOF_R{}]\taddr:{}\tpos:{}\toffset_val:{}\n'.format(vof['id'], raddr.hex, raddr.position, vof['hex']), vof['color'])
                        if not self.no_fix:
                            if not recvived:
                                self._output('io.recv({})\n'.format(raddr.position))
                                self._output('tmp = Address.parseAs(io.recv({}), "{}", "{}", "{}")\n'.format(raddr.length, context.arch, context.endian, raddr.type))
                                self._output('addr_recv_{} = tmp\n'.format(vof['id']))
                                self._output('io.recv({}, timeout={})\n'.format(peer.length - int(raddr.position) - raddr.length, self.recv_timeout))
                                recvived = True
                            else:
                                self._output('addr_recv_{} = tmp\n'.format(vof['id']))
                        else:
                            break
                else:
                    if self.recvuntil and not recvived:
                        self._output('io.recvuntil("{}", timeout={}, expect="{}", mark="peer_1_{}")\n'.format(
                            peer.get_inline_content(-5 if peer.length >= 5 else -1), self.recv_timeout, peer.inline_content, peer.idx))
                    elif not recvived:
                        self._output('io.recv({}, timeout={}, expect="{}", mark="peer_1_{}")\n'.format(
                            peer.length, self.recv_timeout, peer.inline_content, peer.idx))

            elif peer.direction == DIRECTION_SEND:
                self._output_comment('Sending peer{}_{}:\n'.format(peer.direction, peer.idx))
                # send peer will not be repeated
                for vof in valid_offset_list:
                    if peer is vof['send'].peer:
                        raddr = vof['recv']
                        saddr = vof['send']
                        if 'color' not in vof:
                            vof['color'] = self.get_alternate_color() 
                        self._output_comment('[VOF_S{}]\taddr:{}\tpos:{}\toffset_val:{}\n'.format(vof['id'], saddr.hex, saddr.position, vof['hex']), vof['color'])
                        if not self.no_fix:
                            self._output('addr_send_{} = addr_recv_{} - {} + {}\n'.format(vof['id'], vof['id'], raddr.hex, saddr.hex))
                            self._output('payload = "{}"\n'.format(peer.get_inline_content(0, int(saddr.position))))
                            addr_length = saddr.transform()[1]
                            self._output('payload += Address.transformAs(addr_send_{}, "{}", "{}", "{}")\n'.format(vof['id'], context.arch, context.endian, saddr.type))
                            self._output('payload += "{}"\n'.format(peer.get_inline_content(int(saddr.position)+addr_length)))
                            self._output('io.send(payload)\n')
                        else:
                            self._output('payload = "{}"'.format(peer.inline_content))
                            self._output('io.send(payload)\n')
                        break
                else:
                    self._output('payload = "{}"\n'.format(peer.inline_content))
                    self._output('io.send(payload)\n')
        sys.stdout.write('io.interactive()\n')

def main(args):
    rs = ReplayScript(args)
    rs.generate()


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
