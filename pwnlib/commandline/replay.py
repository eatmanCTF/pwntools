#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

from pwnlib.commandline import common
from pwnlib.replay import *
from pwnlib.term import text
from pwnlib.log import getLogger
from pwnlib.context import context
from pwnlib.elf.elf import ELF
from pwnlib.exception import PwnlibException
from pwnlib.args import free_form
import argparse, textwrap
import sys
import os
import re

free_form = False
log = getLogger(__name__)

parser = common.parser_commands.add_parser(
    'replay',
    help='Replay attack helper',
    formatter_class=argparse.RawTextHelpFormatter,
    description=textwrap.dedent('''\
    Example:
    replay --elf [ELF] --p2p --wireshark --host [HOST] --port [PORT] ./ > replay.py
    replay --hexdump peer0_0 --wireshark ./
    '''))

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
    help='Local test target'
)

parser.add_argument(
    '--ld',
    nargs='?',
    type=str,
    default='',
    help='ld for local test',
)

parser.add_argument(
    '--libc',
    nargs='?',
    type=str,
    default='',
    help='libc for local test',
)

parser.add_argument(
    '--lib223',
    action='store_true',
    default=False,
    help='use libc-2.23.so and ld-2.23.so in ubuntu 16',
)

parser.add_argument(
    '--timeout',
    nargs='?',
    type=int,
    help='Blocking time when receiving packet'
)

parser.add_argument(
    '--template',
    nargs='?',
    type=argparse.FileType('r'),
    help='Template for script generate, must be one of infiles'
)

parser.add_argument(
    '--quiet',
    action='store_true',
    help='Do not display comments',
)

parser.add_argument(
    '-l',
    '--level',
    nargs='?',
    type=int,
    default=7,
    help=textwrap.dedent('''\
    Address Level: R_F8|R_M28|R_L12|R_0 
    R_F8: First 8 bits of received addresses must same
    R_M28: Middle 28 bits of received addresses must be different
    R_L12: Last 12 bits of received addresses must same 
    R_0: offset value must not equals to 0
    '''))

parser.add_argument(
    '--no-auto',
    action='store_true',
    default=False,
    help='Do not do auto difference analysis',
)

parser.add_argument(
    '--no-expect',
    action='store_true',
    default=False,
    help='Do not do expect analysis',
)

parser.add_argument(
    '--no-pause',
    action='store',
    default='none',
    type=str,
    choices=['none', 'recv', 'send', 'all'],
    help='Do not pause at sending different detected',
)

parser.add_argument(
    'infiles',
    nargs='*',
    type=str,
    help='Formatted json file(.json) or wireshark\'s c-array file(.carray)'
)

parser.add_argument(
    '--recvuntil',
    action='store_true',
    default=False,
    help='Use recvuntil instead of determin',
)

parser.add_argument(
    '--recvn',
    action='store_true',
    default=False,
    help='Use recvn instead of auto determin',
)

parser.add_argument(
    '-c',
    '--combine',
    action='store_true',
    default=False,
    help='Combine received bytes (default true in p2p mode, otherwise false)',
)

parser.add_argument(
    '--p2p',
    action='store_true',
    default=False,
    help='Analysis in peer-to-peer mode (advanced)',
)

parser.add_argument(
    '--p2p-strict',
    action='store_true',
    default=False,
    help='Analysis in peer-to-peer strict mode (advanced)',
)

parser.add_argument(
    '--endian',
    action='store',
    default='little',
    type=str,
    choices=['little', 'big'],
    help='Received address is big endian',
)

parser.add_argument(
    '--wireshark',
    action='store_true',
    default=False,
    help='Input files are wireshark c-array format',
)

parser.add_argument(
    '-ch',
    '--custom-handler',
    action='store',
    nargs='?',
    type=str,
    default='',
    help='Custom handler script(use -ct to generate custom handler script\'s template file)'
)

parser.add_argument(
    '-ct',
    '--custom-template',
    action='store_true',
    default=False,
    help='Generate custom handler template file',
)

parser.add_argument(
    '--hexdump',
    action='store',
    type=str,
    default='',
    help='Hexdump given peer\'s data',
)

parser.add_argument(
    '--test',
    action='store_true',
    default=False,
    help='Do all tests',
)


class ReplayScript(object):
    alternate_colors = [
        text.red,
        text.green,
        text.blue,
        text.yellow,
        text.cyan
    ]

    content_head = [
        '#!/usr/bin/python',
        'from pwn import *',
        'from pwnlib.replay import Address',
        '',
        'def attack(ip=None, port=None, local_test=False):',
        '    pwn = Pwn("{}", src="2.27", libs=[{}{}], host="{}", port={})',
        '    if local_test:',
        '        context.terminal = ["tmux", "splitw", "-h"]',
        '    else:',
        '        args.REMOTE=True',
        '    io = pwn.start()',
    ]
    content_tail = [
        'if __name__ == "__main__":',
        '    attack(local_test=True)',
    ]

    def __init__(self, args):
        self.files = args.infiles or []
        self.host = args.host or '127.0.0.1'
        self.port = args.port or 9999
        if not args.elf:
            log.warn(
                'You did not specify the ELF file, which will cause the local test to fail!')
        self.elf = ELF(
            args.elf.name) if args.elf is not None else ELF('/bin/sh')
        context.update(arch=self.elf.arch)
        context.update(endian=args.endian)
        self.df_list = []
        self.template = args.template or None
        self.recv_timeout = args.timeout or 3
        self.quiet = args.quiet
        self.no_auto = args.no_auto
        self.custom_handler = args.custom_handler
        self._alternate_color_count = -1
        self.recvuntil = args.recvuntil
        self.recvn = args.recvn
        self.do_expect_analysis = not args.no_expect
        self.no_pause = args.no_pause
        self.wireshark_format = args.wireshark
        self.combine = args.combine if not args.p2p and not args.p2p_strict else True
        self.p2p = args.p2p or args.p2p_strict
        self.strict = args.p2p_strict
        self.ld = args.ld if not args.lib223 else '/mnt/hgfs/share/git/libc-database/db/ld_2.23-0ubuntu10_{}.so'.format(
            self.elf.arch)
        self.libc = args.libc if not args.lib223 else '/mnt/hgfs/share/git/libc-database/db/libc6_2.23-0ubuntu10_{}.so'.format(
            self.elf.arch)

        for f in self.files:
            if os.path.isfile(f):
                if self.template and f != self.template_file.name:
                    continue
                self.df_list.append(
                    DataFile(f, self, wireshark_format=self.wireshark_format))
            elif os.path.isdir(f):
                for fname in os.listdir(f):
                    abs_fname = os.path.join(f, fname)
                    ext = os.path.splitext(fname)[1][1:]
                    if self.wireshark_format and ext != 'carray':
                        continue
                    if not self.wireshark_format and ext != 'json':
                        continue
                    if os.path.isfile(abs_fname):
                        self.df_list.append(
                            DataFile(abs_fname, self, wireshark_format=self.wireshark_format))
            else:
                log.critical(
                    'Given path:{} is not a valid path or file name'.format(f))
                sys.exit(-1)
        if not self.df_list:
            log.critical('No valid data file was found')
            sys.exit(-1)

    @property
    def template_file(self):
        """
        if template is specified, use it
        else use the data file whose wight is highest
        """
        if self.template is not None:
            return DataFile(self.template, self, wireshark_format=self.wireshark_format)
        if not len(self.df_list):
            return None
        template = self.df_list[0]
        # log.info(template.name + ": " + str(template.weight))
        for df in self.df_list:
            # log.info(df.name + ": " + str(df.weight))
            if df.weight > template.weight:
                template = df
        return template

    def _output_comment(self, string, textcolor=None, debug=False):
        if not textcolor:
            textcolor = text.magenta
        if not self.quiet:
            sys.stdout.write(textcolor("# " + str(string).replace("\n", "\n#") + "\n"))
        if debug:
            log.debug(str(string))

    def _output(self, string, textcolor=None, valid=True):
        if not textcolor:
            textcolor = str
        if valid:
            sys.stdout.write('    ' + textcolor(string))
        else:
            sys.stdout.write('    ' + '\'\'\'' +
                             textcolor(string) + '\'\'\'\n')

    def _get_alternate_color(self):
        self._alternate_color_count += 1
        return self.alternate_colors[self._alternate_color_count % len(self.alternate_colors)]

    def _render_receive(self, peer, start, end, expected_recv=[]):
        if not start < end:
            return
        expected_content = None
        if expected_recv:
            expected_recv.sort(key=lambda recv: recv[0].position)
            expected_content = '"""'
            numb = start
            l = []
            for raddr, of in expected_recv:
                if numb <= raddr.position:
                    expected_content += peer.content[numb:raddr.position]
                    expected_content += '{}'
                    l.append((raddr, of))
                    numb = raddr.position + raddr.length
            expected_content += peer.content[numb:end]
            expected_content += '""".format(' + ', '.join(
                ['\n        Address.transformAs({}, "{}", "{}", "{}")'.format(
                    'addr_recv_{} - {} + {}'.format(
                        of.saddr.id, of.raddr.hex, raddr.hex), raddr.arch, raddr.endian, raddr.type
                ) for raddr, of in l]
            ) + ')'
            expected_content = Bytes.to_printable(expected_content)
        if peer[start:end].tail_character is None:
            if peer.recv_method == 'recvuntil':
                self._output(
                    'log.warn("{} length is too long and cannot handled by recvn, so it is treated as an useless recv")\n'.format(peer.name))
                self._output(
                    'io.recvrepeat(timeout={})\n'.format(self.recv_timeout))
                return
        else:
            self._output('io.recvuntil("{}", timeout={}, template=\n"""{}""", {} mark="{}", retrieve="", pause={})\n'.format(
                peer[start:end].tail_character, self.recv_timeout, peer[start:end].printable,
                'expect=\n{}, '.format(
                    expected_content) if expected_content else '', peer.name, str(self.no_pause in ['send', 'none'])
            ), valid=self.recvuntil or peer.recv_method == 'recvuntil')
        self._output('io.recvn({}, timeout={}, template=\n"""{}""", {}mark="{}", retrieve="", pause={})\n'.format(
            peer[start:end].length, self.recv_timeout, peer[start:end].printable,
            'expect=\n{}, '.format(
                expected_content) if expected_content else '', peer.name, str(self.no_pause in ['send', 'none'])
        ), valid=self.recvn or peer.recv_method == 'recvn')

    def _render_received_peer(self, peer, relation_list):
        self._output_comment('*' * 100)
        self._output_comment('Received {}:'.format(peer.name))
        self._output_comment('*' * 100)
        # peer_offsets: all offsets matched peer
        peer_offsets = [rel for rel in relation_list if type(rel) == Offset
                        and peer in [offset.raddr.peer for offset in rel.all()]]
        walking_raddr = []
        for of in peer_offsets:
            for raddr in (of.get_rdiff_by_peer(peer)):
                walking_raddr.append((raddr, of))
        walking_raddr.sort(key=lambda x: x[0].position)
        # numb: bytes that has received
        numb = 0
        expected_recv = []
        for raddr, vof in walking_raddr:
            saddr = vof.saddr
            if raddr.same_as is None:
                # first raddr that contains information in a offset object
                if vof.color is None:
                    vof.color = self._get_alternate_color()
                self._output_comment('[VOF_R{}]\taddr:{}\tpos:{}\toffset_val:{}'.format(
                    vof.id, raddr.hex, raddr.position, vof.hex), vof.color)
                if not raddr.related_to:
                    # receive this raddr first time, do actual receive and numb goes forward
                    if numb > int(raddr.position):
                        log.warn('address conflict in {}\naddr: {} at {}, while handling at byte {}'.format(
                            peer.name, raddr.hex, raddr.position, numb))
                        continue
                    self._render_receive(
                        peer, numb, raddr.position, expected_recv=expected_recv)
                    self._output(
                        'res = io.recvn({})\n'.format(raddr.length))
                    self._output('try:\n')
                    self._output('    res_addr = Address.parseToValue(res, "{}", "{}", "{}")\n'.format(
                        raddr.arch, raddr.endian, raddr.type))
                    self._output('except Exception as e:\n')
                    self._output(
                        '    log.error("Parse error in {}")\n'.format(raddr.peer.name))
                    self._output('    raise e\n')
                    self._output(
                        'addr_recv_{} = res_addr\n'.format(saddr.id))
                    numb = raddr.position + raddr.length
                    saddr.related_to.append(raddr)
                    raddr.related_to.append(saddr)
                    expected_recv = []
                else:
                    self._output(
                        'addr_recv_{} = res_addr\n'.format(saddr.id))
            elif raddr.position >= numb and (raddr not in [recv[0] for recv in expected_recv]) and self.do_expect_analysis:
                # raddr's information has been provided by offset's main raddr
                expected_recv.append((raddr, vof))
        self._render_receive(peer, numb, peer.length, expected_recv)

    def _render_send_peer(self, peer, relation_list):
        self._output_comment('*' * 100)
        self._output_comment('Sending {}:'.format(peer.name))
        self._output_comment('*' * 100)
        # send peer may contains several addresses
        has_valid_addr = False
        # numb is how many bytes has added to payload
        # peer_offsets = [rel for rel in relation_list if type(rel) == Offset
        #                 and peer is rel.saddr.peer]
        numb = 0
        for vof in [rel for rel in relation_list if type(rel) == Offset]:
            if peer is vof.saddr.peer:
                raddr = vof.raddr
                saddr = vof.saddr
                if numb > int(saddr.position):
                    log.warn('address conflict in {}\naddr: {} at {}, while handling at byte {}'.format(
                        peer.name, saddr.hex, saddr.position, numb))
                    continue
                if not has_valid_addr:
                    has_valid_addr = True
                    self._output('payload = ""\n')
                if vof.color is None:
                    vof.color = self._get_alternate_color()
                self._output_comment('[VOF_S{}]\taddr:{}\tpos:{}\toffset_val:{}'.format(
                    vof.id, saddr.hex, saddr.position, vof.hex), vof.color)
                self._output(
                    'addr_send_{} = Address.transformAs(addr_recv_{} - {} + {}, "{}", "{}", "{}")\n'.format(
                        saddr.id, saddr.id, raddr.hex, saddr.hex, saddr.arch, saddr.endian, saddr.type))
                if numb < saddr.position:
                    self._output(
                        'payload += "{}"\n'.format(peer[numb:saddr.position].inline))
                addr_length = saddr.transform()[1]
                self._output('payload += addr_send_{}\n'.format(saddr.id))
                numb = int(saddr.position) + addr_length
        if has_valid_addr:
            if numb < peer.length:
                # inline_content will translate to actual content in expect
                self._output('payload += "{}"\n'.format(peer[numb:].inline))
        else:
            self._output('payload = "{}"\n'.format(peer.inline))
        if peer.is_doubtful and self.p2p:
            diffs = []
            for diff in [diff for diff in peer.difference_list if type(diff) == Difference]:
                diffs.append((diff.position, diff.position + diff.length))
            self._output('io.send(payload, different={}, mark="{}", pause={})\n'.format(
                str(diffs), peer.name, str(self.no_pause in ['recv', 'none'])))
        else:
            self._output('io.send(payload)\n')

    def do_combine(self):
        for df in self.df_list:
            df.peer_sequence.do_combine(DIRECTION_RECV)
            df.peer_sequence.do_combine(DIRECTION_SEND)

    def p2p_init(self):
        '''
        Check validity of data files using in p2p mode, and calculate data files' weight by counting length of corresponding peers.
        '''
        if len(self.df_list) < 2:
            log.error('p2p mode needs 2 data files at least')
        for df in self.df_list:
            log.debug("{}'s peer sequence length: {}".format(
                df.name, len(df.peer_sequence)))
        for i in range(0, len(self.df_list)):
            for j in range(i+1, len(self.df_list)):
                consistency_weight = DataFile.check_consistency(
                    self.df_list[i], self.df_list[j], self.strict)
                self.df_list[i].weight += consistency_weight
                self.df_list[j].weight += consistency_weight
        # max_weight = max(self.df_list, key=lambda df: df.weight).weight
        # if not max_weight:
            # log.error('No valid data file for p2p mode')
        # df_list = [df for df in self.df_list if df.weight == max_weight]
        # if len(df_list) < 2:
            # log.warn(
                # 'We do not have more than 2 max weight data files, using all files in p2p mode')
        # else:
            # self.df_list = df_list
        for df in self.df_list:
            log.info('data_file "{}" is using for p2p mode'.format(df.name))

        for i in range(len(self.df_list)):
            for j in range(i, len(self.df_list)):
                df1 = self.df_list[i]
                df2 = self.df_list[j]
                length = min(len(df1.peer_sequence), len(df2.peer_sequence))
                for k in range(length):
                    if df1.peer_sequence[k].length == df2.peer_sequence[k].length:
                        continue
                    df1.peer_sequence[k].recv_method = 'recvuntil'
                for l in range(length, len(df1.peer_sequence)):
                    df1.peer_sequence[l].recv_method = 'recvuntil'
                for l in range(length, len(df2.peer_sequence)):
                    df2.peer_sequence[l].recv_method = 'recvuntil'

    def difference_analysis(self):
        '''
        Find differences between data files' corresponding peers.
        '''
        # Step1: find valid data file for p2p mode

        # Step2: find different peers in valid data files
        for i in range(0, len(self.df_list)):
            for j in range(i+1, len(self.df_list)):
                DataFile.scan_different_peers(self.df_list[i], self.df_list[j])

    def address_analysis(self):
        '''
        Find valid addresses and in each data files.
        Addresses found will save in peers.difference_list
        '''
        for df in self.df_list:
            df.address_analysis()

    def relation_analysis(self):
        '''
        Analysis relation between data files.
        '''
        for df in self.df_list:
            df.generate_relations()
        for df in self.df_list:
            if df.name != self.template_file.name:
                DataFile.compare(self.template_file, df, self.p2p)
        self.template_file.find_valid_relation()

    def render(self):
        # TODO: use mako template to do render
        df = self.template_file
        log.info('Start rendering...')
        sys.stdout.write('\n'.join(self.content_head).format(
            self.elf.file.name,
            '"{}",'.format(self.ld) if self.ld else '',
            '"{}",'.format(self.libc) if self.libc else '',
            self.host, self.port,
        ) + '\n')
        self._output_comment(
            'Using template: {}'.format(df.name), debug=True)
        if self.custom_handler:
            self._output('Address.register_custom_handler_file("{}")\n'.format(
                self.custom_handler))
        for peer in df.peer_sequence:
            log.debug('Rendering {}...'.format(peer.name))
            if peer.direction == DIRECTION_RECV:
                self._render_received_peer(peer, df.relation_list)
            elif peer.direction == DIRECTION_SEND:
                self._render_send_peer(peer, df.relation_list)
        self._output('io.interactive()\n')
        sys.stdout.write('\n'.join(self.content_tail) + "\n\n\n")
        self._output_comment('*' * 50 +
                             'DEBUG_INFO' + '*' * 50)
        # relation_list is empty if there is no send_addr in data file
        self._output_comment('===============Template file\'s relation list[size: {}]==============='.format(
            len(df.relation_list)), debug=True)
        for rel in df.relation_list:
            self._output_comment(rel, debug=True)
        self._output_comment('===============Template file\'s address list[size: {}]==============='.format(
            len(df.addr_list)), debug=True)
        for addr in df.addr_list:
            self._output_comment(addr, debug=True)

        for cmp_df in self.df_list:
            if not cmp_df is df:
                self._output_comment('===============File {}\'s address list[size: {}]==============='.format(
                    cmp_df.name, len(cmp_df.addr_list)), debug=True)
                for rel in cmp_df.addr_list:
                    self._output_comment(addr, debug=True)

    def do_p2p_analysis(self):
        self.do_combine()
        self.p2p_init()
        self.difference_analysis()
        self.address_analysis()
        self.relation_analysis()
        has_difference = False
        for peer in self.template_file.peer_sequence:
            if peer.direction == DIRECTION_SEND and peer.is_doubtful:
                log.info("Send difference detected in %s", peer.name)
                has_difference = True
        if not has_difference:
            log.success(
                "Congratulations! No send difference detected! We will make it!")

    def do_normal_analysis(self):
        if self.combine:
            self.do_combine()
        if not self.no_auto:
            self.address_analysis()
            self.relation_analysis()


def hexdump_peer(args):
    files = args.infiles or []
    df_list = []
    for f in files:
        if os.path.isfile(f):
            df_list.append(DataFile(f, None, wireshark_format=args.wireshark))
        elif os.path.isdir(f):
            for fname in os.listdir(f):
                abs_fname = os.path.join(f, fname)
                ext = os.path.splitext(fname)[1][1:]
                if args.wireshark and ext != 'carray':
                    continue
                if not args.wireshark and ext != 'json':
                    continue
                if os.path.isfile(abs_fname):
                    df_list.append(
                        DataFile(abs_fname, args, wireshark_format=args.wireshark))
    for df in df_list:
        df.peer_sequence.do_combine(DIRECTION_RECV)
        df.peer_sequence.do_combine(DIRECTION_SEND)

    for pn in [p for p in args.hexdump.split(',')]:
        for df in df_list:
            log.info(pn)
            df.hexdump_peer(pn)


def main(args):
    log.info("Welcome to use AGRS(auto-generate-replay-script) tool")
    if args.custom_handler:
        Address.register_custom_handler_file(args.custom_handler)

    if args.custom_template:
        Address.generate_custom_handler_template(args.quiet)
        return

    # Address.register_custom_handlers('1', '2', '3', Address.parse_raw_amd64_little, Address.trans_raw_amd64_little)
    if args.recvuntil and args.recvn:
        log.error('--recvuntil cannot used with --recv!')
        exit(-1)
    if args.hexdump:
        hexdump_peer(args)
        return
    else:
        try:
            addr_level = args.level
            Offset.set_address_level(addr_level)
            rs = ReplayScript(args)
            if rs.p2p:
                rs.do_p2p_analysis()
            else:
                rs.do_normal_analysis()
            # render
            rs.render()
        except PwnlibException:
            pass


if __name__ == '__main__':
    common.main(__file__)
