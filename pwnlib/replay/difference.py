from pwnlib.replay.bytes import Bytes
from pwnlib.util import fiddling
from pwnlib.util.packing import u32, u64, p32, p64
from pwnlib.log import getLogger
from pwnlib.context import context
import pwnlib.data
from mako.lookup import TemplateLookup
import os, re
log = getLogger(__name__)

class Difference(Bytes):
    '''
    Different bytes in peer.
    '''

    def __init__(self, peer, position, length, data=None):
        if peer:
            super(Difference, self).__init__(
                peer.bytes[position:position+length])
        elif data:
            super(Difference, self).__init__(data)
        self.id = 0
        self.position = position
        self.peer = peer

    def __str__(self):
        return '[Class]Difference [Peer]{} [Position]{} [Length]{} [Hexdump]{}'.format(
            self.peer.name, self.position, self.length, self.hexdump
        )

class Information(object):
    '''
    Information gathered by multi differences.
    '''
    custom_handlers = []
    default_handlers_enabled = True
    def __init__(self, direction, peer_list):
        '''
        same_as : list of Information which contains information that has already provided by this object (same direction)
        related_to: list of Information which can be calcuated by this object and a valid relation (different direction)
        '''
        assert(len(set([peer.direction for peer, position, length in peer_list])) == 1)
        self.direction = self.peer_list[0][0].direction
        self.peer_list = peer_list
        self._same_as = []
        self.related_to = []

class Address(Difference):
    # TODO: gather Address from different peers
    '''
    Bytes that can be explained to an address.
    '''
    custom_handlers = []
    default_handlers_enabled = True

    def __init__(self, peer, position, length, val, addr_type, arch, endian, data=None):
        super(Address, self).__init__(peer, position, length, data)
        self.val = val
        self.type = addr_type
        self.arch = arch
        self.endian = endian
        self.hex = hex(val)
        # same_as : the same_as's different information can be given by self
        self.same_as = None
        # related_to : the recv_send pair
        self.related_to = []

    def __str__(self):
        return '[Class]Address [Peer]{} [Position]{} [Length]{} [HexVal]{}'.format(
            self.peer.name, self.position, self.length, self.hex
        )

    @staticmethod
    def register_custom_handlers(arch, endian, addr_type, parser, transformer):
        Address.custom_handlers.append({
            'type': addr_type,
            'arch': arch,
            'endian': endian,
            'parser': parser,
            'transformer': transformer
        })

    @staticmethod
    def default_handlers():
        # handlers['parser']
        # param1: cdata (chr mode)
        # param2: parse position
        # return: (val, length, real position)

        # handlers['transformer']
        # param1: value (int)
        # return: cdata (chr mode)

        return [
            {'type': 'raw', 'arch': 'amd64', 'endian': 'little',
                'parser': Address.parse_raw_amd64_little, 'transformer': Address.trans_raw_amd64_little},
            {'type': 'raw', 'arch': 'amd64', 'endian': 'big',
                'parser': Address.parse_raw_amd64_big, 'transformer': Address.trans_raw_amd64_big},
            {'type': 'raw', 'arch': 'i386', 'endian': 'little',
                'parser': Address.parse_raw_i386_little, 'transformer': Address.trans_raw_i386_little},
            {'type': 'raw', 'arch': 'i386', 'endian': 'big',
                'parser': Address.parse_raw_i386_big, 'transformer': Address.trans_raw_i386_big},
            {'type': 'hex', 'arch': 'amd64', 'endian': 'little',
                'parser': Address.parse_hex_amd64_little, 'transformer': Address.trans_hex_amd64_little},
            {'type': 'hex', 'arch': 'amd64', 'endian': 'big',
                'parser': Address.parse_hex_amd64_big, 'transformer': Address.trans_hex_amd64_big},
            {'type': 'hex', 'arch': 'i386', 'endian': 'little',
                'parser': Address.parse_hex_i386_little, 'transformer': Address.trans_hex_i386_little},
            {'type': 'hex', 'arch': 'i386', 'endian': 'big',
                'parser': Address.parse_hex_i386_big, 'transformer': Address.trans_hex_i386_big},
            {'type': 'digital', 'arch': 'amd64', 'endian': 'little',
                'parser': Address.parse_digital_amd64, 'transformer': Address.trans_digital_amd64},
            {'type': 'digital', 'arch': 'amd64', 'endian': 'big',
                'parser': Address.parse_digital_amd64, 'transformer': Address.trans_digital_amd64},
            {'type': 'digital', 'arch': 'i386', 'endian': 'little',
                'parser': Address.parse_digital_i386, 'transformer': Address.trans_digital_i386},
            {'type': 'digital', 'arch': 'i386', 'endian': 'big',
                'parser': Address.parse_digital_i386, 'transformer': Address.trans_digital_i386},
        ]

    @staticmethod
    def get_handlers():
        handlers = []
        if Address.default_handlers_enabled:
            handlers += Address.default_handlers()
        handlers += Address.custom_handlers
        return handlers

    @staticmethod
    def generate_custom_handler_template(quiet):
        cache = None

        if cache:
            cache = os.path.join(context.cache_dir, 'mako')

        lookup = TemplateLookup(
            directories      = [os.path.join(pwnlib.data.path, 'templates')],
            module_directory = cache
        )
        template = lookup.get_template('replay_custom_handler.mako')
        output = template.render(quiet)

        # Fix Mako formatting bs
        output = re.sub('\n\n\n', '\n\n', output)
        print output

    @staticmethod
    def register_custom_handler_file(fname):
        if os.path.isfile(fname):
            # sys.path.append(os.path.dirname(os.path.expanduser(f)))
            import imp
            lib = imp.load_source('handler', os.path.abspath(fname))
            custom = lib.custom_handlers
            Address.default_handlers_enabled = custom['default_handlers_enabled']
            for handler in custom['handlers']:
                Address.register_custom_handlers(handler['arch'], handler['endian'], handler['type'], handler['parser'], handler['transformer'])
        else:
            log.critical(
                'Given custom handler script:{} is not a valid file name'.format(fname))
            sys.exit(-1)

    @staticmethod
    def parse_raw_amd64_little(data, i, peer=None, cache=[]):
        # parse 64-bit little-endian raw address to value. eg. '\x78\x56\x34\x12\xf0\x7f' ==> 0x7ff012345678
        # TODO: handle address like "0x7f..55.."
        if data[i] in [chr(0x55), chr(0x56), chr(0x7f)] and i >= 5:
            return Address(peer, i-5, 6, u64(data[i-5:i+1].ljust(8, '\x00')), 'raw', 'amd64', 'little', data=data)
        else:
            return None

    @staticmethod
    def trans_raw_amd64_little(value):
        # translate value to 64-bit little-endian raw address. eg. 0x7ff012345678 ==> '\x78\x56\x34\x12\xf0\x7f'
        try:
            res = p64(value, endian='little')[:6]
        except:
            return None
        return res

    @staticmethod
    def parse_raw_amd64_big(data, i, peer=None, cache=[]):
        # parse 64-bit big-endian raw address to value. eg. 'x7f\xf0\x12\34\x56\x78' ==> 0x7ff012345678
        if data[i] in [chr(0x55), chr(0x56), chr(0x7f)] and len(data) - i >= 6:
            return Address(peer, i, 6, u64(data[i:i+6].rjust(8, '\x00'), endian='big'), 'raw', 'amd64', 'big', data=data)
        else:
            return None

    @staticmethod
    def trans_raw_amd64_big(value):
        # translate value to 64-bit big-endian raw address. eg. 0x7ff012345678 ==> 'x7f\xf0\x12\34\x56\x78'
        try:
            res = p64(value, endian='big')[-6:]
        except:
            return None
        return res

    @staticmethod
    def parse_raw_i386_little(data, i, peer=None, cache=[]):
        # parse 32-bit little-endian raw address to value. eg. 'x56\x34\x12\xf7' ==> 0xf7123456
        if data[i] in [chr(0xf7)] and i >= 3:
            return Address(peer, i-3, 4, u32(data[i-3:i+1], endian='little'), 'raw', 'i386', 'little', data=data)
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
    def parse_raw_i386_big(data, i, peer=None, cache=[]):
        # parse 32-bit big-endian raw address to value. eg. '\xf7\x12\x34\x56' ==> 0xf7123456
        if data[i] in [chr(0xf7)] and len(data) - i >= 4:
            return Address(peer, i, 4, u32(data[i:i+4], endian='big'), 'raw', 'i386', 'big', data=data)
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
    def parse_hex_amd64_little(data, i, peer=None, cache=[]):
        # parse 64-bit little-endian hex address to value. eg. '78563412f07f' ==> 0x7ff012345678
        if int(data[i-1:i+1], 16) in [0x7f, 0x55, 0x56] and i >= 11:
            value_list = [data[i-11+2*j:i-11+2*(j+1)]
                          for j in range(len(data[i-11:i+1]) // 2)]
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return Address(peer, i-11, 12, r, 'hex', 'amd64', 'little', data=data)
        else:
            return None

    @staticmethod
    def trans_hex_amd64_little(value):
        return ''

    @staticmethod
    def parse_hex_amd64_big(data, i, peer=None, cache=[]):
        # parse 64-bit big-endian hex address to value. eg. '7ff012345678' ==> 0x7ff012345678
        if int(data[i-1:i+1], 16) in [0x7f, 0x55, 0x56] and len(data) - i >= 11:
            value_list = [data[i-1+2*j:i-1+2*(j+1)]
                          for j in range(len(data[i-1:i+11]) // 2)]
            value_list.reverse()
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return Address(peer, i-1, 12, r, 'hex', 'amd64', 'big', data=data)
        else:
            return None

    @staticmethod
    def trans_hex_amd64_big(value):
        return ''

    @staticmethod
    def parse_hex_i386_little(data, i, peer=None, cache=[]):
        # parse 32-bit little-endian hex address to value. eg. '563412f7' ==> 0xf7123456
        if int(data[i-1:i+1], 16) in [0xf7] and i >= 7:
            value_list = [data[i-7+2*j:i-7+2*(j+1)]
                          for j in range(len(data[i-7:i+1]) // 2)]
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return Address(peer, i-7, 8, r, 'hex', 'i386', 'little', data=data)
        else:
            return None

    @staticmethod
    def trans_hex_i386_little(value):
        return ''

    @staticmethod
    def parse_hex_i386_big(data, i, peer=None, cache=[]):
        # parse 32-bit big-endian hex address to value. eg. 'f7123456' ==> 0xf7123456
        if int(data[i-1:i+1], 16) in [0xf7] and len(data) - i >= 7:
            value_list = [data[i-1+2*j:i-1+2*(j+1)]
                          for j in range(len(data[i-1:i+7]) // 2)]
            value_list.reverse()
            r = 0
            o = 0
            for value in value_list:
                r += (int(value, 16) << o)
                o += 8
            return Address(peer, i-1, 8, r, 'hex', 'i386', 'big', data=data)
        else:
            return None

    @staticmethod
    def trans_hex_i386_big(value):
        return ''

    @staticmethod
    def parse_digital_amd64(data, i, peer=None, cache=[]):
        # parse 64-bit digital address to value. eg. '140737488355327' ==> 0x7ff012345678
        digital = int(data[i-14:i+1])
        if digital >= 0x7effffffffff and digital <= 0x7fffffffffff:
            return Address(peer, i-14, 15, digital, 'digital', 'amd64', 'big', data=data)
        else:
            return None

    @staticmethod
    def trans_digital_amd64(value):
        return str(value)

    @staticmethod
    def parse_digital_i386(data, i, peer=None, cache=[]):
        # parse 32-bit digital address to value. eg. '4160749567' ==> 0xf7123456
        digital = int(data[i-9:i+1])
        if digital >= 0xf6ffffff and digital <= 0xf7ffffff:
            return Address(peer, i-19, 10, digital, 'digital', 'i386', 'big', data=data)
        else:
            return None

    @staticmethod
    def trans_digital_i386(value):
        return str(value)

    @staticmethod
    def transformAs(value, arch, endian, addr_type):
        handlers = [handler for handler in Address.get_handlers()
                    if handler['arch'] == arch and handler['endian'] == endian and handler['type'] == addr_type]
        if len(handlers) > 0:
            handler = handlers[0]
            res = handler['transformer'](value)
            if res is None:
                raise Exception('transform failed!')
            return res

        else:
            raise Exception('unknow arch, endian or type')

    @staticmethod
    def parse(peer, i):
        res = []
        for handler in Address.get_handlers():
            try:
                address = handler['parser'](
                    peer.content, i, peer, peer.data_file.address_cache)
                if address is not None:
                    res.append(address)
            except:
                continue
        return res

    @staticmethod
    def parseToValue(data, arch, endian, addr_type):
        handlers = [handler for handler in Address.get_handlers()
                    if handler['arch'] == arch and handler['endian'] == endian and handler['type'] == addr_type]
        res = None
        if len(handlers) > 0:
            handler = handlers[0]
            for i in range(len(data)):
                try:
                    # TODO: now parser will stop when first valid address is met
                    # i think it will cause conflict in some cases
                    # may be we can parse address using elf's arch first?
                    res = handler['parser'](data, i)
                    if res is not None:
                        break
                except:
                    continue
            else:
                log.warn('unknown address in peer data: {}'.format(data))
                log.warn(fiddling.hexdump(data))
                raise Exception('parse failed!')
            return res.val
        else:
            raise Exception('unknow arch, endian or type')

    def transform(self):
        handlers = Address.get_handlers()
        if len(handlers) > 0:
            handler = handlers[0]
            res = handler['transformer'](self.val)
            if res is None:
                raise Exception('transform failed!')
            return res, len(res)

        else:
            raise Exception('unknow arch, endian or type')
