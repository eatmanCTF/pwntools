<%page args="quiet=False"/>\
#!/usr/bin/env python2
from pwnlib.replay.difference import Address
from pwn import *

%if not quiet:
#===========================================================
#                    PARSER GOES HERE
#===========================================================
# data: peer's content (str)
# i: current parse index
# peer: PeerBytes object, used when returning an Address
#     Useful properties of peer:
#     peer.direction = 0(send) or 1(recv)
#     peer.id = peer's id (after combine)
#     peer.combined = [id1, id2] (before combine)
# cache: a global storage (is quite useful when an Address is related to more than 1 peer)
# return: Address object or None
#
# example:
# def parse_raw_amd64_little(data, i, peer=None, cache=[]):
#     if data[i] in [chr(0x55), chr(0x56), chr(0x7f)] and i >= 5:
#         return Address(peer, i-5, 6, u64(data[i-5:i+1].ljust(8, '\x00')), 'raw', 'amd64', 'little', data=data)
#     else:
#         return None
%else:
# -- Parser goes here --
%endif

def custom_parser_1(data, i, peer=None, cache=[]):
    return None
%if not quiet:
#===========================================================
#                    TRANSFORMER GOES HERE
#===========================================================
# value: the value to transform
# return: the str object for tube.send()
#
# example:
# def trans_raw_amd64_little(value):
#     try:
#         res = p64(value, endian='little')[:6]
#     except:
#         return None
#     return res
%else:
# -- Transformer goes here --
%endif

def custom_transformer_1(value):
    return None

%if not quiet:
#===========================================================
#                    ADD ALL PARSER AND TRANSFORMER HERE
#===========================================================
%else:
# -- Add all parser and transformer here --
%endif
custom_handlers = {
    'default_handlers_enabled': True,
    'handlers': [
        {'arch': 'custom_1', 'endian': 'custom_1', 'type': 'custom_1', 'parser': custom_parser_1, 'transformer': custom_transformer_1}
    ] 
}