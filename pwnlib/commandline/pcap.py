#!/usr/bin/env python2
from __future__ import absolute_import
from __future__ import division

import argparse
import string
import sys
import pwnlib
from pwnlib.term import text
from hexdump import hexdump
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common


parser = common.parser_commands.add_parser(
    'test',
    help="test"
)


def main(args):
    pass


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
