#!/usr/bin/env python2
# -*- coding:UTF-8 -*-

from __future__ import absolute_import
from __future__ import division
import logging
import argparse
import os
import json
import string
import re
import os
import ipaddress
from scapy.all import *
from builtins import bytes

import argparse
import string
import sys
import pwnlib
from pwnlib.term import text
from hexdump import hexdump
pwnlib.args.free_form = False

from pwn import *
from pwnlib.commandline import common


class Pcap:
    def __init__(self, filename):
        self.filename = filename
        self.pkts = sniff(offline=filename)
        self.streams = self.streams()

    def streams(self):
        """stream对应的是往返ip和端口的所有数据包,返回数组：[('192.168.127.132', 59406, '123.115.4.184', 9999)]"""
        return [self.get_ip_and_port(p) for p in self.pkts if p.getlayer(TCP).flags.flagrepr() == 'S']

    def search(self, data):
        """返回在tcp层数据存在data的pkt列表，其中data是bytes格式"""
        return [p for p in self.pkts if data in raw(p.getlayer(TCP).payload)]

    def regex(self, pattern):
        return [p for p in self.pkts if re.search(pattern, raw(p.getlayer(TCP).payload))]

    def get_ip_and_port(self, pkt):
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        return ip.src, tcp.sport, ip.dst, tcp.dport

    def filter_by_BPF(self, bpf, pkts=None):
        """使用伯克利包过滤(Berkeley Packet Filter)规则,过滤数据包"""
        pkts = pkts or self.pkts
        return sniff(offline=pkts, filter=bpf)

    def filter_by_ip(self, ip, pkts=None):
        bpf = "host {}".format(ip)
        return self.filter_by_BPF(bpf, pkts)

    def filter_by_port(self, port, pkts=None):
        bpf = "port {}".format(ip)
        return self.filter_by_BPF(bpf, pkts)

    def filter_by_ip_and_port(self, ip, port, pkts=None):
        bpf = "host {} and port {}".format(ip, port)
        return self.filter_by_BPF(bpf, pkts)

    def follow_tcp_stream(self, pkt):
        """从任意pkt，返回其所在的tcp流的所有pkts"""
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        pkts = self.filter_by_ip_and_port(ip.src, tcp.sport)
        return self.filter_by_ip_and_port(ip.dst, tcp.dport, pkts)

    def payload_to_ascii(self, payload):
        if payload != None:
            return re.sub(b'[^\x1f-\x7f]', b'.', payload).decode()

    def payload_to_carray(self, payload):
        return ",".join("{:#04x}".format(b) for b in bytes(payload))

    def dump_stream_pkts(self, filename, pkts):

        if pkts[0].getlayer(TCP).flags.flagrepr() != 'S':
            raise Exception("第一个数据包不是syn")

        src, sport, dsc, dport = self.get_ip_and_port(pkts[0])

        type_request = (src, sport, dsc, dport)
        type_response = (dsc, dport, src, sport)

        count_request = 0
        count_response = 0

        res = []

        for i, pkt in enumerate(pkts):
            payload = raw(pkt.getlayer(TCP).payload)
            if payload == b'':
                continue

            if self.get_ip_and_port(pkt) == type_request:
                name = "peer{}_{}".format(0, count_request)
                count_request += 1
            elif self.get_ip_and_port(pkt) == type_response:
                name = "peer{}_{}".format(1, count_response)
                count_response += 1
            else:
                raise Exception("存在四元组不同的异常数据")

            res.append({
                name: {
                    "time": pkt.time,
                    "index": i + 1,
                    "ascii": self.payload_to_ascii(payload),
                    "carray": self.payload_to_carray(payload)
                }
            })

        with open(filename, 'w') as outfile:
            json.dump(res, outfile, indent=4)

    def dump_pkts_as_pcap(self, filename, pkts):
        wrpcap(filename, pkts)


class Config:
    def __init__(self, path="config.json"):
        if not os.path.exists(path):
            config = {
                "teams": {
                    "team1": "127.0.0.1/32"
                },
                "gameboxs": {
                    "suffarring": "127.0.0.1:4444"
                }
            }
            with open("config.json", 'w') as outfile:
                json.dump(config, outfile, indent=4)

        config = json.load(open(path))
        self.gameboxs = config["gameboxs"]
        self.teams = config["teams"]

    def get_gamebox_name(self, ip, port):
        conn = "{}:{}".format(ip, port)
        for name, value in self.gameboxs.items():
            if value == conn:
                return name
        return conn

    def get_team_name(self, ip):
        ip = ipaddress.ip_address(unicode(ip))
        for team, net in self.teams.items():
            if ip in ipaddress.ip_network(unicode(net)):
                return team
        return ip


parser = common.parser_commands.add_parser(
    'pcap',
    help="pcap"
)

parser.add_argument(
    'pcap_file',
    type=argparse.FileType('r'),
    help='input pcap file'
)

parser.add_argument(
    '--list',
    action='store_true',
    default=False,
    help='list streams info of a pcap file',
)


parser.add_argument(
    '-s',
    '--search',
    nargs='?',
    help='search strings in packets',
)

parser.add_argument(
    '-r',
    '--regex',
    nargs='?',
    help='search strings in packets by regex',
)

parser.add_argument(
    '--bpf',
    nargs='?',
    help='use Berkeley Packet Filter filter packets',
)


def main(args):
    pcap = Pcap(args.pcap_file)
    config = Config()

    if args.list:
        for stream in pcap.streams:
            log.info(stream)

    elif args.bpf:
        pkts = pcap.filter_by_BPF(args.bpf)
        pcap.dump_pkts_as_pcap("bpf.out.pcap", pkts)

    elif args.search or args.regex:
        if args.search:
            pkts = pcap.search(args.search)
        else:
            pkts = pcap.regex(args.regex)

        log.info("搜索到符合条件的数据包:{}".format(len(pkts)))

        for p in pkts:
            stream = pcap.follow_tcp_stream(p)
            src, sport, dst, dport = pcap.get_ip_and_port(stream[0])
            home_dir = config.get_gamebox_name(dst, dport)
            sub_dir = "{}/{}".format(home_dir, config.get_team_name(src))
            out_path = "{}/{}.json".format(sub_dir, stream[0].time)
            log.info("保存数据到文件:{}".format(out_path))
            if not os.path.exists(home_dir):
                os.makedirs(home_dir)
            if not os.path.exists(sub_dir):
                os.makedirs(sub_dir)
            pcap.dump_stream_pkts(out_path, stream)


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
