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
        self.load(filename)

    def load(self, filename):
        # 注意，这里没有使用 sniff(offline=filename,filter='tcp')，是因为这个函数有时候会导致程序卡死
        self.pkts = self.get_tcp_pkts(rdpcap(filename))
        self.streams, self.others = self.streams()

    def get_tcp_pkts(self, pkts):
        return [p for p in pkts if p.haslayer(TCP)]

    def streams(self):
        """stream对应的是往返ip和端口的所有数据包,返回字典"""
        streams = {}
        others = []
        for p in self.pkts:
            session_id, session_id_rev = self.get_session_id(p)
            if p.getlayer(TCP).flags.flagrepr() == 'S':
                streams.update({session_id: [p]})
            elif session_id in streams:
                streams[session_id].append(p)
            elif session_id_rev in streams:
                streams[session_id_rev].append(p)
            else:
                others.append(p)
        return streams, others

    def summary(self):
        summary = {}
        # services = self.config["services"]
        # net_blocks = self.config["net_blocks"]
        for stream_id in self.streams.keys():
            src, sport, dst, dport = list(stream_id)

            service = "{}:{}".format(dst, dport)
            # if service in services:
            #     service = services[service]

            client = src
            # for net_block in net_blocks:
            #     ip = ipaddress.ip_address(unicode(src))
            #     if ip in ipaddress.ip_network(unicode(net_block)):
            #         client = net_blocks[net_block]

            if service not in summary:
                summary.update({service: {}})

            if client not in summary[service]:
                summary[service].update({client: 1})
            else:
                summary[service][client] += 1
            # print(client, service)
        return summary

    @staticmethod
    def split(filename, config, vlan=True):
        base = os.path.basename(filename)
        home = os.path.splitext(base)[0]
        os.system("mkdir -p {}".format(home))

        for name, conn in config["gameboxs"].items():
            ip, port = conn.split(":")
            bpf = "(src host {0} and src port {1}) or (dst host {0} and dst port {1})".format(ip, port)
            if vlan:
                bpf = "vlan and " + bpf
            cmd = 'tcpdump -r {} "{}" -w {}/{}.pcap'.format(filename, bpf, home, name)
            os.system(cmd)

    def search(self, data):
        """返回在tcp层数据存在data的pkt列表，其中data是bytes格式"""
        return [p for p in self.pkts if data in raw(p.getlayer(TCP).payload)]

    def regex(self, pattern):
        return [p for p in self.pkts if re.search(pattern, raw(p.getlayer(TCP).payload))]

    def get_ip_and_port(self, pkt):
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        return ip.src, tcp.sport, ip.dst, tcp.dport

    def get_session_id(self, pkt):
        """获取pkt的tcp表示"""
        ip = pkt.getlayer(IP)
        tcp = pkt.getlayer(TCP)
        session_id = (ip.src, tcp.sport, ip.dst, tcp.dport)
        session_id_rev = (ip.dst, tcp.dport, ip.src, tcp.sport)
        return session_id, session_id_rev

    def filter_by_BPF(self, bpf, pkts=None, vlan=True):
        """使用伯克利包过滤(Berkeley Packet Filter)规则,过滤数据包"""
        pkts = pkts or self.pkts
        if vlan:
            bpf = "({0}) or (vlan and {0})".format(bpf)
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
        session_id, sesion_id_rev = self.get_session_id(pkt)
        if session_id in self.streams:
            return self.streams[session_id]
        elif sesion_id_rev in self.streams:
            return self.streams[sesion_id_rev]

    def stream_to_json(self, stream_id, pkts):
        if pkts[0].getlayer(TCP).flags.flagrepr() != 'S':
            raise Exception("第一个数据包不是syn")

        src, sport, dst, dport = self.get_ip_and_port(pkts[0])
        type_request = (src, sport, dst, dport)
        type_response = (dst, dport, src, sport)

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
        return res

    def payload_to_ascii(self, payload):
        if payload != None:
            return re.sub(b'[^\x1f-\x7f]', b'.', payload).decode()

    def payload_to_carray(self, payload):
        return ",".join("{:#04x}".format(b) for b in bytes(payload))

    # def dump_stream_pkts(self, filename, pkts):

    #     if pkts[0].getlayer(TCP).flags.flagrepr() != 'S':
    #         raise Exception("第一个数据包不是syn")

    #     src, sport, dst, dport = self.get_ip_and_port(pkts[0])
    #     type_request = (src, sport, dst, dport)
    #     type_response = (dst, dport, src, sport)

    #     count_request = 0
    #     count_response = 0

    #     res = []

    #     for i, pkt in enumerate(pkts):
    #         payload = raw(pkt.getlayer(TCP).payload)
    #         if payload == b'':
    #             continue

    #         if self.get_ip_and_port(pkt) == type_request:
    #             name = "peer{}_{}".format(0, count_request)
    #             count_request += 1
    #         elif self.get_ip_and_port(pkt) == type_response:
    #             name = "peer{}_{}".format(1, count_response)
    #             count_response += 1
    #         else:
    #             raise Exception("存在四元组不同的异常数据")

    #         res.append({
    #             name: {
    #                 "time": pkt.time,
    #                 "index": i + 1,
    #                 "ascii": self.payload_to_ascii(payload),
    #                 "carray": self.payload_to_carray(payload)
    #             }
    #         })

    #     with open(filename, 'w') as outfile:
    #         json.dump(res, outfile, indent=4)

    def dump_pkts_as_pcap(self, filename, pkts):
        wrpcap(filename, pkts)


# class Config:
#     def __init__(self, path="config.json"):
#         if not os.path.exists(path):
#             config = {
#                 "teams": {
#                     "team1": "127.0.0.1/32"
#                 },
#                 "gameboxs": {
#                     "suffarring": "127.0.0.1:4444"
#                 }
#             }
#             with open("config.json", 'w') as outfile:
#                 json.dump(config, outfile, indent=4)

#         config = json.load(open(path))
#         self.gameboxs = config["gameboxs"]
#         self.teams = config["teams"]

#     def get_gamebox_name(self, ip, port):
#         conn = "{}:{}".format(ip, port)
#         for name, value in self.gameboxs.items():
#             if value == conn:
#                 return name
#         return conn

#     def get_team_name(self, ip):
#         ip = ipaddress.ip_address(unicode(ip))
#         for team, net in self.teams.items():
#             if ip in ipaddress.ip_network(unicode(net)):
#                 return team
#         return ip


parser = common.parser_commands.add_parser(
    'pcap',
    help="pcap"
)

parser.add_argument(
    'pcap_file',
    nargs='?',
    help='input pcap file'
)

parser.add_argument(
    '--init',
    action='store_true',
    default=False,
    help='split big pcap file into small pcap files',
)

parser.add_argument(
    '--summary',
    action='store_true',
    default=False,
    help='get streams info of a pcap file',
)

parser.add_argument(
    '--split',
    action='store_true',
    default=False,
    help='split big pcap file into small pcap files',
)

parser.add_argument(
    '--vlan',
    action='store_true',
    default=False,
    help='set if pcap with vlan',
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


def main(args):

    conf_path = os.path.expanduser("~/.pwn/pcap.json")

    if not os.path.exists(conf_path):
        config = {
            "gameboxs": {
                "gamebox1": "127.0.0.1:4444"
            },
            "teams": {
                "team1": "1192.168.10.0/24"
            }
        }

        with open(conf_path, 'w') as outfile:
            json.dump(config, outfile, indent=4)

    config = json.load(open(conf_path))

    if args.split:
        return Pcap.split(args.pcap_file, config)

    pcap = Pcap(args.pcap_file)

    if args.summary:
        print(json.dumps(pcap.summary(), indent=4))

    elif args.search or args.regex:
        if args.search:
            pkts = pcap.search(args.search)
        else:
            pkts = pcap.regex(args.regex)

        log.info("搜索到符合条件的数据包:{}".format(len(pkts)))

        for p in pkts[0:1]:
            stream = pcap.follow_tcp_stream(p)
            # src, sport, dst, dport = pcap.get_ip_and_port(stream[0])
            # home_dir = config.get_gamebox_name(dst, dport)
            # sub_dir = "{}/{}".format(home_dir, config.get_team_name(src))
            # out_path = "{}/{}.json".format(sub_dir, stream[0].time)
            # log.info("保存数据到文件:{}".format(out_path))
            # if not os.path.exists(home_dir):
            #     os.makedirs(home_dir)
            # if not os.path.exists(sub_dir):
            #     os.makedirs(sub_dir)
        #     pcap.dump_stream_pkts(out_path, stream)


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
