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

    def summary(self, clients={}, servers={}):
        summary = {}
        for stream_id in self.streams.keys():

            client, server = Pcap.stream_id_to_names(stream_id, clients, servers)

            if server not in summary:
                summary.update({server: {}})

            if client not in summary[server]:
                summary[server].update({client: 1})
            else:
                summary[server][client] += 1
        return summary

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
            return session_id
        elif sesion_id_rev in self.streams:
            return sesion_id_rev

    def stream_to_json(self, stream_id):

        pkts = self.streams[stream_id]

        count_request = 0
        count_response = 0

        res = []

        for i, pkt in enumerate(pkts):

            if not pkt.haslayer(Raw):
                continue

            tcp_raw = pkt.getlayer(Raw)
            if tcp_raw.haslayer(Padding):
                tcp_raw.remove_payload()

            tcp_data = raw(tcp_raw)

            session_id, session_id_rev = self.get_session_id(pkt)

            if session_id == stream_id:
                name = "peer{}_{}".format(0, count_request)
                count_request += 1
            elif session_id_rev == stream_id:
                name = "peer{}_{}".format(1, count_response)
                count_response += 1
            else:
                raise Exception("存在四元组不同的异常数据")

            res.append({
                name: {
                    "time": pkt.time,
                    "index": i + 1,
                    "ascii": self.payload_to_ascii(tcp_data),
                    "carray": self.payload_to_carray(tcp_data)
                }
            })
        return res

    def stream_to_vector(self, stream_id, count_only=True):
        stream_json = self.stream_to_json(stream_id)
        res = []
        for pkt_info in stream_json:
            name, info = pkt_info.items()[0]
            if "peer0" in name:
                res.append(len(info['ascii']))
            else:
                res.append(-len(info['ascii']))

        for i in range(len(res) - 1):
            if res[i] * res[i + 1] > 0:
                res[i + 1] += res[i]
                res[i] = 0

        res = [n for n in res if n != 0]

        if count_only:
            return {stream_id[1]: len(res)}
        else:
            return {stream_id[1]: res}

    def payload_to_ascii(self, payload):
        if payload != None:
            return re.sub(b'[^\x1f-\x7f]', b'.', payload).decode()

    def payload_to_carray(self, payload):
        return ",".join("{:#04x}".format(b) for b in bytes(payload))

    def dump_pkts_as_pcap(self, filename, pkts):
        wrpcap(filename, pkts)

    @staticmethod
    def tcpdump(input_file, output_file, bpf, vlan=True):
        if vlan:
            bpf = "vlan and " + bpf
        cmd = 'tcpdump -r {} "{}" -w {}'.format(input_file, bpf, output_file)
        os.system(cmd)

    @staticmethod
    def stream_id_to_names(stream_id, clients={}, servers={}):
        src, sport, dst, dport = list(stream_id)

        client_name = src
        for name, net_block in clients.items():
            ip = ipaddress.ip_address(unicode(src))
            if ip in ipaddress.ip_network(unicode(net_block)):
                client_name = name

        server_name = "{}:{}".format(dst, dport)
        for name, conn in servers.items():
            if server_name == conn:
                server_name = name

        return client_name, server_name


def split(filename, config, vlan=True):
    """"""
    filename = os.path.basename(filename)
    folder, _ = os.path.splitext(filename)

    os.system("mkdir -p {}".format(folder))

    for gamebox_name, conn in config["gameboxs"].items():
        ip, port = conn.split(":")
        bpf = "(src host {0} and src port {1}) or (dst host {0} and dst port {1})".format(ip, port)
        pcap_gamebox = "{}/{}.pcap".format(folder, gamebox_name)
        Pcap.tcpdump(filename, pcap_gamebox, bpf, vlan)

        os.system("mkdir -p {}/{}".format(folder, gamebox_name))
        for team_name, net in config["teams"].items():
            bpf = "net {}".format(net)
            pcap_gamebox_team = "{}/{}/{}.pcap".format(folder, gamebox_name, team_name)
            Pcap.tcpdump(pcap_gamebox, pcap_gamebox_team, bpf, vlan)


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
    '--analyse',
    action='store_true',
    default=False,
    help='stream to vector for analyse',
)

parser.add_argument(
    '--detail',
    action='store_true',
    default=False,
    help='display more',
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

    conf_path = os.path.expanduser("~/.pwn.pcap.conf")

    if not os.path.exists(conf_path):
        config = {
            "gameboxs": {
                "gamebox1": "172.16.5.20:5051"
            },
            "teams": {
                "team1": "172.16.5.12/32",
                "team2": "172.16.5.22/32"
            }
        }

        with open(conf_path, 'w') as outfile:
            json.dump(config, outfile, indent=4)

    config = json.load(open(conf_path))

    if args.split:
        return split(args.pcap_file, config)

    pcap = Pcap(args.pcap_file)

    if args.summary:
        print(json.dumps(pcap.summary(config["teams"], config["gameboxs"]), indent=4))

    if args.analyse:
        for stream_id in pcap.streams:
            print(pcap.stream_to_vector(stream_id, args.detail == False))

    elif args.search or args.regex:
        if args.search:
            pkts = pcap.search(args.search)
        else:
            pkts = pcap.regex(args.regex)

        log.info("搜索到符合条件的数据包:{}".format(len(pkts)))

        if len(pkts) != 0:
            os.system("mkdir -p output")

        for p in pkts:

            stream_id = pcap.follow_tcp_stream(p)
            if stream_id == None:
                log.warning("在非完整流中找到数据包，数据包位置：{}".format(pcap.pkts.index(p)))
                continue
            team, gamebox = Pcap.stream_id_to_names(stream_id, config["teams"], config["gameboxs"])
            pkts = pcap.streams[stream_id]
            out_path = "output/{}_{}_{}_{}.json".format(gamebox, team, pcap.pkts.index(pkts[0]) + 1, len(pkts))
            log.info("保存数据到文件:{}".format(out_path))
            with open(out_path, 'w') as outfile:
                json.dump(pcap.stream_to_json(stream_id), outfile, indent=4)


if __name__ == '__main__':
    pwnlib.commandline.common.main(__file__)
