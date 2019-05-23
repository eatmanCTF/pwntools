from pwnlib.replay.peer import PeerBytes, PeerSequence, DIRECTION_RECV, DIRECTION_SEND
from pwnlib.replay.relation import Offset, Duplication
from pwnlib.replay.difference import Address, Difference
from pwnlib.log import getLogger
from pwnlib.util import fiddling
from pwnlib.term import text
import json
import re

log = getLogger(__name__)

class DataFile(object):

    def __init__(self, fd, rs, wireshark_format=False):
        if type(fd) == str:
            with open(fd) as fp:
                self.name = fp.name
                self.fdata = fp.read()
        else:
            self.name = fd.name
            self.fdata = fd.read()
        self.peer_sequence = PeerSequence(self)
        self.relation_list = []
        self.address_cache = []
        self.weight = 0
        self.rs = rs
        log.info('Building up data file "{}" ...' .format(self.name))
        if not wireshark_format:
            p = re.compile(r'peer(?P<direction>\d+)_(?P<id>\d+)')
            for peer in json.loads(self.fdata):
                peer_name = peer.keys()[0]
                peer_content = peer[peer_name]
                m = re.search(p, peer_name)
                data = [int(d[:4], 16)
                        for d in peer_content['carray'].split(',')]
                direction = m.group('direction')
                idx = m.group('id')
                peer = PeerBytes(data, direction, idx, self)
                self.peer_sequence.append(peer)
        else:
            p = re.compile(
                r'char peer(?P<direction>\d+)_(?P<id>\d+)\[\] = { \/\* Packet \d+ \*\/(?P<data>[^\}]*)};')
            for m in re.finditer(p, self.fdata):
                data = [int(d[:4], 16) for d in m.group('data').split()]
                direction = m.group('direction')
                idx = m.group('id')
                peer = PeerBytes(data, direction, idx, self)
                self.peer_sequence.append(peer)

    @property
    def difference_list(self):
        diff_list = []
        diff_id = 0
        for peer in self.peer_sequence:
            for difference in peer.difference_list:
                difference.id = diff_id
                diff_list.append(difference)
                diff_id += 1
        return diff_list

    @property
    def addr_list(self):
        return [addr for addr in self.difference_list if isinstance(addr, Address)]

    @property
    def recv_addr_list(self):
        return [addr for addr in self.addr_list if addr.peer.direction == DIRECTION_RECV]

    @property
    def send_addr_list(self):
        return [addr for addr in self.addr_list if addr.peer.direction == DIRECTION_SEND]

    @property
    def recv_difference_list(self):
        return [diff for diff in self.difference_list if diff.peer.direction == DIRECTION_RECV]

    @property
    def send_difference_list(self):
        return [diff for diff in self.difference_list if diff.peer.direction == DIRECTION_SEND]

    @property
    def offset_list(self):
        return [of for of in self.relation_list if isinstance(of, Offset)]

    @property
    def duplication_list(self):
        return [dup for dup in self.relation_list if isinstance(dup, Duplication)]

    @staticmethod
    def check_consistency(df1, df2, strict=False):
        if strict:
            if not df1.peer_sequence.feature == df2.peer_sequence.feature:
                return 0
        else:
            length = min(len(df1.peer_sequence), len(df2.peer_sequence))
            log.debug('Check {} and {}'.format(df1.name, df2.name))
            if df1.peer_sequence.feature[:length] == df1.peer_sequence.feature[:length]:
                weight = 0
                for i in range(length):
                    peer1 = df1.peer_sequence[i]
                    peer2 = df2.peer_sequence[i]
                    if peer1.length == peer2.length:
                        weight += 1
                log.debug('Weight between {} and {}: {}'.format(
                    df1.name, df2.name, str(weight)))
                return weight
            else:
                return 0

    @staticmethod
    def scan_different_peers(df1, df2):
        # consistency check has done before, so we don't need to check whether we are in strict mode
        length = min(len(df1.peer_sequence), len(df2.peer_sequence))
        for i in range(length):
            peer1 = df1.peer_sequence[i]
            peer2 = df2.peer_sequence[i]
            # if peer1.content == peer2.content:
            #     if not peer1.difference_list:
            #         # if peer's doubtful has not been checkd by other pairs
            #         peer1.doubtful = False
            #     if not peer2.difference_list:
            #         peer2.doubtful = False
            # else:
            log.debug('Comparing different between {} and {}'.format(peer1.name, peer2.name))
            PeerBytes.compare(peer1, peer2)

    @staticmethod
    def compare(df1, df2, p2p=False):
        log.info('Comparing data file "{}" and "{}"...'.format(
            df1.name, df2.name))
        # Step1: find valid offsets by weight
        for rel1 in df1.offset_list:
            for rel2 in df2.offset_list:
                # it cannot be a address if df1's addr equals to df2's addr
                if rel1.raddr.val != rel2.raddr.val and rel1.saddr.val != rel2.saddr.val:
                    # add weight if offset's value matches
                    if Offset.equals(rel1, rel2) and rel1.raddr.val:
                        # appearance: worth 1000 weight
                        rel1.weight += 1000
                        rel2.weight += 1000
                        break
        # log.info("After compare")
        # for i in df1.offset_list:
        #     log.info(i)

    def address_analysis(self):
        '''
        Gather addresses in different peers.
        Make up difference_list finally.
        '''
        for peer in self.peer_sequence:
            peer.walk_for_address()
        log.debug("===============Diff list in {}===============".format(self.name))
        for diff in self.difference_list:
            log.debug(diff)

    def generate_relations(self):
        '''
        Generate relations in data file.
        Relations that recv peer is before send peer are valid.
        '''
        for rdiff in self.recv_difference_list:
            for sdiff in self.send_difference_list:
                if rdiff.id < sdiff.id:
                    if type(rdiff) == Address and type(sdiff) == Address:
                        self.relation_list.append(
                            Offset(rdiff, sdiff))
                    if type(rdiff) == Difference and type(sdiff) == Difference:
                        r_position = rdiff.content.find(sdiff.content)
                        if r_position != -1:
                            self.relation_list.append(
                                Duplication(
                                    Difference(rdiff.peer, rdiff.position + r_position, sdiff.length), sdiff))

    def refresh_relations(self):
        self.relation_list = []
        self.generate_relations()

    def find_valid_relation(self):
        # Step1: do duplication combine
        for i in range(0, len(self.duplication_list)):
            for j in range(i+1, len(self.duplication_list)):
                dup1 = self.duplication_list[i]
                dup2 = self.duplication_list[j]
                if dup1.r_difference.peer == dup2.r_difference.peer and dup1.s_difference.peer == dup2.s_difference.peer:
                    r_peer = dup1.r_difference.peer
                    s_peer = dup1.s_difference.peer
                    r_peer_start = min(
                        dup1.r_difference.position, dup2.r_difference.position)
                    r_peer_end = max(dup1.r_difference.position+dup1.r_difference.length,
                                     dup2.r_difference.position+dup2.r_difference.length)
                    s_peer_start = min(
                        dup1.s_difference.position, dup2.s_difference.position)
                    s_peer_end = max(dup1.s_difference.position+dup1.s_difference.length,
                                     dup2.s_difference.position+dup2.s_difference.length)
                    if r_peer.content[r_peer_start:r_peer_end] == s_peer.content[s_peer_start:s_peer_end]:
                        for k in range(r_peer_start, r_peer_end):
                            r_peer.mark_different(k)
                        for k in range(s_peer_start, s_peer_end):
                            s_peer.mark_different(k)

        offset_list = []
        for send_addr in self.send_addr_list:
            # Step2: find valid offsets by weight
            valid_offset = None
            for (i, offset) in enumerate(self.offset_list):
                if offset.saddr is send_addr:
                    if (not valid_offset) or (offset.weight > valid_offset.weight):
                        if offset.weight == 0 and len(self.rs.df_list) > 1:
                            # offset will be 0 if there is only 1 data file
                            continue
                        valid_offset = offset
                        valid_offset.id = i
                    if valid_offset and offset.weight == valid_offset.weight:
                        valid_offset.add_related(offset)

            # Step3: handle send address conflict
            if valid_offset:
                is_valid = True
                for (i, offset) in enumerate(offset_list):
                    osaddr = offset.saddr
                    vosaddr = valid_offset.saddr
                    if vosaddr.peer is osaddr.peer and vosaddr.position != osaddr.position:
                        if (vosaddr.position + vosaddr.length > osaddr.position and osaddr.position >= vosaddr.position) or (osaddr.position + osaddr.length > vosaddr.position and vosaddr.position >= osaddr.position):
                            # conflict
                            log.debug('Conflict detected in peer {}'.format(
                                vosaddr.peer.name))
                            log.debug('send_addr:{}, position:{}, length:{}'.format(
                                vosaddr.hex, vosaddr.position, vosaddr.length))
                            log.debug('send_addr:{}, position:{}, length:{}'.format(
                                osaddr.hex, osaddr.position, osaddr.length))
                            if valid_offset.weight > offset.weight:
                                offset_list.remove(offset)
                            else:
                                is_valid = False
                                continue
                if is_valid:
                    offset_list.append(valid_offset)

        # Step4: handle duplication conflict
        for offset in offset_list:
            for diff in [of.raddr for of in offset.all()] + [offset.saddr]:
                for i in range(diff.position, diff.position+diff.length):
                    diff.peer.mark_related(i)
        self.refresh_relations()
        for peer in self.peer_sequence:
            for diff in peer.difference_list:
                log.info(diff)
        self.relation_list = offset_list + self.duplication_list

    def hexdump_peer(self, peer_name):
        hexdump_style = {
            'marker':       text.white,
            'nonprintable': text.white,
            '00':           text.white,
            '0a':           text.white,
            'ff':           text.white,
            'special':      text.white,
        }
        p = re.compile(r'peer(?P<direction>\d+)_(?P<id>\d+)')
        m = re.search(p, peer_name)
        idx = int(m.group('id'))
        direction = m.group('direction')

        for peer in self.peer_sequence:
            if peer.direction == direction and peer.id == idx:
                log.info(fiddling.hexdump(peer.content, style=hexdump_style))
