from pwnlib.replay.bytes import Bytes
from pwnlib.replay.difference import Address, Difference
from pwnlib.log import getLogger
DIRECTION_RECV = str(1)
DIRECTION_SEND = str(0)
log = getLogger(__name__)

class PeerBytes(Bytes):
    '''
    PeerBytes represents peers parsed from data file.
    '''

    def __init__(self, byts, direction, idx, data_file):
        self.id = int(idx)
        self.idx = int(idx)
        self._difference_list = []
        self._bytes = byts
        # 1: doubtful, 2: same, 3: related, 4: confirmed different
        self._bytesmark = [1] * self.length
        self._bytesmark_cache = None
        self.data_file = data_file
        self.direction = direction
        self.recv_method = 'recvn'

    def __str__(self):
        return '{}\t[data_file "{}"] [length: {: 4d}] [content: "{}"]'.format(
            self.name, self.data_file.name,
            self.length,
            self.get_inline(0, 20) + '...' if self.length > 20 else self.inline)

    def __getitem__(self, key):
        return PeerBytes(self._bytes[key], self.direction, self.idx, self.data_file)

    def __len__(self):
        return len(self._bytes)

    @property
    def name(self):
        return 'peer{}_{}'.format(self.direction, self.idx)

    @property
    def tail_character(self):
        i = 0
        if self.length > 2048:
            return None
        for i in range(1, self.length+1):
            if self.content.find(self.content[-i:]) == self.length - i:
                break
        return self.get_inline(self.length-i)

    @property
    def is_doubtful(self):
        return 1 in self._bytesmark or 4 in self._bytesmark

    @property
    def difference_list(self):
        if not self._bytesmark_cache == self._bytesmark:
            self._difference_list = [
                diff for diff in self._difference_list if type(diff) == Address]
            start, end, i = None, None, 0
            while i <= len(self._bytesmark):
                if i != len(self._bytesmark) and self.is_not_same_or_related(i):
                    if start is None:
                        start, end = i, i
                    else:
                        end = i
                else:
                    if start is not None and end is not None:
                        self._difference_list.append(
                            Difference(self, start, end-start+1))
                        start, end = None, None
                i += 1
            self._bytesmark_cache = list(self._bytesmark)
        return self._difference_list

    @staticmethod
    def compare(peer1, peer2):
        length = min(peer1.length, peer2.length)
        # log.info("walking %d...", length)
        for i in range(length):
            # log.info("walking %d of %d...", i, length)
            if peer1.bytes[i] != peer2.bytes[i] and peer1.length == peer2.length:
                # priority is highest if peer1.length == peer2.length
                peer1.mark_different(i)
                peer2.mark_different(i)
            if peer1.bytes[i] == peer2.bytes[i]:
                if not peer1.is_different_at(i):
                    peer1.mark_same(i)
                if not peer2.is_different_at(i):
                    peer2.mark_same(i)
        for i in range(length, peer1.length):
            peer1.mark_doubtful(i)
        for i in range(length, peer2.length):
            peer2.mark_doubtful(i)

    def mark_doubtful(self, position):
        self._bytesmark[position] = 1

    def mark_same(self, position):
        self._bytesmark[position] = 2

    def mark_related(self, position):
        self._bytesmark[position] = 3

    def mark_different(self, position):
        self._bytesmark[position] = 4

    def is_different_at(self, position):
        return self._bytesmark[position] == 4

    def is_not_same_or_related(self, position):
        return self._bytesmark[position] != 2 and self._bytesmark[position] != 3

    def range_doubtful(self, position, length):
        res = False
        l1 = range(position, position+length-1)
        for difference in self.difference_list:
            l2 = range(difference.position,
                       difference.position+difference.length-1)
            if [i for i in l1 if i in l2]:
                res = True
        return res

    def walk_for_address(self):
        # find valid address in doubtful peers
        if self.is_doubtful:
            for i in range(self.length):
                addresses = Address.parse(self, i)
                if addresses:
                    for addr in addresses:
                        if self.range_doubtful(addr.position, addr.length):
                            self.difference_list.append(addr)


class CombinedPeer(PeerBytes):
    def __init__(self, peer):
        super(CombinedPeer, self).__init__(
            [], peer.direction, peer.idx, peer.data_file)
        self._bytes = [peer.bytes]
        self._bytesmark = [0] * self.length
        self.combined = [peer.idx]

    def __getitem__(self, key):
        return CombinedPeer(PeerBytes(self.bytes[key], self.direction, self.idx, self.data_file))

    def __len__(self):
        return len(self.bytes)

    def append(self, peer):
        self._bytes.append(peer.bytes)
        self.combined.append(peer.idx)
        self._bytesmark = self._bytesmark + peer._bytesmark

    @property
    def name(self):
        return 'combined{}_{}[{}]'.format(self.direction, self.id, ', '.join([str(idx)for idx in self.combined]))

    @property
    def bytes(self):
        # flatten self._bytes
        return [y for x in self._bytes for y in x]


class PeerSequence(list):
    '''
    PeerSequence is a collection of PeerBytes, which also contains:
    1. recv-send featue
    2. method to combine peers
    '''

    def __init__(self, data_file):
        self.data_file = data_file

    def do_combine(self, direction):
        if not list.__len__(self):
            return
        i = 0
        recv_id = 0
        send_id = 0
        while True:
            curr_peer = list.__getitem__(self, i)
            if curr_peer is list.__getitem__(self, -1):
                break
            next_peer = list.__getitem__(self, i+1)
            if curr_peer.direction == direction and not isinstance(curr_peer, CombinedPeer):
                curr_peer = CombinedPeer(curr_peer)
                list.__setitem__(self, i, curr_peer)
                if direction == DIRECTION_RECV:
                    curr_peer.id = recv_id
                    recv_id += 1
                else:
                    curr_peer.id = send_id
                    send_id += 1
            if curr_peer.direction == direction and curr_peer.direction == next_peer.direction:
                curr_peer.append(next_peer)
                list.__delitem__(self, i+1)
            else:
                i += 1
            if next_peer is list.__getitem__(self, -1):
                break

    @property
    def feature(self):
        return [peer.direction for peer in list.__iter__(self)]

