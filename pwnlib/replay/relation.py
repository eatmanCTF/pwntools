from pwnlib.replay.difference import Address, Difference
DIRECTION_RECV = str(1)
DIRECTION_SEND = str(0)

class Relation(object):
    def __init__(self, r_difference, s_difference):
        assert(isinstance(r_difference, Difference))
        assert(isinstance(s_difference, Difference))
        self.r_difference = r_difference
        self.s_difference = s_difference
        self._related = []
        self.weight = 0
        self.color = None
        self.id = 0

    @staticmethod
    def equals(r1, r2):
        return r1.r_difference.content == r2.r_difference.content and r1.s_difference.content == r2.s_difference.content

    @staticmethod
    def locate(r1, r2, direction=DIRECTION_RECV):
        # if self.is_same_position(r1, r2):
        pass

    @staticmethod
    def is_same_peer(r1, r2, direction=DIRECTION_RECV):
        res = False
        if direction == DIRECTION_RECV:
            res = r1.r_difference.peer.id == r2.r_difference.peer.id
        elif direction == DIRECTION_SEND:
            res = r1.s_difference.peer.id == r2.s_difference.peer.id
        return res

    @staticmethod
    def is_same_position(r1, r2, direction=DIRECTION_RECV):
        res = False
        if not Relation.is_same_peer(r1, r2, direction):
            return res
        if direction == DIRECTION_RECV:
            res = r1.r_difference.position == r2.r_difference.position and r1.r_difference.length == r2.r_difference.length
        elif direction == DIRECTION_SEND:
            res = r1.s_difference.position == r2.s_difference.position and r1.s_difference.length == r2.s_difference.length
        return res

    def get_rdiff_by_peer(self, peer):
        return [rel.r_difference for rel in self.all() if peer is rel.r_difference.peer]

    def add_related(self, relation):
        if not relation is self and not relation in self._related:
            relation.r_difference.same_as = self.r_difference
            self._related.append(relation)

    def all(self):
        return [self] + self._related


class Duplication(Relation):
    def __init__(self, r_difference, s_difference):
        assert(r_difference.content == s_difference.content)
        super(Duplication, self).__init__(r_difference, s_difference)

    def __str__(self):
        return '[Class]Duplication [RecvPeer]{} [RecvPosition]{} [SendPeer]{} [SendPosition]{} [Length]{} [Content]{} [Hexdump]{}'.format(
            self.r_difference.peer.name, self.r_difference.position,
            self.s_difference.peer.name, self.s_difference.position,
            self.s_difference.length,
            self.s_difference.inline, self.s_difference.hexdump
        )

    @staticmethod
    def equals(dup1, dup2):
        return dup1.s_difference.content == dup2.s_difference.content


class Offset(Relation):
    # {'recv': raddr, 'send': saddr, 'val': val, 'hex': hex(val), 'weight': 0}
    _address_level = 0

    def __init__(self, raddr, saddr):
        assert(isinstance(raddr, Address))
        assert(isinstance(saddr, Address))
        super(Offset, self).__init__(raddr, saddr)

    def __str__(self):
        res = '[Class: {:>14}]\t[value: {:#14x}]\t[weight: {:14d}]\t[id: {}]\n'.format(
            'Offset', self.val, self.weight, self.id)
        res += '[Main]\n'
        res += "\t" + str(self.raddr) + "\n"
        res += "\t" + str(self.saddr) + "\n"
        res += '[Related]\n'
        for rel in self._related:
            res += "\t" + str(rel.raddr) + "\n"
            res += "\t" + str(rel.saddr) + "\n"
        return res

    @property
    def raddr(self):
        return self.r_difference

    @property
    def saddr(self):
        return self.s_difference

    @property
    def val(self):
        return self.raddr.val-self.saddr.val

    @property
    def hex(self):
        return hex(self.val)

    @staticmethod
    def equals(of1, of2):
        res = of1.val == of2.val
        if Offset._address_level & 0x1:
            res = res and of1.val != 0
        if Offset._address_level & 0x2:
            res = res and of1.raddr.val & 0xfff == of2.raddr.val & 0xfff
        if Offset._address_level & 0x4:
            res = res and of1.raddr.val & 0xfffffff000 != of2.raddr.val & 0xfffffff000
        if Offset._address_level & 0x8:
            res = res and (of1.raddr.val >> 40) == (of2.raddr.val >> 40)
        return res

    @staticmethod
    def set_address_level(level):
        Offset._address_level = level