from __future__ import absolute_import

import os
import subprocess
import re, random
from pwnlib.context import context
from pwnlib import gdb
from pwnlib.args import args
from pwnlib.elf import ELF
from pwnlib.log import Logger, getLogger
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import connect
from pwnlib.util.packing import u32, u64, p32, p64, make_packer
import shutil
import sys, string
import math
from ctypes import *

LIBC_DATABASE_PATH = "/mnt/hgfs/share/git/libc-database"
LIBC_SRC_PATH = "/glibc"
ELF_TMPPATH = "/tmp/pwn"


class Pwn(Logger):

	def __init__(self, elf, gdbscript='', src='2.27', libs=[], env=[], host='127.0.0.1', port=9999, remote=False):
		super(Pwn, self).__init__()
		self._src = src
		self._host = host
		self._port = port
		self.gdbscript = gdbscript
		self._ffi = None
		self._remote = remote

		if args.SRC:
		# change elf's iterpreter in src mode
			self.elf = self.change_ld(elf, self._src)
		elif not args.REMOTE and not self._remote:
		# change elf's iterpreter in local mode
			libc = ""
			for (i, lib) in enumerate(libs):
				# if iterpreter is given, change and break
				if Pwn.get_so_name(lib) == 'ld-linux-x86-64.so.2' or Pwn.get_so_name(lib) == 'ld-linux.so.2':
					ld_path = libs.pop(i)
					self.elf = self.change_ld(elf, ld_path)
					break
				if Pwn.get_so_name(lib) == 'libc.so.6':
					libc = lib
			else:
				# iterpreter is not given but libc is given
				for i in range(1):
					if libs and libc:
						libc_id = Pwn.get_ld_by_libc(libc)
						if libc_id:
							ld_id = re.compile("libc6_").sub("ld_", libc_id)
							ld_auto_lookup = LIBC_DATABASE_PATH + "/db/" + ld_id + ".so"
							if os.path.isfile(ld_auto_lookup):
								self.warn("{} was found to load {}".format(ld_auto_lookup, libc_id))
								self.elf = self.change_ld(elf, ld_auto_lookup)
								break
				else:
					# ld is not changed
					if libs:
						self.warn("Both interpreter and libc are not given!")
					if not isinstance(elf, ELF):
						self.elf = ELF(elf)
					else:
						self.elf = elf
		else:
			# remote mode
			if not isinstance(elf, ELF):
				self.elf = ELF(elf)
			else:
				self.elf = elf
		
		library_needed = set()
		if not args.REMOTE and not self._remote:
			r = os.popen("patchelf --print-needed '{}'".format(self.elf.path)).readlines()
			for l in r:
				if not 'ld-' in l:
					library_needed.add(l)

		self._env = {
			'debug': ['{}/{}/{}/lib/{}'.format(LIBC_SRC_PATH, self.elf.arch, src, lib.strip()) for lib in library_needed],
			'local': [os.path.abspath(lib) for lib in libs],
			'common': env
		}
		
	@property
	def libc(self):
		if args.SRC:
			return ELF('{}/{}/{}/lib/libc.so.6'.format(LIBC_SRC_PATH, self.elf.arch, self._src))
		else:
			local_env = self._env['local']
			for lib in local_env:
				if Pwn.get_so_name(lib) == 'libc.so.6':
					return ELF(lib)
			return self.elf.libc
	
	@property
	def ffi(self):
		if not self._ffi:
			self._ffi = MYFFI(self.libc.path, self)
		return self._ffi

	def start(self, argv=[], *a, **kw):
		if args.REMOTE or self._remote:
			return self.remote(argv, *a, **kw)
		else:
			return self.local(argv, *a, **kw)

	def local(self, argv, *a, **kw):
		mode = 'debug' if args.SRC else 'local'
		env = kw.pop('env', {}) 
		if self._env[mode]:
			env['LD_PRELOAD'] = ':'.join(self._env[mode])
		if args.GDB:
			return gdb.debug([self.elf.path] + argv, gdbscript=self.gdbscript, env=env, *a, **kw)
		else:
			io = process([self.elf.path] + argv, env=env, *a, **kw)
			if args.ATTACH:
				gdb.attach(io, gdbscript=self.gdbscript)
			return io

	def remote(self, argv, *a, **kw):
		io = connect(self._host, self._port, *a, **kw)
		return io

	@staticmethod
	def get_so_name(ld_path):
		ld_abspath = os.path.abspath(ld_path)
		r = os.popen("patchelf --print-soname '{}'".format(ld_abspath)).read()
		return r.strip()

	@staticmethod
	def get_ld_by_libc(libc):
		libc_abspath = os.path.abspath(libc)
		p = subprocess.Popen("{}/identify '{}'".format(LIBC_DATABASE_PATH, libc_abspath), 
				shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = p.communicate()
		if stderr:
			self.warn(stderr)
		if stdout:
			return stdout.split()[1]
		else:
			return ''

	@staticmethod
	def set_interpreter(ld_path, binary):
		if not os.path.exists(ELF_TMPPATH):
			os.mkdir(ELF_TMPPATH)
		pwn_elf_name = ELF_TMPPATH + '/' + os.path.split(binary.path)[1]
		shutil.copyfile(binary.path, pwn_elf_name)
		os.chmod(pwn_elf_name, 0o770)
		cmd = 'patchelf --set-interpreter ' + ld_path + ' ' + pwn_elf_name
		os.system(cmd)
		return pwn_elf_name

	@staticmethod
	def change_ld(binary, ld):
		if not isinstance(binary, ELF):
			if not os.path.isfile(binary): 
				self.failure("Invalid path {}: File does not exists".format(binary))
				return None
			else:
				binary = ELF(binary)

		arch = binary.arch

		if not os.path.isfile(ld):
			if not ld in ['2.23', '2.24', '2.25', '2.26', '2.27', '2.28', '2.29']:
				self.failure("Invalid path {}: File does not exists".format(ld))
				return None
			else:
				ld =  '{}/{}/{}/lib/ld-{}.so'.format(LIBC_SRC_PATH, arch, ld, ld)
		ld_abs_path = os.path.abspath(ld)
		pwn_elf_path = Pwn.set_interpreter(ld_abs_path, binary)
		return ELF(pwn_elf_path)

def mod_attack(n, e1, c1, e2, c2):
    """
        RSA mod attack
        known: e1, e2, c1, c2, n
        unknown: m
        conditions:
            m ** e1 % n = c1
            m ** e2 % n = c2
    """
    if isinstance(n, str):
        n = int(n, 16)
    if isinstance(e1, str):
        e1 = int(e1, 16)
    if isinstance(c1, str):
        c1 = int(c1, 16)
    if isinstance(e2, str):
        e2 = int(e2, 16)
    if isinstance(c2, str):
        c2 = int(c2, 16)

    sys.setrecursionlimit(100000)
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(a, m):
        g, x, y = egcd(a, m)
        if g != 1:
            raise Exception('modular inverse does not exist')
        else:
            return x % m

    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    if s1 < 0:
        s1 = -s1
        c1 = modinv(c1, n)
    elif s2 < 0:
        s2 = -s2
        c2 = modinv(c2, n)
    return pow(c1, s1, n) * pow(c2, s2, n) % n

class Tea:

	delta = 0x9e3779b9

	@staticmethod
	def encrtypt_chunk(chunk1, chunk2, key, tround):
		assert(len(chunk1) == 4)
		assert(len(chunk2) == 4)
		assert(len(key) == 16)

		tsum = 0
		x = u32(chunk1)
		y = u32(chunk2)
		keyarr = [key[i:i+4] for i in range(0, len(key), 4)]
		for i in range(tround):
			tsum += Tea.delta
			x += ((y << 4) + u32(keyarr[0])) ^ (y + tsum) ^ ((y >> 5) + u32(keyarr[1]))
			x = x & 0xffffffff
			y += ((x << 4) + u32(keyarr[2])) ^ (x + tsum) ^ ((x >> 5) + u32(keyarr[3]))
			y = y & 0xffffffff
		return x, y 

	@staticmethod
	def encrypt(content, key, tround=32):
		assert(len(content) % 8 == 0)
		assert(len(key) == 16)
		res = []
		content_arr = [content[i:i+8] for i in range(0, len(content), 8)]

		for c in content_arr:
			x, y = Tea.encrtypt_chunk(c[:4], c[4:8], key, tround)
			res.append((y << 32) + x)
		return ''.join([p64(i) for i in res])

	@staticmethod
	def decrypt_chunk(chunk1, chunk2, key, tround=32):
		assert(len(chunk1) == 4)
		assert(len(chunk2) == 4)
		assert(len(key) == 16)

		tsum = Tea.delta << int(math.log(tround, 2))
		x = u32(chunk1)
		y = u32(chunk2)
		keyarr = [key[i:i+4] for i in range(0, len(key), 4)]
		for i in range(tround):
			y -= ((x << 4) + u32(keyarr[2])) ^ (x + tsum) ^ ((x >> 5) + u32(keyarr[3]))
			y = y & 0xffffffff
			x -= ((y << 4) + u32(keyarr[0])) ^ (y + tsum) ^ ((y >> 5) + u32(keyarr[1]))
			x = x & 0xffffffff
			tsum -= Tea.delta
		return x, y 

	@staticmethod
	def decrypt(content, key, tround=32):
		assert(len(content) % 8 == 0)
		assert(len(key) == 16)
		res = []
		content_arr = [content[i:i+8] for i in range(0, len(content), 8)]

		for c in content_arr:
			x, y = Tea.decrypt_chunk(c[:4], c[4:8], key, tround)
			res.append((y << 32) + x)
		return ''.join([p64(i) for i in res])

class MYFFI(CDLL):

	randomelf = os.path.split(os.path.realpath(__file__))[0] + "/random.elf"
	mktimeelf = os.path.split(os.path.realpath(__file__))[0] + "/mktime.elf"

	def __init__(self, libc_path, pwn):
		super(MYFFI, self).__init__(libc_path)
		self._pwn = pwn

	def mktime(self, timestruct):
		assert(type(timestruct) == list and len(timestruct) >= 9)
		p = subprocess.Popen("{} {}".format(MYFFI.mktimeelf, ' '.join([str(i) for i in timestruct])), 
			shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		(stdout, stderr) = p.communicate()
		if stderr:
			self._pwn.warn(stderr)
		if stdout:
			return stdout.split()[0]

class classproperty(property):
    def __get__(self, cls, owner):
        return classmethod(self.fget).__get__(None, owner)()

class JamedArg:

	special_ch = ["|", "<", ">", "&", "\\"]

	def __init__(self, name):
		self._name = name
		self._name_array = []
		self.special = False
		for ch in name:
			if ch in JamedArg.special_ch:
				self.special = True
			self._name_array.append([Jam.varname(), ch])

	@property
	def defarr(self):
		arr = [('{}={};' if pair[1] not in JamedArg.special_ch else '{}=\'{}\';').format(pair[0], pair[1]) for pair in self._name_array]
		return arr

	@property
	def defstr(self):
		arr = [('{}={};' if pair[1] not in JamedArg.special_ch else '{}=\'{}\';').format(pair[0], pair[1]) for pair in self._name_array]
		random.shuffle(arr)
		return ''.join(arr)

	@property
	def callstr(self):
		return ''.join(['${{{}}}'.format(pair[0]) for pair in self._name_array])

class Jam(str):

	_libc = None
	name_used = []
	symbols = [
		'system', 'execve', 'open', 'read', 'write', 'gets', 'setcontext', 
		'__malloc_hook', '__free_hook', '__realloc_hook', 'stdin', 'stdout', '_IO_list_all', '__after_morecore_hook'
	]
	symbol_idx = 0
	_bits = None
	_endian = None
	avoid = []

	def __new__(cls, value, *args, **kwargs):
		return str.__new__(cls, value)

	@classproperty
	def bits(cls):
		if not cls._bits:
			return context.bits
		return cls._bits

	@classproperty
	def endian(cls):
		if not cls._endian:
			return context.endian
		return cls._endian
	
	@classproperty
	def chars(cls):
		return [chr(i) for i in range(0xff) if i not in cls.avoid]

	@classproperty
	def packer(cls):
		return make_packer(cls.bits, endian=cls.endian, sign='unsigned')

	@classproperty
	def libc(cls):
		if cls._libc is None:
			with open(os.path.split(os.path.realpath(__file__))[0] + "/libc_{}".format("amd64" if Jam.bits==64 else "i386"), "r") as fp:
				names =[name.strip() for name in fp.readlines()]
				libc_path = ''
				max_count = 100
				while max_count >= 0:
					libc_path = LIBC_DATABASE_PATH + "/db/" + random.choice(names)
					if os.path.isfile(libc_path):
						break
					max_count -= 1
				else:
					print('unknown libc database path: {}'.format(LIBC_DATABASE_PATH))
				cls._libc = ELF(libc_path)
		return cls._libc

	@staticmethod
	def context(endian=None, bits=None, avoid=[], libc=None):
		if endian:
			Jam.endian = endian
		if bits:
			Jam.bits = bits
		if avoid:
			Jam.avoid = avoid
		if type(libc) == ELF:
			Jam._libc = libc

	@classproperty
	def seed(cls):
		if cls.bits == 64:
			return random.randint(0, 0x1000000) << 12
		else:
			return random.randint(0, 0x100) << 12

	@staticmethod
	def fill(size):
		"""
		return :str
		"""
		ptrsize = context.bits / 8
		count = size / ptrsize
		addition = size % ptrsize
		jam = ''
		for i in range(count):
			while True:
				retries = 0
				try:
					ptr = Jam.libc.symbols[Jam.symbols[Jam.symbol_idx % len(Jam.symbols)]]
					Jam.symbol_idx += 1
				except:
					Jam.symbol_idx += 1
					retries += 1
					if retries <= len(Jam.symbols):
						continue
				break
			jam += Jam.packer(ptr + Jam.seed)
		for i in range(addition):
			jam += random.choice(Jam.chars)
		return jam

	def lfill(self, size):
		"""
		return :str
		"""
		if self.__len__() > size:
			return self
		else:
			return self + Jam.fill(size - self.__len__())
	
	def rfill(self, size):
		if self.__len__() > size:
			return self
		else:
			return Jam.fill(size - self.__len__()) + self

	@staticmethod
	def varname():
		var_len = random.randint(1, 10)
		var_name = ""
		res = ""
		for i in range(var_len):
			var_name += random.choice(string.ascii_letters)
		if not var_name in Jam.name_used:
			Jam.name_used.append(var_name)
			res = var_name
		else:
			res = Jam.varname()
		return res

	@staticmethod
	def _confuse_arg(arg, align=8):
		pass

	@staticmethod
	def bashconfuse(cmd, align=8):
		res = ''
		if not cmd:
			return res
		special_ch = False
		args = cmd.split(" ")
		jamed_arg_list = []
		for arg in args:
			jamed_arg_list.append(JamedArg(arg))
		defarr = reduce(lambda i, sum: i + sum, [j.defarr for j in jamed_arg_list])
		random.shuffle(defarr)

		for j in jamed_arg_list:
			if j.special:
				special_ch = True
				break

		if special_ch:
			jamed_echo = JamedArg("echo")
			jamed_binsh = JamedArg("/bin/sh")
			res = ''.join(defarr) + jamed_binsh.defstr + jamed_echo.defstr + jamed_echo.callstr + " \"" + ' '.join([j.callstr for j in jamed_arg_list]) + "\"|"+ jamed_binsh.callstr
		else:
			res = ''.join(defarr) + ' '.join([j.callstr for j in jamed_arg_list])
		return res

	@staticmethod
	def catflag(align=8):
		return Jam.bashconfuse("/bin/cat flag")
	
	@staticmethod
	def binsh(align=8):
		return Jam.bashconfuse("/bin/sh")

	@staticmethod
	def fakeflag():
		fakeflag = ''
		for i in range(60):
			fakeflag += random.choice(string.digits + string.ascii_letters)
		return fakeflag