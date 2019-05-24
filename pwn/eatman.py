from __future__ import absolute_import

import os
from pwnlib import gdb
from pwnlib.args import args
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from pwnlib.tubes.process import process
from pwnlib.tubes.remote import connect
import shutil
import sys
log = getLogger(__name__)
LD_TMPNAME = "/tmp/lso"
ELF_TMPPATH = "/tmp/pwn"

class Pwn:

	def __init__(self, elf, gdbscript='', src='2.27', libs=[], env=[], host='127.0.0.1', port=9999):
		self._debug_version = src
		self._host = host
		self._port = port
		self.gdbscript = gdbscript
		
		if args.SRC:
			self.elf = self.change_ld(elf, self._debug_version)
		else:
			for (i, lib) in enumerate(libs):
				if Pwn.get_so_name(lib) == 'ld-linux-x86-64.so.2' or Pwn.get_so_name(lib) == 'ld-linux.so.2':
					ld_path = libs.pop(i)
					self.elf = self.change_ld(elf, ld_path)
					break
			else:
				if not isinstance(elf, ELF):
					self.elf = ELF(elf)
				else:
					self.elf = elf
		
		library_needed = set()
		r = os.popen("patchelf --print-needed " + self.elf.path).readlines()
		for l in r:
			if not 'ld-' in l:
				library_needed.add(l)

		self._env = {
			'debug': ['/glibc/{}/{}/lib/{}'.format(self.elf.arch, src, lib.strip()) for lib in library_needed],
			'local': [os.path.abspath(lib) for lib in libs],
			'common': env
		}
		
	@property
	def libc(self):
		if args.SRC:
			return ELF('/glibc/{}/{}/lib/libc.so.6'.format(self.elf.arch, self._debug_version))
		else:
			local_env = self._env['local']
			for lib in local_env:
				if Pwn.get_so_name(lib) == 'libc.so.6':
					return ELF(lib)
			return self.elf.libc

	def start(self, argv=[], *a, **kw):
		if args.REMOTE:
			return self.remote(argv, *a, **kw)
		else:
			return self.local(argv, *a, **kw)

	def local(self, argv, *a, **kw):
		mode = 'debug' if args.SRC else 'local'
		env = kw.pop('env', {}) 
		if self._env[mode]:
			env['LD_PRELOAD'] = ':'.join(self._env[mode])
		if args.GDB:
			return gdb.debug([self.elf.path] + argv, env=env, *a, **kw)
		else:
			io = process([self.elf.path] + argv, env=env, *a, **kw)
			if args.ATTACH:
				gdb.attach(io, gdbscript=self.gdbscript)
			return io

	def remote(self, argv, *a, **kw):
		io = connect(self._host, self._port, *a, **kw)
		if args.GDB:
			gdb.attach(io, gdbscript=self.gdbscript)
		return io

	@staticmethod
	def get_so_name(ld_path):
		ld_abspath = os.path.abspath(ld_path)
		r = os.popen("patchelf --print-soname " + ld_abspath).read()
		return r.strip()

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
				log.failure("Invalid path {}: File does not exists".format(binary))
				return None
			else:
				binary = ELF(binary)

		arch = binary.arch

		if not os.path.isfile(ld):
			if not ld in ['2.23', '2.24', '2.25', '2.26', '2.27', '2.28', '2.29']:
				log.failure("Invalid path {}: File does not exists".format(ld))
				return None
			else:
				ld =  '/glibc/{}/{}/lib/ld-{}.so'.format(arch, ld, ld)
		ld_abs_path = os.path.abspath(ld)
		pwn_elf_path = Pwn.set_interpreter(ld_abs_path, binary)
		return ELF(pwn_elf_path)

def create_symlink(src, dst):
	if os.path.islink(dst):
		log.info("Removing exist link %s", dst)
		os.remove(dst)
	os.symlink(src, dst)
	if not os.access(dst, os.F_OK): 
		log.failure("Create symlink {} ==> {} file failed".format(dst, src))
		return False
	os.chmod(dst, 0b111000000) #rwx------
	return dst

def save_elf(binary):
	if not os.access(ELF_TMPPATH, os.F_OK):
		os.mkdir(ELF_TMPPATH)
	path = '{}/{}'.format(ELF_TMPPATH, os.path.basename(binary.path))
	if os.access(path, os.F_OK): 
		os.remove(path)
		log.info("Removing exist file {}".format(path))
	binary.save(path)
	if not os.access(path, os.F_OK):
		log.failure("Save file {} failed".format(path))
		return False
	os.chmod(path, 0b111000000) #rwx------
	return path

def change_ld(binary, ld):
	"""
	Force to use assigned new ld.so by changing the binary
	"""
	if not os.access(ld, os.R_OK): 
		log.failure("Invalid path {} to ld".format(ld))
		return None
	abs_path = os.path.abspath(ld)
  
	if not isinstance(binary, ELF):
		if not os.access(binary, os.R_OK): 
			log.failure("Invalid path {} to binary".format(binary))
			return None
		binary = ELF(binary)
 
 
	for segment in binary.segments:
		if segment.header['p_type'] == 'PT_INTERP':
			size = segment.header['p_memsz']
			addr = segment.header['p_paddr']
			data = segment.data()
			if size <= len(LD_TMPNAME):
				log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
				return None
			if not create_symlink(abs_path, LD_TMPNAME):
				return None
			binary.write(addr, LD_TMPNAME.ljust(size, '\x00'))
			path = save_elf(binary)
			if not path:
				return None
	log.success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
	return ELF(path)

def change_libc(binary, lib_path):
	return change_lib(binary, "libc.so.6", lib_path)

def change_lib(binary, lib_name, lib_path, lib_id=0):
	"""
	Force to use assigned new lib by changing the binary
	"""
	if not os.path.isfile(lib_path): 
		log.failure("Invalid path {} to {}".format(lib_path, lib_name))
		return None
	abs_path = os.path.abspath(lib_path)

	if not isinstance(binary, ELF):
		if not os.access(binary, os.R_OK): 
			log.failure("Binary file must be an ELF instance")
			return None
		binary = ELF(binary)

	for segment in binary.segments:
		if segment.header['p_type'] == 'PT_INTERP':
			size = segment.header['p_memsz']
			addr = segment.header['p_paddr']
			data = segment.data()

	strtab = binary.dynamic_value_by_tag('DT_STRTAB')
	
	lib_str_offset = None
	lib_id = lib_id
	binary_dynamic = binary.get_section_by_name('.dynamic')
	if not binary_dynamic:
		log.failure("binary_dynamic not found")
		return None
	dynamic_tags = binary_dynamic.iter_tags()
	while True:
		try:
			next_lib_offset = next(t for t in dynamic_tags if 'DT_NEEDED' == t.entry.d_tag).entry.d_val
			lib_tmp_name = '/tmp/l{}'.format(lib_id)
			lib_id += 1
			if binary.string(next_lib_offset + strtab) == lib_name:
				lib_str_offset = next_lib_offset + strtab
				break
		except StopIteration:
			break
	
	if not lib_str_offset:
		log.failure("string {} not found".format(lib_name))
		return None

	if not create_symlink(abs_path, lib_tmp_name):
		log.failure("create symlink from {} to {} failed!".format(abs_path, lib_tmp_name))
		return None

	dir_name, file_name = os.path.split(abs_path)
	if lib_name == "libc.so.6" and os.path.isdir(dir_name + "/.debug"):
		if os.path.isdir(dir_name + "/.debug/" + os.path.splitext(file_name)[0]):
			create_symlink(dir_name + "/.debug/" + os.path.splitext(file_name)[0], '/tmp/.debug')
		else:
			create_symlink(dir_name + "/.debug", '/tmp/.debug')

	binary.write(lib_str_offset, lib_tmp_name.ljust(len(lib_name), '\x00'))	
	path = save_elf(binary)
	if not path:
		log.failure("binary save failed!")
		return None
	return ELF(path)

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
