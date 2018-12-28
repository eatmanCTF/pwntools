from __future__ import absolute_import

import os
from pwnlib.elf import ELF
from pwnlib.log import getLogger
from shutil import copyfile

log = getLogger(__name__)
LD_TMPNAME = "/tmp/lso"
LIBC_TMPNAME = "/tmp/cso"
ELF_TMPPATH = "/tmp/pwn"

def create_symlink(src, dst):
	if os.access(dst, os.F_OK): 
		os.remove(dst)
	os.symlink(src, dst)
	if not os.access(dst, os.F_OK): 
		log.failure("Create symlink {} ==> {} file failed".format(dst, src))
		return False
	os.chmod(dst, 0b111000000) #rwx------
	return dst

def save_elf(binary, end="debug"):
	if not os.access(ELF_TMPPATH, os.F_OK):
		os.mkdir(ELF_TMPPATH)
	path = '{}/{}_{}'.format(ELF_TMPPATH, os.path.basename(binary.path), end)
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
			if not create_symlink(ld, LD_TMPNAME):
				return None
			binary.write(addr, LD_TMPNAME.ljust(size, '\x00'))
			path = save_elf(binary, 'ld')
			if not path:
				return None
	log.success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
	return ELF(path)

def change_libc(binary, libc):
	"""
	Force to use assigned new libc.so by changing the binary
	"""
	if not os.access(libc, os.R_OK): 
		log.failure("Invalid path {} to ld".format(ld))
		return None
  
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

	strtab = binary.dynamic_value_by_tag('DT_STRTAB')
	
	prev_lib = 0
	while True:
		next_lib = binary.dynamic_value_by_tag('DT_NEEDED')
		if binary.string(next_lib + strtab) == 'libc.so.6':
			libc_str_offset = next_lib + strtab
			break
		if next_lib == prev_lib:
			log.failure("string libc.so.6 not found")
			return None
		prev_lib = next_lib

	if not create_symlink(libc, LIBC_TMPNAME):
		return None

	binary.write(libc_str_offset, LIBC_TMPNAME.ljust(9, '\x00'))	
	path = save_elf(binary, 'libc')
	if not path:
		return None
	return ELF(path)