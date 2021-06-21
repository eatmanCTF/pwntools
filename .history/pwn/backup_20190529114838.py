def create_symlink(src, dst):
	if os.path.islink(dst):
		self.info("Removing exist link %s", dst)
		os.remove(dst)
	os.symlink(src, dst)
	if not os.access(dst, os.F_OK): 
		self.failure("Create symlink {} ==> {} file failed".format(dst, src))
		return False
	os.chmod(dst, 0b111000000) #rwx------
	return dst

def save_elf(binary):
	if not os.access(ELF_TMPPATH, os.F_OK):
		os.mkdir(ELF_TMPPATH)
	path = '{}/{}'.format(ELF_TMPPATH, os.path.basename(binary.path))
	if os.access(path, os.F_OK): 
		os.remove(path)
		self.info("Removing exist file {}".format(path))
	binary.save(path)
	if not os.access(path, os.F_OK):
		self.failure("Save file {} failed".format(path))
		return False
	os.chmod(path, 0b111000000) #rwx------
	return path

def change_ld(binary, ld):
	"""
	Force to use assigned new ld.so by changing the binary
	"""
	if not os.access(ld, os.R_OK): 
		# self.failure("Invalid path {} to ld".format(ld))
		return None
	abs_path = os.path.abspath(ld)
  
	if not isinstance(binary, ELF):
		if not os.access(binary, os.R_OK): 
			# log.failure("Invalid path {} to binary".format(binary))
			return None
		binary = ELF(binary)
 
 
	for segment in binary.segments:
		if segment.header['p_type'] == 'PT_INTERP':
			size = segment.header['p_memsz']
			addr = segment.header['p_paddr']
			data = segment.data()
			if size <= len(LD_TMPNAME):
				# log.failure("Failed to change PT_INTERP from {} to {}".format(data, ld))
				return None
			if not create_symlink(abs_path, LD_TMPNAME):
				return None
			binary.write(addr, LD_TMPNAME.ljust(size, '\x00'))
			path = save_elf(binary)
			if not path:
				return None
	# log.success("PT_INTERP has changed from {} to {}. Using temp file {}".format(data, ld, path)) 
	return ELF(path)

def change_libc(binary, lib_path):
	return change_lib(binary, "libc.so.6", lib_path)

def change_lib(binary, lib_name, lib_path, lib_id=0):
	"""
	Force to use assigned new lib by changing the binary
	"""
	if not os.path.isfile(lib_path): 
		# log.failure("Invalid path {} to {}".format(lib_path, lib_name))
		return None
	abs_path = os.path.abspath(lib_path)

	if not isinstance(binary, ELF):
		if not os.access(binary, os.R_OK): 
			# log.failure("Binary file must be an ELF instance")
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
		# log.failure("binary_dynamic not found")
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
		# log.failure("string {} not found".format(lib_name))
		return None

	if not create_symlink(abs_path, lib_tmp_name):
		# log.failure("create symlink from {} to {} failed!".format(abs_path, lib_tmp_name))
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
		# log.failure("binary save failed!")
		return None
	return ELF(path)