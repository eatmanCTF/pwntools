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
import shutil
import sys, string
import re
from ctypes import *

LIBC_DATABASE_UTIL = "/home/ubtu/ctf_local/git_eatman/libc-database"
LIBC_DBROOT = os.path.join(LIBC_DATABASE_UTIL, "db")
LIBC_DBSRCROOT = os.path.join(LIBC_DATABASE_UTIL, "db_source")
ELF_TMPPATH = "/tmp/pwn"


class Pwn(Logger):
    """
	Pwn support 3 modes:
	- source mode: 
		using glibc-libraries with full debug info, the libraires are located at context.eatman_pwn_libc_src_root.
	- local mode: 
		using glibc-libraries provieded by user, it is recommanded to provied both libc and ld libraries.
		at least, a libc library should be provieded, in this case, Pwn will use libc-database to try finding out a propper ld library.
	- remote mode:
		using given host and port to make a new connection

	requirements:
		libc-database repo
		build glibc src using pwn_debug repo's build.sh
		patchelf
	"""
    def __init__(self, elf, mode, **kwargs):
        super(Pwn, self).__init__()
        self.mode = mode
        self._ffi = None
        self._src = kwargs.get("src", "")
        self._host = kwargs.get("host")
        self._port = kwargs.get("port")
        self._libraires = None
        self._gdbscript = kwargs.get("gdbscript")
        self._ld_path = ""
        self._libc_path = ""
        self.elf = elf

        if mode == "src":
            # change libs for source mode
            self.elf = self.change_ld(elf, self._src)
            libraires = set()
            r = os.popen("patchelf --print-needed '{}'".format(
                self.elf.path)).readlines()
            for l in r:
                if not "ld-" in l:
                    libraires.add(l)
                else:
                    self._ld_path = l
            self._libc_path = f"{LIBC_DBSRCROOT}/{self.elf.arch}/{self._src}/lib/libc.so.6"
            self._libraires = [
                f"{LIBC_DBSRCROOT}/{self.elf.arch}/{self._src}/lib/{lib.strip()}"
                for lib in libraires
            ]
        else:
            # change libs for local and remote mode
            libs = kwargs.get("libs", [])

            # search for libc
            for (i, lib) in enumerate(libs):
                # match exactly
                if Pwn.get_so_name(lib) == "libc.so.6":
                    self._libc_path = libs[i]
                    break
            else:
                # match name
                for (i, lib) in enumerate(libs):
                    if re.match(r".*libc.*\.so$", lib):
                        self._libc_path = libs[i]
                        break

            # search for ld
            for (i, lib) in enumerate(libs):
                if Pwn.get_so_name(
                        lib) == "ld-linux-x86-64.so.2" or Pwn.get_so_name(
                            lib) == "ld-linux.so.2":
                    self._ld_path = libs.pop(i)
                    break
            else:
                for (i, lib) in enumerate(libs):

                    if re.match(r".*ld[-_].*\.so$", lib):
                        self._ld_path = libs.pop(i)
                        break

            # ld auto lookup
            if not self._ld_path:
                if self._libc_path:
                    libc_id = Pwn.get_libc_version(self._libc_path)
                    if libc_id:
                        ld_id = f"ld_{libc_id}"
                        self._ld_path = os.path.join(LIBC_DBROOT,
                                                     f"{ld_id}.so")
                        if os.path.isfile(self._ld_path):
                            self.warn("{} was found to load {}".format(
                                self._ld_path, libc_id))

            if not self._ld_path:
                if libs:
                    self.warn("No valid ld - libc peer found in given libs!")
            else:
                self.elf = self.change_ld(elf, self._ld_path)

            if not isinstance(self.elf, ELF):
                self.elf = ELF(elf)

            self._libraires = [os.path.abspath(lib) for lib in libs]
        assert self._libraires is not None
        return

    @property
    def libc(self):
        if self._libc_path:
            return ELF(self._libc_path)
        return self.elf.libc

    @property
    def ffi(self):
        if not self._ffi:
            self._ffi = MYFFI(self.libc.path, self)
        return self._ffi

    def start(self, argv=[], *a, **kw):
        if self.mode == "remote":
            return self.remote(argv, *a, **kw)
        else:
            return self.local(argv, *a, **kw)

    def local(self, argv, *a, **kw):
        env = kw.pop("env", {})
        if self._libraires:
            env["LD_PRELOAD"] = ":".join(self._libraires)
        if args.GDB:
            return gdb.debug([self.elf.path] + argv,
                             gdbscript=self._gdbscript,
                             env=env,
                             *a,
                             **kw)
        else:
            io = process([self.elf.path] + argv, env=env, *a, **kw)
            if args.ATTACH:
                gdb.attach(io, gdbscript=self._gdbscript)
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
    def get_libc_version(libc):
        libc_abspath = os.path.abspath(libc)
        p = subprocess.Popen("{}/identify '{}' | grep -v 'ld_'".format(
            LIBC_DATABASE_UTIL, libc_abspath),
                             shell=True,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        if stderr:
            print(stderr)
        if stdout:
            return stdout.split()[0].decode("utf-8")
        else:
            return ""

    @staticmethod
    def set_interpreter(ld_path, binary):
        if not os.path.exists(ELF_TMPPATH):
            os.mkdir(ELF_TMPPATH)
        pwn_elf_name = ELF_TMPPATH + "/" + os.path.split(binary.path)[1]
        shutil.copyfile(binary.path, pwn_elf_name)
        os.chmod(pwn_elf_name, 0o770)
        cmd = "patchelf --set-interpreter \"" + ld_path + "\" " + pwn_elf_name
        os.system(cmd)
        return pwn_elf_name

    @staticmethod
    def change_ld(binary, ld):
        if not isinstance(binary, ELF):
            if not os.path.isfile(binary):
                print("Invalid path {}: File does not exists".format(binary))
                return None
            else:
                binary = ELF(binary)

        arch = binary.arch

        if not os.path.isfile(ld):
            if not ld in [
                    "2.23", "2.24", "2.25", "2.26", "2.27", "2.28", "2.29",
                    "2.30", "2.31", "2.32"
            ]:
                print("Invalid path {}: File does not exists".format(ld))
                return None
            else:
                ld = f"{LIBC_DBSRCROOT}/{arch}/{ld}/lib/ld-{ld}.so"
        ld_abs_path = os.path.abspath(ld)
        pwn_elf_path = Pwn.set_interpreter(ld_abs_path, binary)
        return ELF(pwn_elf_path)


class MYFFI(CDLL):
    """
	By pass not-really random or mktime check
	"""

    randomelf = os.path.split(os.path.realpath(__file__))[0] + "/random.elf"
    mktimeelf = os.path.split(os.path.realpath(__file__))[0] + "/mktime.elf"

    def __init__(self, libc_path, pwn):
        super(MYFFI, self).__init__(libc_path)
        self._pwn = pwn

    def mktime(self, timestruct):
        assert (type(timestruct) == list and len(timestruct) >= 9)
        p = subprocess.Popen(
            f"{MYFFI.mktimeelf} {' '.join([str(i) for i in timestruct])}",
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        (stdout, stderr) = p.communicate()
        if stderr:
            self._pwn.warn(stderr)
        if stdout:
            return stdout.split()[0]
