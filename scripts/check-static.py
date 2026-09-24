#!/usr/bin/env python3
"""Proves a bridge executable depends on nothing but the operating system.

    scripts/check-static.py <executable>...

Reads the file itself, no ldd, otool or dumpbin, so the check is the same on every machine and
can be run on a binary built for another platform:

  ELF (Linux)      no PT_INTERP and no PT_DYNAMIC: a fully static executable, nothing loaded.
  Mach-O (macOS)   every LC_LOAD_DYLIB is a library every macOS has (libSystem, libc++): no
                   Homebrew path, no OpenSSL dylib.
                   A fat binary is checked slice by slice.
  PE (Windows)     every import is a Windows system DLL, never a vcpkg OpenSSL or an MSVC runtime.

The release fails closed on this: a binary that needs a library the user may not have is not
shipped. Exit status 0 when every file passes, 1 with a line per failure otherwise.
"""
import struct
import sys

WINDOWS_SYSTEM_DLLS = {
    'kernel32.dll', 'advapi32.dll', 'ws2_32.dll', 'user32.dll', 'crypt32.dll', 'bcrypt.dll', 'ntdll.dll',
    'shell32.dll', 'ole32.dll', 'rpcrt4.dll', 'mswsock.dll', 'iphlpapi.dll', 'secur32.dll', 'userenv.dll',
    'shlwapi.dll', 'version.dll', 'wldap32.dll', 'normaliz.dll',
}
# libSystem is the kernel's interface and libc++ is Apple's, present on every macOS; both are
# always there and neither can be linked statically, so they are what "nothing" means on macOS.
MACOS_SYSTEM = {'/usr/lib/libSystem.B.dylib', '/usr/lib/libc++.1.dylib', '/usr/lib/libc++abi.dylib', '/usr/lib/libobjc.A.dylib'}


def elf(data):
    if data[4] not in (1, 2) or data[5] not in (1, 2):
        return ['unreadable ELF header']
    bits64 = data[4] == 2
    endian = '<' if data[5] == 1 else '>'
    if bits64:
        phoff, = struct.unpack_from(endian + 'Q', data, 0x20)
        phentsize, phnum = struct.unpack_from(endian + 'HH', data, 0x36)
    else:
        phoff, = struct.unpack_from(endian + 'I', data, 0x1c)
        phentsize, phnum = struct.unpack_from(endian + 'HH', data, 0x2a)
    problems = []
    for i in range(phnum):
        p_type, = struct.unpack_from(endian + 'I', data, phoff + i * phentsize)
        if p_type == 3:
            problems.append('has a program interpreter (PT_INTERP): dynamically linked')
        if p_type == 2:
            problems.append('has a dynamic section (PT_DYNAMIC)')
    return problems


def macho_slice(data, off):
    magic = data[off:off + 4]
    if magic == b'\xcf\xfa\xed\xfe':
        endian, hdr = '<', 32
    elif magic == b'\xce\xfa\xed\xfe':
        endian, hdr = '<', 28
    else:
        return ['unreadable Mach-O header']
    ncmds, = struct.unpack_from(endian + 'I', data, off + 16)
    problems, pos = [], off + hdr
    for _ in range(ncmds):
        cmd, size = struct.unpack_from(endian + 'II', data, pos)
        if cmd in (0x0c, 0x0d, 0x18, 0x1f, 0x80000018, 0x8000001f):   # LOAD_DYLIB, ID_DYLIB, WEAK, REEXPORT, UPWARD, LAZY
            name_off, = struct.unpack_from(endian + 'I', data, pos + 8)
            name = data[pos + name_off:pos + size].split(b'\0', 1)[0].decode()
            if cmd != 0x0d and name not in MACOS_SYSTEM:
                problems.append('links ' + name)
        pos += size
    return problems


def macho(data):
    if data[:4] == b'\xca\xfe\xba\xbe':   # fat: big-endian header, one slice per architecture
        nfat, = struct.unpack_from('>I', data, 4)
        problems = []
        for i in range(nfat):
            _, _, offset, _, _ = struct.unpack_from('>IIIII', data, 8 + i * 20)
            problems += ['slice %d: %s' % (i, p) for p in macho_slice(data, offset)]
        return problems
    return macho_slice(data, 0)


def pe(data):
    pe_off, = struct.unpack_from('<I', data, 0x3c)
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        return ['unreadable PE header']
    nsections, = struct.unpack_from('<H', data, pe_off + 6)
    opt_size, = struct.unpack_from('<H', data, pe_off + 20)
    opt = pe_off + 24
    magic, = struct.unpack_from('<H', data, opt)
    dir_off = opt + (0x70 if magic == 0x20b else 0x60)
    import_rva, import_size = struct.unpack_from('<II', data, dir_off + 8)   # data directory 1: imports
    sections = []
    sec = opt + opt_size
    for i in range(nsections):
        vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', data, sec + i * 40 + 8)
        sections.append((vaddr, max(vsize, rsize), raddr))

    def file_off(rva):
        for vaddr, size, raddr in sections:
            if vaddr <= rva < vaddr + size:
                return raddr + rva - vaddr
        raise ValueError('rva %#x outside every section' % rva)

    if import_rva == 0:
        return []
    problems, pos = [], file_off(import_rva)
    while True:
        lookup, _, _, name_rva, _ = struct.unpack_from('<IIIII', data, pos)
        if lookup == 0 and name_rva == 0:
            break
        name_off = file_off(name_rva)
        name = data[name_off:data.index(b'\0', name_off)].decode().lower()
        if name not in WINDOWS_SYSTEM_DLLS and not name.startswith('api-ms-win-'):
            problems.append('imports ' + name)
        pos += 20
    return problems


def check(path):
    data = open(path, 'rb').read()
    if data[:4] == b'\x7fELF':
        return elf(data)
    if data[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe'):
        return macho(data)
    if data[:2] == b'MZ':
        return pe(data)
    return ['not an ELF, Mach-O or PE executable']


def main(argv):
    if not argv:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    failed = False
    for path in argv:
        problems = check(path)
        if problems:
            failed = True
            for p in problems:
                print('%s: %s' % (path, p), file=sys.stderr)
        else:
            print('static ok: ' + path)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
