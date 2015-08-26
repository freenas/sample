"""
Cython-based symbolicator.

This is in python because of string handling, and
in C because that's what libbfd uses.
"""

import os, sys
import types
import getopt
import re

Debug = False

cimport cython

cdef extern from "stdint.h":
    ctypedef int uintptr_t

cdef extern from "../sample/Keys.h":
    extern char *TOP_KEY
    extern char *PROCESS_LIST
    extern char *PROCESS_KEY
    extern char *KMOD_LIST
    extern char *KMOD_ENTRY
    extern char *THREAD_LIST
    extern char *THREAD_KEY
    extern char *STACKS_LIST
    extern char *FILE_LIST
    extern char *VERSION_KEY
    extern char *ARCH_KEY
    extern char *KMODULE_ID
    extern char *KMODULE_ADDR
    extern char *KMODULE_SIZE
    extern char *KMODULE_PATH
    extern char *PROC_PID_KEY
    extern char *PROC_NAME_KEY
    extern char *PROC_PATH_KEY
    extern char *PROC_COUNT_KEY
    extern char *THREAD_ID_KEY
    extern char *THREAD_STACKS_KEY
    extern char *FILE_PATH_KEY
    extern char *FILE_ADDR_KEY
    extern char *FILE_END_KEY
    extern char *SAMPLE_COUNT_KEY
    extern char *SAMPLE_ADDR_KEY
    extern char *SAMPLE_FILE_KEY
    extern char *SAMPLE_OFFSET_KEY
    
cdef extern from "bfd.h":
    cdef struct bfd_symbol:
        char *name
        int flags
    ctypedef bfd_symbol asymbol
    cdef struct bfd:
        pass
    ctypedef bfd bfd

    bfd *bfd_openr(const char *fname, const char *target)
    int bfd_check_format(const bfd* abfd, int format)
    # This is actually a macro
    int bfd_get_file_flags(void *bfd)
    int bfd_close(const bfd* abfd)
    int bfd_read_minisymbols(const bfd *abfd, int dynamic, void **syms, unsigned int *sizePtr)
    uintptr_t bfd_asymbol_value(asymbol *sym)
    uintptr_t bfd_asymbol_base(asymbol *sym)
    asymbol *bfd_make_empty_symbol(const bfd *abfd)
    asymbol *bfd_minisymbol_to_symbol(const bfd *abfd, int dynamic, void *sym, asymbol *symbol)
    
    # Picking and choosing the ones I use
    enum:
        bfd_object
    enum:
        HAS_SYMS
    enum:
        BSF_DYNAMIC
        BSF_SECTION_SYM
        BSF_DEBUGGING
        BSF_CONSTRUCTOR
        BSF_WARNING
        BSF_INDIRECT
        BSF_FILE
        BSF_DEBUGGING_RELOC
        BSF_RELC
        BSF_SRELC
        BSF_SYNTHETIC

def SymbolsFromFile(path, root_dir = None, base_addr = 0):
    cdef bfd* b
    cdef int symcount
    cdef asymbol **syms = NULL
    cdef unsigned int size

    if root_dir:
        tpath = root_dir + "/" + path
    else:
        tpath = path
        
    b = bfd_openr(path, NULL)
    if b == NULL:
        raise Exception("Cannot open file %s" % tpath)
    if bfd_check_format(b, bfd_object) == 0:
        raise Exception("Unknown objet type for kernel")

    symcount = 0

    dynamic = 0

    if (bfd_get_file_flags(b) & HAS_SYMS) == 0:
        dynamic = 1
    else:
        symcount = bfd_read_minisymbols(b, dynamic, <void**>&syms, &size)

    if symcount == 0:
        dynamic = 1
        symcount = bfd_read_minisymbols(b, dynamic, <void**>&syms, &size)

    cdef unsigned char *symtab = <unsigned char *>syms
    cdef asymbol *full_sym
    cdef void *sym
    cdef unsigned int sym_index

    retval = {}
    if symcount > 0:
        sym_index = 0
        while sym_index < symcount:
            full_sym = bfd_make_empty_symbol(b)
            if full_sym != NULL:
                sym = <void*>(symtab + (size * sym_index))
                full_sym = bfd_minisymbol_to_symbol(b, dynamic, sym, full_sym)
                if full_sym != NULL:
                    if (full_sym.flags & (BSF_SECTION_SYM | BSF_DEBUGGING | BSF_CONSTRUCTOR | BSF_WARNING | BSF_INDIRECT | BSF_FILE | BSF_DEBUGGING_RELOC | BSF_RELC | BSF_SRELC | BSF_SYNTHETIC)) == 0:
                        if bfd_asymbol_value(full_sym) != 0:
                            taddr = bfd_asymbol_value(full_sym) + base_addr
                            retval[taddr] = { "File" : path,
                                              "Base" : bfd_asymbol_base(full_sym),
                                              "Name" : full_sym.name,
                                              "Dynamic" : bool(full_sym.flags & BSF_DYNAMIC),
                            }
#                            print >> sys.stderr, "%s@%#x (%s)" % (full_sym.name, taddr, "dynamic" if  bool(full_sym.flags & BSF_DYNAMIC) else "non-dynamic")

            sym_index += 1

    bfd_close(b)
    return retval

def FindNearestSymbol(symbols, addr):
    """
    Given the symbols -- which should be a dictionary of addr -> name
    pairs -- find the nearest one to addr.  That is, the one that is >=
    addr, but < the next one.
    """
    sorted_addrs = sorted(symbols.keys())
    # A binary search wuld be bettr, but I'm being lazy for the nonce.
    best = None
    for base in sorted_addrs:
        if addr < base:
            break
        if addr >= base:
            best = base

    if best is None:
        return None
    else:
        return { "Symbol" : symbols[best]["Name"], "Offset" : addr - best, "Dynamic" : symbols[best]["Dynamic"] }
    
def usage():
    print >> sys.stderr, "Usage:  %s [-R|--root dir] sample_file" % sys.argv[0]
    print >> sys.stderr, "\t-R|--root\tSpecify the root directory to find symbol files."
    sys.exit(1)
    
def LoadSampleFile(path):
    """
    Load a sample file.  This must be a JSON file.
    Returns a dictionary, or raises an exception.
    
    """
    import json
    def parse_int(s):
        return int(s, 0)
    
    tdict = json.load(open(path))
    return tdict[TOP_KEY]

class SymbolFile(object):
    """
    Class object for files with symbols.
    SymbolFiles have several required attributes:
    - path
    - offset
    - base address
    - size

    From those, the initializer will also load symbols
    from the file, if it can.
    """
    def __init__(self, path, base, offset = 0, size = 0, force_dynamic = False):
        self._path = path
        self._base = base
        self._offset = offset
        self._size = size
        # path for this already has the root directory loaded
        if not force_dynamic:
            base = 0
        self._symbols = SymbolsFromFile(path, base_addr = base)

    def __str__(self):
        return "<_SymbolFile path '%s' base '%#x'>" % (self._path, self._base)
    
    @property
    def path(self):
        return self._path

    @property
    def base(self):
        return self._base

    @property
    def offset(self):
        return self._offset

    @property
    def size(self):
        return self._size

    @property
    def symbols(self):
        return self._symbols
    
class Symbols(object):
    """
    Class object for symbols.
    This is created by passing in SymbolFile objects into it;
    the base address for each SymbolFile can be over-ridden when
    doing so.  After it adds each set of symbols, it then sorts
    based on the address.
    
    """
 
    def __init__(self):
        self._symbols = {}
        self._keys = []

    def DumpSymbols(self):
        for k in self._keys:
            print "%#x %s" % (k, self._symbols[k])
            
    def AddSymbolFile(self, sf, base = None):
        import bisect
        if base is None:
            base = sf.base
        new_symbols = sf.symbols
        for addr, sym in new_symbols.iteritems():
            if Debug: print >> sys.stderr, "%s:  %#x -> symbol %s" % (sf.path, addr, sym)
            if sym["Dynamic"]:
                addr += base
            if addr in self._symbols:
                print >> sys.stderr, "File %s:  Duplicate address %#x for symbol %s -- %s was here first" % (sf.path, addr, sym["Name"], self._symbols[addr])
            else:
                self._symbols[addr] = sym
                ndx = bisect.bisect_right(self._keys, addr)
                self._keys.insert(ndx, addr)
#        self._keys = sorted(self._symbols.keys())
        
    def FindSymbolForAddress(self, addr):
        import bisect
        addrs = self._keys
        try:
            indx = bisect.bisect_right(addrs, addr)
            if indx > 0: indx -= 1
            return self._symbols[addrs[indx]]
        except:
            return None
        
def LoadKernelModules(sample_dict, root_dir = "/"):
    retval = {}
    try:
        for kmod in sample_dict[KMOD_LIST]:
            real_path = root_dir + "/" + kmod[KMODULE_PATH]
            if not os.path.exists(real_path):
                print >> sys.stderr, "Cannot file kernel module %s in root %s, skipping" % (kmod[KMODULE_PATH], root_dir)
                continue
            kmod_file = SymbolFile(real_path,
                                   int(kmod[KMODULE_ADDR], 0),
                                   size = kmod[KMODULE_SIZE],
                                   force_dynamic = real_path.endswith(".ko"),
            )
            retval[kmod[KMODULE_PATH]] = kmod_file
    except BaseException as e:
        print >> sys.stderr, "No kmodules?  That seems unlikely"
        print >> sys.stderr, "root_dir = %s, real_path = %s" % (root_dir, real_path)
        print >> sys.stderr "%s" % str(e)
        raise e
    return retval if retval else None
    
def LoadProcesses(sample_dict):
    retval = []
    try:
        for process in sample_dict[PROCESS_LIST]:
            p = process[PROCESS_KEY]
            # _Now_ we've got a process object
            retval.append(p)
    except BaseException as e:
        print >> sys.stderr, "What?  How did we get an exception processing processes?"
        print >> sys.stderr, str(e)


    return retval

def PrintStack(sample, indent = 1, symbols = None):
    """
    Print stacks.  This is recursive.
    """
    import traceback
    if type(sample) == dict:
        try:
            addr = int(sample[SAMPLE_ADDR_KEY], 0)
            line = "%s %5d %#x (%s + %#x)" % (" " * (indent - 1),
                                              sample[SAMPLE_COUNT_KEY],
                                              addr,
                                              sample[SAMPLE_FILE_KEY],
                                              sample[SAMPLE_OFFSET_KEY])
            if symbols:
                sym = symbols.FindSymbolForAddress(addr)
                if sym:
                    offset = addr - sym["Base"]
                    line += " [%s + %u]" % (sym["Name"], offset)
            print line
        except KeyError:
            pass
        except BaseException as e:
            print >> sys.stderr, traceback.format_exc()

        try:
            PrintStack(sample[THREAD_STACKS_KEY], indent + 1, symbols)
        except:
            pass
    elif type(sample) == list:
        for stack in sample:
            PrintStack(stack, indent, symbols)
    return

files = {}

short_opts = "R:D"
long_opts = [ "--root=",
              "--debug",
              ]
root_dir = None

try:
    opts, args = getopt.getopt(sys.argv[1:], short_opts, long_opts)
except getopt.GetoptError as err:
    usage()

for o, a in opts:
    if o in ("-R", "--root"):
        root_dir = a
    elif o in ("-D", "--debug"):
        Debug = True
    else:
        print >> sys.stderr, "Unknown option %s" % o
        usage()

if not args or len(args) > 1:
    usage()

sample = LoadSampleFile(args[0])
if sample is None:
    raise Exception("Could not load JSON file from %s" % args[0])

if VERSION_KEY in sample:
    version = sample[VERSION_KEY]
else:
    version = None
if ARCH_KEY in sample:
    arch = sample[ARCH_KEY]
else:
    arch = None
    
# Should deal with root here
if root_dir is None:
    root_dir = "/"
else:
    # Do something else.  For now, nothing
    # We would want to be able tp specify a location for
    # all the files with symbols.
    if os.path.isdir(root_dir + "/" + version):
        root_dir = root_dir + "/" + version
    elif not os.path.isdir(root_dir):
        root_dir = "/"
    
kmods = LoadKernelModules(sample, root_dir)
if Debug:
    for name, kmod in kmods.iteritems():
        print "%s -> %s" % (name, kmod)

processes = LoadProcesses(sample)

print "Version:  %s" % version
print "Architecture: %s" % arch
print ""

if kmods:
    print "Kernel Modules"
    print "%24s %16s %s" % ("Address", "Size", "Path")
    for modname in sorted(kmods.keys()):
        print "%#24x %16u %s" % (kmods[modname].base, kmods[modname].size, modname)
    print ""

for proc in processes:
    print "Process %u (%s, pathname %s)" % (proc[PROC_PID_KEY], proc[PROC_NAME_KEY], proc[PROC_PATH_KEY])
    print "Samples:  %u" % proc[PROC_COUNT_KEY]
    print ""

    symbols = Symbols()
    for kmod in kmods.itervalues():
        symbols.AddSymbolFile(kmod)
        
    real_path = None
    mapped_list = []
    try:
        # Note that kernel processes don't have mapped files
        # Also, we should print this out at the end of the process report.
        mapped_files = proc[FILE_LIST]
        for m in mapped_files:
            if root_dir is None:
                real_path = m[FILE_PATH_KEY]
            else:
                real_path = root_dir + m[FILE_PATH_KEY]
                
            try:
                addr = int(m[FILE_ADDR_KEY], 0)
            except:
                addr = 0
            try:
                end = int(m[FILE_END_KEY], 0)
            except:
                end = 0
                
            if addr or end:
                size = end - addr
            else:
                size = 0
                
            mapped_list.append((m[FILE_PATH_KEY], addr, end))

            sf = SymbolFile(real_path,
                            addr,
                            size,
                            force_dynamic = ".so" in real_path,
            )
            symbols.AddSymbolFile(sf)
    except BaseException as e:
        if real_path:
            print >> sys.stderr, "Unable to add mapped file %s: %s" % (real_path, str(e))
            
    try:
        threads = proc[THREAD_LIST]
        for thread in threads:
            print "Thread ID %u" % thread[THREAD_ID_KEY]
            print ""

            stacks = thread[THREAD_STACKS_KEY]
            for stack in stacks:
                PrintStack(stack, indent = 1, symbols = symbols)
            if Debug: symbols.DumpSymbols()
    except BaseException as e:
        print >> sys.stderr, "e = %s" % str(e)
        threads = None

    if mapped_list:
        print "Mapped Files"
        print "%24s %24s %s" % ("Start", "End", "File")
        for (p, a, e) in mapped_list:
            print "%#24x %#24x %s" % (a, e, p)
        print ""
        
    symbols = None
    
print "Done!"
"""
regex = re.compile("^\s+\d+ 0x[0-9a-f]+ \((\S+) \+ (0x[0-9a-f]+)\)")
for line in sample_file:

    line = line.rstrip()
    if line.startswith("Version: "):
        version = line.split()[1]
        if root_dir:
            if os.path.isdir(os.path.join(root_dir, version)):
                root_dir = os.path.join(root_dir, version)
            else:
                root_dir = None
        continue

    # Now we look for the regexp
    result = regex.match(line)
    symbol = None
    if result:
        (f, a) = result.group(1, 2)
        if not f in files:
            files[f] = SymbolsFromFile(f, root_dir)
        tdict = FindNearestSymbol(files[f], int(a, 0))
        if tdict:
            symbol = " [%s + %d]" % (tdict["Symbol"], tdict["Offset"])

    sys.stdout.write(line)
    if symbol:
        sys.stdout.write(symbol)
    sys.stdout.write("\n")

    
"""
