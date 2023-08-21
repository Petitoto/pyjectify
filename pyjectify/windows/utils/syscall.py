from pyjectify.windows.core.defines import *
from pyjectify.windows.core.process import ProcessHandle
from pyjectify.windows.core.pe import PE

syscode_signatures = [
    b'\xb8',                 # mov    eax, syscode (x86)
    b'\x4c\x8b\xd1\xb8'      # mov    r10,rcx ; mov    rax, syscode (x64)
    ]

syscall_x86 = b'\x58'                     # pop   eax
syscall_x86 += b'\x0f\x34'                # sysenter
syscall_x86 += b'\xc3'                    # ret

syscall_x64 = b'\x48\x89\xc8'             # mov    rax, rcx
syscall_x64 += b'\x48\x89\xd1'            # mov    rcx, rdx
syscall_x64 += b'\x4c\x89\xc2'            # mov    rdx, r8
syscall_x64 += b'\x4d\x89\xc8'            # mov    r8, r9
syscall_x64 += b'\x4c\x8b\x4c\x24\x28'    # mov    r9, QWORD PTR [rsp+0x28]
syscall_x64 += b'\x48\x83\xc4\x08'        # add    rsp, 0x8
syscall_x64 += b'\x49\x89\xca'            # mov    r10, rcx
syscall_x64 += b'\x0f\x05'                # syscall
syscall_x64 += b'\x48\x83\xec\x08'        # sub    rsp, 0x8
syscall_x64 += b'\xc3'                    # ret


class Syscall:
    def __init__(self, syscalltable={}):
        self.syscalltable = syscalltable
        
        self.process = ProcessHandle(-1)
        if self.process.windowsx86:
            syscall = syscall_x86
        else:
            syscall = syscall_x64
        
        addr = self.process.allocate(len(syscall))
        self.process.write(addr, syscall)
        self.process.protect(addr, len(syscall), PAGE_EXECUTE_READ)
        self.syscall = ctypes.CFUNCTYPE(DWORD)(addr)
    
    
    def get_syscode(self, syscall, from_disk=False):
        data = b''
        
        if from_disk:
            ntdll_pe = PE(open(ctypes.util.find_library('ntdll.dll'), 'rb').read())
            ntdll_pe.parse_exports()
            addr = ntdll_pe.exports[syscall]
            data = ntdll_pe.raw[addr:addr+8]
        else:
            addr = ctypes.cast(ntdll.__getattribute__(syscall), ctypes.c_void_p).value
            data = self.process.read(addr, 8)
        
        i = 0
        while i < len(syscode_signatures) and not data.startswith(syscode_signatures[i]):
            i += 1
        
        if i < len(syscode_signatures):
            offset = len(syscode_signatures[i])
            syscode = int.from_bytes(data[offset:offset+5], 'little')
        else:
            raise AssertionError('Syscall code to %s not found in loaded ntdll.dll' % (syscall))
        
        self.syscalltable[syscall] = syscode
        return syscode
    
    
    def __getattr__(self, syscall):
        if not syscall in self.syscalltable:
            return ntdll.__getattribute__(syscall)
        
        syscode = self.syscalltable[syscall]
        
        try:
            self.syscall.argtypes = (DWORD,) + ntdll.__getattribute__(syscall).argtypes
        except:
            pass
        
        def _call(*args):
            return self.syscall(syscode, *args)
        
        return _call