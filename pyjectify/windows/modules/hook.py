from pyjectify.windows.core.defines import *

jmp_x86 = b'\xb8%s'     # mov    eax, address
jmp_x86 += b'\xff\xe0'  # jmp    eax

jmp_x64 = b'\x48\xb8%s' # movabs rax, address
jmp_x64 += b'\xff\xe0'   # jmp    rax

class Hook:
    def __init__(self, process):
        self._process = process
    
    
    def trampoline(self, target, size):
        code = self._process.read(target, size)
        
        target += size
        if self._process.x86:
            jmp = jmp_x86 % target.to_bytes(4, 'little')
        else:
            jmp = jmp_x64 % target.to_bytes(8, 'little')
        code += jmp
        
        trampoline_addr = self._process.allocate(size)
        self._process.write(trampoline_addr, code)
        self._process.protect(trampoline_addr, size, PAGE_EXECUTE_READ)
        return trampoline_addr
    
    
    def inline(self, target, hook):
        if self._process.x86:
            jmp = jmp_x86 % hook.to_bytes(4, 'little')
        else:
            jmp = jmp_x64 % hook.to_bytes(8, 'little')
        
        old_protect = self._process.protect(target, len(jmp), PAGE_READWRITE)
        self._process.write(target, jmp)
        self._process.protect(target, len(jmp), old_protect)