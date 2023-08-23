from pyjectify.windows.core.process import ProcessHandle
from pyjectify.windows.core.defines import *

_jmp_x86 = b'\xb8%s'     # mov    eax, address
_jmp_x86 += b'\xff\xe0'  # jmp    eax

_jmp_x64 = b'\x48\xb8%s' # movabs rax, address
_jmp_x64 += b'\xff\xe0'   # jmp    rax


class Hook:
    """This class provides methods to hook functions of the target process"""
    
    def __init__(self, process: ProcessHandle) -> None:
        self._process = process
    
    
    def trampoline(self, target: int, size: int) -> int:
        """Set up a trampoline to the target function with specified size
        
        Args:
            target: the target address of the function the trampoline will jump to
            size: the size of the bytes of the original function to copy in the trampoline before jumping
        
        Returns:
            The address of the trampoline
        
        Warning:
            For classic inline hooks, the size must be superior to the length of the jump code (7 bytes for 32-bits and 12 bytes for 64-bytes) and must correspond to the size of the first complete instructions of the original function
        """
        code = self._process.read(target, size)
        
        target += size
        if self._process.x86:
            jmp = _jmp_x86 % target.to_bytes(4, 'little')
        else:
            jmp = _jmp_x64 % target.to_bytes(8, 'little')
        code += jmp
        
        trampoline_addr = self._process.allocate(size)
        self._process.write(trampoline_addr, code)
        self._process.protect(trampoline_addr, size, PAGE_EXECUTE_READ)
        return trampoline_addr
    
    
    def inline(self, target: int, hook: int) -> None:
        """Set up an inline hook to the target function
        
        Args:
            target: address of the function to hook
            hook: address of the hooking function
        """
        if self._process.x86:
            jmp = _jmp_x86 % hook.to_bytes(4, 'little')
        else:
            jmp = _jmp_x64 % hook.to_bytes(8, 'little')
        
        old_protect = self._process.protect(target, len(jmp), PAGE_READWRITE)
        self._process.write(target, jmp)
        self._process.protect(target, len(jmp), old_protect)