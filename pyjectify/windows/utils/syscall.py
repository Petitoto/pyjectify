import ctypes.util
from typing import Any, Callable, Dict

from pyjectify.windows.core.defines import *
from pyjectify.windows.core.pe import PE
from pyjectify.windows.core.process import ProcessHandle

_syscode_signatures = [
    b'\xb8',                 # mov    eax, syscode (x86)
    b'\x4c\x8b\xd1\xb8'      # mov    r10,rcx ; mov    rax, syscode (x64)
]

_syscall_x86 = b'\x5a'                     # pop    edx
_syscall_x86 += b'\x58'                    # pop    eax
_syscall_x86 += b'\x50'                    # push   eax
_syscall_x86 += b'\x52'                    # push   edx
_syscall_x86 += b'\x89\xe2'                # mov    edx, esp
_syscall_x86 += b'\x0f\x34'                # sysenter
_syscall_x86 += b'\xc3'                    # ret

_syscall_x64 = b'\x48\x89\xc8'             # mov    rax, rcx
_syscall_x64 += b'\x48\x89\xd1'            # mov    rcx, rdx
_syscall_x64 += b'\x4c\x89\xc2'            # mov    rdx, r8
_syscall_x64 += b'\x4d\x89\xc8'            # mov    r8, r9
_syscall_x64 += b'\x4c\x8b\x4c\x24\x28'    # mov    r9, QWORD PTR [rsp+0x28]
_syscall_x64 += b'\x48\x83\xc4\x08'        # add    rsp, 0x8
_syscall_x64 += b'\x49\x89\xca'            # mov    r10, rcx
_syscall_x64 += b'\x0f\x05'                # syscall
_syscall_x64 += b'\x48\x83\xec\x08'        # sub    rsp, 0x8
_syscall_x64 += b'\xc3'                    # ret


class Syscall:
    """This class represents a ntdll-like object and provides methods parse and use direct syscalls.

    You can use Syscall.NtFunc(args) to call a ntdll function. If the syscode was retrieved, this method will use a direct syscall. Else it will fallback to loaded ntdll.

    This util does not support WOW64.
    """

    def __init__(self, syscalltable: Dict[str, int] = {}) -> None:
        """Initialization: build a method allowing direct syscalls using a shellcode

        Args:
            syscalltable: initial syscall codes (can be filled later)
        """
        self._syscalltable = syscalltable

        self._process = ProcessHandle(-1)
        if self._process.x86 and not self._process.wow64:
            syscall = _syscall_x86
        else:
            syscall = _syscall_x64

        addr = self._process.allocate(len(syscall))
        self._process.write(addr, syscall)
        self._process.protect(addr, len(syscall), PAGE_EXECUTE_READ)
        self._syscall = ctypes.CFUNCTYPE(DWORD)(addr)


    @property
    def syscalltable(self) -> dict[str, int]:
        """Dict of ntdll function name -> syscall code (store the retrieved syscall codes)"""
        return self._syscalltable


    @syscalltable.setter
    def syscalltable(self, syscalltable: dict[str, int]) -> None:
        self._syscalltable = syscalltable


    @property
    def syscall(self) -> Callable[..., int]:
        """Syscall wrapper, first argument is the syscode and other arguments are the sycall arguments"""
        return self._syscall


    def get_syscode(self, syscall: str, from_disk: bool = False) -> int:
        """Retrieve a syscall code from loaded ntdll or from the disk, and update syscalltable attribute accordingly

        Args:
            syscall: syscall name to retrieve
            from_disk: decide wether the syscode are retrieved from the loaded ntdll or from the ntdll.dll on the disk

        Returns:
            The syscode coresponding to the syscall
        """
        data = b''

        if from_disk:
            ntdll_path: str | None = ctypes.util.find_library('ntdll.dll')
            if ntdll_path is None:
                raise InvalidNTDLLSyscall('ntdll.dll not found')
            ntdll_pe = PE(open(ntdll_path, 'rb').read())
            addr = ntdll_pe.exports[syscall]
            data = ntdll_pe.raw[addr:addr+8]
        else:
            addr = ctypes.cast(ntdll.__getattribute__(syscall), ctypes.c_void_p).value
            if addr is None:
                raise InvalidNTDLLSyscall(f'Syscall {syscall} not found in loaded NTDLL')
            data = self._process.read(addr, 8)

        i = 0
        while i < len(_syscode_signatures) and not data.startswith(_syscode_signatures[i]):
            i += 1

        if i < len(_syscode_signatures):
            offset = len(_syscode_signatures[i])
            syscode = int.from_bytes(data[offset:offset+4], 'little')
        else:
            raise AssertionError('Syscall code to %s not found in ntdll' % (syscall))

        self._syscalltable[syscall] = syscode
        return syscode


    def get_common(self, from_disk: bool = False):
        """Retrieve common syscall codes from loaded ntdll or from the disk, and update syscalltable attribute accordingly

        Syscall codes retrieved are those used by PyJectify's core ProcessHandle: NtQueryVirtualMemory, NtAllocateVirtualMemory, NtFreeVirtualMemory, NtProtectVirtualMemory, NtReadVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx

        Args:
            from_disk: decide wether the syscode are retrieved from the loaded ntdll or from the ntdll.dll on the disk
        """
        nt_common = ["NtQueryVirtualMemory", "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory", "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx"]

        for syscall in nt_common:
            self.get_syscode(syscall, from_disk)


    def __getattr__(self, syscall: str) -> Callable[..., int]:
        if syscall not in self._syscalltable:
            return ntdll.__getattribute__(syscall)

        syscode = self._syscalltable[syscall]

        try:
            self._syscall.argtypes = (DWORD,) + ntdll.__getattribute__(syscall).argtypes
        except:
            pass

        def _call(*args: Any):
            return self._syscall(syscode, *args)

        return _call


class InvalidNTDLLSyscall(Exception):
    """Exception for NTDLL syscalls parsing errors"""
    pass
