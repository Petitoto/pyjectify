import ctypes

import pyjectify.windows.core.defines as defines
from pyjectify.windows.core.process import getpid as _getpid, ProcessHandle as _ProcessHandle, WinAPIError as _WinAPIError
from pyjectify.windows.core.pe import PE

from pyjectify.windows.modules.memscan import MemScan as _MemScan
from pyjectify.windows.modules.inject import Inject as _Inject
from pyjectify.windows.modules.hook import Hook as _Hook
from pyjectify.windows.modules.pythonlib import PythonLib as _PythonLib

from pyjectify.windows.utils.apisetschema import ApiSetSchema
from pyjectify.windows.utils.syscall import Syscall


__all__ = ['PyJectifyWin', 'byName', 'defines', 'PE', 'ApiSetSchema', 'Syscall', 'x86', 'wow64', 'windowsx86']


x86: bool #: Specify if PyJectify process runs in 32-bit mode
wow64: bool #: Specify if PyJectify process is a wow64 process
windowsx86: bool #: Specify if Windows is 32-bit

x86 = ctypes.sizeof(defines.SIZE_T) == 4
wow64 = defines.BOOL()
if not defines.kernel32.IsWow64Process(-1, ctypes.byref(wow64)):
    raise _WinAPIError('IsWow64Process - %s' % (defines.kernel32.GetLastError()))
wow64 = wow64.value > 0
windowsx86 = x86 and not wow64


class PyJectifyWin:
    """This class represents the main Pyjectify object for Windows and gives access to all modules"""
    
    process: _ProcessHandle  #: Target Process
    memscan: _MemScan #: MemScan module initialized for the target process
    hook: _Hook #: Hook module initialized for the target process
    inject: _Inject #: Inject module initialized for the target process
    pythonlib: _PythonLib #: PythonLib module initialized for the target process
    
    def __init__(self, pid: int) -> None:
        self.process = _ProcessHandle(pid)
        
        self.memscan = _MemScan(self.process)
        self.inject = _Inject(self.process)
        self.hook = _Hook(self.process)
        self.pythonlib = _PythonLib(self.process)


def byName(process: str) -> list[PyJectifyWin]:
    """Return a list of PyjectifyWin objects based on a process name
    
    Args:
        process: Process name
    
    Returns:
        List of PyJectifyWin objects associated with the process name
    """
    return [PyJectifyWin(pid) for pid in _getpid(process)]