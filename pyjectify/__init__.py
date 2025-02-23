import platform as _platform

system = _platform.system()  #: Current operating system

if system == 'Windows':
    from pyjectify.windows import *
    __all__ = ['PyJectifyWin', 'open', 'defines', 'PE', 'ApiSetSchema',
               'Syscall', 'x86', 'wow64', 'windowsx86', 'system']
else:
    print('Warning: PyJectify does not support your system!')
