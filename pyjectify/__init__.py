import platform as platform

system = platform.system() #: Current operating system

if system == 'Windows':
    from pyjectify.windows import *
    __all__ = ['PyJectifyWin', 'byName', 'defines', 'PE', 'ApiSetSchema', 'Syscall', 'x86', 'wow64', 'windowsx86', 'system']
else:
    print('Warning: PyJectify does not support your system!')