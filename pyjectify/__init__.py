import platform as platform

system = platform.system() #: Current operating system

if system == 'Windows':
    from pyjectify.windows import *
    __all__ = ['PyJectifyWin', 'byName', 'defines', 'PE', 'ApiSetSchema', 'Syscall', 'system']
else:
    raise ValueError('PyJectify does not support your system!')