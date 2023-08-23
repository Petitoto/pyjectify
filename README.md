<img height="100" align="left" style="float: left; margin: 0 10px 0 0;" alt="PyJectify logo" src="https://raw.githubusercontent.com/Petitoto/pyjectify/main/pyjectify.png">

# PyJectify
A Python library for memory manipulation, code injection and function hooking.


## Quick start
PyJectify is available on [Pypi](https://pypi.org/project/pyjectify/).

Alternatively, you can download releases from GitHub or clone the project.

Documentation is available at https://petitoto.github.io/pyjectify/


## Features
### Windows
#### Core
- Allocate / Free / Read / Write memory
- Create threads
- List loaded modules
- PE parser
- Use kernel32 or ntdll functions

#### Modules
- MemScan: scan memory using regex patterns
- Inject: load library, from disk (remote LoadLibrary) or from memory (fully map the DLL into the remote process)
- Hook: set up inline hooks in the target process
- PythonLib: embed python into a remote process

#### Utils
- Syscall: Parse syscall codes from ntdll.dll (from the loaded library or from the disk), and produce a ntdll-like object which can be used by the Inject module to use direct syscalls
- ApiSetSchema: parse Windows ApiSet


## Example
```python
import pyjectify

# Open notepad.exe process (only the first found if multiple instances of notepad are running)
notepad = pyjectify.byName('Notepad.exe')[0]

# Search for the secret in notepad memory:
pattern = rb's;e;c;r;e;t;( ;i;s;)?:; (;.){10}'.replace(b';', b'\x00') # ; -> \x00 just to keep the pattern readable (notepad use wide strings)
addrs = notepad.memscan.scan(pattern)
for addr in addrs:
    secret = notepad.process.read(addr, 50)
    print('[+] Found secret:', str(secret.replace(b'\x00', b'')))
    notepad.process.write(addr, b'*\x00'*25) # let's hide the secret

# Inject Python DLL, from bytes loaded in memory
notepad.pythonlib.python_mod = notepad.inject.load_library("python3xx.dll")
notepad.pythonlib.python_mod.parse_exports()

# Run some Python code from notepad
notepad.pythonlib.initialize()
notepad.pythonlib.exec('import os; os.system("calc.exe")')

# Let's hook GetClipboardData!
# Step 1: define our new function
pycode = """
import ctypes
def GetClipboardData(uFormat:ctypes.c_uint) -> ctypes.c_void_p:
  ctypes.windll.user32.MessageBoxW(0, "I hooked you :D", "MyNewGetClipboardData", 0)
  return o_GetClipboardData(uFormat)
"""
notepad.pythonlib.exec(pycode)

# Step 2: get original function address and setup a trampoline (of 15 bytes size)
user32 = notepad.process.get_module('user32.dll')
user32.parse_exports()
oaddr = user32.exports['GetClipboardData'] + user32.base_addr
trampoline_addr = notepad.hook.trampoline(oaddr, 15)

# Step 3: prepare Python function hooking, ie create o_GetClipboardData and get ou Python GetClipboardData address
hook_addr = notepad.pythonlib.prepare_hook('GetClipboardData', trampoline_addr)

# Step 4: inline hook
notepad.hook.inline(oaddr, hook_addr)

# A final fix (for now)
# To prevent Python API to clean our Python hook, we need to exit a PyRun_SimpleString abruptly, or keeping it open using a sleep
# This issue is investigated and should be fixed in the next release
notepad.pythonlib.exec('ctypes.windll.kernel32.ExitThread(0)')
```