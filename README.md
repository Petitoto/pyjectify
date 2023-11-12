<img height="100" align="left" style="float: left; margin: 0 10px 0 0;" alt="PyJectify logo" src="https://raw.githubusercontent.com/Petitoto/pyjectify/main/pyjectify.png" href="#">

# PyJectify
A Python library for memory manipulation, code injection and function hooking.


## Quick start
PyJectify is available on [PyPI](https://pypi.org/project/pyjectify/).

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
- PythonLib: embed python into a remote process (Python 3.10 - 3.11 supported)

#### Utils
- Syscall: Parse syscall codes from ntdll.dll (from the loaded library or from the disk), and produce a ntdll-like object which can be used by the Inject module to use direct syscalls
- ApiSetSchema: parse Windows ApiSet


## Examples

### Memory search & basic operations
```python
import pyjectify

# Open notepad process (only the first found if multiple instances of notepad are running)
notepad = pyjectify.byName('Notepad.exe')[0]

# Use the pattern "secret( is)?: (.){10}", but encoded in utf-16-le because Notepad uses wchar_t
words = ['secret', ' is', ': ', '.']
pattern = b'%b(%b)?%b(%b){10}' % tuple(e.encode('utf-16-le') for e in words)

# Search for the secret in notepad's memory
addrs = notepad.memscan.scan(pattern)

# Process found addresses
for addr in addrs:
    secret = notepad.process.read(addr, 50).decode('utf-16-le')
    print('[+] Found secret:', secret)
    notepad.process.write(addr, ('*'*len(secret)).encode('utf-16-le')) # let's hide the secret!

# Reset memscan to perform a new search regardless of the previous scan
notepad.memscan.reset()
```

### Python code injection
```python
import pyjectify

# Open notepad process
notepad = pyjectify.byName('Notepad.exe')[0]

# Inject Python DLL
notepad.pythonlib.python_mod = notepad.inject.load_library("C:\\path\\to\\python-embed\\python311.dll")

# Run some Python code from notepad
notepad.pythonlib.initialize()
notepad.pythonlib.exec('import os; os.system("calc.exe")')

# Undo all initializations
notepad.pythonlib.finalize()
```

### Setup an inline hook written in Python
```python
import pyjectify

# Open notepad process & inject Python DLL
notepad = pyjectify.byName('Notepad.exe')[0]
notepad.pythonlib.python_mod = notepad.inject.load_library("C:\\path\\to\\python-embed\\python311.dll")
notepad.pythonlib.initialize()

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
oaddr = user32.exports['GetClipboardData'] + user32.base_addr
trampoline_addr = notepad.hook.trampoline(oaddr, 15)

# Step 3: prepare Python function hooking, ie create o_GetClipboardData and get ou Python GetClipboardData address
hook_addr = notepad.pythonlib.prepare_hook('GetClipboardData', trampoline_addr)

# Step 4: inline hook
notepad.hook.inline(oaddr, hook_addr)
```

### Advanced DLL injection
```python
import pyjectify

# Open processes
proc1 = pyjectify.byName('proc1.exe')[0]
proc2 = pyjectify.byName('proc2.exe')[0]

# Extract a library from proc1's memory
module = proc1.process.get_module('module.dll')[0]

# Extract common syscalls from ntdll.dll and wrap them into a ntdll-like object
syscall = pyjectify.windows.Syscall()
syscall.get_common(from_disk=True)

# Use direct syscalls to operate on proc2 (memory read / write / protect, thread creation...)
proc2.process.ntdll = syscall

# Inject the module directly from memory into proc2, at a random location and without copying PE headers
proc2.inject.memory_loader(module, prefer_base_addr=False, copy_headers=False)
```