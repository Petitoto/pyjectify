# PyJectify
A Python library for memory manipulation, code injection and function hooking 

Work in progress

## Install
```
git clone https://github.com/Petitoto/pyjectify
```

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
- Inject: load library, from disk (LoadLibrary in a remote thread) or from memory (fully map the DLL into the remote process: no need of a custom DLL with a reflective loader!)
- PythonLib: embed python into a remote process

#### Utils
- ApiSetSchema: parse Windows API sets