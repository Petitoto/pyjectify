from pyjectify.windows.core.defines import *
from pyjectify.windows.core.process import ProcessHandle, WinAPIError
from pyjectify.windows.core.pe import PE
from pyjectify.windows.utils.apisetschema import ApiSetSchema

_entry_call_x86 = b'\xb8%s'                                                     # mov    eax, entry_point
_entry_call_x86 += b'\x5b'                                                      # pop    ebx
_entry_call_x86 += b'\x6a\x00'                                                  # push   0x0
_entry_call_x86 += b'\x68' + DLL_PROCESS_ATTACH.to_bytes(4, 'little')           # push   DLL_PROCESS_ATTACH
_entry_call_x86 += b'\x68%s'                                                    # push   base_addr
_entry_call_x86 += b'\x53'                                                      # push   ebx
_entry_call_x86 += b'\xff\xe0'                                                  # jmp    eax

_entry_call_x64 = b'\x48\xb8%s'                                                 # movabs rax, entry_point
_entry_call_x64 += b'\x48\xb9%s'                                                # movabs rcx, base_addr
_entry_call_x64 += b'\x48\xc7\xc2' + DLL_PROCESS_ATTACH.to_bytes(4, 'little')   # mov    rdx, DLL_PROCESS_ATTACH
_entry_call_x64 += b'\xff\xe0'                                                  # jmp    rax


class Inject:
    """This class provides methods for code injection into a remote process"""
    
    def __init__(self, process: ProcessHandle) -> None:
        self._process = process
    
    def load_library(self, libpath: str) -> PE:
        """Run LoadLibrary in the target process to load a library from the disk
        
        Args:
            libpath: the path of the library to load in the target process
        
        Returns:
            A PyJectify's PE object representing the library loaded in the target process
        """
        addr = self._process.allocate(len(libpath))
        self._process.write(addr, libpath)
        kernel32_mod = self._process.get_module('kernel32.dll')
        loadlibrary_addr = kernel32_mod.base_addr + kernel32_mod.exports['LoadLibraryA']
        thread_h = self._process.start_thread(loadlibrary_addr, addr)
        lib_h = self._process.join_thread(thread_h)
        self._process.free(addr)
        
        if self._process.x86:
            if not lib_h.value:
                raise WinAPIError('Remote LoadLibraryA failed')
            return self._process.module_from_hmodule(lib_h.value)
        else:
            return self._process.get_module(libpath)
    
    
    def memory_loader(self, module: PE, prefer_base_addr: bool = True, copy_headers: bool = True) -> PE:
        """Fully map a library from memory in the target process, resolving imports and ApiSet
        
        Args:
            module: a PyJectify's PE object representinf the library to load in the target process
            prefer_base_addr: specify whether to load the module at the PE's default base address
            copy_headers: specify whether to copy the PE headers to the target process memory
        
        Returns:
            A PyJectify's PE object representing the library loaded in the target process
        """
        start = 0
        if not copy_headers:
            start = module.sections_header[0].VirtualAddress
        
        try:
            preferred_addr = None
            if prefer_base_addr:
                preferred_addr = module.base_addr + start
            addr = self._process.allocate(len(module.raw) - start, preferred_addr=preferred_addr)
        except:
            addr = self._process.allocate(len(module.raw) - start)
        module.change_base(addr - start)
        
        apisetschema = ApiSetSchema()
        
        for import_dll in module.imports.keys():
            import_module = self.load_library(apisetschema.resolve(import_dll))
            
            for proc_name, thunk_addr in module.imports[import_dll]:
                forwarded = import_module.forwarded_export(proc_name)
                
                if forwarded:
                    forwarded_dll = forwarded.split('.')[0] + '.dll'
                    forwarded_export = forwarded.split('.')[1]
                    
                    if forwarded_export.startswith('#'):
                        forwarded_export = int(forwarded_export[1:])
                    
                    forwarded_module = self.load_library(apisetschema.resolve(forwarded_dll))
                    proc_addr = forwarded_module.base_addr + forwarded_module.exports[forwarded_export]
                
                else:
                    proc_addr = import_module.base_addr + import_module.exports[proc_name]
                
                module.patch_import(thunk_addr, proc_addr)
        
        self._process.write(module.base_addr+start, module.raw[start:])
        self._process.protect(module.base_addr+start, len(module.raw[start:]), PAGE_READONLY)
        
        for section_addr, section_size, protect in module.sections:
            self._process.protect(module.base_addr + section_addr, section_size, protect)
        
        entry_point = module.base_addr + module.nt_header.OptionalHeader.AddressOfEntryPoint
        
        if self._process.x86:
            entry_call = _entry_call_x86 % (entry_point.to_bytes(4, 'little'), module.base_addr.to_bytes(4, 'little'))
        else:
            entry_call = _entry_call_x64 % (entry_point.to_bytes(8, 'little'), module.base_addr.to_bytes(8, 'little'))
        
        entry_call_addr = self._process.allocate(len(entry_call), protect=PAGE_READWRITE)
        self._process.write(entry_call_addr, entry_call)
        self._process.protect(entry_call_addr, len(entry_call), PAGE_EXECUTE_READ)
        
        thread = self._process.start_thread(entry_call_addr)
        self._process.join_thread(thread)
        self._process.free(entry_call_addr)
        
        return module