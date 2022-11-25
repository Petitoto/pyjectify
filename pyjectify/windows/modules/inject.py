from pyjectify.windows.core.defines import *
from pyjectify.windows.utils.apisetschema import ApiSetSchema

entry_call_x86 = b'\xb8%s'                                                     # mov    eax, entry_point
entry_call_x86 += b'\x5b'                                                      # pop ebx
entry_call_x86 += b'\x6a\x00'                                                  # push   0x0
entry_call_x86 += b'\x68' + DLL_PROCESS_ATTACH.to_bytes(4, 'little')           # push   DLL_PROCESS_ATTACH
entry_call_x86 += b'\x68%s'                                                    # push   base_addr
entry_call_x86 += b'\x53'                                                      # push ebx
entry_call_x86 += b'\xff\xe0'                                                  # jmp    eax

entry_call_x64 = b'\x48\xb8%s'                                                 # movabs rax, entry_point
entry_call_x64 += b'\x48\xb9%s'                                                # movabs rcx, base_addr
entry_call_x64 += b'\x48\xc7\xc2' + DLL_PROCESS_ATTACH.to_bytes(4, 'little')   # mov    rdx, DLL_PROCESS_ATTACH
entry_call_x64 += b'\xff\xe0'                                                  # jmp    rax


class Inject:
    def __init__(self, process):
        self._process = process
    
    def load_library(self, libpath):
        addr = self._process.allocate(len(libpath))
        self._process.write(addr, libpath)
        kernel32_mod = self._process.get_module('kernel32.dll')
        kernel32_mod.parse_exports()
        loadlibrary_addr = kernel32_mod.base_addr + kernel32_mod.exports['LoadLibraryA']
        thread_h = self._process.start_thread(loadlibrary_addr, addr)
        lib_h = self._process.join_thread(thread_h)
        self._process.free(addr)
        
        if self._process.x86:
            if not lib_h.value: raise WinAPIError('Remote LoadLibraryA failed')
            return self._process.module_from_hmodule(lib_h.value)
        else:
            return self._process.get_module(libpath)
    
    
    def memory_loader(self, module, copy_headers=True):
        module.map_to_memory()
        module.parse_imports()
        
        try:
            addr = self._process.allocate(len(module.raw), preferred_addr=module.base_addr)
        except:
            addr = self._process.allocate(len(module.raw))
        module.change_base(addr)
        
        apisetschema = ApiSetSchema()
        
        for import_dll in module.imports.keys():
            import_module = self.load_library(apisetschema.resolve(import_dll))
            import_module.parse_exports()
            
            for import_proc in module.imports[import_dll]:
                proc_name = import_proc[0]
                thunk_addr = import_proc[1]
                forwarded = import_module.forwarded_export(proc_name)
                
                if forwarded:
                    forwarded_dll = forwarded.split('.')[0] + '.dll'
                    forwarded_export = forwarded.split('.')[1]
                    
                    if forwarded_export.startswith('#'):
                        forwarded_export = int(forwarded_export[1:])
                    
                    forwarded_module = self.load_library(apisetschema.resolve(forwarded_dll))
                    forwarded_module.parse_exports()
                    proc_addr = forwarded_module.base_addr + forwarded_module.exports[forwarded_export]
                
                else:
                    proc_addr = import_module.base_addr + import_module.exports[proc_name]
                
                module.patch_import(thunk_addr, proc_addr)
        
        if not copy_headers:
            module.raw = b'\x00'*module.sections_header[0].VirtualAddress + module.raw[module.sections_header[0].VirtualAddress:]
        
        self._process.write(module.base_addr, module.raw)
        
        self._process.protect(module.base_addr, module.sections_header[0].VirtualAddress, PAGE_READONLY)
        
        for section_addr, section_size, protect in module.sections:
            self._process.protect(module.base_addr + section_addr, section_size, protect)
        
        entry_point = module.base_addr + module.nt_header.OptionalHeader.AddressOfEntryPoint
        
        if self._process.x86:
            entry_call = entry_call_x86 % (entry_point.to_bytes(4, 'little'), module.base_addr.to_bytes(4, 'little'))
        else:
            entry_call = entry_call_x64 % (entry_point.to_bytes(8, 'little'), module.base_addr.to_bytes(8, 'little'))
        
        entry_call_addr = self._process.allocate(len(entry_call), protect=PAGE_READWRITE)
        self._process.write(entry_call_addr, entry_call)
        self._process.protect(entry_call_addr, len(entry_call), PAGE_EXECUTE_READ)
        
        thread = self._process.start_thread(entry_call_addr)
        self._process.join_thread(thread)
        self._process.free(entry_call_addr)
        
        return module


class WinAPIError(Exception):
    pass