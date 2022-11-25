from os.path import isabs
from io import BytesIO

from pyjectify.windows.core.defines import *
from pyjectify.windows.core.pe import PE

def getpid(process):
    pids = []
    
    hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcessSnap == -1: raise WinAPIError('CreateToolhelp32Snapshot - %s' % (kernel32.GetLastError()))
    
    processentry = PROCESSENTRY32()
    processentry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not kernel32.Process32First(hProcessSnap, ctypes.byref(processentry)): raise WinAPIError('Process32First - %s' % (kernel32.GetLastError()))
    
    while True:
        if processentry.szExeFile.decode() in process:
            pids.append(int(processentry.th32ProcessID))
        if not kernel32.Process32Next(hProcessSnap, ctypes.byref(processentry)):
            break
    
    if not kernel32.CloseHandle(hProcessSnap): raise WinAPIError('CloseHandle - %s' % (kernel32.GetLastError()))
    return pids



class ProcessHandle:
    def __init__(self, pid, ntdll=None, flags=PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE):      
        self.pid = pid
        self.ntdll = ntdll
        
        if self.pid == -1:
            self.handle = kernel32.GetCurrentProcess()
        else:
            self.handle = kernel32.OpenProcess(flags, False, self.pid)
        if not self.handle: raise WinAPIError('OpenProcess - %s' % (kernel32.GetLastError()))
        
        self.wow64 = BOOL()
        if not kernel32.IsWow64Process(self.handle, ctypes.byref(self.wow64)): raise WinAPIError('IsWow64Process - %s' % (kernel32.GetLastError()))
        self.injectorx86 = ctypes.sizeof(SIZE_T) == 4
        self.injectorwow64 = BOOL()
        if not kernel32.IsWow64Process(-1, ctypes.byref(self.injectorwow64)): raise WinAPIError('IsWow64Process - %s' % (kernel32.GetLastError()))
        self.windowsx86 = self.injectorx86 and not self.injectorwow64
        self.x86 = self.wow64 or self.windowsx86
        
        self._init_func()
    
    
    def _init_func(self):
        if self.pid == -1:
            self.query = self._virtual_query
            self.allocate = self._virtual_alloc
            self.free = self._virtual_free
            self.protect = self._virtual_protect
            self.read = self._read_memory
            self.write = self._rtl_move_memory
            self.start_thread = self._create_thread 
        elif not self.ntdll:
            self.query = self._virtual_query_ex
            self.allocate = self._virtual_alloc_ex
            self.free = self._virtual_free_ex
            self.protect = self._virtual_protect_ex
            self.read = self._read_process_memory
            self.write = self._write_process_memory
            self.start_thread = self._create_remote_thread
        else:
            self.query = self._nt_query_virtual_memorry
            self.allocate = self._nt_allocate_virtual_memory
            self.free = self._nt_free_virtual_memory
            self.protect = self._nt_protect_virtual_memory
            self.read = self._nt_read_virtual_memory
            self.write = self._nt_write_virtual_memory
            self.start_thread = self._nt_create_thread_ex
    
    
    def close(self):
        if not kernel32.CloseHandle(self.handle): raise WinAPIError('CloseHandle - %s' % (kernel32.GetLastError()))
    
    
    def _virtual_query(self, addr):
        mem_info = MEMORY_BASIC_INFORMATION()
        if not kernel32.VirtualQuery(addr, mem_info, ctypes.sizeof(mem_info)): raise WinAPIError('VirtualQuery - %s' % (kernel32.GetLastError()))
        return mem_info
    
    
    def _virtual_query_ex(self, addr):
        mem_info = MEMORY_BASIC_INFORMATION()
        if not kernel32.VirtualQueryEx(self.handle, addr, mem_info, ctypes.sizeof(mem_info)): raise WinAPIError('VirtualQueryEx - %s' % (kernel32.GetLastError()))
        return mem_info
    
    
    def _nt_query_virtual_memorry(self, addr):
        mem_info = MEMORY_BASIC_INFORMATION()
        status = ntdll.NtQueryVirtualMemory(self.handle, addr, MemoryBasicInformation, ctypes.byref(mem_info), ctypes.sizeof(mem_info), None)
        if status: raise WinAPIError('NtQueryVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return mem_info
    
    
    def _virtual_alloc(self, size, protect=PAGE_READWRITE, preferred_addr=None):
        flags = MEM_RESERVE | MEM_COMMIT
        addr = kernel32.VirtualAlloc(preferred_addr, size, flags, protect)
        if not addr: raise WinAPIError('VirtualAlloc - %s' % (kernel32.GetLastError()))
        return addr
    
    
    def _virtual_alloc_ex(self, size, protect=PAGE_READWRITE, preferred_addr=None):
        flags = MEM_RESERVE | MEM_COMMIT
        addr = kernel32.VirtualAllocEx(self.handle, preferred_addr, size, flags, protect)
        if not addr: raise WinAPIError('VirtualAllocEx - %s' % (kernel32.GetLastError()))
        return addr
    
    
    def _nt_allocate_virtual_memory(self, size, protect=PAGE_READWRITE, preferred_addr=None):
        flags = MEM_RESERVE | MEM_COMMIT
        addr = HANDLE(preferred_addr)
        status = self.ntdll.NtAllocateVirtualMemory(self.handle, ctypes.byref(addr), None, ctypes.byref(SIZE_T(size)), flags, protect)
        if status: raise WinAPIError('NtAllocateVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return addr.value
    
    
    def _virtual_free(self, addr, size=0, flags=MEM_RELEASE):
        if not kernel32.VirtualFree(addr, size, flags): raise WinAPIError('VirtualFree - %s' % (kernel32.GetLastError()))
    
    
    def _virtual_free_ex(self, addr, size=0, flags=MEM_RELEASE):
        if not kernel32.VirtualFreeEx(self.handle, addr, size, flags): raise WinAPIError('VirtualFreeEx - %s' % (kernel32.GetLastError()))
    
    
    def _nt_free_virtual_memory(self, addr, size=0, flags=MEM_RELEASE):
        status = self.ntdll.NtFreeVirtualMemory(self.handle, ctypes.byref(HANDLE(addr)), ctypes.byref(SIZE_T(size)), flags)
        if status: raise WinAPIError('NtFreeVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
    
    
    def _virtual_protect(self, addr, size, protect):
        old_protect = DWORD()
        if not kernel32.VirtualProtect(addr, size, protect, ctypes.byref(old_protect)): raise WinAPIError('VirtualProtect - %s' % (kernel32.GetLastError()))
        return old_protect.value
    
    
    def _virtual_protect_ex(self, addr, size, protect):
        old_protect = DWORD()
        if not kernel32.VirtualProtectEx(self.handle, addr, size, protect, ctypes.byref(old_protect)): raise WinAPIError('VirtualProtectEx - %s' % (kernel32.GetLastError()))
        return old_protect.value
    
    
    def _nt_protect_virtual_memory(self, addr, size, protect):
        old_protect = DWORD()
        status = self.ntdll.NtProtectVirtualMemory(self.handle, ctypes.byref(HANDLE(addr)), ctypes.byref(SIZE_T(size)), protect, ctypes.byref(old_protect))
        if status: raise WinAPIError('NtProtectVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return old_protect.value
    
    
    def _read_memory(self, addr, size):
        data = (ctypes.c_char * size).from_address(addr)
        return data.raw
    
    
    def _read_process_memory(self, addr, size):
        data = (ctypes.c_char * size)()
        if not kernel32.ReadProcessMemory(self.handle, addr, ctypes.byref(data), ctypes.sizeof(data), None): raise WinAPIError('ReadProcessMemory - %s' % (kernel32.GetLastError()))
        return data.raw
    
    
    def _nt_read_virtual_memory(self, addr, size):
        data = (ctypes.c_char * size)()
        status = self.ntdll.NtReadVirtualMemory(self.handle, addr, ctypes.byref(data), ctypes.sizeof(data), None)
        if status: raise WinAPIError('NtReadVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return data.raw
    
    
    def _rtl_move_memory(self, addr, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        wr_data = (ctypes.c_char * len(data))()
        wr_data.value = data
        if not kernel32.RtlMoveMemory(addr, ctypes.byref(wr_data), ctypes.sizeof(wr_data)): raise WinAPIError('RtlMoveMemory - %s' % (kernel32.GetLastError()))
    
    
    def _write_process_memory(self, addr, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        wr_data = (ctypes.c_char * len(data))()
        wr_data.value = data
        if not kernel32.WriteProcessMemory(self.handle, addr, ctypes.byref(wr_data), ctypes.sizeof(wr_data), None): raise WinAPIError('WriteProcessMemory - %s' % (kernel32.GetLastError()))
    
    
    def _nt_write_virtual_memory(self, addr, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        wr_data = (ctypes.c_char * len(data))()
        wr_data.value = data
        status = self.ntdll.NtWriteVirtualMemory(self.handle, addr, ctypes.byref(wr_data), ctypes.sizeof(wr_data), None)
        if status: raise WinAPIError('NtWriteVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
    
    
    def _create_thread(self, addr, arg=None):
        handle = kernel32.CreateThread(None, 0, addr, arg, 0, None)
        if not handle: raise WinAPIError('CreateThread - %s' % (kernel32.GetLastError()))
        return handle
    
    
    def _create_remote_thread(self, addr, arg=None):
        handle = kernel32.CreateRemoteThread(self.handle, None, 0, addr, arg, 0, None)
        if not handle: raise WinAPIError('CreateRemoteThread - %s' % (kernel32.GetLastError()))
        return handle
    
    
    def _nt_create_thread_ex(self, addr, arg=None):
        flags = SYNCHRONIZE | THREAD_QUERY_INFORMATION
        handle = HANDLE()
        status = self.ntdll.NtCreateThreadEx(ctypes.byref(handle), flags, None, self.handle, addr, arg, False, 0, 0, 0, None)
        if not handle.value: raise WinAPIError('NtCreateThreadEx - %s' % ('0x{0:08x}'.format(status)))
        return handle.value
    
    
    def join_thread(self, handle):
        kernel32.WaitForSingleObject(handle, -1)
        exit_code = DWORD()
        if not kernel32.GetExitCodeThread(handle, ctypes.byref(exit_code)): raise WinAPIError('GetExitCodeThread - %s' % (kernel32.GetLastError()))
        if not kernel32.CloseHandle(handle): raise WinAPIError('CloseHandle - %s' % (kernel32.GetLastError()))
        return exit_code
    
    
    def module_from_hmodule(self, hmodule):
        sysinfo = SYSTEM_INFO()
        kernel32.GetNativeSystemInfo(ctypes.byref(sysinfo))
        headers = PE(self.read(hmodule, sysinfo.dwPageSize), hmodule)

        raw = BytesIO(b'\x00'*headers.nt_header.OptionalHeader.SizeOfImage)
        raw.write(headers.raw)
        
        for section in headers.sections_header:
            raw.seek(section.VirtualAddress)
            raw.write(self.read(hmodule + section.VirtualAddress, section.Misc.VirtualSize))
        
        raw.seek(0)
        return PE(raw.read(), base_addr=hmodule, mapped=True)
    
    
    def get_module(self, lib):
        fullpath = isabs(lib)
        
        modules = (ctypes.wintypes.HANDLE * 1)()
        size = DWORD()
        if not psapi.EnumProcessModulesEx(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(size), LIST_MODULES_ALL): raise WinAPIError('EnumProcessModulesEx - %s' % (kernel32.GetLastError()))
        modules = (ctypes.wintypes.HANDLE * size.value)()
        if not psapi.EnumProcessModulesEx(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(size), LIST_MODULES_ALL): raise WinAPIError('EnumProcessModulesEx - %s' % (kernel32.GetLastError()))
        
        for module in modules:
            name = ctypes.c_char_p(b' '*1024)
            if fullpath:
                if not psapi.GetModuleFileNameExA(self.handle, module, name, ctypes.c_ulong(1024)): raise WinAPIError('GetModuleFileNameExA - %s' % (kernel32.GetLastError()))
            else:
                if not psapi.GetModuleBaseNameA(self.handle, module, name, ctypes.c_ulong(1024)): raise WinAPIError('GetModuleBaseNameA - %s' % (kernel32.GetLastError()))
            
            if str(name.value.decode().lower()) == lib.lower():
                return self.module_from_hmodule(module)
        
        raise WinAPIError('EnumProcessModulesEx + %s - Module %s not found' % ('GetModuleFileNameExA' if fullpath else 'GetModuleBaseNameA', lib))



class WinAPIError(Exception):
    pass