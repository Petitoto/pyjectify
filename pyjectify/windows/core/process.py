from os.path import isabs
from io import BytesIO

from pyjectify.windows.core.defines import *
from pyjectify.windows.core.pe import PE


_run_func_x86 = b'\xb8%s'                   # mov    eax, addr
_run_func_x86 += b'\x68%s'                  # push   arg
_run_func_x86 += b'\xff\xd0'                # call   eax
_run_func_x86 += b'\xba%s'                  # mov    edx, ret_addr
_run_func_x86 += b'\x89\x02'                # mov    DWORD PTR [edx], eax

_run_func_x64 = b'\x48\xb8%s'               # mov    rax, addr
_run_func_x64 += b'\x48\xb9%s'              # mov    rcx, arg
_run_func_x64 += b'\xff\xd0'                # call   rax
_run_func_x64 += b'\x48\xba%s'              # mov    rdx, ret_addr
_run_func_x64 += b'\x48\x89\x02'            # mov    QWORD PTR [rdx], rax

_run_func_ret = b'\x5b'                     # pop    rbx
_run_func_ret += b'%s'                      # _run_func, _run_func, _run_func...
_run_func_ret += b'\x53'                    # push   rbx
_run_func_ret += b'\xc3'                    # ret


def getpid(process: str) -> list[int]:
    """Get PIDs associated with a process name
    
    Args:
        process: Process name
    
    Returns:
        List of PIDs associated with the process name
    """
    pids = []
    
    hProcessSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if hProcessSnap == -1:
        raise WinAPIError('CreateToolhelp32Snapshot - %s' % (kernel32.GetLastError()))
    
    processentry = PROCESSENTRY32()
    processentry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    if not kernel32.Process32First(hProcessSnap, ctypes.byref(processentry)):
        raise WinAPIError('Process32First - %s' % (kernel32.GetLastError()))
    
    while True:
        if processentry.szExeFile.decode() == process:
            pids.append(int(processentry.th32ProcessID))
        if not kernel32.Process32Next(hProcessSnap, ctypes.byref(processentry)):
            break
    
    if not kernel32.CloseHandle(hProcessSnap):
        raise WinAPIError('CloseHandle - %s' % (kernel32.GetLastError()))
    return pids



class ProcessHandle:
    """This class represents a Windows process and provides methods to manipulate it"""
    
    pid: int #: PID of the target process
    ntdll: object #: ctypes.windll.ntdll or pyjectify.windows.utils.syscall.Syscall instance or None. Determine the functions called for basic operations (WinAPI, NTDLL or direct syscalls).
    handle: int #: Handle to the target process
    x86: bool #: Specify if the target process runs in 32-bit mode
    wow64: bool #: Specify if the target process is a wow64 process
    
    def __init__(self, pid: int, ntdll: object = None, desired_access: int = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE) -> None:
        self.pid = pid
        self.ntdll = ntdll
        
        if self.pid == -1:
            self.handle = kernel32.GetCurrentProcess()
        else:
            self.handle = kernel32.OpenProcess(desired_access, False, self.pid)
        if not self.handle:
            raise WinAPIError('OpenProcess - %s' % (kernel32.GetLastError()))
        
        self.wow64 = BOOL()
        if not kernel32.IsWow64Process(self.handle, ctypes.byref(self.wow64)):
            raise WinAPIError('IsWow64Process - %s' % (kernel32.GetLastError()))
        self.wow64 = self.wow64.value > 0
        injectorx86 = ctypes.sizeof(SIZE_T) == 4
        injectorwow64 = BOOL()
        if not kernel32.IsWow64Process(-1, ctypes.byref(injectorwow64)):
            raise WinAPIError('IsWow64Process - %s' % (kernel32.GetLastError()))
        windowsx86 = injectorx86 and not injectorwow64
        self.x86 = self.wow64 or windowsx86
        
        self._init_func()
    
    
    def _init_func(self) -> None:
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
    
    
    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        if name == "ntdll":
            self._init_func()
    
    
    def close(self) -> None:
        """Close the handle to the target process"""
        if not kernel32.CloseHandle(self.handle):
            raise WinAPIError('CloseHandle - %s' % (kernel32.GetLastError()))
    
    
    def query(self, addr: int) -> MEMORY_BASIC_INFORMATION:
        """Get information about a range of memory pages in the target process
        
        Args:
            addr: address of the range of memory pages
        
        Returns:
            The MEMORY_BASIC_INFORMATION linked to the range of memory pages
        """
    
    
    def _virtual_query(self, addr: int) -> MEMORY_BASIC_INFORMATION:
        mem_info = MEMORY_BASIC_INFORMATION()
        if not kernel32.VirtualQuery(addr, mem_info, ctypes.sizeof(mem_info)):
            raise WinAPIError('VirtualQuery - %s' % (kernel32.GetLastError()))
        return mem_info
    
    
    def _virtual_query_ex(self, addr: int) -> MEMORY_BASIC_INFORMATION:
        mem_info = MEMORY_BASIC_INFORMATION()
        if not kernel32.VirtualQueryEx(self.handle, addr, mem_info, ctypes.sizeof(mem_info)):
            raise WinAPIError('VirtualQueryEx - %s' % (kernel32.GetLastError()))
        return mem_info
    
    
    def _nt_query_virtual_memorry(self, addr: int) -> MEMORY_BASIC_INFORMATION:
        mem_info = MEMORY_BASIC_INFORMATION()
        status = ntdll.NtQueryVirtualMemory(self.handle, addr, MemoryBasicInformation, ctypes.byref(mem_info), ctypes.sizeof(mem_info), None)
        if status:
            raise WinAPIError('NtQueryVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return mem_info
    
    
    def allocate(self, size: int, protect: int = PAGE_READWRITE, preferred_addr: int | None = None) -> int:
        """Allocate a region of memory in the target process
        
        Args:
            size: size of the memory region to allocate
            protect: proctection of the allocated memory region
            preferred_addr: preferred address for the memory region to allocate
        
        Returns:
            The address of the allocated memory region
        """
    
    
    def _virtual_alloc(self, size: int, protect: int = PAGE_READWRITE, preferred_addr: int | None = None) -> int:
        flags = MEM_RESERVE | MEM_COMMIT
        addr = kernel32.VirtualAlloc(preferred_addr, size, flags, protect)
        if not addr:
            raise WinAPIError('VirtualAlloc - %s' % (kernel32.GetLastError()))
        return addr
    
    
    def _virtual_alloc_ex(self, size: int, protect: int = PAGE_READWRITE, preferred_addr: int | None = None) -> int:
        flags = MEM_RESERVE | MEM_COMMIT
        addr = kernel32.VirtualAllocEx(self.handle, preferred_addr, size, flags, protect)
        if not addr:
            raise WinAPIError('VirtualAllocEx - %s' % (kernel32.GetLastError()))
        return addr
    
    
    def _nt_allocate_virtual_memory(self, size: int, protect: int = PAGE_READWRITE, preferred_addr: int | None = None) -> int:
        flags = MEM_RESERVE | MEM_COMMIT
        addr = HANDLE(preferred_addr)
        status = self.ntdll.NtAllocateVirtualMemory(self.handle, ctypes.byref(addr), None, ctypes.byref(SIZE_T(size)), flags, protect)
        if status:
            raise WinAPIError('NtAllocateVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return addr.value
    
    
    def free(self, addr: int, size: int = 0, flags: int = MEM_RELEASE) -> None:
        """Free a region of memory pages in the target process
        
        Args:
            addr: address of the memory region to free
            size: size of the memory region to free (must be 0 if flag is MEM_RELEASE)
            flags: the type of free operation
        """
    
    
    def _virtual_free(self, addr: int, size: int = 0, flags: int = MEM_RELEASE) -> None:
        if not kernel32.VirtualFree(addr, size, flags):
            raise WinAPIError('VirtualFree - %s' % (kernel32.GetLastError()))
    
    
    def _virtual_free_ex(self, addr: int, size: int = 0, flags: int = MEM_RELEASE) -> None:
        if not kernel32.VirtualFreeEx(self.handle, addr, size, flags):
            raise WinAPIError('VirtualFreeEx - %s' % (kernel32.GetLastError()))
    
    
    def _nt_free_virtual_memory(self, addr: int, size: int = 0, flags: int = MEM_RELEASE) -> None:
        status = self.ntdll.NtFreeVirtualMemory(self.handle, ctypes.byref(HANDLE(addr)), ctypes.byref(SIZE_T(size)), flags)
        if status:
            raise WinAPIError('NtFreeVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
    
    
    def protect(self, addr: int, size: int, protect: int) -> int:
        """Change the protection on a region of memory in the target process
        
        Args:
            addr: address of the memory region
            size: size of the memory region
            protect: new protection to apply to the memory region
        
        Returns:
            The old protection of the memory region
        """
    
    
    def _virtual_protect(self, addr: int, size: int, protect: int) -> int:
        old_protect = DWORD()
        if not kernel32.VirtualProtect(addr, size, protect, ctypes.byref(old_protect)):
            raise WinAPIError('VirtualProtect - %s' % (kernel32.GetLastError()))
        return old_protect.value
    
    
    def _virtual_protect_ex(self, addr: int, size: int, protect: int) -> int:
        old_protect = DWORD()
        if not kernel32.VirtualProtectEx(self.handle, addr, size, protect, ctypes.byref(old_protect)):
            raise WinAPIError('VirtualProtectEx - %s' % (kernel32.GetLastError()))
        return old_protect.value
    
    
    def _nt_protect_virtual_memory(self, addr: int, size: int, protect: int) -> int:
        old_protect = DWORD()
        status = self.ntdll.NtProtectVirtualMemory(self.handle, ctypes.byref(HANDLE(addr)), ctypes.byref(SIZE_T(size)), protect, ctypes.byref(old_protect))
        if status:
            raise WinAPIError('NtProtectVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return old_protect.value
    
    
    def read(self, addr: int, size: int) -> bytes:
        """Read an area of memory of the target process
        
        Args:
            addr: the address of the memory area to read
            size: the size of the memory area to read
        
        Returns:
            Bytes of the memory area read
        """
    
    
    def _read_memory(self, addr: int, size: int) -> bytes:
        data = (CHAR * size).from_address(addr)
        return data.raw
    
    
    def _read_process_memory(self, addr: int, size: int) -> bytes:
        data = (CHAR * size)()
        if not kernel32.ReadProcessMemory(self.handle, addr, ctypes.byref(data), ctypes.sizeof(data), None):
            raise WinAPIError('ReadProcessMemory - %s' % (kernel32.GetLastError()))
        return data.raw
    
    
    def _nt_read_virtual_memory(self, addr: int, size: int) -> bytes:
        data = (CHAR * size)()
        status = self.ntdll.NtReadVirtualMemory(self.handle, addr, ctypes.byref(data), ctypes.sizeof(data), None)
        if status:
            raise WinAPIError('NtReadVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
        return data.raw
        
    
    def write(self, addr: int, data: str | bytes) -> None:
        """Write to an area of memory of the target process
        
        Args:
            addr: address of the memory area
            data: bytes to write at the specified address
        """
    
    
    def _rtl_move_memory(self, addr: int, data: str | bytes) -> None:
        if isinstance(data, str):
            data = data.encode('utf-8')
        wr_data = (CHAR * len(data))()
        wr_data.value = data
        if not kernel32.RtlMoveMemory(addr, ctypes.byref(wr_data), ctypes.sizeof(wr_data)):
            raise WinAPIError('RtlMoveMemory - %s' % (kernel32.GetLastError()))
    
    
    def _write_process_memory(self, addr: int, data: str | bytes) -> None:
        if isinstance(data, str):
            data = data.encode('utf-8')
        wr_data = (CHAR * len(data))()
        wr_data.value = data
        if not kernel32.WriteProcessMemory(self.handle, addr, ctypes.byref(wr_data), ctypes.sizeof(wr_data), None):
            raise WinAPIError('WriteProcessMemory - %s' % (kernel32.GetLastError()))
    
    
    def _nt_write_virtual_memory(self, addr: int, data: str | bytes) -> None:
        if isinstance(data, str):
            data = data.encode('utf-8')
        wr_data = (CHAR * len(data))()
        wr_data.value = data
        status = self.ntdll.NtWriteVirtualMemory(self.handle, addr, ctypes.byref(wr_data), ctypes.sizeof(wr_data), None)
        if status:
            raise WinAPIError('NtWriteVirtualMemory - %s' % ('0x{0:08x}'.format(status)))
    
    
    def start_thread(self, addr: int, arg: int | None = None) -> int:
        """Start a thread in the target process
        
        Args:
            addr: address of the function
            arg: address of the parameter to pass to the function
        
        Returns:
            A handle to the thread started
        """
    
    
    def _create_thread(self, addr: int, arg: int | None = None) -> int:
        handle = kernel32.CreateThread(None, 0, addr, arg, 0, None)
        if not handle:
            raise WinAPIError('CreateThread - %s' % (kernel32.GetLastError()))
        return handle
    
    
    def _create_remote_thread(self, addr: int, arg: int | None = None) -> int:
        handle = kernel32.CreateRemoteThread(self.handle, None, 0, addr, arg, 0, None)
        if not handle:
            raise WinAPIError('CreateRemoteThread - %s' % (kernel32.GetLastError()))
        return handle
    
    
    def _nt_create_thread_ex(self, addr: int, arg: int | None = None) -> int:
        flags = SYNCHRONIZE | THREAD_QUERY_INFORMATION
        handle = HANDLE()
        status = self.ntdll.NtCreateThreadEx(ctypes.byref(handle), flags, None, self.handle, addr, arg, False, 0, 0, 0, None)
        if not handle.value:
            raise WinAPIError('NtCreateThreadEx - %s' % ('0x{0:08x}'.format(status)))
        return handle.value
    
    
    def join_thread(self, handle: int) -> int:
        """Join a thread in the target process
        
        Args:
            handle: handle to the thread
        
        Returns:
            The exit code (32-bits) of the thread
        """
        kernel32.WaitForSingleObject(handle, -1)
        exit_code = DWORD()
        if not kernel32.GetExitCodeThread(handle, ctypes.byref(exit_code)):
            raise WinAPIError('GetExitCodeThread - %s' % (kernel32.GetLastError()))
        if not kernel32.CloseHandle(handle):
            raise WinAPIError('CloseHandle - %s' % (kernel32.GetLastError()))
        return exit_code.value
    
    
    def run_funcs(self, funcs: list[tuple[int, int]]) -> list[int]:
        """Run multiple functions in the same new thread
        
        Args:
            funcs: list of tuples (addr, arg) with each function to call with its parameter
        
        Returns:
            A list of the return values for each called function
        """
        n = len(funcs)
        if self.x86:
            run_func = _run_func_x86
            basesize = 4
        else:
            run_func = _run_func_x64
            basesize = 8
        
        ret_addr = self.allocate(n*basesize)
        
        thread_code = b''
        for i, (addr, arg) in enumerate(funcs):
            addr = addr.to_bytes(basesize, 'little')
            arg = arg.to_bytes(basesize, 'little')
            ret = (ret_addr + i*basesize).to_bytes(basesize, 'little')
            thread_code += run_func % (addr, arg, ret)
        thread_code = _run_func_ret % thread_code
        
        thread_code_addr = self.allocate(len(thread_code))
        self.write(thread_code_addr, thread_code)
        self.protect(thread_code_addr, len(thread_code), PAGE_EXECUTE_READ)
        
        thread = self.start_thread(thread_code_addr)
        self.join_thread(thread)
        
        retvals = []
        for i in range(n):
            retval = self.read(ret_addr + i*basesize, basesize)
            retvals.append(int.from_bytes(retval, 'little'))
        
        self.free(ret_addr)
        self.free(thread_code_addr)
        return retvals
    
    
    def module_from_hmodule(self, hmodule: int) -> PE:
        """Get a PE object from a handle to a module
        
        Args:
            hmodule: handle to the module
        
        Returns:
            A PyJectify's PE object representing the module
        """
        sysinfo = SYSTEM_INFO()
        kernel32.GetNativeSystemInfo(ctypes.byref(sysinfo))
        headers = PE(self.read(hmodule, sysinfo.dwPageSize), hmodule, headers_only=True)

        raw = BytesIO(b'\x00'*headers.nt_header.OptionalHeader.SizeOfImage)
        raw.write(headers.raw)
        
        for section in headers.sections_header:
            raw.seek(section.VirtualAddress)
            raw.write(self.read(hmodule + section.VirtualAddress, section.Misc.VirtualSize))
        
        raw.seek(0)
        return PE(raw.read(), base_addr=hmodule)
    
    
    def get_module(self, lib: str) -> PE:
        """Get a PE object from a library loaded by the target process
        
        Args:
            lib: library name
        
        Returns:
            A PyJectify's PE object representing the library
        """
        fullpath = isabs(lib)
        
        modules = (HANDLE * 1)()
        size = DWORD()
        if not psapi.EnumProcessModulesEx(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(size), LIST_MODULES_ALL):
            raise WinAPIError('EnumProcessModulesEx - %s' % (kernel32.GetLastError()))
        modules = (HANDLE * size.value)()
        if not psapi.EnumProcessModulesEx(self.handle, modules, ctypes.sizeof(modules), ctypes.byref(size), LIST_MODULES_ALL):
            raise WinAPIError('EnumProcessModulesEx - %s' % (kernel32.GetLastError()))
        
        for module in modules:
            name = LPCSTR(b' '*1024)
            if fullpath:
                if not psapi.GetModuleFileNameExA(self.handle, module, name, ULONG(1024)):
                    raise WinAPIError('GetModuleFileNameExA - %s' % (kernel32.GetLastError()))
            else:
                if not psapi.GetModuleBaseNameA(self.handle, module, name, ULONG(1024)):
                    raise WinAPIError('GetModuleBaseNameA - %s' % (kernel32.GetLastError()))
            
            if str(name.value.decode().lower()) == lib.lower():
                return self.module_from_hmodule(module)
        
        raise WinAPIError('EnumProcessModulesEx + %s - Module %s not found' % ('GetModuleFileNameExA' if fullpath else 'GetModuleBaseNameA', lib))



class WinAPIError(Exception):
    """Exception for Windows API errors"""
    pass