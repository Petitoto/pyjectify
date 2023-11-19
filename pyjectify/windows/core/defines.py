import ctypes


# Windows libraries
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
psapi = ctypes.windll.psapi


# Windows data types from ctypes.wintypes
BYTE = ctypes.c_ubyte
WORD = ctypes.c_ushort
DWORD = ctypes.c_ulong

#UCHAR = ctypes.c_uchar
CHAR = ctypes.c_char
WCHAR = ctypes.c_wchar
UINT = ctypes.c_uint
INT = ctypes.c_int

DOUBLE = ctypes.c_double
FLOAT = ctypes.c_float

BOOLEAN = BYTE
BOOL = ctypes.c_long

class VARIANT_BOOL(ctypes._SimpleCData):
    _type_ = "v"
    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.value)

ULONG = ctypes.c_ulong
LONG = ctypes.c_long

USHORT = ctypes.c_ushort
SHORT = ctypes.c_short

_LARGE_INTEGER = LARGE_INTEGER = ctypes.c_longlong
_ULARGE_INTEGER = ULARGE_INTEGER = ctypes.c_ulonglong

LPCOLESTR = LPOLESTR = OLESTR = ctypes.c_wchar_p
LPCWSTR = LPWSTR = ctypes.c_wchar_p
LPCSTR = LPSTR = ctypes.c_char_p
LPCVOID = LPVOID = ctypes.c_void_p

if ctypes.sizeof(ctypes.c_long) == ctypes.sizeof(ctypes.c_void_p):
    WPARAM = ctypes.c_ulong
    LPARAM = ctypes.c_long
elif ctypes.sizeof(ctypes.c_longlong) == ctypes.sizeof(ctypes.c_void_p):
    WPARAM = ctypes.c_ulonglong
    LPARAM = ctypes.c_longlong

ATOM = WORD
LANGID = WORD

COLORREF = DWORD
LGRPID = DWORD
LCTYPE = DWORD

LCID = DWORD

HANDLE = ctypes.c_void_p

HACCEL = HANDLE
HBITMAP = HANDLE
HBRUSH = HANDLE
HCOLORSPACE = HANDLE
HDC = HANDLE
HDESK = HANDLE
HDWP = HANDLE
HENHMETAFILE = HANDLE
HFONT = HANDLE
HGDIOBJ = HANDLE
HGLOBAL = HANDLE
HHOOK = HANDLE
HICON = HANDLE
HINSTANCE = HANDLE
HKEY = HANDLE
HKL = HANDLE
HLOCAL = HANDLE
HMENU = HANDLE
HMETAFILE = HANDLE
HMODULE = HANDLE
HMONITOR = HANDLE
HPALETTE = HANDLE
HPEN = HANDLE
HRGN = HANDLE
HRSRC = HANDLE
HSTR = HANDLE
HTASK = HANDLE
HWINSTA = HANDLE
HWND = HANDLE
SC_HANDLE = HANDLE
SERVICE_STATUS_HANDLE = HANDLE

class RECT(ctypes.Structure):
    _fields_ = [("left", LONG),
                ("top", LONG),
                ("right", LONG),
                ("bottom", LONG)]
tagRECT = _RECTL = RECTL = RECT

class _SMALL_RECT(ctypes.Structure):
    _fields_ = [('Left', SHORT),
                ('Top', SHORT),
                ('Right', SHORT),
                ('Bottom', SHORT)]
SMALL_RECT = _SMALL_RECT

class _COORD(ctypes.Structure):
    _fields_ = [('X', SHORT),
                ('Y', SHORT)]

class POINT(ctypes.Structure):
    _fields_ = [("x", LONG),
                ("y", LONG)]
tagPOINT = _POINTL = POINTL = POINT

class SIZE(ctypes.Structure):
    _fields_ = [("cx", LONG),
                ("cy", LONG)]
tagSIZE = SIZEL = SIZE

def RGB(red, green, blue):
    return red + (green << 8) + (blue << 16)

class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", DWORD),
                ("dwHighDateTime", DWORD)]
_FILETIME = FILETIME

class MSG(ctypes.Structure):
    _fields_ = [("hWnd", HWND),
                ("message", UINT),
                ("wParam", WPARAM),
                ("lParam", LPARAM),
                ("time", DWORD),
                ("pt", POINT)]
tagMSG = MSG
MAX_PATH = 260

class WIN32_FIND_DATAA(ctypes.Structure):
    _fields_ = [("dwFileAttributes", DWORD),
                ("ftCreationTime", FILETIME),
                ("ftLastAccessTime", FILETIME),
                ("ftLastWriteTime", FILETIME),
                ("nFileSizeHigh", DWORD),
                ("nFileSizeLow", DWORD),
                ("dwReserved0", DWORD),
                ("dwReserved1", DWORD),
                ("cFileName", CHAR * MAX_PATH),
                ("cAlternateFileName", CHAR * 14)]

class WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = [("dwFileAttributes", DWORD),
                ("ftCreationTime", FILETIME),
                ("ftLastAccessTime", FILETIME),
                ("ftLastWriteTime", FILETIME),
                ("nFileSizeHigh", DWORD),
                ("nFileSizeLow", DWORD),
                ("dwReserved0", DWORD),
                ("dwReserved1", DWORD),
                ("cFileName", WCHAR * MAX_PATH),
                ("cAlternateFileName", WCHAR * 14)]

LPBOOL = PBOOL = ctypes.POINTER(BOOL)
PBOOLEAN = ctypes.POINTER(BOOLEAN)
LPBYTE = PBYTE = ctypes.POINTER(BYTE)
PCHAR = ctypes.POINTER(CHAR)
LPCOLORREF = ctypes.POINTER(COLORREF)
LPDWORD = PDWORD = ctypes.POINTER(DWORD)
LPFILETIME = PFILETIME = ctypes.POINTER(FILETIME)
PFLOAT = ctypes.POINTER(FLOAT)
LPHANDLE = PHANDLE = ctypes.POINTER(HANDLE)
PHKEY = ctypes.POINTER(HKEY)
LPHKL = ctypes.POINTER(HKL)
LPINT = PINT = ctypes.POINTER(INT)
PLARGE_INTEGER = ctypes.POINTER(LARGE_INTEGER)
PLCID = ctypes.POINTER(LCID)
LPLONG = PLONG = ctypes.POINTER(LONG)
LPMSG = PMSG = ctypes.POINTER(MSG)
LPPOINT = PPOINT = ctypes.POINTER(POINT)
PPOINTL = ctypes.POINTER(POINTL)
LPRECT = PRECT = ctypes.POINTER(RECT)
LPRECTL = PRECTL = ctypes.POINTER(RECTL)
LPSC_HANDLE = ctypes.POINTER(SC_HANDLE)
PSHORT = ctypes.POINTER(SHORT)
LPSIZE = PSIZE = ctypes.POINTER(SIZE)
LPSIZEL = PSIZEL = ctypes.POINTER(SIZEL)
PSMALL_RECT = ctypes.POINTER(SMALL_RECT)
LPUINT = PUINT = ctypes.POINTER(UINT)
PULARGE_INTEGER = ctypes.POINTER(ULARGE_INTEGER)
PULONG = ctypes.POINTER(ULONG)
PUSHORT = ctypes.POINTER(USHORT)
PWCHAR = ctypes.POINTER(WCHAR)
LPWIN32_FIND_DATAA = PWIN32_FIND_DATAA = ctypes.POINTER(WIN32_FIND_DATAA)
LPWIN32_FIND_DATAW = PWIN32_FIND_DATAW = ctypes.POINTER(WIN32_FIND_DATAW)
LPWORD = PWORD = ctypes.POINTER(WORD)


# Adding some Windows types
ULONGLONG = ctypes.c_ulonglong
SIZE_T = ctypes.c_size_t
POINTER = ctypes.POINTER


# Windows macros
def LOWORD(dword):
    return dword & 0x0000ffff

def HIWORD(dword):
    return dword >> 16


# PE flags
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_DIR64 = 10
IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x80000000 << 32
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
DLL_PROCESS_ATTACH = 1


# Process flags
PROCESS_CREATE_PROCESS = 0x80
PROCESS_CREATE_THREAD = 0x02
PROCESS_DUP_HANDLE = 0x40
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_INFORMATION = 0x0200
PROCESS_SET_QUOTA = 0x0100
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_TERMINATE = 0x01
PROCESS_VM_OPERATION = 0x08
PROCESS_VM_READ = 0x10
PROCESS_VM_WRITE = 0x20


# Threads flags
SYNCHRONIZE = 0x100000
THREAD_DIRECT_IMPERSONATION = 0x0200
THREAD_GET_CONTEXT = 0x08
THREAD_IMPERSONATE = 0x0100
THREAD_QUERY_INFORMATION = 0x40
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_SET_CONTEXT = 0x10
THREAD_SET_INFORMATION = 0x20
THREAD_SET_LIMITED_INFORMATION = 0x0400
THREAD_SET_THREAD_TOKEN = 0x0080
THREAD_SUSPEND_RESUME = 0x02
THREAD_TERMINATE = 0x01


# Memory flags
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
MEM_FREE = 0x10000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400


# Other Windows flags
LIST_MODULES_ALL = 0x03
TH32CS_SNAPPROCESS = 0x02


# PE structs
def IMAGE_ORDINAL32(Ordinal):
  return (Ordinal & 0xffff)

def IMAGE_ORDINAL64(Ordinal):
  return (Ordinal & 0xffff)

def IMAGE_SNAP_BY_ORDINAL32(ordinal):
    return ordinal & IMAGE_ORDINAL_FLAG32 != 0

def IMAGE_SNAP_BY_ORDINAL64(ordinal):
    return ordinal & IMAGE_ORDINAL_FLAG64 != 0

class IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ('e_magic', WORD),
        ('e_cblp', WORD),
        ('e_cp', WORD),
        ('e_crlc', WORD),
        ('e_cparhdr', WORD),
        ('e_minalloc', WORD),
        ('e_maxalloc', WORD),
        ('e_ss', WORD),
        ('e_sp', WORD),
        ('e_csum', WORD),
        ('e_ip', WORD),
        ('e_cs', WORD),
        ('e_lfarlc', WORD),
        ('e_ovno', WORD),
        ('e_res', WORD * 4),
        ('e_oemid', WORD),
        ('e_oeminfo', WORD),
        ('e_res2', WORD * 10),
        ('e_lfanew', LONG),
    ]

class IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ('Machine', WORD),
        ('NumberOfSections', WORD),
        ('TimeDateStamp', DWORD),
        ('PointerToSymbolTable', DWORD),
        ('NumberOfSymbols', DWORD),
        ('SizeOfOptionalHeader', WORD),
        ('Characteristics', WORD),
    ]

class IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('VirtualAddress', DWORD),
        ('Size', DWORD),
    ]

class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
    _fields_ = [
        ('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitializedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        ('BaseOfData', DWORD),
        ('ImageBase', DWORD),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperatingSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Win32VersionValue', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', DWORD),
        ('SizeOfStackCommit', DWORD),
        ('SizeOfHeapReserve', DWORD),
        ('SizeOfHeapCommit', DWORD),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ('Magic', WORD),
        ('MajorLinkerVersion', BYTE),
        ('MinorLinkerVersion', BYTE),
        ('SizeOfCode', DWORD),
        ('SizeOfInitializedData', DWORD),
        ('SizeOfUninitializedData', DWORD),
        ('AddressOfEntryPoint', DWORD),
        ('BaseOfCode', DWORD),
        ('ImageBase', ULONGLONG),
        ('SectionAlignment', DWORD),
        ('FileAlignment', DWORD),
        ('MajorOperatingSystemVersion', WORD),
        ('MinorOperatingSystemVersion', WORD),
        ('MajorImageVersion', WORD),
        ('MinorImageVersion', WORD),
        ('MajorSubsystemVersion', WORD),
        ('MinorSubsystemVersion', WORD),
        ('Win32VersionValue', DWORD),
        ('SizeOfImage', DWORD),
        ('SizeOfHeaders', DWORD),
        ('CheckSum', DWORD),
        ('Subsystem', WORD),
        ('DllCharacteristics', WORD),
        ('SizeOfStackReserve', ULONGLONG),
        ('SizeOfStackCommit', ULONGLONG),
        ('SizeOfHeapReserve', ULONGLONG),
        ('SizeOfHeapCommit', ULONGLONG),
        ('LoaderFlags', DWORD),
        ('NumberOfRvaAndSizes', DWORD),
        ('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
    ]

class IMAGE_NT_HEADERS32(ctypes.Structure):
    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER32),
    ]

class IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ('Signature', DWORD),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER64),
    ]

class IMAGE_SECTION_HEADER(ctypes.Structure):
    class Misc(ctypes.Union):
        _fields_ = [
            ('PhysicalAddress', DWORD),
            ('VirtualSize', DWORD),
        ]
    _fields_ = [
        ('Name', BYTE * 8),
        ('Misc', Misc),
        ('VirtualAddress', DWORD),
        ('SizeOfRawData', DWORD),
        ('PointerToRawData', DWORD),
        ('PointerToRelocations', DWORD),
        ('PointerToLinenumbers', DWORD),
        ('NumberOfRelocations', WORD),
        ('NumberOfLinenumbers', WORD),
        ('Characteristics', DWORD),
    ]

class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ('Characteristics', DWORD),
        ('TimeDateStamp', DWORD),
        ('MajorVersion', WORD),
        ('MinorVersion', WORD),
        ('Name', DWORD),
        ('Base', DWORD),
        ('NumberOfFunctions', DWORD),
        ('NumberOfNames', DWORD),
        ('AddressOfFunctions', DWORD),
        ('AddressOfNames', DWORD),
        ('AddressOfNameOrdinals', DWORD),
    ]

class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [
            ('Characteristics', DWORD),
            ('OriginalFirstThunk', DWORD),
        ]
    _anonymous_ = ('_u',)
    _fields_ = [
        ('_u', _U),
        ('TimeDateStamp', DWORD),
        ('ForwarderChain', DWORD),
        ('Name', DWORD),
        ('FirstThunk', DWORD),
    ]

class IMAGE_THUNK_DATA32(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [
            ('ForwarderString', DWORD),
            ('Function', DWORD),
            ('Ordinal', DWORD),
            ('AddressOfData', DWORD),
        ]
    _fields_ = [
        ('u1',  _U),
    ]

class IMAGE_THUNK_DATA64(ctypes.Structure):
    class _U(ctypes.Union):
        _fields_ = [
            ('ForwarderString', ULONGLONG),
            ('Function', ULONGLONG),
            ('Ordinal', ULONGLONG),
            ('AddressOfData', ULONGLONG),
        ]
    _fields_ = [
        ('u1', _U),
    ]

class IMAGE_IMPORT_BY_NAME(ctypes.Structure):
    _fields_ = [
        ('Hint', WORD),
        ('Name', CHAR * 512),
    ]

class BASE_RELOCATION_BLOCK(ctypes.Structure):
    _fields_ = [
        ('PageAddress', DWORD),
        ('BlockSize', DWORD),
    ]

class BASE_RELOCATION_ENTRY(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('Offset', UINT, 12),
        ('Type', UINT, 4),
    ]


# Process structs
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', DWORD),
        ('cntUsage', DWORD),
        ('th32ProcessID', DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(ULONG)),
        ('th32ModuleID', DWORD),
        ('cntThreads', DWORD),
        ('th32ParentProcessID', DWORD),
        ('pcPriClassBase', LONG),
        ('dwFlags', DWORD),
        ('szExeFile', CHAR * 260),
        ]


# Memory & Module structs
MemoryBasicInformation = 0
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', LPVOID),
        ('AllocationBase', LPVOID),
        ('AllocationProtect', DWORD),
        ('PartitionId', WORD),
        ('RegionSize', SIZE_T),
        ('State', DWORD),
        ('Protect', DWORD),
        ('Type', DWORD)
    ]

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ('lpBaseOfDll', LPVOID),
        ('SizeOfImage', DWORD),
        ('EntryPoint', LPVOID),
    ]


# ApiSetSchema structs
class StructApiSetValueEntryRedirectionV2(ctypes.Structure):
    _fields_ = [
        ('NameOffset', ctypes.c_uint32),
        ('NameLength', ctypes.c_uint32),
        ('ValueOffset', ctypes.c_uint32),
        ('ValueLength', ctypes.c_uint32),
    ]

class StructApiSetValueEntryV2(ctypes.Structure):
    _fields_ = [
        ('NumberOfRedirections', ctypes.c_uint32),
    ]

class StructApiSetNamespaceEntryV2(ctypes.Structure):
    _fields_ = [
        ('NameOffset', ctypes.c_uint32),
        ('NameLength', ctypes.c_uint32),
        ('DataOffset', ctypes.c_uint32),
    ]

class StructApiSetNamespaceV2(ctypes.Structure):
    _fields_ = [
        ('Version', ctypes.c_uint32),
        ('Count', ctypes.c_uint32),
    ]

class StructApiSetValueEntryRedirectionV4(ctypes.Structure):
    _fields_ = [
        ('Flags', ctypes.c_uint32),
        ('NameOffset', ctypes.c_uint32),
        ('NameLength', ctypes.c_uint32),
        ('ValueOffset', ctypes.c_uint32),
        ('ValueLength', ctypes.c_uint32),
    ]

class StructApiSetValueEntryV4(ctypes.Structure):
    _fields_ = [
        ('Flags', ctypes.c_uint32),
        ('NumberOfRedirections', ctypes.c_uint32),
    ]

class StructApiSetNamespaceEntryV4(ctypes.Structure):
    _fields_ = [
        ('Flags', ctypes.c_uint32),
        ('NameOffset', ctypes.c_uint32),
        ('NameLength', ctypes.c_uint32),
        ('AliasOffset', ctypes.c_uint32),
        ('AliasLength', ctypes.c_uint32),
        ('DataOffset', ctypes.c_uint32),
    ]

class StructApiSetNamespaceV4(ctypes.Structure):
    _fields_ = [
        ('Version', ctypes.c_uint32),
        ('Size', ctypes.c_uint32),
        ('Flags', ctypes.c_uint32),
        ('Count', ctypes.c_uint32),
    ]

class StructApiSetHashEntryV6(ctypes.Structure):
    _fields_ = [
        ('Hash', ctypes.c_uint32),
        ('Index', ctypes.c_uint32),
    ]

class StructApiSetNamespaceEntryV6(ctypes.Structure):
    _fields_ = [
        ('Flags', ctypes.c_uint32),
        ('NameOffset', ctypes.c_uint32),
        ('NameLength', ctypes.c_uint32),
        ('HashedLength', ctypes.c_uint32),
        ('ValueOffset', ctypes.c_uint32),
        ('ValueCount', ctypes.c_uint32),
    ]

class StructApiSetValueEntryV6(ctypes.Structure):
    _fields_ = [
        ('Flags', ctypes.c_uint32),
        ('NameOffset', ctypes.c_uint32),
        ('NameLength', ctypes.c_uint32),
        ('ValueOffset', ctypes.c_uint32),
        ('ValueLength', ctypes.c_uint32),
    ]

class StructApiSetNamespaceV6(ctypes.Structure):
    _fields_ = [
        ('Version', ctypes.c_uint32),
        ('Size', ctypes.c_uint32),
        ('Flags', ctypes.c_uint32),
        ('Count', ctypes.c_uint32),
        ('EntryOffset', ctypes.c_uint32),
        ('HashOffset', ctypes.c_uint32),
        ('HashFactor', ctypes.c_uint32),
    ]


# Other Windows structs
class SYSTEM_INFO(ctypes.Structure):
    class _U(ctypes.Union):
        class _S(ctypes.Structure):
            _fields_ = [
                ('wProcessorArchitecture', WORD),
                ('wReserved', WORD),
            ]
        _fields_ = [
            ('dwOemId', DWORD),
            ('struct', _S),
        ]
    _fields_ = [
        ('union', _U),
        ('dwPageSize', DWORD),
        ('lpMinimumApplicationAddress', LPVOID),
        ('lpMaximumApplicationAddress', LPVOID),
        ('dwActiveProcessorMask', DWORD),
        ('dwNumberOfProcessors', DWORD),
        ('dwProcessorType', DWORD),
        ('dwAllocationGranularity', DWORD),
        ('wProcessorLevel', WORD),
        ('wProcessorRevision', WORD),
    ]


# Windows functions restype & argtypes
kernel32.CloseHandle.restype = BOOL
kernel32.CloseHandle.argtypes = (HANDLE, )
kernel32.CreateThread.restype = HANDLE
kernel32.CreateThread.argtypes = (LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD)
kernel32.CreateRemoteThread.restype = HANDLE
kernel32.CreateRemoteThread.argtypes = (HANDLE, LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPDWORD)
kernel32.CreateToolhelp32Snapshot.restype = HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = (DWORD, DWORD)
kernel32.GetCurrentProcess.restype = HANDLE
kernel32.GetCurrentProcess.argtypes = ()
kernel32.GetExitCodeThread.restype = BOOL
kernel32.GetExitCodeThread.argtypes = (HANDLE, LPDWORD)
kernel32.GetLastError.restype = DWORD
kernel32.GetLastError.argtypes = ()
kernel32.GetNativeSystemInfo.restype = None
kernel32.GetNativeSystemInfo.argtypes = (POINTER(SYSTEM_INFO), )
kernel32.IsWow64Process.restype = BOOL
kernel32.IsWow64Process.argtypes = (HANDLE, PBOOL)
kernel32.OpenProcess.restype = HANDLE
kernel32.OpenProcess.argtypes = (DWORD, BOOL, DWORD)
kernel32.Process32First.restype = BOOL
kernel32.Process32First.argtypes = (HANDLE, POINTER(PROCESSENTRY32))
kernel32.Process32Next.restype = BOOL
kernel32.Process32Next.argtypes = (HANDLE, POINTER(PROCESSENTRY32))
kernel32.ReadProcessMemory.restype = BOOL
kernel32.ReadProcessMemory.argtypes = (HANDLE, LPCVOID, LPVOID, SIZE_T, LPVOID)
kernel32.RtlMoveMemory.restype = LPVOID
kernel32.RtlMoveMemory.argtypes = (LPVOID, LPVOID, SIZE_T)
kernel32.VirtualAlloc.restype = LPVOID
kernel32.VirtualAlloc.argtypes = (LPVOID, SIZE_T, DWORD, DWORD)
kernel32.VirtualAllocEx.restype = LPVOID
kernel32.VirtualAllocEx.argtypes = (HANDLE, LPVOID, SIZE_T, DWORD, DWORD)
kernel32.VirtualFree.restype = BOOL
kernel32.VirtualFree.argtypes = (LPVOID, SIZE_T, DWORD)
kernel32.VirtualFreeEx.restype = BOOL
kernel32.VirtualFreeEx.argtypes = (HANDLE, LPVOID, SIZE_T, DWORD)
kernel32.VirtualProtect.restype = BOOL
kernel32.VirtualProtect.argtypes = (LPVOID, SIZE_T, DWORD, POINTER(DWORD))
kernel32.VirtualProtectEx.restype = BOOL
kernel32.VirtualProtectEx.argtypes = (HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD))
kernel32.VirtualQuery.restype = SIZE_T
kernel32.VirtualQuery.argtypes = (LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), SIZE_T)
kernel32.VirtualQueryEx.restype = SIZE_T
kernel32.VirtualQueryEx.argtypes = (HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), SIZE_T)
kernel32.WaitForSingleObject.restype = HANDLE
kernel32.WaitForSingleObject.argtypes = (HANDLE, DWORD)
kernel32.Wow64DisableWow64FsRedirection.restype	= BOOL
kernel32.Wow64DisableWow64FsRedirection.argtypes = (LPVOID, )
kernel32.Wow64RevertWow64FsRedirection.restype	= BOOL
kernel32.Wow64RevertWow64FsRedirection.argtypes = (LPVOID, )
kernel32.WriteProcessMemory.restype = BOOL
kernel32.WriteProcessMemory.argtypes = (HANDLE, LPVOID, LPCVOID, SIZE_T, LPVOID)

ntdll.NtAllocateVirtualMemory.restype = DWORD
ntdll.NtAllocateVirtualMemory.argtypes = (HANDLE, LPVOID, LPVOID, POINTER(SIZE_T), DWORD, DWORD)
ntdll.NtCreateThreadEx.restype = DWORD
ntdll.NtCreateThreadEx.argtypes = (PHANDLE, DWORD, LPVOID, HANDLE, LPVOID, LPVOID, BOOL, SIZE_T, SIZE_T, SIZE_T, LPVOID)
ntdll.NtFreeVirtualMemory.restype = DWORD
ntdll.NtFreeVirtualMemory.argtypes = (HANDLE, LPVOID, POINTER(SIZE_T), DWORD)
ntdll.NtProtectVirtualMemory.restype = DWORD
ntdll.NtProtectVirtualMemory.argtypes = (HANDLE, LPVOID, POINTER(SIZE_T), DWORD, POINTER(DWORD))
ntdll.NtQueryVirtualMemory.restype = DWORD
ntdll.NtQueryVirtualMemory.argtypes = (HANDLE, LPVOID, UINT, LPVOID, SIZE_T, POINTER(SIZE_T))
ntdll.NtReadVirtualMemory.restype = DWORD
ntdll.NtReadVirtualMemory.argtypes = (HANDLE, LPCVOID, LPVOID, SIZE_T, LPVOID)
ntdll.NtWriteVirtualMemory.restype = DWORD
ntdll.NtWriteVirtualMemory.argtypes = (HANDLE, LPVOID, LPCVOID, SIZE_T, LPVOID)

psapi.EnumProcessModulesEx.restype = BOOL
psapi.EnumProcessModulesEx.argtypes = (HANDLE, PHANDLE, DWORD, LPDWORD, DWORD)
psapi.GetModuleBaseNameA.restype = DWORD
psapi.GetModuleBaseNameA.argtypes = (HANDLE, HANDLE, LPSTR, DWORD)
psapi.GetModuleFileNameExA.restype = DWORD
psapi.GetModuleFileNameExA.argtypes = (HANDLE, HANDLE, LPSTR, DWORD)
psapi.GetModuleInformation.restype = BOOL
psapi.GetModuleInformation.argtypes = (HANDLE, HMODULE, POINTER(MODULEINFO), DWORD)