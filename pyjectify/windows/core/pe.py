from io import BytesIO
from typing import TypeVar

from pyjectify.windows.core.defines import *


STRUCT = TypeVar('STRUCT', bound=ctypes.Structure)


class PE:
    """This class represents a PE and provides methods to parse it."""

    def __init__(self, raw: bytes, base_addr: int = 0, headers_only: bool = False) -> None:
        """Initialization: parse PE headers and sections

        Args:
            raw: raw bytes of the PE, from a file or already mapped to memory
            base_addr: force PE base address (if null, get it from the PE headers)
            headers_only: specify whether the raw bytes contain the entire PE or just its headers
        """
        self._raw: bytes = raw
        self._base_addr: int = base_addr
        self._sections_header: list[IMAGE_SECTION_HEADER] = []
        self._sections: list[tuple[int, int, int]] = []
        self._exports: dict[str|int, int] = {}
        self._imports: dict[str, list[tuple[str|int, int]]] = {}
        self._imports_thunk: dict[str, list[tuple[str|int, int]]] = {}

        self._dos_header = self._fill_struct(IMAGE_DOS_HEADER, 0)
        if bytes(WORD(self._dos_header.e_magic)) != b'MZ':
            raise InvalidPEHeader('Invalid MZ signature - %s' % (self._dos_header.e_magic))

        self._nt_header = self._fill_struct(IMAGE_NT_HEADERS32, self._dos_header.e_lfanew)
        if bytes(DWORD(self._nt_header.Signature)) != b'PE\x00\x00':
            raise InvalidPEHeader('Invalid PE signature - %s' % (self._nt_header.Signature))

        if self._nt_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            self._x86 = True
            self._nt_header = self._fill_struct(IMAGE_NT_HEADERS32, self._dos_header.e_lfanew)
            section_addr = self._dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS32)
        elif self._nt_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            self._x86 = False
            self._nt_header = self._fill_struct(IMAGE_NT_HEADERS64, self._dos_header.e_lfanew)
            section_addr = self._dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS64)
        else:
            raise InvalidPEHeader('Invalid Optional Magic Header - %s' % (self._nt_header.OptionalHeader.Magic))

        if not self._base_addr:
            self._base_addr = self._nt_header.OptionalHeader.ImageBase

        for i in range(self._nt_header.FileHeader.NumberOfSections):
            section_header = self._fill_struct(IMAGE_SECTION_HEADER, section_addr + i*ctypes.sizeof(IMAGE_SECTION_HEADER))
            self._sections_header.append(section_header)

            protectR = section_header.Characteristics & IMAGE_SCN_MEM_READ
            protectW = section_header.Characteristics & IMAGE_SCN_MEM_WRITE
            protectX = section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE

            if not protectR and not protectW and protectX:
                protect = PAGE_EXECUTE
            elif protectR and not protectW and protectX:
                protect = PAGE_EXECUTE_READ
            elif protectR and not protectW and protectX:
                protect = PAGE_EXECUTE_READWRITE
            elif not protectR and protectW and protectX:
                protect = PAGE_EXECUTE_WRITECOPY
            elif not protectR and not protectW and not protectX:
                protect = PAGE_NOACCESS
            elif not protectR and protectW and not protectX:
                protect = PAGE_WRITECOPY
            elif protectR and not protectW and not protectX:
                protect = PAGE_READONLY
            elif protectR and protectW and not protectX:
                protect = PAGE_READWRITE
            else:
                raise InvalidPEHeader('Invalid section protection')

            self._sections.append((section_header.VirtualAddress, section_header.Misc.VirtualSize, protect))

        if not headers_only:
            self._map_to_memory()
            self._parse_imports()
            self._parse_exports()


    def _fill_struct(self, struct: type[STRUCT], addr: int) -> STRUCT:
        length = ctypes.sizeof(struct)
        buf = self._read_raw(addr, length)
        return struct.from_buffer_copy(buf)


    def _read_raw(self, addr: int, length: int) -> bytes:
        return self._raw[addr:addr + length]


    def _read_int(self, addr: int, length: int) -> int:
        return int.from_bytes(self._raw[addr:addr + length], byteorder='little')


    def _read_str(self, addr: int, length: int = 1024) -> str:
        data = self._raw[addr:addr+length]
        return data[:data.find(0)].decode()


    def _is_mapped(self) -> bool:
        if self._x86:
            section_addr = self._dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS32)
        else:
            section_addr = self._dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS64)

        data = b''
        virtual_end = section_addr + len(self._sections_header) * ctypes.sizeof(IMAGE_SECTION_HEADER)
        for section_header in self._sections_header:
            data = self._raw[virtual_end:section_header.VirtualAddress]
            if data != b'\x00'*len(data):
                break
            virtual_end = section_header.VirtualAddress + section_header.Misc.VirtualSize

        return data == b'\x00'*len(data)


    def _map_to_memory(self) -> None:
        if not self._sections_header:
            raise InvalidPEHeader('No sections found')

        if self._is_mapped():
            return

        size = self._nt_header.OptionalHeader.SizeOfImage
        raw = BytesIO(b'\x00'*size)

        raw.write(self._read_raw(0, self._nt_header.OptionalHeader.SizeOfHeaders))

        for section_header in self._sections_header:
            raw.seek(section_header.VirtualAddress)
            raw.write(self._read_raw(section_header.PointerToRawData, section_header.SizeOfRawData))

        raw.seek(0)
        self._raw = raw.read()


    def _parse_imports(self) -> None:
        data_directory = self._nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]

        if not data_directory.VirtualAddress:
            return

        offset = 0
        import_dir = self._fill_struct(IMAGE_IMPORT_DESCRIPTOR, data_directory.VirtualAddress)

        while import_dir.Characteristics:
            dll_name = self._read_str(import_dir.Name)
            self._imports[dll_name] = []
            self._imports_thunk[dll_name] = []

            i = 0
            while True:
                thunk: IMAGE_THUNK_DATA32 | IMAGE_THUNK_DATA64
                othunk: IMAGE_THUNK_DATA32 | IMAGE_THUNK_DATA64
                if self._x86:
                    thunk_addr = import_dir.FirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA32)
                    thunk = self._fill_struct(IMAGE_THUNK_DATA32, thunk_addr)
                    othunk_addr = import_dir._u.OriginalFirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA32)
                    othunk = self._fill_struct(IMAGE_THUNK_DATA32, othunk_addr)
                else:
                    thunk_addr = import_dir.FirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA64)
                    thunk = self._fill_struct(IMAGE_THUNK_DATA64, thunk_addr)
                    othunk_addr = import_dir.OriginalFirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA64)
                    othunk = self._fill_struct(IMAGE_THUNK_DATA64, othunk_addr)

                if not othunk.u1.AddressOfData:
                    break

                if self._x86 and IMAGE_SNAP_BY_ORDINAL32(othunk.u1.Ordinal):
                    self._imports_thunk[dll_name].append((IMAGE_ORDINAL32(othunk.u1.Ordinal), thunk_addr))
                    self._imports[dll_name].append((IMAGE_ORDINAL32(othunk.u1.Ordinal), thunk.u1.Function))
                    i += 1
                    continue
                elif not self._x86 and IMAGE_SNAP_BY_ORDINAL64(othunk.u1.Ordinal):
                    self._imports_thunk[dll_name].append((IMAGE_ORDINAL64(othunk.u1.Ordinal), thunk_addr))
                    self._imports[dll_name].append((IMAGE_ORDINAL64(othunk.u1.Ordinal), thunk.u1.Function))
                    i += 1
                    continue

                import_by_name = self._fill_struct(IMAGE_IMPORT_BY_NAME, othunk.u1.AddressOfData)
                self._imports_thunk[dll_name].append((import_by_name.Name.decode(), thunk_addr))
                self._imports[dll_name].append((import_by_name.Name.decode(), thunk.u1.Function))

                i += 1

            offset += ctypes.sizeof(IMAGE_IMPORT_DESCRIPTOR)
            import_dir = self._fill_struct(IMAGE_IMPORT_DESCRIPTOR, data_directory.VirtualAddress + offset)


    def _parse_exports(self) -> None:
        data_directory = self._nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

        if not data_directory.VirtualAddress:
            return

        export_directory = self._fill_struct(IMAGE_EXPORT_DIRECTORY, data_directory.VirtualAddress)

        if export_directory.AddressOfFunctions:
            for i in range(export_directory.NumberOfFunctions):
                function_addr = self._read_int(export_directory.AddressOfFunctions + 4*i, 4)
                self._exports[i] = function_addr

            for i in range(export_directory.NumberOfNames):
                ord = self._read_int(export_directory.AddressOfNameOrdinals + 2*i, 2)
                function_addr = self._exports[ord]
                name_addr = self._read_int(export_directory.AddressOfNames + 4*i, 4)
                name = self._read_str(name_addr)
                self._exports[name] = function_addr


    @property
    def raw(self) -> bytes:
        """Raw bytes of the PE, mapped to memory"""
        return self._raw


    @property
    def base_addr(self) -> int:
        """Base address of the PE"""
        return self._base_addr


    @property
    def dos_header(self) -> IMAGE_DOS_HEADER:
        """DOS headers"""
        return self._dos_header


    @property
    def nt_header(self) -> IMAGE_NT_HEADERS32 | IMAGE_NT_HEADERS64:
        """NT headers"""
        return self._nt_header


    @property
    def x86(self) -> bool:
        """Specify if the PE is a 32-bit PE"""
        return self._x86


    @property
    def sections_header(self) -> list[IMAGE_SECTION_HEADER]:
        """PE sections headers"""
        return self._sections_header


    @property
    def sections(self) -> list[tuple[int, int, int]]:
        """PE sections, list of (VirtualAddress, VirtualSize, PageProtection) tuple"""
        return self._sections


    @property
    def exports(self) -> dict[str|int, int]:
        """PE exports, dict of function_name | ordinal -> function_address

        Note: addresses are relative to the module base address
        """
        return self._exports


    @property
    def imports(self) -> dict[str, list[tuple[str|int, int]]]:
        """PE imports, dict of library_name -> [(function_name | ordinal, function_address)...]"""
        return self._imports


    def forwarded_export(self, name: str | int) -> str:
        """Resolve a forwarded export

        Args:
            name: the name (or the ordinal) of the forwarded export

        Returns:
            The name of the resolved forwarded export
        """
        addr = self._exports[name]

        begin_exports = self._nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        end_exports = begin_exports + self._nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size

        if begin_exports <= addr < end_exports:
            return self._read_str(addr)

        return ""


    def change_base(self, base_addr: int) -> None:
        """Change PE base address and perform base relocation

        Args:
            base_addr: new base address of the PE
        """
        delta = base_addr - self._base_addr

        if delta:
            raw = BytesIO(self._raw)
            relocations = self._nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]

            if relocations.Size:
                offset = 0
                relocation = self._fill_struct(BASE_RELOCATION_BLOCK, relocations.VirtualAddress)

                while relocation.PageAddress:
                    offset += ctypes.sizeof(BASE_RELOCATION_BLOCK)

                    entries_count = (relocation.BlockSize - ctypes.sizeof(BASE_RELOCATION_BLOCK)) // ctypes.sizeof(BASE_RELOCATION_ENTRY)

                    for _ in range(entries_count):
                        entry = self._fill_struct(BASE_RELOCATION_ENTRY, relocations.VirtualAddress + offset)
                        offset += ctypes.sizeof(BASE_RELOCATION_ENTRY)

                        relocation_addr = relocation.PageAddress + entry.Offset
                        raw.seek(relocation_addr)

                        if entry.Type == IMAGE_REL_BASED_ABSOLUTE:
                            continue

                        elif entry.Type == IMAGE_REL_BASED_HIGH:
                            address = self._read_int(relocation_addr, 2) + HIWORD(delta)
                            raw.write(address.to_bytes(2, byteorder='little'))

                        elif entry.Type == IMAGE_REL_BASED_LOW:
                            address = self._read_int(relocation_addr, 2) + LOWORD(delta)
                            raw.write(address.to_bytes(2, byteorder='little'))

                        elif entry.Type == IMAGE_REL_BASED_HIGHLOW:
                            address = self._read_int(relocation_addr, 4) + delta
                            raw.write(address.to_bytes(4, byteorder='little'))

                        elif entry.Type == IMAGE_REL_BASED_HIGHADJ:
                            address = self._read_int(relocation_addr, 2) + HIWORD(delta)
                            raw.write(address.to_bytes(2, byteorder='little'))
                            raw.write(LOWORD(delta).to_bytes(2, byteorder='little'))

                        elif entry.Type == IMAGE_REL_BASED_DIR64:
                            address = self._read_int(relocation_addr, 8) + delta
                            raw.write(address.to_bytes(8, byteorder='little'))

                        else:
                            raise InvalidPEHeader('Unknown relocation entry type - %s' % entry.Type)

                    relocation = self._fill_struct(BASE_RELOCATION_BLOCK, relocations.VirtualAddress + offset)

            if self._x86:
                self._nt_header.OptionalHeader.ImageBase = DWORD(base_addr)
                raw.seek(self._dos_header.e_lfanew + IMAGE_NT_HEADERS32.OptionalHeader.offset + IMAGE_OPTIONAL_HEADER32.ImageBase.offset)
                raw.write(base_addr.to_bytes(4, byteorder='little'))
            else:
                self._nt_header.OptionalHeader.ImageBase = ULONGLONG(base_addr)
                raw.seek(self._dos_header.e_lfanew + IMAGE_NT_HEADERS64.OptionalHeader.offset + IMAGE_OPTIONAL_HEADER64.ImageBase.offset)
                raw.write(base_addr.to_bytes(8, byteorder='little'))

            raw.seek(0)
            self._raw = raw.read()
            self._base_addr = base_addr


    def patch_import(self, dll_name: str, import_name: str|int, address: int) -> None:
        """Patch PE imports

        Args:
            dll_name: name of the imported dll
            import_name: name or ordinal of the imported function
            address: new function address for the import
        """
        raw = BytesIO(self._raw)

        for func_name, thunk_addr in self._imports_thunk[dll_name]:
            if func_name  == import_name:
                thunk: IMAGE_THUNK_DATA32 | IMAGE_THUNK_DATA64
                if self._x86:
                    thunk = self._fill_struct(IMAGE_THUNK_DATA32, thunk_addr)
                else:
                    thunk = self._fill_struct(IMAGE_THUNK_DATA64, thunk_addr)
                thunk.u1.Function = address
                raw.seek(thunk_addr)
                raw.write(thunk)
                break

        raw.seek(0)
        self._raw = raw.read()



class InvalidPEHeader(Exception):
    """Exception for PE parsing errors"""
    pass
