from io import BytesIO

from pyjectify.windows.core.defines import *


class PE:
    """This class represents a PE and provides methods to parse it"""
    
    raw: bytes #: Raw bytes of the PE, mapped to memory
    base_addr: int #: Base address of the PE
    dos_header: IMAGE_DOS_HEADER #: DOS headers
    nt_header: IMAGE_NT_HEADERS32 #: NT headers
    x86: bool #: Specify if the PE is a 32-bit PE
    sections_header: list[IMAGE_SECTION_HEADER] #: PE sections headers
    sections: list #: PE sections, list of (VirtualAddress, VirtualSize, PageProtection) tuple
    exports: dict #: PE exports, dict of function_name -> function_address ; addresses are relative to the module base address
    imports: dict #: PE imports, dict of library_name -> [(function_name, function_address)...]
    
    def __init__(self, raw: bytes, base_addr: int = 0, headers_only: bool = False) -> None:
        self.raw = raw
        self.base_addr = base_addr
        self.sections_header = []
        self.sections = []
        self.exports = {}
        self.imports = {}
        
        self.dos_header = self._fill_struct(IMAGE_DOS_HEADER, 0)
        if bytes(WORD(self.dos_header.e_magic)) != b'MZ':
            raise InvalidPEHeader('Invalid MZ signature - %s' % (self.dos_header.e_magic))
        
        self.nt_header = self._fill_struct(IMAGE_NT_HEADERS32, self.dos_header.e_lfanew)
        if bytes(DWORD(self.nt_header.Signature)) != b'PE\x00\x00':
            raise InvalidPEHeader('Invalid PE signature - %s' % (self.nt_header.Signature))
        
        if self.nt_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            self.x86 = True
            self.nt_header = self._fill_struct(IMAGE_NT_HEADERS32, self.dos_header.e_lfanew)
            section_addr = self.dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS32)
        elif self.nt_header.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            self.x86 = False
            self.nt_header = self._fill_struct(IMAGE_NT_HEADERS64, self.dos_header.e_lfanew)
            section_addr = self.dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS64)
        else:
            raise InvalidPEHeader('Invalid Optional Magic Header - %s' % (self.nt_header.OptionalHeader.Magic))
        
        if not self.base_addr:
            self.base_addr = self.nt_header.OptionalHeader.ImageBase
        
        for i in range(self.nt_header.FileHeader.NumberOfSections):
            section_header = self._fill_struct(IMAGE_SECTION_HEADER, section_addr + i*ctypes.sizeof(IMAGE_SECTION_HEADER))
            self.sections_header.append(section_header)
            
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
            
            self.sections.append((section_header.VirtualAddress, section_header.Misc.VirtualSize, protect))
        
        if not headers_only:
            self._map_to_memory()
            self._parse_imports()
            self._parse_exports()
    
    
    def _fill_struct(self, struct: ctypes.Structure, addr: ctypes.Structure) -> ctypes.Structure:
        length = ctypes.sizeof(struct)
        buf = self._read_raw(addr, length)
        return struct.from_buffer_copy(buf)
    
    
    def _read_raw(self, addr: int, length: int) -> bytes:
        return self.raw[addr:addr + length]
    
    
    def _read_int(self, addr: int, length: int) -> int:
        return int.from_bytes(self.raw[addr:addr + length], byteorder='little')
    
    
    def _read_str(self, addr: int, length: int = 1024) -> str:
        data = self.raw[addr:addr+length]
        return data[:data.find(0)].decode()
    
    
    def _is_mapped(self) -> None:
        if self.x86:
            section_addr = self.dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS32)
        else:
            section_addr = self.dos_header.e_lfanew + ctypes.sizeof(IMAGE_NT_HEADERS64)
        
        virtual_end = section_addr + len(self.sections_header) * ctypes.sizeof(IMAGE_SECTION_HEADER)
        for section_header in self.sections_header:
            data = self.raw[virtual_end:section_header.VirtualAddress]
            if data != b'\x00'*len(data):
                break
            virtual_end = section_header.VirtualAddress + section_header.Misc.VirtualSize
        
        return data == b'\x00'*len(data)
    
    
    def _map_to_memory(self) -> None:
        if not self.sections_header:
            raise InvalidPEHeader('No sections found')
        
        if self._is_mapped():
            return
        
        size = self.nt_header.OptionalHeader.SizeOfImage
        raw = BytesIO(b'\x00'*size)
        
        raw.write(self._read_raw(0, self.nt_header.OptionalHeader.SizeOfHeaders))
        
        for section_header in self.sections_header:
            raw.seek(section_header.VirtualAddress)
            raw.write(self._read_raw(section_header.PointerToRawData, section_header.SizeOfRawData))
        
        raw.seek(0)
        self.raw = raw.read()
    
    
    def _parse_imports(self) -> None:
        data_directory = self.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        
        if not data_directory.VirtualAddress:
            return
        
        offset = 0
        import_dir = self._fill_struct(IMAGE_IMPORT_DESCRIPTOR, data_directory.VirtualAddress)
        
        while import_dir.Characteristics:
            dll_name = self._read_str(import_dir.Name)
            self.imports[dll_name] = []
            
            i = 0
            while True:
                if self.x86:
                    thunk_addr = import_dir.FirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA32)
                    othunk_addr = import_dir._u.OriginalFirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA32)
                    othunk = self._fill_struct(IMAGE_THUNK_DATA32, othunk_addr)
                else:
                    thunk_addr = import_dir.FirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA64)
                    othunk_addr = import_dir.OriginalFirstThunk + i*ctypes.sizeof(IMAGE_THUNK_DATA64)
                    othunk = self._fill_struct(IMAGE_THUNK_DATA64, othunk_addr)
                
                if not othunk.u1.AddressOfData:
                    break
                
                if self.x86 and IMAGE_SNAP_BY_ORDINAL32(othunk.u1.Ordinal):
                    self.imports[dll_name].append((IMAGE_ORDINAL32(othunk.u1.Ordinal), thunk_addr))
                    i += 1
                    continue
                elif not self.x86 and IMAGE_SNAP_BY_ORDINAL64(othunk.u1.Ordinal):
                    self.imports[dll_name].append((IMAGE_ORDINAL64(othunk.u1.Ordinal), thunk_addr))
                    i += 1
                    continue
                
                import_by_name = self._fill_struct(IMAGE_IMPORT_BY_NAME, othunk.u1.AddressOfData)
                self.imports[dll_name].append((import_by_name.Name.decode(), thunk_addr))
                
                i += 1
            
            offset += ctypes.sizeof(IMAGE_IMPORT_DESCRIPTOR)
            import_dir = self._fill_struct(IMAGE_IMPORT_DESCRIPTOR, data_directory.VirtualAddress + offset)
    
    
    def _parse_exports(self) -> None:
        data_directory = self.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        
        if not data_directory.VirtualAddress:
            return
        
        export_directory = self._fill_struct(IMAGE_EXPORT_DIRECTORY, data_directory.VirtualAddress)
        
        if export_directory.AddressOfFunctions:
            for i in range(export_directory.NumberOfFunctions):
                function_addr = self._read_int(export_directory.AddressOfFunctions + 4*i, 4)
                self.exports[i] = function_addr
            
            for i in range(export_directory.NumberOfNames):
                ord = self._read_int(export_directory.AddressOfNameOrdinals + 2*i, 2)
                function_addr = self.exports[ord]
                name_addr = self._read_int(export_directory.AddressOfNames + 4*i, 4)
                name = self._read_str(name_addr)
                self.exports[name] = function_addr
    
    
    def forwarded_export(self, name: str) -> str:
        """Resolve a forwarded export
        
        Args:
            name: the name of the forwarded export
        
        Returns:
            The name of the resolved forwarded export
        """
        addr = self.exports[name]
        
        begin_exports = self.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        end_exports = begin_exports + self.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size
        
        if begin_exports <= addr < end_exports:
            return self._read_str(addr)
    
    
    def change_base(self, base_addr: int) -> None:
        """Change PE base address and perform base relocation
        
        Args:
            base_addr: new base address of the PE
        """
        delta = base_addr - self.base_addr
        
        if delta:
            raw = BytesIO(self.raw)
            relocations = self.nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            
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
                            break
                        
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
            
            raw.seek(0)
            self.raw = raw.read()
            self.base_addr = base_addr
    
    
    def patch_import(self, thunk_addr: int, address: int) -> None:
        """Patch PE imports
        
        Args:
            thunk_addr: address of the thunk data of the import
            address: new function address for the import
        """
        raw = BytesIO(self.raw)
        
        if self.x86:
            thunk = self._fill_struct(IMAGE_THUNK_DATA32, thunk_addr)
        else:
            thunk = self._fill_struct(IMAGE_THUNK_DATA64, thunk_addr)
        
        thunk.u1.Function = address
        raw.seek(thunk_addr)
        raw.write(thunk)
        
        raw.seek(0)
        self.raw = raw.read()



class InvalidPEHeader(Exception):
    """Exception for PE parsing errors"""
    pass