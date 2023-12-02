import os

from pyjectify.windows.core.defines import *
from pyjectify.windows.core.pe import PE


class ApiSetSchema:
    """This class provide methods to parse and resolve Windows ApiSet"""
    
    entries: dict #: Dict of api name -> api name defined by Windows ApiSet
    
    def __init__(self) -> None:
        self._data = None
        self.entries = {}
        
        kernel32.Wow64DisableWow64FsRedirection(LPVOID())
        apisetschema_path = os.path.join(os.environ['WINDIR'], os.path.join('System32', 'apisetschema.dll'))
        apisetschema = PE(open(apisetschema_path, 'rb').read())
        kernel32.Wow64RevertWow64FsRedirection(LPVOID())
        
        for section in apisetschema.sections_header:
            if bytes(section.Name).strip(b'\x00') == b'.apiset':
                self._data = apisetschema.raw[section.VirtualAddress:section.VirtualAddress+section.Misc.VirtualSize]
                break
        
        if not self._data:
            raise InvalidApiSetSchema('ApiSet section not found')
        
        version = self._read_int(0, 1)
        if version == 2:
            self._apiset2()
        elif version == 4:
            self._apiset4()
        elif version == 6:
            self._apiset6()
        else:
            raise InvalidApiSetSchema('Invalid ApiSetSchema version - %s' % (version))
    
    
    def _apiset2(self) -> None:
        header = self._fill_struct(StructApiSetNamespaceV2, 0)
        
        for i in range(header.Count):
            entry_header = self._fill_struct(StructApiSetNamespaceEntryV2, ctypes.sizeof(StructApiSetNamespaceV2) + i * ctypes.sizeof(StructApiSetNamespaceEntryV2))
            entry_name = self._read_str(entry_header.NameOffset, entry_header.NameLength)
            
            entry_value_header = self._fill_struct(StructApiSetValueEntryV2, entry_header.DataOffset)
            
            entry_values = []
            for j in range(entry_value_header.NumberOfRedirections):
                redirection_header = self._fill_struct(StructApiSetValueEntryRedirectionV2, entry_header.DataOffset + ctypes.sizeof(StructApiSetValueEntryV2) + j * ctypes.sizeof(StructApiSetValueEntryRedirectionV2))
                value = self._read_str(redirection_header.ValueOffset, redirection_header.ValueLength).replace('\x00', '')
                entry_values.append(value)
            
            entry_name = entry_name[:entry_name.rfind('-')].replace('\x00', '')
            self.entries[entry_name] = entry_values
    
    
    def _apiset4(self) -> None:
        header = self._fill_struct(StructApiSetNamespaceV4, 0)
        
        for i in range(header.Count):
            entry_header = self._fill_struct(StructApiSetNamespaceEntryV4, ctypes.sizeof(StructApiSetNamespaceV4) + i * ctypes.sizeof(StructApiSetNamespaceEntryV4))
            entry_name = self._read_str(entry_header.NameOffset, entry_header.NameLength)
            
            entry_value_header = self._fill_struct(StructApiSetValueEntryV4, entry_header.DataOffset)
            
            entry_values = []
            for j in range(entry_value_header.NumberOfRedirections):
                redirection_header = self._fill_struct(StructApiSetValueEntryRedirectionV4, entry_header.DataOffset + ctypes.sizeof(StructApiSetValueEntryV4) + j * ctypes.sizeof(StructApiSetValueEntryRedirectionV4))
                value = self._read_str(redirection_header.ValueOffset, redirection_header.ValueLength).replace('\x00', '')
                entry_values.append(value)
            
            entry_name = entry_name[:entry_name.rfind('-')].replace('\x00', '')
            self.entries[entry_name] = entry_values
    
    
    def _apiset6(self) -> None:
        header = self._fill_struct(StructApiSetNamespaceV6, 0)
        
        for i in range(header.Count):
            entry_header = self._fill_struct(StructApiSetNamespaceEntryV6, header.EntryOffset + i * ctypes.sizeof(StructApiSetNamespaceEntryV6))
            entry_name = self._read_str(entry_header.NameOffset, entry_header.NameLength)
            
            entry_values = []
            for j in range(entry_header.ValueCount):
                redirection_header = self._fill_struct(StructApiSetValueEntryV6, entry_header.ValueOffset + j * ctypes.sizeof(StructApiSetValueEntryRedirectionV4))
                value = self._read_str(redirection_header.ValueOffset, redirection_header.ValueLength).replace('\x00', '')
                entry_values.append(value)
            
            entry_name = entry_name[:entry_name.rfind('-')].replace('\x00', '')
            self.entries[entry_name] = entry_values
    
    
    def _fill_struct(self, struct: ctypes.Structure, addr: int) -> ctypes.Structure:
        length = ctypes.sizeof(struct)
        buf = self._read_raw(addr, length)
        return struct.from_buffer_copy(buf)
    
    
    def _read_raw(self, addr: int, length: int) -> bytes:
        return self._data[addr:addr + length]
    
    
    def _read_int(self, addr: int, length: int) -> int:
        return int.from_bytes(self._data[addr:addr + length], byteorder='little')
    
    
    def _read_str(self, addr: int, length: int = 1024) -> str:
        data = self._data[addr:addr+length]
        return data[:data.find(b'\x00\x00')].decode().strip('\x00')
    
    
    def resolve(self, name: str) -> str:
        """Resolve a Windows ApiSet
        
        Args:
            name: name of the Windows ApiSet
        
        Returns:
            The resolved name of the Windows ApiSet
        """
        cutname = name[:name.rfind('-')]
        if cutname in self.entries:
            return self.entries[cutname][-1]
        else:
            return name



class InvalidApiSetSchema(Exception):
    """Exception for ApiSet parsing errors"""
    pass