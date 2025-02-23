import re

from pyjectify.windows.core.defines import *
from pyjectify.windows.core.process import ProcessHandle


class MemScan:
    """This class provides methods to find a pattern inside a remote process memory."""

    def __init__(self, process: ProcessHandle) -> None:
        """Initialization: bind the module to a specific process

        Args:
            process: ProcessHandle targeted by the module
        """
        self._process = process
        self._addrs = []


    @property
    def addrs(self) -> list[int]:
        """Addresses to scan, matching with the previous search. If empty, scan all addresses."""
        return self._addrs


    @addrs.setter
    def addrs(self, addrs: list[int]) -> None:
        self._addrs = addrs


    def reset(self) -> None:
        """Reset found memory addresses (clear the 'addrs' attribute)"""
        self._addrs = []


    def scan(self, pattern: bytes) -> list[int]:
        """Search a pattern in the whole memory of the target process or among previously found memory addresses

        Set the 'addrs' attribute to the matching addresses

        Args:
            pattern: regex pattern
        Returns:
            The addresses with bytes matching with the pattern
        """
        def gen_meminfo():
            if self._addrs:
                for addr in self._addrs:
                    yield self._process.query(addr)

            else:
                sysinfo = SYSTEM_INFO()
                kernel32.GetNativeSystemInfo(sysinfo)
                lastpage = sysinfo.lpMaximumApplicationAddress

                offset = 0
                while offset < lastpage:
                    mem_info = self._process.query(offset)
                    offset = mem_info.RegionSize
                    if mem_info.BaseAddress:
                        offset += mem_info.BaseAddress
                    yield mem_info

        scanned_addr: list[int] = []
        for mem_info in gen_meminfo():
            if mem_info.State == MEM_COMMIT and not mem_info.Protect == PAGE_NOACCESS and not mem_info.Protect & PAGE_GUARD:
                raw = self._process.read(mem_info.BaseAddress, mem_info.RegionSize)
                for match in re.finditer(pattern, raw):
                    scanned_addr.append(mem_info.BaseAddress + match.span()[0])

        self._addrs = scanned_addr
        return scanned_addr[:]
