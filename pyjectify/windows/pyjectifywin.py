from pyjectify.windows.core.process import getpid, ProcessHandle
from pyjectify.windows.core.pe import PE

from pyjectify.windows.modules.memscan import MemScan
from pyjectify.windows.modules.inject import Inject
from pyjectify.windows.modules.pythonlib import PythonLib


def byName(process):
    return [PyJectifyWin(pid) for pid in getpid(process)]


class PyJectifyWin:
    def __init__(self, pid):
        self.process = ProcessHandle(pid)
        
        self.memscan = MemScan(self.process)
        self.inject = Inject(self.process)
        self.pythonlib = PythonLib(self.process)