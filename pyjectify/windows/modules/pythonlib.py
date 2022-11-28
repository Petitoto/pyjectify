from pyjectify.windows.core.defines import *


class PythonLib:
    def __init__(self, process, python_mod=None):
        self._process = process
        self.python_mod = python_mod
    
    
    def setprogramname(self, programname):
        programname = bytes(programname, encoding='utf-16le')
        addr = self._process.allocate(len(programname))
        self._process.write(addr, programname)
        
        py_setprogramname = self.python_mod.base_addr + self.python_mod.exports['Py_SetProgramName']
        
        thread = self._process.start_thread(py_setprogramname, addr)
        self._process.join_thread(thread)
        
        self._process.free(addr)
    
    
    def setpath(self, pythonpath):
        pythonpath = bytes(pythonpath, encoding='utf-16le')
        addr = self._process.allocate(len(pythonpath))
        self._process.write(addr, pythonpath)
        
        py_setpath = self.python_mod.base_addr + self.python_mod.exports['Py_SetPath']
        
        thread = self._process.start_thread(py_setpath, addr)
        self._process.join_thread(thread)
        
        self._process.free(addr)
    
    
    def setpythonhome(self, pythonhome):
        pythonhome = bytes(pythonhome, encoding='utf-16le')
        addr = self._process.allocate(len(pythonhome))
        self._process.write(addr, pythonhome)
        
        py_setpythonhome = self.python_mod.base_addr + self.python_mod.exports['Py_SetPythonHome']
        
        thread = self._process.start_thread(py_setpythonhome, addr)
        self._process.join_thread(thread)
        
        self._process.free(addr)
    
    
    def isinitialized(self):
        py_isinitialized = self.python_mod.base_addr + self.python_mod.exports['Py_IsInitialized']
        
        thread = self._process.start_thread(py_isinitialized)
        ret = self._process.join_thread(thread)
        
        return bool(ret)
    
    
    def initialize(self, initsigs=0):
        py_initialize_ex = self.python_mod.base_addr + self.python_mod.exports['Py_InitializeEx']
        
        thread = self._process.start_thread(py_initialize_ex, initsigs)
        self._process.join_thread(thread)
    
    
    def run_simplestring(self, py_code):
        py_run_simple_string = self.python_mod.base_addr + self.python_mod.exports['PyRun_SimpleString']
        
        addr = self._process.allocate(len(py_code))
        self._process.write(addr, py_code)
        
        thread = self._process.start_thread(py_run_simple_string, addr)
        self._process.join_thread(thread)
    
    
    def finalize(self):
        py_finalize_ex = self.python_mod.base_addr + self.python_mod.exports['Py_FinalizeEx']
        
        thread = self._process.start_thread(py_finalize_ex)
        self._process.join_thread(thread)