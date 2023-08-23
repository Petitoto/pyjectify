from pyjectify.windows.core.defines import *
from pyjectify.windows.core.process import ProcessHandle
from pyjectify.windows.core.pe import PE

_py_prepare_hook = '''
import ctypes, inspect
func_name = bytes.fromhex('{func}').decode('utf8')
addr = ctypes.cast({ret_addr}, ctypes.POINTER(ctypes.c_ulonglong))
if func_name in globals():
    func = globals()[func_name]
    args = inspect.getfullargspec(func).annotations.values()
    if not args:
        args = [ctypes.c_void_p]
    if {ofunc}:
        globals()['o_'+func_name] = ctypes.WINFUNCTYPE(*args)({ofunc})
    addr.contents.value = ctypes.cast(ctypes.WINFUNCTYPE(*args)(func), ctypes.c_void_p).value
'''


class PythonLib:
    """This class provides methods to run Python inside a target process"""
    
    python_mod: int #: Handle to the Python library loaded in the target process
    
    def __init__(self, process: ProcessHandle, python_mod: PE | None = None) -> None:
        self._process = process
        self.python_mod = python_mod
    
    
    def setprogramname(self, programname: str) -> None:
        """Set the value of the argv[0] argument to the main() function
        
        Args:
            programname: the new programname
        """
        programname = bytes(programname, encoding='utf-16le')
        addr = self._process.allocate(len(programname))
        self._process.write(addr, programname)
        
        py_setprogramname = self.python_mod.base_addr + self.python_mod.exports['Py_SetProgramName']
        
        thread = self._process.start_thread(py_setprogramname, addr)
        self._process.join_thread(thread)
        
        self._process.free(addr)
    
    
    def setpath(self, pythonpath: str) -> None:
        """Set the default module search path
        
        Args:
            pythonpath: the PYTHON_PATH value
        """
        pythonpath = bytes(pythonpath, encoding='utf-16le')
        addr = self._process.allocate(len(pythonpath))
        self._process.write(addr, pythonpath)
        
        py_setpath = self.python_mod.base_addr + self.python_mod.exports['Py_SetPath']
        
        thread = self._process.start_thread(py_setpath, addr)
        self._process.join_thread(thread)
        
        self._process.free(addr)
    
    
    def setpythonhome(self, pythonhome: str) -> None:
        """Set the default "home" directory
        
        Args:
            pythonhome: the PYTHON_HOME value
        """
        pythonhome = bytes(pythonhome, encoding='utf-16le')
        addr = self._process.allocate(len(pythonhome))
        self._process.write(addr, pythonhome)
        
        py_setpythonhome = self.python_mod.base_addr + self.python_mod.exports['Py_SetPythonHome']
        
        thread = self._process.start_thread(py_setpythonhome, addr)
        self._process.join_thread(thread)
        
        self._process.free(addr)
    
    
    def isinitialized(self) -> bool:
        """Check if the Python interpreter is initialized in the target process
        
        Returns:
            A boolean specifying if the Python interpreter is initialized
        """
        py_isinitialized = self.python_mod.base_addr + self.python_mod.exports['Py_IsInitialized']
        
        thread = self._process.start_thread(py_isinitialized)
        ret = self._process.join_thread(thread)
        
        return bool(ret)
    
    
    def initialize(self, initsigs: int = 0) -> None:
        """Initialize the Python interpreter in the target process
        
        Args:
            initsigs: initsigs for Py_InitializeEx
        """
        py_initialize_ex = self.python_mod.base_addr + self.python_mod.exports['Py_InitializeEx']
        
        thread = self._process.start_thread(py_initialize_ex, initsigs)
        self._process.join_thread(thread)
    
    
    def exec(self, py_code: str) -> None:
        """Execute python code in the target process. Python interpreter MUST be initialized.
        
        Args:
            py_code: the python code to run
        """
        py_run_simple_string = self.python_mod.base_addr + self.python_mod.exports['PyRun_SimpleString']
        
        addr = self._process.allocate(len(py_code))
        self._process.write(addr, py_code)
        
        thread = self._process.start_thread(py_run_simple_string, addr)
        self._process.join_thread(thread)
    
    
    def finalize(self) -> None:
        """Undo all initializations of the Python interpreter in the target process"""
        py_finalize_ex = self.python_mod.base_addr + self.python_mod.exports['Py_FinalizeEx']
        
        thread = self._process.start_thread(py_finalize_ex)
        self._process.join_thread(thread)
    
    
    def prepare_hook(self, func: str, ofunc_addr: int = 0) -> int:
        """Utility for using a python function as a hook.
         
        This method returns the address of the function and optionally creates the global function o_{func} which points to the original function.
        
        Args:
            func: the name of the Python function to get the address
            ofunc_addr: address of the original function
        
        Returns:
            The address of the Python function. If the method succeeds, this address is nonzero.
        """
        encoded_func = bytes(func, 'utf8').hex()
        ret_addr = self._process.allocate(8)
        
        py_code = _py_prepare_hook.format(func=encoded_func, ofunc=ofunc_addr, ret_addr=ret_addr)
        self.exec(py_code)
        
        addr = self._process.read(ret_addr, 8)
        return int.from_bytes(addr, 'little')