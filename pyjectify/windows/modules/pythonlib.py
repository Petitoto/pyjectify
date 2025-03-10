from pyjectify.windows.core.defines import *
from pyjectify.windows.core.pe import PE
from pyjectify.windows.core.process import ProcessHandle

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
    """This class provides methods to run Python inside a target process."""

    def __init__(self, process: ProcessHandle, python_mod: PE | None = None) -> None:
        """Initialization: bind the module to a specific process

        Args:
            process: ProcessHandle targeted by the module
            python_mod: handle to the Python library loaded in the target process (optional, can be set later)
        """
        self._process = process
        self._tstate = 0
        if python_mod:
            self._python_mod = python_mod


    @property
    def python_mod(self) -> PE:
        """Handle to the Python library loaded in the target process"""
        return self._python_mod


    @python_mod.setter
    def python_mod(self, python_mod: PE) -> None:
        self._python_mod = python_mod


    def set_program_name(self, name: str) -> None:
        """Set the value of the argv[0] argument to the main() function

        Args:
            name: the new program name
        """
        programname = b'\x00'
        if name:
            programname = bytes(name, encoding='utf-16le')

        addr = self._process.allocate(len(programname))
        self._process.write(addr, programname)

        py_setprogramname = self._python_mod.base_addr + self._python_mod.exports['Py_SetProgramName']

        thread = self._process.start_thread(py_setprogramname, addr)
        self._process.join_thread(thread)

        self._process.free(addr)


    def set_path(self, path: str) -> None:
        """Set the default module search path

        Args:
            path: the PYTHON_PATH value
        """
        pythonpath = b'\x00'
        if path:
            pythonpath = bytes(path, encoding='utf-16le')

        addr = self._process.allocate(len(pythonpath))
        self._process.write(addr, pythonpath)

        py_setpath = self._python_mod.base_addr + self._python_mod.exports['Py_SetPath']

        thread = self._process.start_thread(py_setpath, addr)
        self._process.join_thread(thread)

        self._process.free(addr)


    def set_python_home(self, home: str) -> None:
        """Set the default "home" directory

        This method calls Py_SetPythonHome

        Args:
            home: the PYTHON_HOME value
        """
        pythonhome = b'\x00'
        if home:
            pythonhome = bytes(home, encoding='utf-16le')

        addr = self._process.allocate(len(pythonhome))
        self._process.write(addr, pythonhome)

        py_setpythonhome = self._python_mod.base_addr + self._python_mod.exports['Py_SetPythonHome']

        thread = self._process.start_thread(py_setpythonhome, addr)
        self._process.join_thread(thread)

        self._process.free(addr)


    def is_initialized(self) -> bool:
        """Check if the Python interpreter is initialized in the target process

        This method calls Py_IsInitialized

        Returns:
            A boolean specifying if the Python interpreter is initialized
        """
        py_isinitialized = self._python_mod.base_addr + self._python_mod.exports['Py_IsInitialized']

        thread = self._process.start_thread(py_isinitialized)
        ret = self._process.join_thread(thread)

        return bool(ret)


    def initialize(self, initsigs: int = 0) -> None:
        """Initialize the Python interpreter in the target process and release the GIL

        This method calls Py_IsInitialized + Py_InitializeEx + PyEval_SaveThread

        Args:
            initsigs: initsigs for Py_InitializeEx
        """
        if not self.is_initialized():
            py_initialize_ex = self._python_mod.base_addr + self._python_mod.exports['Py_InitializeEx']
            py_eval_save_thread = self._python_mod.base_addr + self._python_mod.exports['PyEval_SaveThread']

            ret = self._process.run_funcs([(py_initialize_ex, initsigs), (py_eval_save_thread, 0)])
            self._tstate = ret[1]


    def exec(self, py_code: str) -> None:
        """Run Python code in the target process (acquire and then release the GIL)

        The Python interpreter must have been initialized by PyJectify before calling this method

        This method calls PyEval_RestoreThread + PyRun_SimpleString + PyEval_SaveThread

        Args:
            py_code: the python code to run
        """
        if not py_code:
            return

        py_eval_restore_thread = self._python_mod.base_addr + self._python_mod.exports['PyEval_RestoreThread']
        py_run_simple_string = self._python_mod.base_addr + self._python_mod.exports['PyRun_SimpleString']
        py_eval_save_thread = self._python_mod.base_addr + self._python_mod.exports['PyEval_SaveThread']

        pycode_addr = self._process.allocate(len(py_code))
        self._process.write(pycode_addr, py_code)

        ret = self._process.run_funcs([(py_eval_restore_thread, self._tstate), (py_run_simple_string, pycode_addr), (py_eval_save_thread, 0)])
        self._tstate = ret[2]
        return


    def finalize(self) -> None:
        """Undo all initializations of the Python interpreter in the target process

        The Python interpreter must have been initialized by PyJectify before calling this method

        This method calls PyEval_RestoreThread + Py_FinalizeEx
        """
        py_eval_restore_thread = self._python_mod.base_addr + self._python_mod.exports['PyEval_RestoreThread']
        py_finalize_ex = self._python_mod.base_addr + self._python_mod.exports['Py_FinalizeEx']

        self._process.run_funcs([(py_eval_restore_thread, self._tstate), (py_finalize_ex, 0)])
        self._tstate = 0


    def prepare_hook(self, func: str, ofunc_addr: int = 0) -> int:
        """Utility for using a Python function as a hook

        This method returns the address of the function and optionally creates the global function o_{func} which points to the original function

        The Python interpreter must have been initialized by PyJectify before calling this method

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
        self._process.free(ret_addr)

        return int.from_bytes(addr, 'little')
