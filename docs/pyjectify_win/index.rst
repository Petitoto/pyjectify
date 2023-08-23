:mod:`pyjectify.windows`
========================

This subpackage provides classes, functions and exceptions specific to Windows.

.. toctree::
   :caption: Contents:
   :maxdepth: 2
   
   core/index.rst
   modules/index.rst
   utils/index.rst

.. automodule:: pyjectify.windows
   :members:
   :exclude-members: defines, PE, ApiSetSchema, Syscall
   
   .. class:: pyjectify.windows.defines:
   
      Alias of :py:mod:`pyjectify.windows.core.defines`

   .. class:: PE
   
      Alias of :py:class:`pyjectify.windows.core.pe.PE`

   .. class:: ApiSetSchema
   
      Alias of :py:class:`pyjectify.windows.utils.apisetschema.ApiSetSchema`

   .. class:: Syscall
   
      Alias of :py:class:`pyjectify.windows.utils.syscall.Syscall`