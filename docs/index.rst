PyJectify documentation
=======================

A Python library for memory manipulation, code injection and function hooking.

Install
-------

PyJectify requires Python >= 3.10.

* `GitHub homepage`_
* `PyPI homepage`_

Run
---

Importing ``pyjectify`` imports the submodule corresponding to your operating system.

* Windows:
    * ``import pyjectify`` gives direct access to :mod:`pyjectify.windows` classes and methods

Other operating systems are not supported for now.

.. automodule:: pyjectify
   :members: system

 
.. toctree::
   :caption: Contents:
   :maxdepth: 1
   
   examples.rst
   pyjectify_win/index.rst

.. _GitHub homepage: https://github.com/Petitoto/pyjectify
.. _PyPI homepage: https://pypi.org/project/pyjectify/