"""Gate plugins. One file per gate, each registering itself on import.

Dropping a new module in this package is the whole procedure for adding a gate: the kernel
(``warrnt/proxy.py``) discovers this package with ``pkgutil`` and never names a gate itself.
"""
