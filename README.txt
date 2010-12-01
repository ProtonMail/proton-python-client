
This package provides a Python Implementation of the Secure Remote Password
Protocol. It consists of 3 modules: A pure Python implementation, A ctypes
+ OpenSSL implementation, and a C extension module. The ctypes/extension 
modules are approximately 10x faster than the pure Python implementation
and can take advantage of multiple CPUs. The ctypes/extension module will
be used if available, otherwise the library will fall back to the pure
Python implementation.


Installation:
   python setup.py install
   
   
Documentation:
   cd doc
   sphinx-build -b html . <desired output directory>
   
