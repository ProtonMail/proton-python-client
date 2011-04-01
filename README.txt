
This package provides an implementation of the Secure Remote
Password protocol (SRP). SRP is a cryptographically
strong authentication protocol for password-based, mutual
authentication over an insecure network connection.

It consists of 3 modules: A pure Python implementation, A ctypes +
OpenSSL implementation, and a C extension module. The ctypes &
extension modules are approximately 10-20x faster than the pure Python
implementation and can take advantage of multiple CPUs. The extension
module will be used if available, otherwise the library will fall back
to the ctypes implementation followed by the pure Python
implementation.

Note: The test_srp.py script prints the performance timings for each
combination of hash algorithm and prime number size. This may be of
use in deciding which pair of parameters to use in the unlikely
event that the defaults are unacceptable.

Installation:
   python setup.py install
   
Validity & Performance Testing:
   python setup.py build
   python test_srp.py
   
Documentation:
   cd srp/doc
   sphinx-build -b html . <desired output directory>
   

** Note: The Sphinx documentation system is easy-installable:
   easy-install sphinx
