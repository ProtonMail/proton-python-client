#!/usr/bin/env python

from distutils.core      import setup
from distutils.extension import Extension


long_description = '''

This package provides an implementation of the Secure Remote Password
protocol (SRP). SRP is a cryptographically strong authentication
protocol for password-based, mutual authentication over an insecure
network connection.

Unlike other common challenge-response autentication protocols, such
as Kereros and SSL, SRP does not rely on an external infrastructure
of trusted key servers or certificate management. Instead, SRP server
applications use verification keys derived from each user's password
to determine the authenticity of a network connection.

SRP provides mutual-authentication in that successful authentication
requires that both sides of the connection must have knowledge of the
user's password. If the client side lacks the user's password or the
server side lacks the proper verification key, the authentication will
fail.

Unlike SSL, SRP does not directly encrypt all data flowing through
the authenticated connection. However, successful authentication does
result in a cryptographically strong shared key that can be used
for symmetric-key encryption.

For a full description of the pysrp package and the SRP protocol,
please refer to the `srp module documentation`_.

.. _`srp module documentation`: http://packages.python.org/pysrp

'''

ext_modules = [ Extension('srp._srp', ['srp/_srp.c',], libraries = ['ssl',]), ]

setup(name             = 'srp',
      version          = '1.0',
      description      = 'Secure Remote Password',
      author           = 'Tom Cocagne',
      author_email     = 'tom.cocagne@gmail.com',
      url              = 'http://code.google.com/p/pysrp/',
      download_url     = 'http://pypi.python.org/pypi/pysrp',
      long_description = long_description,
      packages         = ['srp'],
      package_data     = {'srp' : ['doc/*.rst', 'doc/*.py']},
      ext_modules      = ext_modules,
      license          = "New BSD",
      platforms        = "OS Independent",
      classifiers      = [
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: C',
        'Topic :: Security',
        ],)
