#!/usr/bin/env python

from distutils.core      import setup
from distutils.extension import Extension

py_modules = ['_pysrp', '_ctsrp', 'srp']

ext_modules = [ Extension('_srp', ['_srp.c',], libraries = ['ssl',]), ]

setup(name         = 'srp',
	  version      = '1.0',
	  description  = 'Secure Remote Password Protocol',
	  author       = 'Tom Cocagne',
	  author_email = 'tom.cocagne@gmail.com',
      url          = 'http://code.google.com/p/pysrp/',
	  py_modules   = py_modules,
	  ext_modules  = ext_modules,
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: C',
        'Topic :: Security',
        ],)
