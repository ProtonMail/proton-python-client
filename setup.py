#!/usr/bin/env python

from distutils.core      import setup
from distutils.extension import Extension

py_modules = ['_pysrp', '_ctsrp', 'srp']

ext_modules = [ Extension('_srp', ['_srp.c',], libraries = ['ssl',]), ]

setup(name         = 'srp',
	  version      = '0.9',
	  description  = 'Secure Remote Password Protocol',
	  author       = 'Tom Cocagne',
	  author_email = 'tom.cocagne@gmail.com',
	  py_modules   = py_modules,
	  ext_modules  = ext_modules)