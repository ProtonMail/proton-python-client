#!/usr/bin/env python

from distutils.core      import setup
from distutils.extension import Extension


long_description = '''

This package, originally forked from python-srp module implements a simple
wrapper to the Proton Technologies API, abstracting from the SRP authentication.
'''

setup(name             = 'proton-client',
      version          = '0.0.2',
      description      = 'Proton Technologies API wrapper',
      author           = 'Proton Technologies',
      author_email     = 'contact@protonmail.com',
      url              = 'https://github.com/ProtonMail/proton-python-client',
      long_description = long_description,
      install_requires = ['six'],
      packages         = ['proton'],
      package_data     = {'proton' : ['doc/*.rst', 'doc/*.py']},
      license          = "MIT",
      platforms        = "OS Independent",
      classifiers      = [
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python',
        'Topic :: Security',
        ],)
