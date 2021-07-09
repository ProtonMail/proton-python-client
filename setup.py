#!/usr/bin/env python

from setuptools import setup, find_packages
from proton.constants import VERSION

setup(
    name="proton-client",
    version=VERSION,
    description="Proton Technologies API wrapper",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/proton-python-client",
    install_requires=["requests", "bcrypt", "python-gnupg", "pyopenssl"],
    packages=find_packages(),
    include_package_data=True,
    license="GPLv3",
    platforms="OS Independent",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
