#!/home/dnspy/node/dns/bin/python3
# distutils: language=3

from setuptools import setup
from Cython.Build import cythonize
import os
thisdir = os.path.dirname(os.path.abspath(__file__))
setup(
    ext_modules = cythonize(thisdir+"/cparser.pyx"),
)