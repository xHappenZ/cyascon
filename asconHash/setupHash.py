from distutils.core import setup, Extension
from Cython.Build import cythonize
import numpy


package = Extension('asconHash', ['../ascon_buffering.c', '../ascon_permutations.c', 'asconHash.pyx'], include_dirs=[numpy.get_include()])
setup(ext_modules=cythonize([package]))
