from distutils.core import setup, Extension
from Cython.Build import cythonize
import numpy


package = Extension('asconAead', ['../ascon_buffering.c', 'ascon_aead80pq.c', 'ascon_aead128.c', 'ascon_aead128a.c', '../ascon_permutations.c', 'asconAead.pyx'], include_dirs=[numpy.get_include()])
setup(ext_modules=cythonize([package]))