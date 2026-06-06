"""Build the TetraMCP Cython recovery fixture.

Usage:
    python3 setup.py build_ext --inplace

Produces tetramcp_fixture.<abi>.so next to the .pyx (e.g.
tetramcp_fixture.cpython-312-x86_64-linux-gnu.so).

Requirements: a CPython 3.10-3.13 interpreter, Cython (pip install cython),
and a C compiler (gcc/clang). Build with a standard (non-debug, non
Py_TRACE_REFS) interpreter on x86-64 so the recovered struct offsets match
TetraMCP's PyLayouts.
"""
from setuptools import setup
from Cython.Build import cythonize

setup(
    name="tetramcp_fixture",
    ext_modules=cythonize(
        "tetramcp_fixture.pyx",
        language_level="3",
        annotate=False,
    ),
)
