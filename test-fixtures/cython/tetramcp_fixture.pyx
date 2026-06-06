# cython: language_level=3
"""TetraMCP Cython recovery fixture.

Module name: tetramcp_fixture  (export PyInit_tetramcp_fixture)
This docstring is the PyModuleDef m_doc and should be recovered by
cython_parse_moduledef. Every public name below is deliberately distinctive
(MAGIC_*, tetramcp_marker_*) so recovered symbols are unambiguous when grepping
the analyzed .so.

Line numbers of each `def`/`class` are the expected PyCode firstlineno; keep
them stable (see BUILD.md checklist).
"""

# --- Module-level constants (cython_decode_constants / interned strings) ---
MAGIC_INT = 0x1337BEEF                  # 322420463 -> __pyx_int_322420463
SMALL_INT = 42
NEG_INT = -7
MAGIC_STR = "tetramcp_marker_alpha"     # unicode const / interned name
MAGIC_BYTES = b"tetramcp_bytes_marker"
MAGIC_TUPLE = (1, 2, 3, "four")
MAGIC_FLOAT = 3.14159


# --- Module-level functions (CyFunction_New qualnames + code objects) ---

def func_simple(a, b):
    """func_simple docstring."""
    return a + b


def func_posonly(a, b, /, c, d):        # posonlyargcount = 2
    return a * b + c - d


def func_kwonly(a, *, key1, key2=10):   # kwonlyargcount = 2
    return a + key1 + key2


def func_varargs(first, *args, **kwargs):   # CO_VARARGS | CO_VARKEYWORDS
    return first, args, kwargs


def func_defaults(x, y=5, z="zed"):
    return x, y, z


def func_annotated(n: int, label: str = "lbl") -> str:
    return label + ":" + str(n)


def func_with_closure(base):
    offset = 100                        # cellvar captured by inner
    def inner(v):                       # qualname func_with_closure.<locals>.inner
        return v + base + offset
    return inner


def gen_function(n):                    # CO_GENERATOR
    for i in range(n):
        yield i * i


async def async_function(x):            # CO_COROUTINE
    return x + 1


# --- Pure-Python class (qualnames Class.method) ---

class PlainClass:
    """PlainClass docstring."""
    CLASS_CONST = "plainclass_const"

    def method_one(self, arg):          # qualname PlainClass.method_one
        return arg * 2

    def method_two(self, a, b=3):
        return a - b

    @staticmethod
    def static_method(z):               # qualname PlainClass.static_method
        return z + 1000

    @classmethod
    def class_method(cls, w):           # qualname PlainClass.class_method
        return w


# --- cdef extension type (PyTypeObject recovery: tp_name, tp_methods, tp_doc) ---

cdef class ExtClass:
    """ExtClass extension type docstring."""
    cdef public int counter
    cdef double scale

    def __init__(self, int start, double scale):
        self.counter = start
        self.scale = scale

    cpdef double scaled(self, double v):    # appears in tp_methods
        return v * self.scale + self.counter

    def increment(self, int by=1):
        self.counter += by
        return self.counter
