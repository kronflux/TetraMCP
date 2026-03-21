# Cython Fixture — Build & Verification

Ground-truth module (`tetramcp_fixture.pyx`) for validating TetraMCP's Cython
recovery tools against a binary whose source is fully known.

## Build

Prerequisites: CPython 3.10-3.13 (standard non-debug, x86-64), `pip install cython`, a C compiler.

```bash
cd test-fixtures/cython
python3 setup.py build_ext --inplace        # -> tetramcp_fixture.<abi>.so
cython -3 tetramcp_fixture.pyx               # -> tetramcp_fixture.c (inspect generated symbols)
cp tetramcp_fixture.*.so tetramcp_fixture.stripped.so
strip --strip-all tetramcp_fixture.stripped.so   # stripped target = realistic RE case
```

Build with both a 3.10 interpreter and a 3.12/3.13 interpreter to exercise the
two `PyCode_NewWithPosOnlyArgs` layouts (16 args vs 18). The `.so` ABI tag
records the CPython version (e.g. `cpython-310`, `cpython-312`).

Analyze in Ghidra (GUI or `analyzeHeadless`), then run the tools below against
the loaded program.

## Per-tool expected values

| Tool | Expected |
|---|---|
| `cython_detect` | export `PyInit_tetramcp_fixture`; CPython version matching the build (`.so` ABI tag) |
| `cython_find_init` | module name `tetramcp_fixture`; a resolved `__pyx_moduledef` address |
| `cython_parse_moduledef` | `m_name` = `tetramcp_fixture`; `m_doc` = the module docstring; `Py_mod_exec` resolves to a real function; `m_methods` table present |
| `cython_map_cyfunctions` | qualnames: `func_simple`, `func_posonly`, `func_kwonly`, `func_varargs`, `func_defaults`, `func_annotated`, `func_with_closure`, `func_with_closure.<locals>.inner`, `gen_function`, `async_function`, `PlainClass.method_one`, `PlainClass.method_two`, `PlainClass.static_method`, `PlainClass.class_method`, `ExtClass.__init__`, `ExtClass.scaled`, `ExtClass.increment` |
| `cython_recover_codeobjects` | `co_filename` = `tetramcp_fixture.pyx`; `co_name` matches each function; `firstlineno` = the `def` line in the `.pyx`; `func_posonly` posonlyargcount=2; `func_kwonly` kwonlyargcount=2; `func_varargs` has CO_VARARGS+CO_VARKEYWORDS; `gen_function` CO_GENERATOR; `async_function` CO_COROUTINE |
| `cython_decode_pytypeobject` (on the `ExtClass` type address) | `tp_name` = `tetramcp_fixture.ExtClass`; `tp_doc` = ExtClass docstring; `tp_methods` includes `scaled`, `increment` |
| `cython_recover_strtab` (B2) | interned names including `MAGIC_STR`/`tetramcp_marker_alpha`, function/qualname strings, class names |
| `cython_decode_constants` (B2) | `MAGIC_INT` = 322420463 (0x1337BEEF); `SMALL_INT` = 42; `NEG_INT` = -7; `MAGIC_STR` = `tetramcp_marker_alpha`; `MAGIC_BYTES` = `tetramcp_bytes_marker`; `MAGIC_TUPLE` = (1,2,3,"four") |
| `cython_dump_module_dict` (B2) | module namespace mapping each public name above to its value |

## Notes

- The `.c` from `cython -3` shows the exact generated symbol names
  (`__pyx_pw_*`, `__pyx_pf_*`, `__pyx_mdef_*`, `__pyx_moduledef`,
  `__pyx_n_s_*`, `__pyx_codeobj_*`), which are the ground truth for what the
  tools reconstruct from the stripped `.so`.
- Recovered struct offsets assume a non-debug build. A `Py_TRACE_REFS` build
  shifts every PyObject header by 16 bytes and will not match `PyLayouts`.
- For B2 generalization, keep `.so` files from multiple CPython versions and,
  if possible, multiple Cython releases, since the `__Pyx_StringTabEntry` stride
  and init-function codegen vary by Cython version.
