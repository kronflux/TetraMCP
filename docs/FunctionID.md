# FunctionID in TetraMCP

FunctionID identifies statically-linked library functions in stripped binaries by
hashing function bodies and matching against a `.fidb` database. This is high value
for the Cython/C use case: compiled Cython modules statically link libc, the CPython
runtime, and often OpenSSL/libsodium.

## Using it

- `fid_list_databases` — list `.fidb` databases Ghidra knows about.
- `fid_attach_database` (path) — attach a `.fidb` file.
- `fid_identify` (apply=false|true) — match the open program; optionally rename hits.

TetraMCP does not ship `.fidb` binaries (they are generated from reference libraries).
Obtain them one of two ways:

### 1. Prebuilt databases
Drop `.fidb` files into `<ghidra>/Ghidra/Features/FunctionID/data/` (Ghidra auto-loads
them) or attach at runtime with `fid_attach_database`. A community set covering
libc/gcc/openssl/libsodium/qt5/SDL across many architectures is published by the
threatrack `ghidra-fidb-repo` project.

### 2. Generate a custom database
Use the `ghidra-fid-generator` workflow (or Ghidra's `Tools -> Function ID -> Create
new empty FidDb` + `Populate FidDb from programs`) against reference binaries — e.g. a
known `libpython3.x.a` / `python3.x` build — to fingerprint the exact CPython runtime
in your target, then `fid_attach_database` the result and run `fid_identify`.
