# 3ds_ida

(WIP) IDA Pro 7.6+ resources for reverse engineering Nintendo 3DS userland code.

## Setup

[Python 3.4+](https://www.python.org/) is required.

### Loader

Copy `ctru_loader.py` in `{IDA_PATH}/loaders`. The loader supports the following formats:

- Raw: the binary must be named `code.bin`. An external exheader binary is required, else the user will be asked to provide any information.
- ExeFS: the binary name must end with the `exefs` extension and must contain a `.code` file. An external exheader binary is required, else the user will be asked to provide any information.
- CXI: the binary must be decrypted and it must contain an ExeFS with a `.code` file.
- ~~CIA~~.
- ~~CRO~~.

### Types

`File -> Load file -> Parse C header file...`, then select `types.h`.

### Plugins

Capstone is required:

```
python -m pip install capstone==4.0.2
```

Launch each script with `File -> Script file`.

- `find_syscalls.py`: find each function that uses syscalls, optionally renaming wrappers and functions that call `svcSendSyncRequest`.
- `fix_decomp.py`: fix syscalls and TLS access decompilation. Types must be loaded.
- ~~`load_crs_syms.py`: load symbols from CRS files.~~