# 3ds_ida

(WIP) IDA Pro 7.6+ resources for reverse engineering Nintendo 3DS binaries.

## Setup

[Python 3.6+](https://www.python.org/) is required.

### Loader

Copy `ctr_loader.py` in `{IDA_PATH}/loaders`.

`ctr_loader.py` support the following formats:

- Raw: the binary must be named `code.bin`. An external exheader binary is required, else the user will be asked to provide any information.
- ExeFS: the binary name must end with the `exefs` extension and must contain a `.code` file. An external exheader binary is required, else the user will be asked to provide any information.
- CXI: the binary must be decrypted and it must contain an ExeFS with a `.code` file.
- ~~CIA~~.

### Types

`File -> Load file -> Parse C header file...`, then select `types.h`.

### Plugins

Capstone is required:

```
python -m pip install capstone==5.0.1
```

Launch each script with `File -> Script file`.

- `find_syscalls.py`: find each function that uses syscalls, optionally renaming wrappers and functions that call `svcSendSyncRequest`.
- `fix_decomp.py`: fix special instructions decompilation. Types must be loaded.
- `fix_switches.py`: fix handling of switch cases.
- ~~`load_crs_syms.py`: load symbols from CRS files.~~