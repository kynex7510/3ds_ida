# 3ds_ida

(WIP) IDA Pro 7.6+ resources for reverse engineering Nintendo 3DS userland code.

## Setup

[Python 3+](https://www.python.org/) is required.

### Loader

Copy `ctru_loader.py` in `{IDA_PATH}/loaders`. The loader supports the following formats:

- Raw: the file must be named `code.bin` and it should not be compressed; an external exheader file is required, else the user will be asked to provide any information.
- ~~ExeFS: the file must end with the `exefs` extension and must contain a `.code` section; an external exheader file is required, else the user will be asked to provide any information.~~
- ~~CXI~~.
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

- `find_sync_requests.py`: find each function that uses `svcSendSyncRequest`, optionally renaming the results.
- ~~`find_syscalls.py`: find syscalls, setting the appropriate name and type for each subroutine (requires types).~~
- ~~`fix_decomp.py`: fix syscalls and TLS access decompilation. This plugin must be run everytime else the decompilation will break.~~
- ~~`load_crs_syms.py`: load symbols from CRS files.~~