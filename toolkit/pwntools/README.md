# Pwntools

This section covers many of the useful features of the Pwntools library. All of this information comes straight from the Pwntools documentation.

All of our exploits will be written in Python3, so we will be using the Python3 version of Pwntools.

## Installation 
Pwntools can be installed on Linux systems using:
```nasm
pip3 install pwntools
```

## Usage
Pwntools can be imported into a Python3 script using:
```python
from pwn import *
```

This imports every function from Pwntools into the current namespace. This includes a number of functions.
### Context
* `context.binary`
* `context.log_level`
* `context.arch`
* `context.os`

### Connection
* `remote()`
* `process()`
* `listen()`
* `ssh()`

### Assembly
* `asm()`
* `disasm()`
* `shellcraft`

### ELF
* `ELF()`
* `ROP()`
* `DynELF()`

### Packing/Unpacking
* `pack()`
* `unpack()`
* `p32()` / `p64()`
* `u32()` / `u64()`

### GDB
* `gdb.attach()`
* `gdb.debug()`

### Misc
* `hexdump()`
* `read()` and `write()`
* `enhex()` and `unhex()`
* `align()` and `align_down()`
* `urlencode()` and `urldecode()`

### Other Modules
The following are automatically imported:
* `import os`
* `import sys`
* `import time`
* `import random`
* `import requests`
* `import re`