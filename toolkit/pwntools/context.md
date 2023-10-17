# Context

**Context** is a global object used to store information about the target binary and the environment it's being run.  There are a number of attributes that can be set.

## Primary Attributes

### `context.arch`
We can use this to set the architecture of the target binary.  This is useful for packing and unpacking data, as well as for shellcode generation.
```python
context.arch = 'i386'
```

### `context.os`
We can use this to set the operating system of the target binary.  This is useful for shellcode generation.
```python
context.os = 'linux'
```

### `context.endian`
We can use this to set the endianness of the target binary.  This is useful for packing and unpacking data.
```python
context.endian = 'little'
```

### `context.word_size`
We can use this to set the word size of the target binary.  This is useful for shellcode generation (and packing data with `flat`).
```python
context.word_size = 32
```

## Grouping this together
We can simply set `context.binary` to the binary we're using, and pwntools will automatically set the architecture, operating system, endianness, and word size.

This takes an `ELF` object.  More information on the `ELF` class [here](./elf.md).
```python
context.binary = ELF('./win32')
```

## Other Attributes
### `context.log_level`
We can set the verbosity of the output logger.
```python
context.log_level = 'debug'
```

### `context.terminal`
For those that use the `tmux`, we can use `context.terminal` to set how the window is split.
```python
context.terminal = ['tmux', 'splitw', '-h']
```