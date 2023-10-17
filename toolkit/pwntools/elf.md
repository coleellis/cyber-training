# The `ELF` Class

This class is super useful for many of our exploits because of the feature set it has. It allows us to find the addresses of functions and symbols without looking them up.

## Creating an `ELF` object
We create an object using `ELF()`, which takes the filename.
```python
elf = ELF('./win32')
```

Most commonly, this is used in conjunction with `context.binary` to set both at the same time.
```python
elf = context.binary = ELF('./win32')
```

## Getting Addresses
We can get the address of a function or symbol using the `ELF` object.  We can use `elf.symbols` (shorthand: `elf.sym`) to do this.  We can access via index (like an array) or using the dot operator (like an object, Javascript syntax).
```python
f_win = elf.symbols['win']
f_win = elf.sym.win
```

We can also use `elf.functions` to do this.  `elf.functions` returns a dictionary of all functions in the binary, with the function name as the key and the address as the value.
```python
f_win = elf.functions['win'].address
```

## PLT and GOT Tables
We can use `elf.plt` to get the address of a function in the PLT table.  We can use `elf.got` to get the address of a function in the GOT table.
```python
system_plt = elf.plt.system
system_got = elf.got.system
```

## Base Address with PIE
If the binary is compiled without PIE, we can find the base address using `elf.address`. All symbols will be based on this address.
```python
base = elf.address
```

If PIE is enabled, we can store the base address once leaked in `elf.address`.  Before we leak the address, `elf.address` is defaulted to `0`.

{% hint style="warning" %}
### Implications
This means that before we leak the PIE base address, `elf.sym` will contain the **relative addresses** of each function.  After we leak the PIE base address, `elf.sym` will contain the **absolute addresses** of each function.
{% endhint %}

## Searching for Strings
We can use `elf.search()` to search for a string in the binary.  This returns a *generator* object.  We can use `next()` to get the first result, or we can iterate through the results.
```python
a_shell = next(elf.search(b'/bin/sh'))
```

## Using `libc`
We can use `elf.libc` to get the `libc` object the binary uses when running.  This returns another `ELF` object, meaning we can use `libc.sym` to get the address of a function or symbol in `libc`.
```python
libc = elf.libc
```

If we are provided a `libc` file, we can also set it.
```python
libc = ELF('./libc.so.6')
```


