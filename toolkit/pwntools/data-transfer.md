# Data Transfer

You often need to send data to a remote process, and receive data back.  Pwntools provides a number of convenience functions to make this easier.

A method not involving pwntools involves the `struct` module, which can be used to pack and unpack data based on size and endianness.

```python
import struct

x = struct.pack('<Q', 0xdeadbeef)
```

More information on `struct` documentation, including the format strings they use for packing, can be found [here](https://docs.python.org/3/library/struct.html).

## Packing Data
Pwntools makes this process easier. We can use `p32()` for packing into a 32-bit byte string, and `p64()` for packing into a 64-bit byte string.
```python
f_win32 = p32(0x080491e2)
f_win64 = p64(0x4011d6)
```

{% hint style="warning" %}
Pwntools automatically assumes that the binary is written in **little-endian** architecture. To change this, you must change `context.endian`.
{% endhint %}

## Unpacking Data
Pwntools provides `u32()` and `u64()` for unpacking 32-bit and 64-bit integers, respectively.
```python
leak = u32(b'\x00\x00\x00\x00')
```

This is most often used in conjunction with `read()` and `recv()`.
```python
leak = u32(p.recv(4))
```

{% hint style="info" %}
Note that `p.recv()` takes the number of **bytes** to read as its argument, and `u32()` is written as unpacking 32 **bits**.  $$4 \text{ bytes} = 32 \text{ bits}$$.
{% endhint %}

Unpacking also supports other sizes, such as `u16()` and `u8()`.
```python
leak = u8(b'A')
```

## Sending Data
Pwntools provides `send()` and `sendline()` for sending data to a remote process.  `send()` sends the data as-is, while `sendline()` appends a newline character (`\n`) to the end of the data.
```python
p.send(b'Hello, world!\n')
p.sendline(b'Hello, world!')
```
{% hint style="info" %}
These two lines are equivalent.
{% endhint %}

Pwntools also has a `sendafter()` and `sendlineafter()` function, which sends data after a given byte string.
```python
p.sendafter(b'Name: ', payload)
```

Finally, pwntools has a packing mechanism called `flat()` that packs multiple sets of data into a single byte string.  **`flat` is packed using `context.endian` and `context.word_size`.**
```python
payload = flat(
    b'A' * 0x10
    f_win32
)
```

## Receiving Data
There are a number of ways to receive data, each with their own advantages.

{% hint style="warning" %}
### Timeout
All of these functions take a `timeout` argument to ensure that the program doesn't hang forever.  Implement it using the `timeout` keyword argument.
```python
p.recv(4, timeout=1)
```
{% endhint %}


#### `recv()`
`recv()` takes the number of bytes to receive as its argument.  This is useful when you know exactly how many bytes you need to receive.
```python
p.recv(4)
```

#### `recvline()`
`recvline()` receives data until it reaches a newline character (`\n`).  This is useful when you know that the data you need is on a single line.
```python
p.recvline()
```

#### `recvuntil()`
`recvuntil()` receives data until it reaches a given byte string.  This is useful when you know that the data you need is on a single line, but you don't know what the newline character is.
```python
p.recvuntil(b'System is at: ')
```

#### `recvall()`
`recvall()` receives all data until the remote process closes the connection.  This is not one that's used very often because the timeout is set to `default` by default, which is 10 seconds.  This is not very user-friendly.
```python
p.recvall()
```

#### `clean()`
`clean()` clears the receive buffer.  This is good when you don't know exactly what you're receiving, but want to ensure you've received all data before sending more.
```python
p.clean()
```

#### `interactive()`
`interactive()` is a function that allows you to interact with the remote process.  This is **required** for popping shells, but also is useful for continuing to interact with the remote process after you've finished exploiting it.
```python
p.interactive()
```
