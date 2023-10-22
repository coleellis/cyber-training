---
description: Pre-running analysis of a binary.
---

# Static Analysis

This section will cover the static analysis of a binary, including function disassembly, viewing the stack, and viewing the registers.

{% hint style="info" %}
We will use the `win32` binary for sample output.
{% endhint %}

## Checking Security

We can use `checksec` in `gdb` to get the security features.

```nasm
gef➤  checksec
```

```
[+] checksec for '/home/joybuzzer/win32'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

{% hint style="warning" %}
This is a GEF feature. Ensure you have GEF installed.
{% endhint %}

## Listing Functions

To view the list of available functions:

```nasm
gef➤  info functions
```

```nasm
All defined functions:

Non-debugging symbols:
0x08049000  _init
0x08049040  __libc_start_main@plt
0x08049050  fflush@plt
0x08049060  gets@plt
0x08049070  puts@plt
0x08049080  system@plt
0x08049090  _start
0x080490d0  _dl_relocate_static_pie
0x080490e0  __x86.get_pc_thunk.bx
0x080490f0  deregister_tm_clones
0x08049130  register_tm_clones
0x08049170  __do_global_dtors_aux
0x080491a0  frame_dummy
0x080491a6  win
0x080491d1  read_in
0x0804921e  main
0x0804925e  __x86.get_pc_thunk.ax
0x08049264  _fini
```

`info functions` takes another optional argument: the function keyword to search for. This is useful for not bloating standard output if you want a single function's address.

```nasm
gef➤  info functions win
```

```nasm
All functions matching regular expression "win":

Non-debugging symbols:
0x080491a6  win
```

{% hint style="info" %}
Notice that the output says, "_All functions matching regular expression_." This will find every function with the keyword `win` in it. Functions like `winner` would also be printed.
{% endhint %}

## Disassembling Functions

We can use the `disassemble` function to disassemble a function. So long as the binary can find the function, it will print the assembly code.

{% hint style="success" %}
`disassemble` can be abbreviated as `disas`.
{% endhint %}

```nasm
gef➤  disas win
```

```nasm
Dump of assembler code for function win:
   0x080491a6 <+0>:	push   ebp
   0x080491a7 <+1>:	mov    ebp,esp
   0x080491a9 <+3>:	push   ebx
   0x080491aa <+4>:	sub    esp,0x4
   0x080491ad <+7>:	call   0x804925e <__x86.get_pc_thunk.ax>
   0x080491b2 <+12>:	add    eax,0x2e4e
   0x080491b7 <+17>:	sub    esp,0xc
   0x080491ba <+20>:	lea    edx,[eax-0x1ff8]
   0x080491c0 <+26>:	push   edx
   0x080491c1 <+27>:	mov    ebx,eax
   0x080491c3 <+29>:	call   0x8049080 <system@plt>
   0x080491c8 <+34>:	add    esp,0x10
   0x080491cb <+37>:	nop
   0x080491cc <+38>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x080491cf <+41>:	leave  
   0x080491d0 <+42>:	ret    
End of assembler dump.
```

### PLT Functions

You don't need to list `@plt` for the PLT functions. They won't resolve if you do:

```nasm
gef➤  disas system@plt
No symbol table is loaded.  Use the "file" command.

gef➤  disas system
Dump of assembler code for function system@plt:
   0x08049080 <+0>:	jmp    DWORD PTR ds:0x804c01c
   0x08049086 <+6>:	push   0x20
   0x0804908b <+11>:	jmp    0x8049030
```

If the binary is running, `disas system` will output differently:

```nasm
gef➤  disas system
```

```nasm
Dump of assembler code for function system:
   0xf7c48170 <+0>:	endbr32 
   0xf7c48174 <+4>:	call   0xf7d71e2d
   0xf7c48179 <+9>:	add    edx,0x1e1e87
   0xf7c4817f <+15>:	sub    esp,0xc
   0xf7c48182 <+18>:	mov    eax,DWORD PTR [esp+0x10]
   0xf7c48186 <+22>:	test   eax,eax
   0xf7c48188 <+24>:	je     0xf7c48198 <system+40>
   0xf7c4818a <+26>:	add    esp,0xc
   0xf7c4818d <+29>:	jmp    0xf7c47cb0
   0xf7c48192 <+34>:	lea    esi,[esi+0x0]
   0xf7c48198 <+40>:	lea    eax,[edx-0x6cf03]
   0xf7c4819e <+46>:	call   0xf7c47cb0
   0xf7c481a3 <+51>:	test   eax,eax
   0xf7c481a5 <+53>:	sete   al
   0xf7c481a8 <+56>:	add    esp,0xc
   0xf7c481ab <+59>:	movzx  eax,al
   0xf7c481ae <+62>:	ret    
End of assembler dump.
```

Why does this happen? When the binary is running, the PLT functions are resolved to their actual addresses. For more information, read [this page](../../binex/07-aslr/).

### The GOT Table

You can use `got` to view the GOT table. _You can only do this when the binary is running_ since the GOT resolves at runtime.

```nasm
gef➤  got
```

```nasm
GOT protection: Partial RelRO | GOT functions: 5
 
[0x804c00c] __libc_start_main@GLIBC_2.34  →  0xf7c21560
[0x804c010] fflush@GLIBC_2.0  →  0x8049056
[0x804c014] gets@GLIBC_2.0  →  0x8049066
[0x804c018] puts@GLIBC_2.0  →  0x8049076
[0x804c01c] system@GLIBC_2.0  →  0x8049086
```
