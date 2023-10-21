---
description: Understanding security measures in the debugged environment.
---

# Security Measures, Illustrated
These commands are useful for further dissection of the security measures placed on the binary.

## `checksec`
The `checksec` command is inspired from the `checksec` used on the command line. It's a convenient way to check security within `gdb`.
```bash
gef➤  checksec
[+] checksec for '/home/joybuzzer/args'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

**Fortify** is a security feature we haven't seen yet; it's a compile-time feature that adds extra checks to detect buffer overflows.  I haven't written any articles on this yet, but you can read more about it [here](https://developers.redhat.com/articles/2022/09/17/gccs-new-fortification-level#2__better_fortification_coverage).

## `canary`
The `canary` tool is one of my favorite GEF tools and what sets it apart from the other `gdb` extensions.  This command finds the canary value and prints its location and value.
```bash
gef➤  canary
[+] The canary of process 19692 is at 0xffffd84b, value is 0x2bf28900
```

This makes locating the canary on the stack much easier:
```bash
gef➤  x/28wx $esp
0xffffd570:	0xffffd58c	0x00000001	0xf7ffda40	0x080491d2
0xffffd580:	0xf7fc4540	0xffffffff	0x08048034	0xf7fc66d0
0xffffd590:	0xf7ffd608	0x00000020	0x00000000	0xffffd790
0xffffd5a0:	0x00000000	0x00000000	0x01000000	0x0000000b
0xffffd5b0:	0xf7fc4540	0x00000000	0xf7c184be	0xf7e2a054
0xffffd5c0:	0xf7fbe4a0	0xf7fd6f90	0xf7c184be	0x2bf28900
0xffffd5d0:	0xffffd610	0x0804c000	0xffffd5e8	0x080492b8
```

## `aslr`
You can enable or disable ASLR on the debugged binary.  Remember that this is internal GEF setting and does not affect ASLR on the kernel.  Since we never know if ASLR is running on a remote binary, we should assume it is on.
```bash
gef➤  aslr
ASLR is currently disabled
```
```bash
gef➤  aslr on
gef➤  aslr off
```

{% hint style="warning" %}
This will not work on a process which was loaded and `gdb` was then attached.  You must initiate the process using `gdb`.
{% endhint %}

## `pie`
The `pie` command is used when handling position-independent executables (PIE enabled). It provides a series of commands to use in place of the typical `gdb` commands that automatically resolve absolute addresses for the run.

Use `pie breakpoint <offset>` to set a breakpoint.  It can be used like the normal `b` command in `gdb` and will automatically resolve the address.
```bash
gef➤  pie breakpoint main
```

Use `pie info` the same way you would use `info break` in `gdb`. This lists the breakpoints.
```bash
gef➤  pie info
VNum    Num     Addr              
     1  N/A     0x11cd 
```

Use `pie delete <number>` to delete a breakpoint.  It can be used like the normal `delete` command in `gdb`.
```bash
gef➤  pie delete 1
```

Finally, when running the binary, use `pie run` instead of the typical `run` command. This converts the PIE breakpoints to real breakpoints at runtime.
```bash
gef➤  pie run
```



