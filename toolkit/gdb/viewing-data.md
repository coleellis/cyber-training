---
description: Memory and Register Analysis.
---

# Viewing Data

Printing data is essential for understanding the contents of registers and memory. This section will cover the various ways to print data in `gdb`.

## Summary Information

We can use various summary commands to see lots of data simultaneously. GEF's preview pane shadows a few of these commands, but they are still useful to know.

### `info registers`

This command shows all the available registers and their current value.

```bash
gef➤  info registers
eax            0x804923c           0x804923c
ecx            0x22d4b89d          0x22d4b89d
edx            0xffffd6c0          0xffffd6c0
ebx            0xf7e2a000          0xf7e2a000
esp            0xffffd698          0xffffd698
ebp            0xffffd698          0xffffd698
esi            0xffffd754          0xffffd754
edi            0xf7ffcb80          0xf7ffcb80
eip            0x804923f           0x804923f <main+3>
eflags         0x246               [ PF ZF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
k0             0x0                 0x0
k1             0x0                 0x0
k2             0x0                 0x0
k3             0x0                 0x0
k4             0x0                 0x0
k5             0x0                 0x0
k6             0x0                 0x0
k7             0x0                 0x0
```

GEF provides a similar command, `registers`, outputs the registers that it shows in the GEF output. Its output is a bit more verbose and only shows the most important registers.

```bash
gef➤  registers
$eax   : 0x0804923c  →  <main+0> push ebp
$ebx   : 0xf7e2a000  →  0x00229dac
$ecx   : 0x22d4b89d
$edx   : 0xffffd6c0  →  0xf7e2a000  →  0x00229dac
$esp   : 0xffffd698  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$ebp   : 0xffffd698  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0xffffd754  →  0xffffd90e  →  "/home/joybuzzer/args"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x0804923f  →  <main+3> and esp, 0xfffffff0
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
```

`registers` takes an optional argument to show only a subset of registers. Remember that GDB uses `$` syntax for registers.

```bash
gef➤  registers $eip $esp $edi
$esp   : 0xffffd698  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x0804923f  →  <main+3> and esp, 0xfffffff0
```

### `info frame`

This gives us extra details on the stack frame. I do not commonly use this command because GEF provides a lot of this information in the GEF output.

```bash
gef➤  info frame
Stack level 0, frame at 0xffffd6a0:
 eip = 0x804923f in main; saved eip = 0xf7c21519
 Arglist at 0xffffd698, args: 
 Locals at 0xffffd698, Previous frame's sp is 0xffffd6a0
 Saved registers:
  ebp at 0xffffd698, eip at 0xffffd69c
```

### `info proc mappings` and `elf-info`

This is one of the most useful commands in this section. It shows us the memory mappings for the process. This is useful for understanding the memory sections, where data is allocated, and the permissions of each section.

GEF's `elf-info` provides more detailed information on the binary's segments. This includes the `got` and `plt` locations as well as the `.text`, `.data`, and `.bss` sections.

{% tabs %}
{% tab title="info proc mappings" %}
```bash
gef➤  info proc mappings
process 10029
Mapped address spaces:

	Start Addr   End Addr       Size     Offset  Perms   objfile
	 0x8048000  0x8049000     0x1000        0x0  r--p   /home/joybuzzer/args
	 0x8049000  0x804a000     0x1000     0x1000  r-xp   /home/joybuzzer/args
	 0x804a000  0x804b000     0x1000     0x2000  r--p   /home/joybuzzer/args
	 0x804b000  0x804c000     0x1000     0x2000  r--p   /home/joybuzzer/args
	 0x804c000  0x804d000     0x1000     0x3000  rw-p   /home/joybuzzer/args
	0xf7c00000 0xf7c20000    0x20000        0x0  r--p   /usr/lib/i386-linux-gnu/libc.so.6
	0xf7c20000 0xf7da2000   0x182000    0x20000  r-xp   /usr/lib/i386-linux-gnu/libc.so.6
	0xf7da2000 0xf7e27000    0x85000   0x1a2000  r--p   /usr/lib/i386-linux-gnu/libc.so.6
	0xf7e27000 0xf7e28000     0x1000   0x227000  ---p   /usr/lib/i386-linux-gnu/libc.so.6
	0xf7e28000 0xf7e2a000     0x2000   0x227000  r--p   /usr/lib/i386-linux-gnu/libc.so.6
	0xf7e2a000 0xf7e2b000     0x1000   0x229000  rw-p   /usr/lib/i386-linux-gnu/libc.so.6
	0xf7e2b000 0xf7e35000     0xa000        0x0  rw-p   
	0xf7fbe000 0xf7fc0000     0x2000        0x0  rw-p   
	0xf7fc0000 0xf7fc4000     0x4000        0x0  r--p   [vvar]
	0xf7fc4000 0xf7fc6000     0x2000        0x0  r-xp   [vdso]
	0xf7fc6000 0xf7fc7000     0x1000        0x0  r--p   /usr/lib/i386-linux-gnu/ld-linux.so.2
	0xf7fc7000 0xf7fec000    0x25000     0x1000  r-xp   /usr/lib/i386-linux-gnu/ld-linux.so.2
	0xf7fec000 0xf7ffb000     0xf000    0x26000  r--p   /usr/lib/i386-linux-gnu/ld-linux.so.2
	0xf7ffb000 0xf7ffd000     0x2000    0x34000  r--p   /usr/lib/i386-linux-gnu/ld-linux.so.2
	0xf7ffd000 0xf7ffe000     0x1000    0x36000  rw-p   /usr/lib/i386-linux-gnu/ld-linux.so.2
	0xfffdd000 0xffffe000    0x21000        0x0  rwxp   [stack]
```
{% endtab %}

{% tab title="elf-info" %}
```bash
gef➤  elf-info
──────────────────────────────────────────────── Section Header ────────────────────────────────────────────────
  [ #] Name                            Type    Address   Offset     Size   EntSiz Flags Link Info    Align
  [ 0]                                 UNKN        0x0      0x0      0x0      0x0 UNKNOWN_FLAG  0x0  0x0      0x0
  [ 1] .interp                 SHT_PROGBITS  0x8048194    0x194     0x13      0x0 ALLOC  0x0  0x0      0x1
  [ 2] .note.gnu.build-id          SHT_NOTE  0x80481a8    0x1a8     0x24      0x0 ALLOC  0x0  0x0      0x4
  [ 3] .note.ABI-tag               SHT_NOTE  0x80481cc    0x1cc     0x20      0x0 ALLOC  0x0  0x0      0x4
  [ 4] .gnu.hash               SHT_GNU_HASH  0x80481ec    0x1ec     0x20      0x4 ALLOC  0x5  0x0      0x4
  [ 5] .dynsym                   SHT_DYNSYM  0x804820c    0x20c     0x90     0x10 ALLOC  0x6  0x1      0x4
  [ 6] .dynstr                   SHT_STRTAB  0x804829c    0x29c     0x6f      0x0 ALLOC  0x0  0x0      0x1
  [ 7] .gnu.version          SHT_GNU_versym  0x804830c    0x30c     0x12      0x2 ALLOC  0x5  0x0      0x2
  [ 8] .gnu.version_r       SHT_GNU_verneed  0x8048320    0x320     0x30      0x0 ALLOC  0x6  0x1      0x4
  [ 9] .rel.dyn                     SHT_REL  0x8048350    0x350     0x10      0x8 ALLOC  0x5  0x0      0x4
  [10] .rel.plt                     SHT_REL  0x8048360    0x360     0x28      0x8 UNKNOWN_FLAG  0x5 0x16      0x4
  [11] .init                   SHT_PROGBITS  0x8049000   0x1000     0x24      0x0 UNKNOWN_FLAG  0x0  0x0      0x4
  [12] .plt                    SHT_PROGBITS  0x8049030   0x1030     0x60      0x4 UNKNOWN_FLAG  0x0  0x0     0x10
  [13] .text                   SHT_PROGBITS  0x8049090   0x1090    0x1c8      0x0 UNKNOWN_FLAG  0x0  0x0     0x10
  [14] .fini                   SHT_PROGBITS  0x8049258   0x1258     0x18      0x0 UNKNOWN_FLAG  0x0  0x0      0x4
  [15] .rodata                 SHT_PROGBITS  0x804a000   0x2000     0x37      0x0 ALLOC  0x0  0x0      0x4
  [16] .eh_frame_hdr           SHT_PROGBITS  0x804a038   0x2038     0x44      0x0 ALLOC  0x0  0x0      0x4
  [17] .eh_frame               SHT_PROGBITS  0x804a07c   0x207c     0xe4      0x0 ALLOC  0x0  0x0      0x4
  [18] .init_array           SHT_INIT_ARRAY  0x804bf08   0x2f08      0x4      0x4 UNKNOWN_FLAG  0x0  0x0      0x4
  [19] .fini_array           SHT_FINI_ARRAY  0x804bf0c   0x2f0c      0x4      0x4 UNKNOWN_FLAG  0x0  0x0      0x4
  [20] .dynamic                 SHT_DYNAMIC  0x804bf10   0x2f10     0xe8      0x8 UNKNOWN_FLAG  0x6  0x0      0x4
  [21] .got                    SHT_PROGBITS  0x804bff8   0x2ff8      0x8      0x4 UNKNOWN_FLAG  0x0  0x0      0x4
  [22] .got.plt                SHT_PROGBITS  0x804c000   0x3000     0x20      0x4 UNKNOWN_FLAG  0x0  0x0      0x4
  [23] .data                   SHT_PROGBITS  0x804c020   0x3020      0x8      0x0 UNKNOWN_FLAG  0x0  0x0      0x4
  [24] .bss                      SHT_NOBITS  0x804c028   0x3028      0x4      0x0 UNKNOWN_FLAG  0x0  0x0      0x1
  [25] .comment                SHT_PROGBITS        0x0   0x3028     0x2d      0x1 UNKNOWN_FLAG  0x0  0x0      0x1
  [26] .symtab                   SHT_SYMTAB        0x0   0x3058    0x2b0     0x10 UNKNOWN_FLAG 0x1b 0x12      0x4
  [27] .strtab                   SHT_STRTAB        0x0   0x3308    0x21f      0x0 UNKNOWN_FLAG  0x0  0x0      0x1
  [28] .shstrtab                 SHT_STRTAB        0x0   0x3527    0x101      0x0 UNKNOWN_FLAG  0x0  0x0      0x1
```
{% endtab %}
{% endtabs %}

{% hint style="info" %}
Remember, this function only works during runtime.
{% endhint %}

### `info variables`

This command shows us the global variables in the program. This is useful for understanding the program's layout and where data is stored. There is a lot of bloat in this output because the binary automatically includes a lot of variables for the C runtime.

```bash
gef➤  info variables
All defined variables:

Non-debugging symbols:
0x080481cc  __abi_tag
0x0804a000  _fp_hw
0x0804a004  _IO_stdin_used
0x0804a038  __GNU_EH_FRAME_HDR
0x0804a15c  __FRAME_END__
0x0804bf08  __frame_dummy_init_array_entry
0x0804bf0c  __do_global_dtors_aux_fini_array_entry
0x0804bf10  _DYNAMIC
0x0804c000  _GLOBAL_OFFSET_TABLE_
0x0804c020  __data_start
0x0804c020  data_start
0x0804c024  __dso_handle
0x0804c028  __TMC_END__
0x0804c028  __bss_start
0x0804c028  _edata
0x0804c028  completed
...
```

{% hint style="info" %}
Remember, this function only works during runtime.
{% endhint %}

### `info functions`

We use this command whenever we open a binary to see the available functions.

```bash
gef➤  info functions
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
0x080491ef  read_in
0x0804923c  main
0x08049254  __x86.get_pc_thunk.ax
0x08049258  _fini
```

{% hint style="warning" %}
If you run this command at runtime, every function from the C runtime will be included in the output. This includes every function in `libc`.
{% endhint %}

## Printing Data

The `print` command (`p` for short) is the driving force behind examining data. It allows us to print the value of an **expression**.

```bash
gef➤  print 0x10-0x8
$1 = 0x8
```

### Examining Memory

We can use the `x` command to examine memory. It takes an address or a register as its argument:

```bash
gef➤  x $esp
0xffffd640:	0xffffd658
gef➤  x 0xffffd640
0xffffd640:	0xffffd658
```

There are three formatting parameters formatted like so: `x/NFU <ADDRESS>`. The three format parameters are:

* `N`: _The repeat count_. The repeat count is the number of times to repeat the format. This is used to print arrays (or large amounts of data from the stack or heap).
* `F`: _The display format_. The display format is how to display the data. The default is hexadecimal (`x`). The types available are `x` (hex), `d` (decimal), `u` (unsigned), `o` (octal), `t` (binary), `f` (float), `a` (address), `c` (char), `s` (string), and `i` (instruction).
* `U`: _The unit size_. The unit size is the size of each block. The four types are `b` (byte), `h` (halfword), `w` (word), and `g` (giant, 8 bytes). The default is word size (`w`). 32-bit binaries used `w`-sized data and 64-bit uses `g`-sized data.

Here is this in action in two common use cases:

```bash
# in 32-bit (understanding passed parameters)
gef➤  x/20wx $esp
0xffffd640:	0xffffd658	0x00000000	0x01000000	0x080491fb
0xffffd650:	0xf7fc4540	0x00000000	0xf7c184be	0xf7e2a054
0xffffd660:	0xf7fbe4a0	0xf7fd6f90	0xf7c184be	0xf7fbe4a0
0xffffd670:	0xffffd6b0	0xf7fbe66c	0xf7fbeb10	0x00000001
0xffffd680:	0x00000001	0xf7e2a000	0xffffd698	0x08049251
gef➤  x/i $eip
=> 0x804922e <read_in+63>:	call   0x8049060 <gets@plt>

# in 64-bit (identifying a return pointer)
gef➤  x/20gx $rsp
0x7fffffffe3e0:	0x0000000000000000	0x0000000000000000
0x7fffffffe3f0:	0x0000000000000000	0x0000000000000000
0x7fffffffe400:	0x0000000000000000	0x0000000000000000
0x7fffffffe410:	0x00007fffffffe420	0x0000000000401205
0x7fffffffe420:	0x0000000000000001	0x00007ffff7c29d90
0x7fffffffe430:	0x0000000000000000	0x00000000004011f3
0x7fffffffe440:	0x0000000100000000	0x00007fffffffe538
0x7fffffffe450:	0x0000000000000000	0x827c501b62b87baa
0x7fffffffe460:	0x00007fffffffe538	0x00000000004011f3
0x7fffffffe470:	0x0000000000403e18	0x00007ffff7ffd040
gef➤  x/i 0x0000000000401205
   0x401205 <main+18>:	lea    rax,[rip+0xe30]
```

{% hint style="danger" %}
Ensure you're comfortable doing this. This is the crux of dynamic analysis with `gdb`, so get some practice examining data.
{% endhint %}

### Searching Memory

There are two major commands for finding data in memory: `find` and `search-pattern`.

### `find`

`find` is built into GDB directly and is used for finding expressions within memory. The format of the `find` command is `find [/UN] start, +len|end, expr1 [, expr2, ...]`.

* `/UN`: _Unit size and number flags_. These are the same flags you would use with `x`.
* `start`: _Start address_. Where to start searching.
* `+len|end`: _End of search_. You can specify a number of bytes to search or an end address. Addresses are inclusive by default.
* `expr1`: _Expression_. This is the expression to search for.

In action:

```bash
gef➤  find 0x08049000, +0x1000, "/bin/sh"
Pattern not found.

gef➤  find 0x08049000, +0x1000, 0xc3
0x8049023 <_init+35>
0x804926f <_fini+23>
2 patterns found.
```

### `search-pattern`

`search-pattern` is a GEF command used for finding strings. It takes a string argument and searches across the binary and loaded libraries for all instances of the string.

```bash
gef➤  search-pattern "/bin/cat flag.txt"
[+] Searching '/bin/cat flag.txt' in memory
[+] In '/home/joybuzzer/split'(0x601000-0x602000), permission=rw-
  0x601060 - 0x601071  →   "/bin/cat flag.txt" 

gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/usr/lib/i386-linux-gnu/libc.so.6'(0xf7da2000-0xf7e27000), permission=r--
  0xf7dbd0f5 - 0xf7dbd0fc  →   "/bin/sh" 
```

`search-pattern` can also search based on endianness and can restrict search in only a certain part of memory.

```bash
gef➤  search-pattern /bin/sh little 0x0-0x80500000
[+] Searching '/bin/sh' in 0x0-0x80500000
```

{% hint style="warning" %}
If you want to search in only a certain section of memory, the endian argument is required.
{% endhint %}
