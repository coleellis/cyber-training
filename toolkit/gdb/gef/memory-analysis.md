---
description: Further analysis of memory segments.
---

# Memory Analysis

The commands here provide a better analysis of memory segments and the registers.

## `elf-info`

`elf-info` (`elf` for short) provides basic information about the ELF file. This is most useful for viewing memory segments, the entry point, and the ELF header.

```as
gef➤  elf-info
Magic                 : 7f 45 4c 46
Class                 : 0x1 - ELF_32_BITS
Endianness            : 0x1 - LITTLE_ENDIAN
Version               : 0x1
OS ABI                : 0x0 - SYSTEMV
ABI Version           : 0x0
Type                  : 0x2 - ET_EXEC
Machine               : 0x3 - X86_32
Program Header Table  : 0x00000034
Section Header Table  : 0x00003628
Header Table          : 0x00000034
ELF Version           : 0x1
Header size           : 52 (0x34)
Entry point           : 0x08049090

──────────────────────────────────────────────── Program Header ────────────────────────────────────────────────
  [ #] Type           Offset   Virtaddr   Physaddr  FileSiz   MemSiz Flags    Align
  [ 0] PT_PHDR          0x34  0x8048034  0x8048034    0x160    0x160 PF_R       0x4
  [ 1] PT_INTERP       0x194  0x8048194  0x8048194     0x13     0x13 PF_R       0x1
  [ 2] PT_LOAD           0x0  0x8048000  0x8048000    0x388    0x388 PF_R    0x1000
  [ 3] PT_LOAD        0x1000  0x8049000  0x8049000    0x270    0x270 None    0x1000
  [ 4] PT_LOAD        0x2000  0x804a000  0x804a000    0x160    0x160 PF_R    0x1000
  [ 5] PT_LOAD        0x2f08  0x804bf08  0x804bf08    0x120    0x124 None    0x1000
  [ 6] PT_DYNAMIC     0x2f10  0x804bf10  0x804bf10     0xe8     0xe8 None       0x4
  [ 7] PT_NOTE         0x1a8  0x80481a8  0x80481a8     0x44     0x44 PF_R       0x4
  [ 8] PT_GNU_EH_FRAME   0x2038  0x804a038  0x804a038     0x44     0x44 PF_R       0x4
  [ 9] PT_GNU_STACK      0x0        0x0        0x0      0x0      0x0 None      0x10
  [10] PT_GNU_RELRO   0x2f08  0x804bf08  0x804bf08     0xf8     0xf8 PF_R       0x1

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

## `got`

The `got` command prints the GOT table.

```bash
gef➤  got

GOT protection: Partial RelRO | GOT functions: 5
 
[0x804c00c] __libc_start_main@GLIBC_2.34  →  0xf7c21560
[0x804c010] fflush@GLIBC_2.0  →  0xf7c71410
[0x804c014] gets@GLIBC_2.0  →  0x8049066
[0x804c018] puts@GLIBC_2.0  →  0xf7c732a0
[0x804c01c] system@GLIBC_2.0  →  0x8049086
```

`got` can apply filters to the output. You can filter by symbol name and can also use more than one filter.

```bash
gef➤  got puts
GOT protection: Partial RelRO | GOT functions: 5
[0x804c018] puts@GLIBC_2.0  →  0xf7c732a0

gef➤  got puts system
GOT protection: Partial RelRO | GOT functions: 5
[0x804c018] puts@GLIBC_2.0  →  0xf7c732a0
[0x804c01c] system@GLIBC_2.0  →  0x8049086
```

{% hint style="info" %}
The GOT table is resolved at runtime. Therefore, you can only use `got` at runtime.
{% endhint %}

## `heap`

The `heap` command provides information on the heap chunks.

Use `heap arenas` to view the heap arenas.

```bash
gef➤  heap arenas
Arena(base=0x7ffff7e19c80, top=0x5555555596d0, last_remainder=0x0, next=0x7ffff7e19c80)
```

Use `heap chunks` to view the heap chunks.

```bash
gef➤  heap chunks
Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x0000555555559010     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592a0, size=0x30, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592a0     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x5555555592d0, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
    [0x00005555555592d0     45 6e 74 65 72 20 74 68 65 20 66 6c 61 67 20 68    Enter the flag h]
Chunk(addr=0x5555555596e0, size=0x20930, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
```

{% hint style="info" %}
Since this guide doesn't cover heap exploits, I won't go into detail about the heap commands.

...yet.
{% endhint %}

## `dereference`

The `dereference` (`deref` for short) command provides similar output to the Stack section of `context`. It takes three optional arguments:

* A start address, symbol, or register (by default, `$sp`)
* The number of consecutive addresses to reference
* The base location for offset (by default, the start address)

```bash
gef➤  deref
0xffffd640│+0x0000: 0xffffd658  →  0xf7c184be  →  "_dl_audit_preinit"	 ← $esp
0xffffd644│+0x0004: 0x00000000
0xffffd648│+0x0008: 0x01000000
0xffffd64c│+0x000c: 0x080491fb  →  <read_in+12> add ebx, 0x2e05
0xffffd650│+0x0010: 0xf7fc4540  →  <__kernel_vsyscall+0> push ecx
0xffffd654│+0x0014: 0x00000000
0xffffd658│+0x0018: 0xf7c184be  →  "_dl_audit_preinit"
0xffffd65c│+0x001c: 0xf7e2a054  →  0xf7fdde10  →  <_dl_audit_preinit+0> endbr32 
0xffffd660│+0x0020: 0xf7fbe4a0  →  0xf7c00000  →  0x464c457f
0xffffd664│+0x0024: 0xf7fd6f90  →   mov edi, eax
```

With arguments:

```bash
gef➤  deref $esp -l 7 -r $ebp
0xffffd640│-0x0048: 0xffffd658  →  0xf7c184be  →  "_dl_audit_preinit"	 ← $esp
0xffffd644│-0x0044: 0x00000000
0xffffd648│-0x0040: 0x01000000
0xffffd64c│-0x003c: 0x080491fb  →  <read_in+12> add ebx, 0x2e05
0xffffd650│-0x0038: 0xf7fc4540  →  <__kernel_vsyscall+0> push ecx
0xffffd654│-0x0034: 0x00000000
0xffffd658│-0x0030: 0xf7c184be  →  "_dl_audit_preinit"
```

## `registers`

The `registers` command is a wrapper for `info registers`. It shows the current state of the registers in the same format it is printed in `context`.

```bash
gef➤  registers
$eax   : 0xffffd228  →  0xf7c184be  →  "_dl_audit_preinit"
$ebx   : 0x0804c000  →  0x0804bf10  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
$ecx   : 0x6c0     
$edx   : 0xf7e2b9b4  →  0x00000000
$esp   : 0xffffd210  →  0xffffd228  →  0xf7c184be  →  "_dl_audit_preinit"
$ebp   : 0xffffd258  →  0xffffd268  →  0xf7ffd020  →  0xf7ffda40  →  0x00000000
$esi   : 0xffffd324  →  0xffffd4ea  →  "/home/joybuzzer/args"
$edi   : 0xf7ffcb80  →  0x00000000
$eip   : 0x0804922e  →  0xfffe2de8  →  0x00000000
$eflags: [zero carry PARITY ADJUST SIGN trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x23 $ss: 0x2b $ds: 0x2b $es: 0x2b $fs: 0x00 $gs: 0x63 
```

Like `info registers`, you can filter by register.

```bash
gef➤  registers $eip $esi
$eip   : 0x0804922e  →  0xfffe2de8  →  0x00000000
$esi   : 0xffffd324  →  0xffffd4ea  →  "/home/joybuzzer/args"
```

## `vmmap`

`vmmap` performs an extended function to `info proc mappings`. It shows all loaded memory segments.

```bash
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-- /home/joybuzzer/args
0x08049000 0x0804a000 0x00001000 r-x /home/joybuzzer/args
0x0804a000 0x0804b000 0x00002000 r-- /home/joybuzzer/args
0x0804b000 0x0804c000 0x00002000 r-- /home/joybuzzer/args
0x0804c000 0x0804d000 0x00003000 rw- /home/joybuzzer/args
0xf7c00000 0xf7c20000 0x00000000 r-- /usr/lib/i386-linux-gnu/libc.so.6
0xf7c20000 0xf7da2000 0x00020000 r-x /usr/lib/i386-linux-gnu/libc.so.6
0xf7da2000 0xf7e27000 0x001a2000 r-- /usr/lib/i386-linux-gnu/libc.so.6
0xf7e27000 0xf7e28000 0x00227000 --- /usr/lib/i386-linux-gnu/libc.so.6
0xf7e28000 0xf7e2a000 0x00227000 r-- /usr/lib/i386-linux-gnu/libc.so.6
0xf7e2a000 0xf7e2b000 0x00229000 rw- /usr/lib/i386-linux-gnu/libc.so.6
0xf7e2b000 0xf7e35000 0x00000000 rw- 
0xf7fbe000 0xf7fc0000 0x00000000 rw- 
0xf7fc0000 0xf7fc4000 0x00000000 r-- [vvar]
0xf7fc4000 0xf7fc6000 0x00000000 r-x [vdso]
0xf7fc6000 0xf7fc7000 0x00000000 r-- /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7fc7000 0xf7fec000 0x00001000 r-x /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7fec000 0xf7ffb000 0x00026000 r-- /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7ffb000 0xf7ffd000 0x00034000 r-- /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7ffd000 0xf7ffe000 0x00036000 rw- /usr/lib/i386-linux-gnu/ld-linux.so.2
0xfffdd000 0xffffe000 0x00000000 rwx [stack]
```

`vmmap` also takes an optional argument. It takes an address and will resolve that address to a certain memory segment.

```bash
gef➤  x/wx $ebp-0x30
0xffffd228:     0xf7c18400
gef➤  vmmap 0xffffd228
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0xfffdd000 0xffffe000 0x00000000 rwx [stack]
```

## `scan`

`scan` searches for addresses of one memory region inside another region. This is also known as _needle-in-haystack scanning_.

```bash
gef➤  scan stack libc
[+] Searching for addresses in 'stack' that point to 'libc'
[stack]: 0x00007fffffffd6a8│+0x1f6a8: 0x00007ffff77cf482  →  "__tunable_get_val"
[stack]: 0x00007fffffffd6b0│+0x1f6b0: 0x00007ffff77bff78  →  0x0000001200001ab2
[stack]: 0x00007fffffffd758│+0x1f758: 0x00007ffff77cd9d0  →  0x6c5f755f72647800
[stack]: 0x00007fffffffd778│+0x1f778: 0x00007ffff77bda6c  →  0x0000090900000907
[stack]: 0x00007fffffffd7d8│+0x1f7d8: 0x00007ffff77cd9d0  →  0x6c5f755f72647800
[...]
```

You can check mappings without a path associated using an address range.

```bash
gef➤  scan 0x555555554000-0x555555555000 libc
[+] Searching for addresses in '0x555555554000-0x555555555000' that point to 'libc'
```
