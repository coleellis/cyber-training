---
description: Memory and Register Analysis.
---

# Viewing Data

## Summary Information
These commands come from the debugger (`d`) and information (`i`) modules.

### Viewing Registers
Use the `dr` submodule to get more information about the registers. 
{% hint style="info" %}
Use `dr?` to view the help pages for this submodule.
{% endhint %}

```nasm
[0x0804923c]> dr
eax = 0x0804923c
ebx = 0xf7e2a000
ecx = 0x8e819449
edx = 0xffe4a930
esi = 0xffe4a9c4
edi = 0xf7f47b80
esp = 0xffe4a90c
ebp = 0xf7f48020
eip = 0x0804923c
eflags = 0x00000246
oeax = 0xffffffff
```

### Viewing Memory Segments
Use the `dm` submodule to get more information about the memory segments.
```nasm
[0x0804923c]> dm
0x08048000 - 0x08049000 - usr     4K s r-- /home/joybuzzer/args /home/joybuzzer/args ; segment.ehdr
0x08049000 - 0x0804a000 * usr     4K s r-x /home/joybuzzer/args /home/joybuzzer/args ; map._home_joybuzzer_args.r_x
0x0804a000 - 0x0804b000 - usr     4K s r-- /home/joybuzzer/args /home/joybuzzer/args ; map._home_joybuzzer_args.r__
0x0804b000 - 0x0804c000 - usr     4K s r-- /home/joybuzzer/args /home/joybuzzer/args ; map._home_joybuzzer_args.rw_
0x0804c000 - 0x0804d000 - usr     4K s rw- /home/joybuzzer/args /home/joybuzzer/args ; obj._GLOBAL_OFFSET_TABLE_
0xf7c00000 - 0xf7c20000 - usr   128K s r-- /usr/lib/i386-linux-gnu/libc.so.6 /usr/lib/i386-linux-gnu/libc.so.6
0xf7c20000 - 0xf7da2000 - usr   1.5M s r-x /usr/lib/i386-linux-gnu/libc.so.6 /usr/lib/i386-linux-gnu/libc.so.6
0xf7da2000 - 0xf7e27000 - usr   532K s r-- /usr/lib/i386-linux-gnu/libc.so.6 /usr/lib/i386-linux-gnu/libc.so.6
0xf7e27000 - 0xf7e28000 - usr     4K s --- /usr/lib/i386-linux-gnu/libc.so.6 /usr/lib/i386-linux-gnu/libc.so.6
0xf7e28000 - 0xf7e2a000 - usr     8K s r-- /usr/lib/i386-linux-gnu/libc.so.6 /usr/lib/i386-linux-gnu/libc.so.6
0xf7e2a000 - 0xf7e2b000 - usr     4K s rw- /usr/lib/i386-linux-gnu/libc.so.6 /usr/lib/i386-linux-gnu/libc.so.6 ; ebx
0xf7e2b000 - 0xf7e35000 - usr    40K s rw- unk0 unk0
0xf7f09000 - 0xf7f0b000 - usr     8K s rw- unk1 unk1
0xf7f0b000 - 0xf7f0f000 - usr    16K s r-- [vvar] [vvar] ; map._vvar_.r__
0xf7f0f000 - 0xf7f11000 - usr     8K s r-x [vdso] [vdso] ; map._vdso_.r_x
0xf7f11000 - 0xf7f12000 - usr     4K s r-- /usr/lib/i386-linux-gnu/ld-linux.so.2 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xf7f12000 - 0xf7f37000 - usr   148K s r-x /usr/lib/i386-linux-gnu/ld-linux.so.2 /usr/lib/i386-linux-gnu/ld-linux.so.2 ; map._usr_lib_i386_linux_gnu_ld_linux.so.2.r_x
0xf7f37000 - 0xf7f46000 - usr    60K s r-- /usr/lib/i386-linux-gnu/ld-linux.so.2 /usr/lib/i386-linux-gnu/ld-linux.so.2 ; map._usr_lib_i386_linux_gnu_ld_linux.so.2.r__
0xf7f46000 - 0xf7f48000 - usr     8K s r-- /usr/lib/i386-linux-gnu/ld-linux.so.2 /usr/lib/i386-linux-gnu/ld-linux.so.2 ; map._usr_lib_i386_linux_gnu_ld_linux.so.2.rw_
0xf7f48000 - 0xf7f49000 - usr     4K s rw- /usr/lib/i386-linux-gnu/ld-linux.so.2 /usr/lib/i386-linux-gnu/ld-linux.so.2
0xffe2c000 - 0xffe4d000 - usr   132K s rwx [stack] [stack] ; map._stack_.rwx
```

We can use the `dm.` command to find the memory segment of a specific address.  It defaults to the seek address if no address is provided.
```nasm
[0x0804923c]> dm.
0x08049000 - 0x0804a000 * usr     4K s r-x /home/joybuzzer/args /home/joybuzzer/args ; map._home_joybuzzer_args.r_x

[0x0804923c]> dm. @ 0xffe4a90c
0xffe2c000 - 0xffe4d000 * usr   132K s rwx [stack] [stack] ; map._stack_.rwx
```

This submodule provides a number of commands to allocate, deallocate, and map virtual memory. I don't have any writeups using the write flag, but in the future I might make this addition.

### Symbols and Variables
Use the `is` command to list the available symbols.
```nasm
[0x0804923c]> is
[Symbols]
nth paddr      vaddr      bind   type   size lib name                                   demangled
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――
8   0x00002004 0x0804a004 GLOBAL OBJ    4        _IO_stdin_used
1   ---------- 0x00000000 LOCAL  FILE   0        crt1.o
2   0x000001cc 0x080481cc LOCAL  OBJ    32       __abi_tag
3   ---------- 0x00000000 LOCAL  FILE   0        crtstuff.c
4   0x000010f0 0x080490f0 LOCAL  FUNC   0        deregister_tm_clones
5   0x00001130 0x08049130 LOCAL  FUNC   0        register_tm_clones
6   0x00001170 0x08049170 LOCAL  FUNC   0        __do_global_dtors_aux
7   ---------- 0x0804c028 LOCAL  OBJ    1        completed.0
8   0x00002f0c 0x0804bf0c LOCAL  OBJ    0        __do_global_dtors_aux_fini_array_entry
9   0x000011a0 0x080491a0 LOCAL  FUNC   0        frame_dummy
10  0x00002f08 0x0804bf08 LOCAL  OBJ    0        __frame_dummy_init_array_entry
11  ---------- 0x00000000 LOCAL  FILE   0        args.c
12  ---------- 0x00000000 LOCAL  FILE   0        crtstuff.c
13  0x0000215c 0x0804a15c LOCAL  OBJ    0        __FRAME_END__
14  ---------- 0x00000000 LOCAL  FILE   0
15  0x00002f10 0x0804bf10 LOCAL  OBJ    0        _DYNAMIC
16  0x00002038 0x0804a038 LOCAL  NOTYPE 0        __GNU_EH_FRAME_HDR
17  0x00003000 0x0804c000 LOCAL  OBJ    0        _GLOBAL_OFFSET_TABLE_
19  0x000010e0 0x080490e0 GLOBAL FUNC   4        __x86.get_pc_thunk.bx
20  0x00003020 0x0804c020 WEAK   NOTYPE 0        data_start
23  ---------- 0x0804c028 GLOBAL NOTYPE 0        _edata
24  0x00001258 0x08049258 GLOBAL FUNC   0        _fini
25  0x00003020 0x0804c020 GLOBAL NOTYPE 0        __data_start
29  0x00003024 0x0804c024 GLOBAL OBJ    0        __dso_handle
30  0x00002004 0x0804a004 GLOBAL OBJ    4        _IO_stdin_used
31  0x000011a6 0x080491a6 GLOBAL FUNC   73       win
32  ---------- 0x0804c02c GLOBAL NOTYPE 0        _end
33  0x000010d0 0x080490d0 GLOBAL FUNC   5        _dl_relocate_static_pie
34  0x00001090 0x08049090 GLOBAL FUNC   49       _start
35  0x00002000 0x0804a000 GLOBAL OBJ    4        _fp_hw
37  ---------- 0x0804c028 GLOBAL NOTYPE 0        __bss_start
38  0x0000123c 0x0804923c GLOBAL FUNC   24       main
39  0x00001254 0x08049254 GLOBAL FUNC   0        __x86.get_pc_thunk.ax
40  0x000011ef 0x080491ef GLOBAL FUNC   77       read_in
41  ---------- 0x0804c028 GLOBAL OBJ    0        __TMC_END__
42  0x00001000 0x08049000 GLOBAL FUNC   0        _init
1   0x00001040 0x08049040 GLOBAL FUNC   16       imp.__libc_start_main
2   0x00001050 0x08049050 GLOBAL FUNC   16       imp.fflush
3   0x00001060 0x08049060 GLOBAL FUNC   16       imp.gets
4   0x00001070 0x08049070 GLOBAL FUNC   16       imp.puts
5   0x00001080 0x08049080 GLOBAL FUNC   16       imp.system
6   ---------- ---------- WEAK   NOTYPE 16       imp.__gmon_start__
7   ---------- ---------- GLOBAL OBJ    16       imp.stdout
```

To get the list of variables, we need to filter for the **objects** in this list.  We can do this using the `~` operator (the `grep` operator).
```nasm
[0x0804923c]> is~OBJ
8   0x00002004 0x0804a004 GLOBAL OBJ    4        _IO_stdin_used
2   0x000001cc 0x080481cc LOCAL  OBJ    32       __abi_tag
7   ---------- 0x0804c028 LOCAL  OBJ    1        completed.0
8   0x00002f0c 0x0804bf0c LOCAL  OBJ    0        __do_global_dtors_aux_fini_array_entry
10  0x00002f08 0x0804bf08 LOCAL  OBJ    0        __frame_dummy_init_array_entry
13  0x0000215c 0x0804a15c LOCAL  OBJ    0        __FRAME_END__
15  0x00002f10 0x0804bf10 LOCAL  OBJ    0        _DYNAMIC
17  0x00003000 0x0804c000 LOCAL  OBJ    0        _GLOBAL_OFFSET_TABLE_
29  0x00003024 0x0804c024 GLOBAL OBJ    0        __dso_handle
30  0x00002004 0x0804a004 GLOBAL OBJ    4        _IO_stdin_used
35  0x00002000 0x0804a000 GLOBAL OBJ    4        _fp_hw
41  ---------- 0x0804c028 GLOBAL OBJ    0        __TMC_END__
7   ---------- ---------- GLOBAL OBJ    16       imp.stdout
```

### Listing Functions

Use the `afl` command to list the available functions.  The `afll` command provides the list of available commands in verbose mode.

{% tabs %}
{% tab title="afl" %}
```nasm
[0x0804923c]> afl
0x08049040    1      6 sym.imp.__libc_start_main
0x08049050    1      6 sym.imp.fflush
0x08049060    1      6 sym.imp.gets
0x08049070    1      6 sym.imp.puts
0x08049080    1      6 sym.imp.system
0x08049090    1     44 entry0
0x080490bd    1      4 fcn.080490bd
0x080490f0    4     40 sym.deregister_tm_clones
0x08049130    4     53 sym.register_tm_clones
0x08049170    3     34 sym.__do_global_dtors_aux
0x080491a0    1      6 sym.frame_dummy
0x080490e0    1      4 sym.__x86.get_pc_thunk.bx
0x08049258    1     24 sym._fini
0x080491a6    4     73 sym.win
0x080490d0    1      5 sym._dl_relocate_static_pie
0x0804923c    1     24 main
0x08049254    1      4 sym.__x86.get_pc_thunk.ax
0x080491ef    1     77 sym.read_in
0x08049000    3     36 sym._init
```
{% endtab %}

{% tab title="afll" %}
```nasm
[0x0804923c]> afll
address    noret size  nbbs edges    cc cost  min bound range max bound  calls locals args xref frame name
========== ===== ===== ===== ===== ===== ==== ========== ===== ========== ===== ====== ==== ==== ===== ====
0x08049040     1    6     1     0     1    3 0x08049040     6 0x08049046     0    0      0    1     0 sym.imp.__libc_start_main
0x08049050     0    6     1     0     1    3 0x08049050     6 0x08049056     0    0      0    1     0 sym.imp.fflush
0x08049060     0    6     1     0     1    3 0x08049060     6 0x08049066     0    0      0    1     0 sym.imp.gets
0x08049070     0    6     1     0     1    3 0x08049070     6 0x08049076     0    0      0    2     0 sym.imp.puts
0x08049080     0    6     1     0     1    3 0x08049080     6 0x08049086     0    0      0    1     0 sym.imp.system
0x08049090     1   44     1     0     1   21 0x08049090    44 0x080490bc     2    0      0    0    28 entry0
0x080490bd     0    4     1     0     1    4 0x080490bd     4 0x080490c1     0    0      0    1     0 fcn.080490bd
0x080490f0     0   40     4     4     4   23 0x080490f0    49 0x08049121     0    0      0    1    28 sym.deregister_tm_clones
0x08049130     0   53     4     4     4   29 0x08049130    57 0x08049169     0    0      0    0    28 sym.register_tm_clones
0x08049170     0   34     3     2     3   18 0x08049170    41 0x08049199     1    0      0    0    12 sym.__do_global_dtors_aux
0x080491a0     0    6     1     0     1    3 0x080491a0     6 0x080491a6     0    0      0    0     0 sym.frame_dummy
0x080490e0     0    4     1     0     1    4 0x080490e0     4 0x080490e4     0    0      0    3     0 sym.__x86.get_pc_thunk.bx
0x08049258     0   24     1     0     1   12 0x08049258    24 0x08049270     1    0      0    0    12 sym._fini
0x080491a6     0   73     4     4     2   34 0x080491a6    73 0x080491ef     3    1      1    0    28 sym.win
0x080490d0     0    5     1     0     1    4 0x080490d0     5 0x080490d5     0    0      0    0     0 sym._dl_relocate_static_pie
0x0804923c     0   24     1     0     1   15 0x0804923c    24 0x08049254     2    0      0    2     4 main
0x08049254     0    4     1     0     1    4 0x08049254     4 0x08049258     0    0      0    2     0 sym.__x86.get_pc_thunk.ax
0x080491ef     0   77     1     0     1   36 0x080491ef    77 0x0804923c     4    2      0    1    76 sym.read_in
0x08049000     0   36     3     3     2   19 0x08049000    36 0x08049024     1    0      0    0    12 sym._init
``` 
{% endtab %}
{% endtabs %}

You can use the `aflm` command to list the commands based on the function they're called in.
```nasm
[0x0804923c]> aflm
entry0:
    fcn.080490bd
    sym.imp.__libc_start_main

sym.__do_global_dtors_aux:
    sym.deregister_tm_clones

sym._fini:
    sym.__x86.get_pc_thunk.bx

sym.win:
    sym.__x86.get_pc_thunk.ax
    sym.imp.puts
    sym.imp.system

main:
    sym.__x86.get_pc_thunk.ax
    sym.read_in

sym.read_in:
    sym.__x86.get_pc_thunk.bx
    sym.imp.puts
    sym.imp.fflush
    sym.imp.gets

sym._init:
    sym.__x86.get_pc_thunk.bx
```

 ## Printing Data
 ### Examining Memory
 ### Searching Memory
 