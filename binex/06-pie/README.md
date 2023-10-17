# 0x6: PIE

**PIE** stands for _**P**osition **I**ndependent **E**xecutable_. This is a **compile-time** security feature that loads the binary into a different memory address each time it's run. This means that we can't hardcode function addresses into our exploit.

### The Theory

Binaries with PIE enabled are not impossible to exploit. The driving theory around PIE exploits is that all code is relative to a base address. Moreover, loading the binary does not change the functions' length or order.

For example, consider the following functions list:

```as
0x000011cd  main
0x000011e9  read_in
0x0000123d  win
```

`gdb` recognizes that PIE is enabled and will show the addresses during disassembly based on the base address. No matter where we set the base address of the binary, `main` will always be at `0x000011cd` from the base address, `read_in` will always be at `0x000011e9` from the base address, etc.

### Attack Vector

To perform this exploit, we only need to find a single address in the binary. Given the offset, we can find the base address, bypassing PIE!

One way that this can be done is to _leak the return pointer_. The return pointer for any function is always a static offset from the base, meaning that if we can get the return pointer, we can find the base address.

This is often done using a format string vulnerability or some way to leak values off the stack.

### Essential Notes

Modern operating systems use **paging** to manage memory. These pages are 4 kilobytes in size (the equivalent of `0x1000`).

Because of paging, the OS loads a PIE executable into memory at a **page-aligned** address. This means that the base address will always be a multiple of `0x1000`. This means that as a preliminary check, we can check the base address of the binary and see if it's a multiple of `0x1000`. If it's not, we most likely leaked the base address incorrectly.
