# 0x7: ASLR

**ASLR** (**A**ddress **S**pace **L**ayout **R**andomization) is a popular security feature that randomizes the location of the _library file_. ASLR is a kernel protection feature, meaning that it's turned on or off _for the entire system_.

This is the equivalent of PIE for `libc`. This means that you cannot hardcode `libc` addresses into your exploit (such as `system` or `binsh`).

{% hint style="warning" %}
You can turn **on** ASLR using the following command:

```bash
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

ASLR can be turned **off** using:

```bash
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

This is useful for debugging. However, just be mindful that you're not hardcoding addresses in your exploit until the `libc` base address is leaked.
{% endhint %}

### The Theory

The exploit for this challenge is slightly different than that of the PIE exploit. Using a format string vulnerability isn't as simple as you'd think for two main reasons:

1. **Different `libc` versions**: Different systems run different `libc` versions, and unless the specific `libc` version is provided, the offsets for the return pointers can vary.
2. **Function Remnants**: When functions are called and then return, their code is not removed from memory. Instead, the stack frames used by these functions are considered free for reuse. If you're trying to leak a `libc` address, you might leak an old address used by a function that has already returned.

Instead, we look to the **GOT** (**G**lobal **O**ffset **T**able). The GOT is a table of addresses that are used by the binary. GOT addresses are valid _for the entire execution_ and don't become invalid when a function returns. It is the most reliable way to determine the address of a `libc` function.

### Attack Vector

If you can read an address from the GOT, you can get the actual address of where that function resides in memory, in turn providing the `libc` base address.

While ASLR will cause the `libc` base address to change between different executions of a program, the offset from the `libc` base to a particular function remains consistent for a given `libc` version. So, if you can leak one `libc` function address from the GOT, you can reliably calculate the address of other functions or gadgets in `libc`.

### The PLT and GOT Tables

When we discuss bypassing ASLR, it's essential to understand how library functions are linked to the binary. There are two ways binaries can be linked to libraries: statically and dynamically. **Static linking** is when the library functions are compiled directly into the binary. **Dynamic linking** is when the binary uses the library functions from a separate file.

Dynamic linking is the most common method of linking. This is because it allows the binary to be much smaller for distribution and achieves the same purpose. Every computer has a copy of the `libc` library, so there's no need to include it in the binary.

The primary issue with dynamic linking is that the binary needs to know where the library functions are in memory. This is where the **PLT** and **GOT** tables come in.

* The **PLT** (**P**rocedure **L**inkage **T**able) is used to call external functions. Each library function the binary uses has a corresponding entry in the PLT table. Calling a function from the PLT table is equivalent to calling the library function itself.
* The **GOT** (**G**lobal **O**ffset **T**able) is a big table of addresses. These addresses contain the locations in memory of the `libc` functions.

When a function is called, the binary goes to the PLT table and reads the GOT address from the corresponding entry. This is the address of the function in memory. The binary then jumps to this address and executes the function.

{% hint style="info" %}
If the address is empty, it checks the _dynamic linker_ to get the function address and then writes it to the GOT table.
{% endhint %}

_Why is this important?_ The GOT table resides within the binary itself, and it contains all the addresses of the `libc` functions. Because the GOT is part of the binary, it has a constant offset from the binary's base address. If PIE is disabled, or you can beat PIE, you know the exact address of the GOT table. This means that you can read the GOT table and get the address of any `libc` function. This beats ASLR!

The most common exploit that uses this is the `ret2plt` which will be discussed in the third binary.

### Essential Notes

`libc` base addresses are also multiples of `0x1000`, for the same reason as PIE. This means that you can check the base address of `libc` and see if it's a multiple of `0x1000`. If it's not, you most likely leaked the address incorrectly.
