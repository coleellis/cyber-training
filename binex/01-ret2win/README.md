# 0x1: ret2win

A ret2win is the most straightforward class of binary we can exploit.

### The Theory

The crux of the ret2win exploit is that, by default, binaries store essential addresses on the stack. At the same time, when we provide input to the binary, we also write our data to the stack. In vulnerable binaries, we can write more data than allotted by the buffer. If the binary does not take proper precautions to check that we don't write too much data, we can overwrite the function's return address. We can go anywhere we want by overwriting the return pointer in the binary.

The most important idea to note is that we cannot add new instructions to the binary in nearly all cases. We must work with the current instructions to achieve the desired results.

{% hint style="info" %}
_The only time we can add new instructions is using **shellcode** exploits. This requires the prerequisite that the stack is marked as executable. If this is the case, we can write new instructions to the stack, point the instruction pointer to that location, and force those instructions to execute._
{% endhint %}

ret2win vulnerable binaries will have a `win()` function that does a desired action, such as printing a flag. Therefore, the goal of the exploit is to overwrite the return address of the current function with the address of the `win()` function. This will cause the program to execute the `win()` function, and print the flag.
