# 0x4: stack canaries

**Stack Canaries** are one of the most common protections against buffer overflow attacks. They are a simple yet effective compile-time solution that requires no extra coding effort from the developer.

## The Theory

A stack canary is an address-sized value randomly generated every time the program runs. Whenever a function is called, the random canary value is generated, pushed into a global address, and then also onto the stack. Right before the function returns, the program checks the canary on the stack to the canary stored in the global address. If they are not the same, the canary has been overwritten, and the program will immediately crash.

To beat a stack canary, you must find it on the stack somehow. In `gdb`, this is an easy task because we have clear access to the stack frame. However, this is impossible against remote servers because we can't use `gdb` when interacting with a remote process.

The most common way we leak stack canaries is through the format string bug. Because the canary is stored on the stack, we can use the format string bug to find the canary directly. Once we have the canary, we can append this to our payload.

### Some Notes

`gdb-gef` allows us to directly check the value of a canary while inside a function. Using the `canary` function, it will show us where the canary is stored in memory and its value.

It's important to note that despite random number generation, canaries always end in `0x00`. This is because the canary is stored as a string, and strings are null-terminated. We can use this to our advantage when searching for canaries on the stack, because we can look for this pattern.
