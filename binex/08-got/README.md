# 0x8: GOT overwrites

The GOT overwrite is a simple concept to explain. The driving idea behind the exploit is in the name -- we are overwriting data inside the GOT table.

### The Theory

We know the GOT table contains pointers to the absolute addresses inside the `libc` library. Imagine a scenario where the GOT table was writeable. We know the address of the GOT table because it's inside the binary. If we overwrite the GOT table, we can effectively change where a PLT function points.

This is only effective if we can beat PIE or if PIE is disabled. We need the absolute address of the GOT table to overwrite it. If PIE is enabled, the GOT table will be randomized, and we won't know its address.

Let's look at why the GOT overwrite is effective. Imagine the following code:

```c
char buffer[40];
gets(buffer);
puts(buffer);
```

This code would take our data and send it back to us. However, if we were able to manipulate the GOT table, we could change the address of the `puts` function to the address of another function, like `system`. This would effectively change the program to the following:

```c
char buffer[40];
gets(buffer);
system(buffer);
```

I wonder what we could do with this. Maybe read the flag? Spawn a shell? We could do anything.

### Restrictions

This is where the last restriction on the `checksec` output comes into play. The one we haven't discussed in detail is **RELRO**.

**RELRO** (**RE**location **L**ink **R**ead-**O**nly) is a security feature that makes the GOT table read-only. This means that we can't overwrite the GOT table. This is a problem because we need to overwrite the GOT table to exploit the program.
