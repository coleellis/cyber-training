---
description: Writing shellcode, but we're limited on space.
---

# constrained

{% file src="../../.gitbook/assets/constrained.zip" %}

Category: shellcodes (0x2)\
Points: 50

## Description

> Sometimes you have to work in tight spaces... can you still manage to pop the shell?\
> `nc vunrotc.cole-ellis.com 2200`

This is a 32-bit shellcode where the user is provided the address of the buffer.

## Flag

```
flag{shellstorm_is_really_useful}
```

## Solution

You'll realize that your solution from `shell` works here if you use Shellstorm 811 for your shellode. The buffer is small enough to hold the entire shellcode. Change the return pointer, and you'll pop a shell!
