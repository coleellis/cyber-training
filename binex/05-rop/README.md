# 0x5: ROP

ROP, or **Return Oriented Programming**, is the creation of payloads that use the existing code in the binary, as well as the control of the instruction pointer, to execute instructions out of order to achieve a desired result.

ROP is primarily a 64-bit technique. Performing ROP exploits involves building chains of **gadgets**, which are small snippets of instructions already in the binary that end in a `ret` statement. These gadgets are chained to jump from function to function, loading registers with desired values, until the desired result is achieved.

{% hint style="info" %}

### _Why is ROP not used on 32-bit?_

The primary use of ROP is to load registers with desired values so they can be passed to functions. In 32-bit, parameters to functions are passed on the stack, so careful stack placement could be used to pass parameters. In 64-bit, parameters are passed in registers, so ROP is necessary to load registers with desired values.

{% endhint %}

ROP is a difficult technique to master, but it is a powerful one. It relies on the existence of a buffer overflow because we need access to write to the return pointer. It also relies on the existence of gadgets, which are not always present in binaries. However, when it works, it is a powerful technique.

### The Challenges

All the challenges in this section are sourced from [ROP Emporium](https://ropemporium.com/). It is the best resource I know for learning ROP. The challenges I host are the 64-bit editions of these challenges.

There are 8 challenges on the site, but I only cover the first five. They are more than enough to understand ROP. Frankly, the last three are really hard! If you want to challenge yourself, they're a great place to test your skills.
