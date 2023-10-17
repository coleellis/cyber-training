# What is Reverse Engineering?

Reverse Engineering, also written as **RE** and sometimes shorted to **rev**, decomposes a binary to a C-level to understand how it works. This skill is very important to have and works hand-in-hand with binary exploitation.

In reverse engineering challenges, software is used to decompile the binary into C code. The most common software to use is:

* [Ghidra](https://ghidra-sre.org/) - Free, open-source, and super popular
* [IDA Pro](https://www.hex-rays.com/products/ida/) - Paid, but has a free version
* [Binary Ninja](https://binary.ninja/) - Paid, but has a free version

Once you have the C code, it's a lot easier to understand what is happening.

The primary challenge behind reverse engineering challenges is that the program intentionally obfuscates the flag and then validates your input against the obfuscated code. Solving this involves reversing this obfuscation process, which results in the flag in raw bytes.

This can often be a challenging process and is hard to study for. Many techniques undergo various reversing challenges, and covering them all is impossible. To this day, I find myself struggling at the more advanced CTF reversing challenges because _they're just hard_.

This section will cover the basics of reverse engineering to provide an expectation of your base knowledge, plus how to use various decompiler software.
