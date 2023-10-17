# 0x2: shellcodes

Shellcode exploits are a tricky concept to understand and execute. **Shellcode** is a series of instructions passed as data to the binary. The goal of a shellcode exploit is to pass new instructions into the binary and then move the instruction pointer to the location of the shellcode so that our instructions are executed.

For example, if we used shellcode to open and read the file _flag.txt_, the _binary would read the flag itself._ This is particularly effective if the flag has restricted permissions that prevent anyone from reading the file. Because the binary is reading the file, it would have the same permissions as the creator of the binary, which is usually the owner of the flag.

### The Theory

The reason that shellcodes work is because of the way that modern computers are built. Modern computers are built using _Von Neumann Architecture_, which uses the premise that data instructions are stored in the same memory. Because of this, **Von Neumann Architecture cannot tell the difference between data and instructions**.

The primary method the binary uses to distinguish data from instructions is the memory segment—the text segment, where the code of the binary lies, is marked as _executable_. On the contrary, other sections of memory are marked as _non-executable_. This means that the binary will only execute instructions in the text segment and will not execute instructions in other segments.

However, what happens when the stack is marked executable? That means we can pass instructions to the binary through the stack and then execute them. This is the basis of shellcode exploits. There are other types of shellcode exploits that don't rely on an executable stack, but those are more advanced and not covered in this course.
