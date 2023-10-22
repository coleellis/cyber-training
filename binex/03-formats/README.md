# 0x3: format strings

### Theory

The format string bug is a vulnerability caused when a program uses `printf` or `sprintf` without correctly specifying the arguments. Proper use of the `printf` function takes a string containing format specifiers, then secondary arguments with the value for those specifiers.

Here is an example of the proper use of `printf`:

```c
char* name = "Hello World";
printf("Your string: %s\n", name);
```

Rather than printing the value of `name` directly, the `%s` (string) specifier is used. There are many format specifiers; the most common are:

* `%s` - string
* `%d` - decimal
* `%x` - hexadecimal
* `%p` - pointer

What happens if we request more format specifiers than there are arguments? For example, what if we do the following:

```c
char* name = "Hello World";
printf("Your string: %s %s\n", name);
```

This prints the following: `Your string: Hello World ��Fb�`.

{% hint style="warning" %}
#### _What is the second string?_

When `printf` uses a format string specifier, it requests another parameter to be passed into the function. Depending on the architecture, the binary will then look inside either the next parameter register (x64), or the top of the stack (x86) for that parameter. Sometimes this is gibberish, but if we leak enough data we can almost always leak something important. Or, as we'll discuss in this challenge, we can write data to an address of our choice.
{% endhint %}

The bug becomes more vulnerable when the program uses `printf` to print a variable directly rather than using a format specifier. For example, the following code is vulnerable:

```c
#include <stdio.h>

int main(void)
{
	char buffer[100];
	fgets(buffer, sizeof(buffer), stdin);
	printf(buffer);
	return 0;
}
```

This code is **not** susceptible to stack smashing because the `fgets` call verifies that no more than `100` bytes of data are inputted into the buffer. However, the `printf` call is vulnerable. If we choose our input to have format specifiers, we can leak data from registers or the stack. Consider this run:

```nasm
$ ./vuln
%x %x %x
78252078 fbad2288 366932a9
```

In this case, we leaked data off the stack! This is the basis of the format string bug.

We can further improve its usability by directly deciding where we want to leak. C provides syntax for printing variables in any order by listing their index. The format of this is `%k$x`, where `k` is the index of the variable to print. For example, the following code prints the first and second variables in reverse order:

```c
#include <stdio.h>

int main(void)
{
    int x = 4; int y = 5;
    printf("%2$x %1$x\n", x, y);
    return 0;
}
```
