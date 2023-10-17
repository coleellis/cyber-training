# 0xA: Programming

This part of the programming section covers all data that is not serialized. This means that the data can be read as plaintext. Our goal will be to read the data, parse it as indicated by the instructions, and print the resulting flag.

These challenges vary in difficulty. The hardest challenges will often be non-serialized because a much broader spectrum of challenges can appear. Covering every type of challenge is impossible, so exposure and practice is the best way to prepare.

Some challenges may not require that you design the solution in C. For example, you may be solving a higher-level real-world challenge where it is impractical to use a low-level language. I recommend you be familiar with a high-level language (**Python** is a great choice) to make easy work of these challenges.

Below is a list of topics essential to do well in the programming section and essential functions that we use in C to read and parse data.

## Data Structures

The driving knowledge behind the programming section is comfort with **data structures**. This is typically covered in a second-year computer science course. The challenge is building these in C because C _has no classes_. Below is a list of essential data structures that you should be familiar with:

* Static and Dynamic Arrays
* **\*Linked Lists\***
* Stacks and Queues
* Trees and Tries (Binary and N-ary)
* Maps and Hash Tables

Because we have no classes in C, our only way to concatenate data is by using `struct`. A `struct` is a collection of data. All the data in the `struct` is "public"; however, C does not recognize public and private (unlike C++). `struct`s cannot have methods, so all functions we use are independent. We often pass `struct`s as pointers to these functions as the first parameter.

Here is an example of a `struct`:

```c
struct Point {
    int x;
    int y;
};
```

When we want to reference this `struct`, we must use the `struct` keyword. This is because `struct`s are not objects, so we must specify that we are using a `struct`. Here is an example:

```c
struct Point p;
```

If we want to avoid using the `struct` keyword, we can use a `typedef` on the same line to rename it. Here is an example:

```c
typedef struct {
    int x;
    int y;
} Point;
```

Then, when we want to reference this `struct`:

```c
Point p;
```

This comes with one caveat. If we want to reference the `struct` inside of the `struct` itself, we must provide the `struct` a name before we use `typedef`. The most common example is a linked list node. Here's how we get around this:

```c
typedef struct NodeItem {
    int data;
    struct NodeItem *next;
} Node;
```

## Algorithms

We define **algorithms** as a process that uses our data structure to perform a specific operation. This is often covered in more detail within a third-year CS course, but the second-year fundamentals course is usually enough. These are the most common algorithms that we use in CTFs:

* Sorting (quicksort, mergesort, heapsort, etc.)
* Searching (linear, binary, etc.)
* Traversals (BFS/DFS, shortest path, etc.)
* Recursion

## Time Complexity

This is an essential topic to computer science. **Time complexity** is a function that represents the speed of a function relative to various parameters. The most common parameter is _the size of the input_. In each challenge, you should aim for the lowest time complexity possible. Time complexities are a combination of the complexity of the sub-functions used.

You should know the time complexities for the algorithms you use. For example:

* The fastest way to sort is `O(n log n)`.
* Binary search is achieved in `O(log n)`.
* The fastest DFS algorithm is `O(V + E)`. `V` is the number of vertices and `E` is the number of edges.
* Using a `for` loop to iterate through an array is `O(n)`.
* Arithmetic Operations are `O(1)`.

As we see with DFS, there can be more than one parameter that defines the size of the input.

_As a general note_, no solution to a challenge should be slower than `O(n^2)`. `n^2` algorithms are generally considered slow, especially for very large inputs. You should aim for `O(n log n)` when sorting is required and `O(n)` otherwise.

## Essential Functions

Let's discuss the most common functions we use in C for these challenges. These are important for reading and parsing data.

### Opening Files and the File Pointer

We use `fopen()` to open a file. This returns a `FILE *` that we can use to read the file. Here is an example:

```c
FILE* fp = fopen("input.txt", "r");
```

If the file was not found or could not be opened for reading, `fopen` returns `NULL`. We should always make this check before we continue.

```c
if (fp == NULL) {
    printf("Could not open file.\n");
    exit(EXIT_FAILURE);                     // EXIT_FAILURE = 1
}
```

We can modify the file pointer to change where we are in the file. We do this using `fseek()`. `fseek` is a tricky function to use because it depends on the _number of characters read_ rather than the number of lines read. The most common way we use `fseek` to return to the start of the file. We do this using the following:

```c
fseek(fp, 0, SEEK_SET);                     // SEEK_SET = start of file
```

In this function, `0` represents the offset from `SEEK_SET`, meaning we want to move `fp` to the start of the file. The other two macros we see are `SEEK_CUR` (where the file pointer is) and `SEEK_END` (end of the file).

We can use `ftell()` to tell us where we are in the file. It takes the argument of `fp` and returns the number of characters read thus far.

Once we are finished, we need to close the file using `fclose(fp)`.

### Reading Files

There are many ways to read files. We will use a combination of techniques based on the data we are reading. Let's look at these further.

If we want to read an entire line of data, we can use `getline()`. This function takes a `char**` which acts as a pointer to a string, a `size_t*` which acts as the size of the string, and a `FILE*` which is the file pointer. This function will read the entire line of data and store it in the string. It will also update the size of the string. Here is an example:

```c
char* line = NULL;
size_t len = 0;
getline(&line, &len, fp);
```

`getline` returns an `ssize_t` which is the number of bytes _actually read_. If the line is empty, it will return `-1`. We should always check this to ensure we are not at the end of the file. Here is an example:

```c
ssize_t read;
while ((read = getline(&line, &len, fp)) != -1) {
    // do something
}
```

{% hint style="warning" %}
#### _What is the difference between `read` and `len`?_

`read` represents the number of bytes actually read into `line`, while `len` is the maximum size of the buffer.
{% endhint %}

If we want to read a certain number of bytes, we can use `fgets()`. This is not a new function for us. Instead of reading from `stdin`, we'll pass the file pointer as the third argument. Here is an example:

```c
char line[100];
fgets(line, 100, fp);
```

If we know the format of the string we are reading and want to directly collect the data, we can use `fscanf()`. This function takes a format string representing how we want to read the data and then pointers to each data we will read. Here is an example:

```c
int a, b, c;
fscanf(fp, "%d %d %d", &a, &b, &c);
```

### Parsing Data

We will use a combination of functions to parse data. Since most of our data is using strings, we will frequently use the `string.h` library functions.

If we want to split a string into tokens, we can use `strtok()`. This function takes a string and a delimiter and returns the next token. Here is an example:

```c
char* first_token = strtok(line, " ");
```

This function internally remembers where we are on the line. Therefore, if we want to continue parsing the line, we can pass `NULL` as the first argument. Here is an example:

```c
char* second_token = strtok(NULL, " ");
```

To introduce a new string to parse, just pass the new string as the first argument.

If we want to convert a string to an integer, we can use `atoi()`. This function takes a string and returns the integer representation. Here is an example:

```c
int a = atoi(first_token);
```

If we want to convert a single-character string to a character, we can use `strtol()`, or simply index the string. Here is an example:

```c
char c = first_token[0];
```
