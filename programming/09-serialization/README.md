# 0x9: Data Serialization

This part of the programming section covers **serialized data**. Serialized data is stored in binary, meaning it is not readily human-readable. Since many characters stored will not be in ASCII, reading the file does nothing for us.

Each challenge will instruct us on how the data is formatted. We will typically be provided a data structure that is used to store the serialized elements. Each part of the data structure will have a specific size (either fixed or variable). We will use this to read the data into the structure.

We must process the data once we read the structure to get the flag. This will be different for each challenge, but we will walk through each. This is typically not terribly challenging, especially if you're confident in the other half of the programming section.

## Reading Data

When we read data, we will use the binary flag on `fopen` to indicate we are reading binary data. We will use `fread` to read all the data because this lets us specify the number of bytes we want to read. This way, we can control how much data is read into the variable we store.

We will almost always build a `struct` containing a data structure representing the serialized data. When we read the data, we can read it right into the `struct` without any trouble. Then, we can process the data stored in the struct.

We will use two primary methods for storing the `struct`. There are some advantages and disadvantages to both:

* **Static Array**. This is the easiest way to do it and requires the least overhead. It's the hardest to mess up and the easiest to clean up once the program is done. The challenge is determining the amount of space to allocate, leading to a non-space-efficient solution. We can use this for nearly every challenge.
* **Linked Lists**. This is best for challenges involving stacks, queues, and linked lists. This is a space-efficient solution because we only use the space we need to store data. However, it's much more painful to build and even worse to clean up. We must be careful when using linked lists not to cause memory leaks.

Nearly all the challenges are formatted the same. We can use the same template for nearly all of them. This is almost true for the non-serialized section, too.

Let's get solving!
