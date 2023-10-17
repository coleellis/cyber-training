---
description: Navigating the Linux file system using the command line.
---

# root-2

Category: introduction (0x0)\
Points: 50

## Description

> There's a file somewhere with the flag name. Can you find this filename?
>
> Note: The file is in the format `flag_this_is_flag_contents`. Submit this as `flag{this_is_flag_contents}`.

This challenge was designed to test your ability to use the `man` pages to understand how functions work and successfully and efficiently navigate the Linux terminal.

## Flag

```
flag{grep_is_super_useful}
```

## Solution

```bash
$ find . -type f -name "flag_*"

./YGE8xafxo1aDyyDaP64vFT5R/OYPuOaJxX4NlA2doAGOpb04y/v6nhCxEFm5Jk8xXfwi9vSEXS/i2nqw0ZUHwUy5G9udh0PqZCe/CQY19DujzCEOFWExctTxlA8e/JvPJDSFg5SmSEjQzDvYXBfjr/gF69ZBN0AZ5eke6UKGbn8zUH/83CTJbSYq5nsMmDit68YSLwL/uvHFF8dtJ2ieBAgy2EzMXyqd/jyqsAjz1XqC0wRP7YcsUR3J5/VC7GYjfmHx8TDJDalRHXQp9u/uKNLe5JiOBzvpTgUWaiGORLu/cFMWlaQzHYNev7SBxsTsv9P7/QnBl6PAppZ6phL6FqPRoCTd6/flag_grep_is_super_useful
```
