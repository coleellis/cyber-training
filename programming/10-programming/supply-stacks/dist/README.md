# Supply Stacks

*You should be able to code this challenge in C.*

## Overview
You are going to write an algorithm which opens a file `input.txt` and follows a series of instructions to switch supply crates between stacks. You must track the crates that are on the top of each stack.

## Instructions
A MEU is about to depart on mission but are waiting for their final supplies to be unloaded from the ships.  Supplies are stored in stacks of marked crates, but because the supplies they need are buried under other crates, the crates need to be rearranged.

The ship has a giant carg crane capable of moving crates between stacks. To ensure none of them get crushed or fall over, the crane operator will rearrange them in a series of carefully planned steps.  After the crates are rearranged, the desired crates are on the top of the stack.

### Reading the File
The Marines have a drawing of the starting stacks and the rearrangement procedure (the input).  For example:
```
    [D]    
[N] [C]    
[Z] [M] [P]
 1   2   3 

move 1 from 2 to 1
move 3 from 1 to 3
move 2 from 2 to 1
move 1 from 1 to 2
```

In this example, we have three stacks of crates. The top of the file contains the current arrangement of the crates.  Following that is the rearrangement procedure, which is done as follows:
```
                                              [Z]                [Z]                [Z]
    [D]            [D]                        [N]                [N]                [N]
[N] [C]       ->   [N] [C]       ->       [C] [D]   ->   [M]     [D]   ->           [D]
[Z] [M] [P]        [Z] [M] [P]            [M] [P]        [C]     [P]        [C] [M] [P]
 1   2   3          1   2   3          1   2   3          1   2   3          1   2   3 
```

### Printing the Flag
The Marines just need to know which crates are going to be on top of the stack. In this case, our tops are `CMZ`.

Submit your flag as the order of what's on the top of each stack wrapped in flag braces, i.e. `flag{CMZ}`.

## Scoring 
When preparing a writeup, you will be evaluated based on the following software engineering pillars:
* Correctness (printing the flag)
* Safe from bugs (handles bad input without crashing)
* Easy to understand (commented and inuitive program structure)
* Ready for change (modular implementation)
* Adherence to the [Google C Style Guide](https://google.github.io/styleguide/cppguide.html).
