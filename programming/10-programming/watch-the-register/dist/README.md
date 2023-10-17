# Watch the Register

*You should be able to code this challenge in C.*

## Overview


## Instructions
You are working with a very simple model of CPU that only has one register, `X`.  This register, on startup, holds the value `1`.  This register only supports two instructions:
* `addx n` takes *two cycles* to complete.  After two cycles, the `X` register is increased by the value of `n` (`n` is an integer).
* `noop` takes one cycle to complete.  It has no other effect.

You are passing the CPU these instructions in the form of a program (the input), which tells the CPU how to display output.

### Reading the File
Upon further investigaiton, you found that the `X` register controls the horizontal position of a sprite.  Specifically, the sprite is 3 pixels wide, and the `X` register sets the horizontal position of the middle of the sprite.  The CPU's display is 40 pixels wide and 6 pixels tall.  The CPU draws a single pixel during each cycle count, either a `#` or a `.`.  Here is an example of how the display is formatted:
```
Cycle   1 -> ######################################## <- Cycle  40
Cycle  41 -> ######################################## <- Cycle  80
Cycle  81 -> ######################################## <- Cycle 120
Cycle 121 -> ######################################## <- Cycle 160
Cycle 161 -> ######################################## <- Cycle 200
Cycle 201 -> ######################################## <- Cycle 240
```

Each pixel is formatted as follows.  If the sprite is positioned such that one of its three pixels is the pixel currently being drawn, the screen produces a lit pixel (`#`); otherwise, the screen leaves the pixel dark (`.`).

### Printing the Flag
Render the image that the CPU would output given the input program in *input.txt*.  Determine the 8 capital letters that appear on the display, and turn in those letters embraced in `flag{}` braces.

### Example
Consider the following small program:
```
noop
addx 3
addx -5
```
Execution of this program proceeds as follows:
* At the start of the first cycle, the `noop` instruction begins execution. During the first cycle, `X` is `1`. After the first cycle, the noop instruction finishes execution, doing nothing.
* At the start of the second cycle, the `addx 3` instruction begins execution. During the second cycle, `X` is still `1`.
* During the third cycle, `X` is still `1`. After the third cycle, the `addx 3` instruction finishes execution, setting `X` to `4`.
* At the start of the fourth cycle, the `addx -5` instruction begins execution. During the fourth cycle, `X` is still `4`.
* During the fifth cycle, `X` is still `4`. After the fifth cycle, the `addx -5` instruction finishes execution, setting `X` to `-1`.

Now, let's see how this outputs. Here's a slightly larger program:
```
addx 15
addx -11
addx 6
addx -3
```

Here is the execution:
```
Sprite position: ###.....................................

Start cycle   1: begin executing addx 15
During cycle  1: CPU draws pixel in position 0
Current CRT row: #

During cycle  2: CPU draws pixel in position 1
Current CRT row: ##
End of cycle  2: finish executing addx 15 (Register X is now 16)
Sprite position: ...............###......................

Start cycle   3: begin executing addx -11
During cycle  3: CPU draws pixel in position 2
Current CRT row: ##.

During cycle  4: CPU draws pixel in position 3
Current CRT row: ##..
End of cycle  4: finish executing addx -11 (Register X is now 5)
Sprite position: ....###.................................

Start cycle   5: begin executing addx 6
During cycle  5: CPU draws pixel in position 4
Current CRT row: ##..#

During cycle  6: CPU draws pixel in position 5
Current CRT row: ##..##
End of cycle  6: finish executing addx 6 (Register X is now 11)
Sprite position: ..........###...........................

Start cycle   7: begin executing addx -3
During cycle  7: CPU draws pixel in position 6
Current CRT row: ##..##.

During cycle  8: CPU draws pixel in position 7
Current CRT row: ##..##..
End of cycle  8: finish executing addx -3 (Register X is now 8)
Sprite position: .......###..............................
```

## Scoring 
When preparing a writeup, you will be evaluated based on the following software engineering pillars:
* Correctness (printing the flag)
* Safe from bugs (handles bad input without crashing)
* Easy to understand (commented and inuitive program structure)
* Ready for change (modular implementation)
* Adherence to the [Google C Style Guide](https://google.github.io/styleguide/cppguide.html).
