# Mountain Climbers

*You should be able to solve this in C.*

## Overview
You are going to write a program which opens the file `input.txt` and finds the shortest path from the starting position to the end position.  The path is constrained by the elevation of the surrounding area.

## Instructions
A group of motivated MIDN are lost and are trying to reach the highest point in the local area to figure out where they are.  They handily have a contour map which shows them the elevation levels of the surrounding area.  The contour map is broken into a grid; the elevation of each square on the grid is given by a single lowercase letter, where `a` is the lowest elevation and `z` is the highest elevation.

Also included in the heightmap are your current position (`S`) and the target position for the best view (`E`).  Your current position has elevation `a` and the target position has elevation `z`.

You would like to reach `E`, but to save energy for the rest of the trip home, want to do it in as few steps as possible.  During each step, you can move exactly one square up, down, left, or right.  Because a certain MIDN forgot their climbing gear at home, the elevation of the destination square can be ***at most one higher*** than the elevation of the current square.  Meaning, if you are at an elevation of height `m`, you can step to `n` but not to `o`.  This also means that the elevation of the destination square can be much lower than the elevation of your current square.

### Reading the File
Consider the following input:
```
Sabqponm
abcryxxl
accszExk
acctuvwj
abdefghi
```

You start in the top-left corner and your end goal is in the right middle.  You could start moving down, and there a few ways to do this, but eventuually you need to reach the `e` to start the spiral up the mountin. 
```
v..v<<<<
>v.vv<<^
.>vv>E^^
..v>>>^^
..>>>>>^
```

This path reaches the goal in `31` steps, which is the fewest possible.

### Printing the Flag
You have two parts to this challenge:
1. Find the fewest number of steps to move from starting position `S` to the target location.
2. Find the fewest number of steps to move from any base position `a` to the target location.

Concatenate these answers in flag braces separated by a semicolon (`flag{part1:part2}`).

## Scoring 
When preparing a writeup, you will be evaluated based on the following software engineering pillars:
* Correctness (printing the flag)
* Safe from bugs (handles bad input without crashing)
* Easy to understand (commented and inuitive program structure)
* Ready for change (modular implementation)
* Adherence to the [Google C Style Guide](https://google.github.io/styleguide/cppguide.html).
