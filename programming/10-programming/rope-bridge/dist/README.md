# Rope Bridge

*You should be able to code this challenge in C.*

## Overview
You are going to write an algorithm which opens a file `input.txt` and follows a series of motions for the head of a rope. The rope is made up of a series of knots that move in accordance with the rules of the rope.  You will track the movement of the tail of the rope throughout the motions.

## Instructions
The Army is currently crossing a rope bridge that creases when walked on.  The bridge spans a gorge that was carved out be a massive river far below.  The bridge steps and twists; scared for their lives, the Army decides to model the rope physics and figure out where not to step.

Consider a rop with a knot at each end; these knots mark the head and the tail of the rope. If the head moves far enough away from the tail, the tail is pulled toward the head.  You are able to model the positions of the knots on a two-dimensional grid.  Following a series of motions for the head, you will determine how the tail will move.

### Reading the File
Take this example of two knots. Two adjacent knots must always be touching.  Here are some examples of valid positions:
```
....
.TH.
....

....
.H..
..T.
....

...
.H. (H covers T)
...
```

If the head is ever two steps up, down, left, or right from the tail, the tail must also move in one step that direction so it's close enough.
```
.....    .....    .....
.TH.. -> .T.H. -> ..TH.
.....    .....    .....

...    ...    ...
.T.    .T.    ...
.H. -> ... -> .T.
...    .H.    .H.
...    ...    ...
```

Otherwise, if the head and tail aren't touching and aren't in the same row or column, the tail always moves one step diagonally to keep up:
```
.....    .....    .....
.....    ..H..    ..H..
..H.. -> ..... -> ..T..
.T...    .T...    .....
.....    .....    .....

.....    .....    .....
.....    .....    .....
..H.. -> ...H. -> ..TH.
.T...    .T...    .....
.....    .....    .....
```

Your goal is to simulate a rope consisting of *ten* knots. One knot is the head of the rop and moves according to the series of motions. Each knot further down the rope follows the knot in front of it using the same rules above.  You need to keep track of the positions that the new tail, `9`, visits.

The file *sample.txt* considers a large sample of the following input:
```
R 5
U 8
L 8
D 3
R 17
D 10
L 25
U 20
```

### Printing the Flag
You are going to compute the *number of positions that the tail of the rope visits at least once*.
Note that the start point is arbitrary.

Encapsulate your answer in flag braces, i.e. `flag{36}`.

## Scoring 
When preparing a writeup, you will be evaluated based on the following software engineering pillars:
* Correctness (printing the flag)
* Safe from bugs (handles bad input without crashing)
* Easy to understand (commented and inuitive program structure)
* Ready for change (modular implementation)
* Adherence to the [Google C Style Guide](https://google.github.io/styleguide/cppguide.html).
