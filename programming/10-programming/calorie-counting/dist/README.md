# Calorie Counting

*You should be able to code this challenge in C.*

## Overview
We are going to write an algorithm which opens the file `input.txt`, load in a list of data, and compute a total Calorie amount based on the below specification. The flag can be printed out by printing the total Calorie amount of the top three Cadets.

## Instructions
### Introduction
A group of VUAROTC Cadets are carrying rucksacks that are full of meal rations for their time at advanced camp.  In order to best determine how much supply they have, they use the amount of calories in each of their meal portions to determine how much time they can survive off their rations.

When each Cadet arrives into formation, they are tasked with writing down the amount of calories that each of them has in their rucksack.  They write each item in its own line and separate each cadet with a unique line.  The goal of the First Sergeant is to determine which 3 Cadets are carrying the longest supply of food in their rucksack (i.e. who has the most number of Calories).

### Reading the File
Consider the following list of Cadets and their rucksack amounts:
```
1000
2000
3000

4000

5000
6000

7000
8000
9000

10000
```

From here, we would see that the **fourth** Cadet is the one with the highest number of Calories, holding *24,000* Calories in his rucksack.

### Printing the Flag
Given the input file, `input.txt`, figure out which 3 Cadets have the most number of Calories in their rucksack, and find the total number of Calories that each of them have.  

Submit your answer as an integer wrapped in the `flag{}` braces (for example, `flag{24000}`).

## Scoring 
When preparing a writeup, you will be evaluated based on the following software engineering pillars:
* Correctness (printing the flag)
* Safe from bugs (handles bad input without crashing)
* Easy to understand (commented and inuitive program structure)
* Ready for change (modular implementation)
* Adherence to the [Google C Style Guide](https://google.github.io/styleguide/cppguide.html).
