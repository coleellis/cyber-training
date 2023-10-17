# Rock Paper Scissors

*You should be able to code this challenge in C.*

## Overview
You are going to write an algorithm which opens a file `input.txt` and 

## Instructions
A group of Midshipmen are trying to decide who gets the best summer cruise slots for the upcoming summer cruise.  They decide that a Rock Paper Scissors tournament is the best way to decide who gets what.

Rock Paper Scissors is a game between two players. Each game contains many rounds; in each round, the players each simultaneously choose one of Rock, Paper, or Scissors using a hand shape. Then, a winner for that round is selected: Rock defeats Scissors, Scissors defeats Paper, and Paper defeats Rock. If both players choose the same shape, the round instead ends in a draw.

In support of your victory, an unnamed Active Duty Officer gives you an encrypted strategy guide that they say will be for sure to help you win. *The first column is what your opponent is going to play: `A` for Rock, `B` for Paper, and `C` for Scissors.  The second column....* The Active Duty Officer is called away to help with more urgent matters.

### Part 1

You reason that the second column must be what you should play in response: `X` for Rock, `Y` for Paper, and `Z` for Scissors.

The winner of the whole tournament is the player with the highest score. Your total score is the sum of the scores per round. The score for a round is the score for the *shape you selected* (1 for Rock, 2 for Paper, and 3 for Scissors), plus the score of the outcome round (0 if you lose, 3 if you draw, and 6 if you win).

Consider the following strategy guide:
```
A Y
B X
C Z
```

This strategy guide recommends the following:
* In the first round, your opponent chooses Rock and you should choose Paper. This ends in a win with a score of **8** (2 for paper + 6 for win).
* In the second round, your opponent chooses Paper and you should choose Rock. This ends in a loss with a score of **1** (1 + 0).
* The thid round is a draw with both players choosing Scissors, giving a score of 3 + 3 = **6**.

Therefore, following the strategy guide, you would get a total of **15**.

Your part 1 answer is the total score if everything goes according to the strategy guide.

### Part 2

The unnamed Active Duty Officer returns to you.  He says, "*Anyway, the second column indicates how the round needs to end. `X` meaning a loss, `Y` meaning a draw, and `Z` meaning a win. Good luck MIDN!*"

The total score is figured out the same way, but now you need to figure out what to choose so the round ends as indicated. The example now goes like this:
* Round 1: Your opponent chooses Rock, and you must Draw, therefore you also choose Rock. This gives a score of 1 + 3 = **4**.
* Round 2: Your opponent chooses Paper, and you choose Rock so you lose with a score of 1 + 0 = **1**.
* Round 3: You defeat your opponent's Scissors with Rock for a score of 1 + 6 = **7**.

With this strategy, you will get a top score of 12.

Your part 2 answer is the total score if everything goes according to the strategy guide.

### Final Answer

Submit your final answer in the form `flag{Part1_Part2}` where `Part1` and `Part2` are the answers for each part.  In the example above, `flag{15_12}` would be your answer.

## Scoring 
When preparing a writeup, you will be evaluated based on the following software engineering pillars:
* Correctness (printing the flag)
* Safe from bugs (handles bad input without crashing)
* Easy to understand (commented and inuitive program structure)
* Ready for change (modular implementation)
* Adherence to the [Google C Style Guide](https://google.github.io/styleguide/cppguide.html).
