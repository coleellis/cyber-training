# Hash

## Overview
Hashing is a very common technique in the cryptography sector that converts data into a small readable value.  Hashing is essential for data authentication because it allows for the comparison of data without having to store the original data.

You are going to hash your own data in this problem using the MD5 hash algorithm.

## Instructions
The Vanderbilt Blockchain Club needs help mining some VandyCoins to use as gifts for all the economically forward-thinking little girls and boys.

To do this, they need to find the MD5 hashes in which, in hexadecimal, start with at least **six zeroes**.  The input to the MD5 has is some secret key, followed by a number in decimal.  To mine VandyCoins, you must find the lowest positive number with no leading zeroes (1, 2, 3...) that produces such a hash.

For example, if the secret key is `abcdef`, the answer is **6742839** because the MD5 hash of `abcdef6742839` starts with 5 zeroes (`000000072a1e4320d13deee9d934ae29`), and is the lowest to do so.

Your input is `ckczppom`.  Encapsulate your answer in `flag{}` braces.