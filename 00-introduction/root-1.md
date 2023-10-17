---
description: Navigating the Linux file system using the command line.
---

# root-1

Category: introduction (0x0)\
Points: 50

## Description

> This flag is contained somewhere in some file. Can you find this flag?

This challenge was designed to test your ability to use the `man` pages to understand how functions work and successfully and efficiently navigate the Linux terminal.

## Flag

```
flag{hope_you_didnt_solve_manually}
```

## Hints

1. Think about the format of the directory. What types of characters are in the files? What might not be there?

## Solution

```bash
$ grep -r "flag{" .  

./YGE8xafxo1aDyyDaP64vFT5R/OYPuOaJxX4NlA2doAGOpb04y/v6nhCxEFm5Jk8xXfwi9vSEXS/i2nqw0ZUHwUy5G9udh0PqZCe/CQY19DujzCEOFWExctTxlA8e/e6kbvlh6ZCYcfTp9Yq5eJMwb:UP4APiMOtGHslVhRxPiJeYUYxTV2mJycZq7ahaO4MgjpSiflag{hope_you_didnt_solve_manually}5V6qrPfFCXvWQPFZcavAKw3GVbiw3S1dXc7fI8An9vDnIMknAdtijd2VAFQb8vobfN4q14sTFvqJrcjWWVJtxCIqMmvRz6Y4ECz9v6QNFjL6zr0LL0cEYTrCKQwqeX1pAV2fLF7CG6S1nT0lQcDJXJ470I3WCe1xJcTDf7PXFukVvKoQb1xMODvoIOTQ10HUVEaZFX70H8WtMGqLYLeRyicAFwuSkbPcoWxXhS33ZltFOtROXs8ivDJMfMNy7iIiCBVeomXJXCwKLe2XxayiXXPL2BaArnQEg8L2oca2o6UugMXLIrSvIVi67oPVDyZBNLYNX8T2UqSeTFpwiMf6iefp6iBhRSIbuS1GtwH6EMIDgVed5tclJoGu3eemBnwKJsWQpjbhfPHlEdK87cGR1a40qUHqGudjNMlHnzyz32J5a3qvStcFqYJ2IRpUptRKCXlXboGx4LhKdFMh9HIzuSsF77Y6mbJLdMDFHRTXD7ThYs7WnF3tqK7qjzND73vy7TDlFxi5w3ZsJWg9Tpu85oC1EwGEROMwqtKQ4ZiP1GUj3XmSlEUIzRvHr08TNNPManY7acGlOcBjFU49DWWm4Q6vToHisYUu9CSyQoGG2cCEoL52xjRP3o8seUDuvKkFsU192CyEujhKjyEK1vLuZJY6mb1pxKVUW4kGx76jR2HlRLNz4ZU0
```

`grep` formats results `./file:content_match`.
