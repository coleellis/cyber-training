---
description: Using git to find changes in files.
---

# git-good

{% file src="../.gitbook/assets/git-good.zip" %}

Category: introduction (0x0)\
Points: 50

## Description

> Sometimes people think they can use Git to hide information... they're wrong.

The goal of this challenge is to have an understanding of how to use Git.

## Flag

```
flag{git_overwrites_still_visible_1738592}
```

## Solution

The most recent commit redacted the flag. We can grab the old commit by using `git log` to get the desired commit ID and then `git checkout <commit-id> filename` to get the old version of the file.
