# Cyber Training Guide

Welcome to my notes on offensive cybersecurity and low-level programming.

The site is being live hosted at: [https://cyber.coleellis.com](https://cyber.coleellis.com).\
The GitHub repository is located at: [https://github.com/coleellis/cyber-training](https://github.com/coleellis/cyber-training).

If this resource helped you out at all, consider supporting me on [Buymeacoffee](https://buymeacoffee.com/cyberguide) :)

### Who am I?

My name is Cole. I graduated from Vanderbilt University with a degree in computer science. During my time, I was a member of VandyHacks, Vanderbilt's CTF Team, and our SWE Internship Prep Team.

There are many sites out there that provide resources for learning binary exploitation, low-level programming, and reverse engineering. However, I found that many of these sites don't provide enough explanation of the theory; I always felt like something was missing in my understanding. I created these notes to help bridge the gap and provide a more comprehensive resource.

These notes primarily accompany an in-person lecture series I provide at Vanderbilt for NROTC students. I also aim to have these notes serve as a standalone resource for those who (1) may not go to Vanderbilt or (2) prefer to learn independently.

[My GitHub Account](https://github.com/thecae)\
[CTFTime Profile](https://ctftime.org/user/146369)

### What background is expected?

You are strongly recommended to have a basic understanding of computer science, especially with a lower-level language. I recommend that students from a higher-level language background (like Python) begin to study an object-oriented, statically typed language (like C, C++, or Java). Starting in the [Programming Section](programming/what-is-the-programming-section.md) may be a good idea if you're not confident in your programming skills.

The content in these lecture notes relies heavily on low-level programming, especially for binary exploitation. Much of our analysis is based on assembly code, which is the most accurate representation of the instructions being executed. Exploits are written in Python using the [pwntools](https://docs.pwntools.com/en/stable/) library, a Python library for binary exploitation.

The programming section requires familiarity with C. You should be comfortable with pointers, memory management in C, and file I/O for text and binary files.

### What are some other resources?

These notes are inspired by a series of helpful sources. I developed most of the challenges myself, but other sources inspired some. A few binaries come directly from CTF competitions; I cite those in the descriptions of the challenges.

Here is a list of the resources I recommend:

Learning Content

* [Ir0nstone's Binex Notes](https://ir0nstone.gitbook.io/notes/) (_Lots of Inspiration came from here, shoutout Andrej_)
* [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w)
* [Nightmare](https://guyinatuxedo.github.io/)
* _Hacking: The Art of Exploitation_ by Jon Erickson
* _Cracking the Coding Interview_ by Gayle Laakmann McDowell

Practicing Material

* [PicoCTF](https://picoctf.com/)
* [HackTheBox](https://www.hackthebox.eu/)
* [OverTheWire](https://overthewire.org/wargames/)
* [Advent of Code](https://adventofcode.com/)
* Registering for a CTF competition on [CTFTime](https://ctftime.org/)
