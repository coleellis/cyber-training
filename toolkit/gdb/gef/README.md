# GEF's Extended Feature Set

The GEF extension provides a number of features to the binary that are extremely helpful for debugging.

These are not all the commands that GEF provides. These are the ones I use most often in most debugging scenarios. For the full list of command, consult the [GEF documentation](https://hugsy.github.io/gef/).

I orrganize the commands into a few categories:
* *Ease of Use*: Commands that make the debugging experience easier.
* *Security Measures*: Commands that provide extra guidance based on the implemented security measures.
* *Memory Analysis*: Extra commands that show various memory segments better than the default `gdb` commands.
* *Debugging UI*: Commands to control the GEF debugging experience.
* *Exploit Development*: Commands useful for exploit development.

## Installation
The easiest way to install GEF is through `wget`:
```bash
$ bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

## Usage
GEF is automatically loaded when you run `gdb`, so no further action is required!