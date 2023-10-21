# GEF Features

The GEF extension provides several features to the binary that are extremely helpful for debugging.

These are not all the commands that GEF provides. These are the ones I use most often in most debugging scenarios. For the complete list of commands, consult the [GEF documentation](https://hugsy.github.io/gef/).

I organize the commands into a few categories:

* _Ease of Use_: Commands that make the debugging experience easier.
* _Security Measures_: Commands that provide extra guidance based on the implemented security measures.
* _Memory Analysis_: Extra commands that show various memory segments better than the default `gdb` commands.
* _Debugging UI_: Commands to control the GEF debugging experience.
* _Exploit Development_: Commands useful for exploit development.

## Installation

The easiest way to install GEF is through `wget`:

```bash
$ bash -c "$(wget https://gef.blah.cat/sh -O -)"
```

## Usage

GEF is automatically loaded when you run `gdb` so no further action is required!
