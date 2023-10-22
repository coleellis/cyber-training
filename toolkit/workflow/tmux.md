---
description: Organizing multiple terminal windows in one tab.
---

# Tmux

## Installation

Installing `tmux` is easy using `apt`:

```bash
sudo apt install tmux
```

The default configuration of `tmux` disables the mouse, which isn't ideal for me. This removes scrolling capability within the window, which is difficult for horizontal windows. To enable the mouse, create a file at `~/.tmux.conf` with the following contents:

```bash
set -g mouse on
```

Then, reload the configuration:

```bash
$ tmux kill-server
$ tmux
```

{% hint style="success" %}
Use `tmux` to start a new `tmux` session.
{% endhint %}

## Usage

I split the usage section up into various sections based on the functionalities `tmux` provides.

By default, `tmux` uses a **hotkey** to activate its commands. This hotkey is `Ctrl + b`. The hotkey must precede all commands.

### Windows

These commands are for making and removing windows.

* `c` - Create a new window
* `&` - Kill the current window
* `w` - List all windows

These commands are for navigating between windows.

* `n` - Go to the next window
* `p` - Go to the previous window
* `f` - Find a window by name
* `,` - Rename the current window

### Panes

These commands are for making and removing panes.

* `%` - Split the current pane vertically
* `"` - Split the current pane horizontally

Use the arrow keys to navigate between panes.

These commands are for handling panes.

* `x` - Kill the current pane
* `o` - Swap panes
* `q` - Show pane numbers

These commands are for resizing panes.

* `Ctrl + <arrow key>` - Resize the current pane in the direction of the arrow key
* `+` - Break the current pane out of the window
* `-` - Restore the current pane to the window

### Copy Mode

Use `Ctrl + b` and then `[` to enter copy mode. This allows you to use the cursor to navigate the pane. Use `Esc` to exit copy mode.

Copy mode supports the same navigation commands as `Vim`:

* `h|j|k|l` - Navigate left/down/up/right
* `w|b` - Navigate forward/backward by word
* `gg|G` - Navigate to the top/bottom of the pane
* `0|$` - Navigate to the beginning/end of the line

## Downsides of Tmux

Arguably, the worst part of `tmux` is the inability to copy and paste properly. Copying is defaulted to go across the terminal; however, with horizontal terminals, this causes the copy to go across both terminals.

The only way around this is to use Copy Mode, which is hard to manage. It almost becomes easier to open a new tab and reproduce the command to copy.
