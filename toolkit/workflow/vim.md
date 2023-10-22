---
description: Everyone's favorite text editor, said no one ever.
---

# Vim

## Installation

You can install `vim` using `apt`:

```bash
sudo apt install vim
```

You can use `vim` to open a plain text editor, or can use `vim <filename>` to open a file in `vim`.  If that file doesn't already exist, `vim` will create it.

{% hint style="success" %}
Unles you save the file, `vim` will not create it.
{% endhint %}

## Usage
Vim is a modal editor.  Vim has three modes:
* **Normal mode** - Used for navigating text.
* **Insert mode** - Used for inserting text.
* **Visual mode** - Used for selecting text.

These are not all the `vim` commands, but these are the ones I use the most.  I use the [Vim Cheatsheet](https://vim.rtorr.com/) as a common reference for `vim` commands.

### Movement
Movement is done in *normal mode*. There are lots of ways to move around in `vim`.

Here is the standard way to move around in `vim`:
* `h` - Move left
* `j` - Move down
* `k` - Move up
* `l` - Move right

{% hint style="info" %}
You can also use the arrow keys to move around in `vim`.
{% endhint %}

You can also jump by words:
* `w` - Jump to the start of the next word
* `W` - Jump to the start of the next word (ignoring punctuation)
* `e` - Jump to the end of the next word
* `E` - Jump to the end of the next word (ignoring punctuation)
* `b` - Jump to the start of the previous word
* `B` - Jump to the start of the previous word (ignoring punctuation)
* `ge` - Jump to the end of the previous word
* `gE` - Jump to the end of the previous word (ignoring punctuation)

You can also jump across the entire file:
* `gg` - Jump to the start of the file
* `G` - Jump to the end of the file
* `5gg` - Jump to line 5

You can jump by screen:
* `H` - Jump to the top of the screen
* `M` - Jump to the middle of the screen
* `L` - Jump to the bottom of the screen
* `Ctrl + u` - Jump up half a screen
* `Ctrl + d` - Jump down half a screen
* `Ctrl + b` - Jump up a screen
* `Ctrl + f` - Jump down a screen

You can jump by line:
* `0` - Jump to the start of the line
* `^` - Jump to the first non-whitespace character of the line
* `$` - Jump to the end of the line

You can jump by paragraph:
* `{` - Jump to the start of the previous paragraph
* `}` - Jump to the start of the next paragraph

### Editing
Editing is done in *normal mode* and *insert mode*.  **Use `i` to enter *insert mode*.  Use `Esc` to exit *insert mode*.**

You can delete text:
* `x` - Delete the character under the cursor
* `X` - Delete the character before the cursor
* `dw` - Delete the word under the cursor
* `d$` - Delete from the cursor to the end of the line
* `dd` - Delete (cut) the current line

You can copy and paste text:
* `yy` - (Yank) Copy the current line
* `dd` - Cut the current line
* `p` - Paste the copied text after the cursor
* `P` - Paste the copied text before the cursor

You can undo and redo changes:
* `u` - Undo the last change
* `Ctrl + r` - Redo the last change

You can replace text:
* `r` - Replace the character under the cursor
* `R` - Replace characters until `Esc` is pressed
* `cw` - Replace the word under the cursor
* `c$` - Replace from the cursor to the end of the line
* `cc` - Replace the current line

You can indent and unindent text:
* `>>` - Indent the current line
* `<<` - Unindent the current line

You can search for text:
* `/` - Search forward
* `?` - Search backward
* `n` - Go to the next search result
* `N` - Go to the previous search result

### Visual Mode
Visual mode is used for selecting text.  **Use `v` to enter *visual mode*.  Use `Esc` to exit *visual mode*.**

You can select text:
* `v` - Select the character under the cursor
* `V` - Select the current line
* `Ctrl + v` - Select a block of text

You can indent and unindent text:
* `>` - Indent the selected text
* `<` - Unindent the selected text

You can copy and paste text:
* `y` - Copy the selected text
* `d` - Cut the selected text
* `p` - Paste the copied text after the cursor
* `P` - Paste the copied text before the cursor

### Saving and Quitting
Saving and quitting is done in *normal mode*.

You can save and quit:
* `:w` - Save the file
* `:q` - Quit the file
* `:wq` - Save and quit the file

You can force save and quit:
* `:w!` - Force save the file
* `:q!` - Force quit the file
* `:wq!` - Force save and quit the file

You can save and quit all files:
* `:wa` - Save all files
* `:qa` - Quit all files
* `:wqa` - Save and quit all files

### Other
You can use `vim` to run commands:
* `:!` - Run a shell command
* `:r` - Read a file into the current file
* `:e` - Edit a file
* `:tabe` - Edit a file in a new tab

You can use `vim` to run macros:
* `q` - Start recording a macro
* `q` - Stop recording a macro
* `@` - Run a macro