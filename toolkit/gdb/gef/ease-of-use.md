---
description: Making GDB easier to use.
---

# Ease of Use
There are a few commands `gdb` uses to make the debugging experience better. These don't provide any extra information, but they make debugging quicker.

### `aliases`
GEF overrides the typical `gdb` aliasing mechanism (which is done via `alias`).

Use `aliases add <alias> <command>` to add an alias. Use `aliases rm <alias>` to remove an alias.
```bash
gef➤  aliases add p64 x/gx
gef➤  aliases rm p64
```

Use `aliases ls` to view the current alias list.
```bash
gef➤  aliases ls 
[+] Aliases defined:
ctx                             →  context
telescope                       →  dereference
flags                           →  edit-flags
start                           →  entry-break
fmtstr-helper                   →  format-string-helper
hl                              →  highlight
highlight set                   →  highlight add
hla                             →  highlight add
hlc                             →  highlight clear
highlight ls                    →  highlight list
hll                             →  highlight list
highlight delete                →  highlight remove
highlight del                   →  highlight remove
highlight unset                 →  highlight remove
highlight rm                    →  highlight remove
hlr                             →  highlight remove
nb                              →  name-break
pattern offset                  →  pattern search
pf                              →  print-format
ps                              →  process-search
status                          →  process-status
lookup                          →  scan
grep                            →  search-pattern
xref                            →  search-pattern
sc-get                          →  shellcode get
sc-search                       →  shellcode search
screen-setup                    →  tmux-setup
```

{% hint style="info" %}
Aliases are stored in `~/.gef.rc`. You can edit the aliases directly in this file.
{% endhint %}