---
description: Making GDB easier to use.
---

# Ease of Use
There are a few commands `gdb` uses to make the debugging experience better. These don't provide any extra information, but they make debugging quicker.

## `aliases`
GEF overrides the typical `gdb` aliasing mechanism (which is done via `alias`).

Use `aliases add <alias> <command>` to add an alias. Use `aliases rm <alias>` to remove an alias.
```nasm
gef➤  aliases add p64 x/gx
gef➤  aliases rm p64
```

Use `aliases ls` to view the current alias list.
```nasm
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

## `config`
This command shows the current GEF configuration. It reads from `~/.gef.rc` and the `gef` section of `~/.gdbinit`.

```nasm
gef➤  gef config
─────────── GEF configuration settings ───────────
assemble.default_architecture (str) = "X86"
assemble.default_mode (str) = "64"
capstone-disassemble.use-capstone (bool) = False
context.clear_screen (bool) = True
context.enable (bool) = True
context.grow_stack_down (bool) = False
...
...
theme.source_current_line (str) = "green"
theme.table_heading (str) = "blue"
trace-run.max_tracing_recursion (int) = 1
trace-run.tracefile_prefix (str) = "./gef-trace-"
unicorn-emulate.show_disassembly (bool) = False
unicorn-emulate.verbose (bool) = False
vereference.max_recursion (int) = 7
```

You can set a value in this configuration with `gef config <key> <value>`. For example, `gef config context.enable False` will disable the context.

{% hint style="danger" %}
### Changing the Configuration

These changes are **temporary**.  You can restore the original configuration using:
```nasm
gef➤  gef restore
[+] Configuration from '/home/joybuzzer/.gef.rc' restored
```

You can make permanent changes by editing `~/.gef.rc` or using `gef save`.
```nasm
gef➤  gef save
[+] Configuration saved to '/home/joybuzzer/.gef.rc'
```
{% endhint %}