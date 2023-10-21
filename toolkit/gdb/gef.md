# GEF's Extended Feature Set

The GEF extension provides a number of features to the binary that are extremely helpful for debugging.

These are not all the commands that GEF provides. These are the ones I use most often in most debugging scenarios. For the full list of command, consult the [GEF documentation](https://hugsy.github.io/gef/).

I orrganize the commands into a few categories:
* *Ease of Use*: Commands that make the debugging experience easier.
* *Security Measures*: Commands that provide extra guidance based on the implemented security measures.
* *Memory Analysis*: Extra commands that show various memory segments better than the default `gdb` commands.
* *Debugging UI*: Commands to control the GEF debugging experience.
* *Exploit Development*: Commands useful for exploit development.

## Ease of Use
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
## Security Measures, Illustrated
### `checksec`
The `checksec` command is inspired from the `checksec` used on the command line. It's a convenient way to check security within `gdb`.
```bash
gef➤  checksec
[+] checksec for '/home/joybuzzer/args'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

**Fortify** is a security feature we haven't seen yet; it's a compile-time feature that adds extra checks to detect buffer overflows.  I haven't written any articles on this yet, but you can read more about it [here](https://developers.redhat.com/articles/2022/09/17/gccs-new-fortification-level#2__better_fortification_coverage).

### `canary`
The `canary` tool is one of my favorite GEF tools and what sets it apart from the other `gdb` extensions.  This command finds the canary value and prints its location and value.
```bash
gef➤  canary
[+] The canary of process 19692 is at 0xffffd84b, value is 0x2bf28900
```

This makes locating the canary on the stack much easier:
```bash
gef➤  x/28wx $esp
0xffffd570:	0xffffd58c	0x00000001	0xf7ffda40	0x080491d2
0xffffd580:	0xf7fc4540	0xffffffff	0x08048034	0xf7fc66d0
0xffffd590:	0xf7ffd608	0x00000020	0x00000000	0xffffd790
0xffffd5a0:	0x00000000	0x00000000	0x01000000	0x0000000b
0xffffd5b0:	0xf7fc4540	0x00000000	0xf7c184be	0xf7e2a054
0xffffd5c0:	0xf7fbe4a0	0xf7fd6f90	0xf7c184be	0x2bf28900
0xffffd5d0:	0xffffd610	0x0804c000	0xffffd5e8	0x080492b8
```

### `aslr`
You can enable or disable ASLR on the debugged binary.  Remember that this is internal GEF setting and does not affect ASLR on the kernel.  Since we never know if ASLR is running on a remote binary, we should assume it is on.
```bash
gef➤  aslr
ASLR is currently disabled
```
```bash
gef➤  aslr on
gef➤  aslr off
```

{% hint style="warning" %}
This will not work on a process which was loaded and `gdb` was then attached.  You must initiate the process using `gdb`.
{% endhint %}

### `pie`
The `pie` command is used when handling position-independent executables (PIE enabled). It provides a series of commands to use in place of the typical `gdb` commands that automatically resolve absolute addresses for the run.

Use `pie breakpoint <offset>` to set a breakpoint.  It can be used like the normal `b` command in `gdb` and will automatically resolve the address.
```bash
gef➤  pie breakpoint main
```

Use `pie info` the same way you would use `info break` in `gdb`. This lists the breakpoints.
```bash
gef➤  pie info
VNum    Num     Addr              
     1  N/A     0x11cd 
```

Use `pie delete <number>` to delete a breakpoint.  It can be used like the normal `delete` command in `gdb`.
```bash
gef➤  pie delete 1
```

Finally, when running the binary, use `pie run` instead of the typical `run` command. This converts the PIE breakpoints to real breakpoints at runtime.
```bash
gef➤  pie run
```

## Memory Analysis
### `elf-info`
### `got`
### `heap`
### `registers`
### `scan`

## Debugging UI
### `context`
### `tmux-setup`

## Exploit Development
### `format-string-helper`
The format string helper is a tool to help with format string vulnerabilities. It adds breakpoints at the start of `printf` and similar functions. If a potentially vulnerable format string is found, it will trigger the breakpoint.

We use the [*format*](/binex/03-formats/format.md) binary for this example.
```bash
gef➤  format-string-helper
[+] Enabled 5 FormatString breakpoints
```
If we continue the program, we see there is a potential format string bug:
```as
────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0xf7c57a90 → printf()
[#1] 0x80491fb → main()
────────────────────────────────────────────────────────────────────────────────────────────────────── extra ────
[*] Format string helper
Possible insecure format string: printf('[sp + 0x4]'  →  0xffffd57c: 'AAAA\n')
Reason: Call to 'printf()' with format string argument in position #0 is in page 0xfffdd000 ([stack]) that has write permission
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

The best course is to use `finish` to reach the end of the `printf` command since the helper puts the breakpoint *inside* the function.  We can then check the disassembly to see if there is truly a format string bug.
```bash
0x80491f2 <main+76>        lea    eax, [ebp-0x6c]
0x80491f5 <main+79>        push   eax
0x80491f6 <main+80>        call   0x8049050 <printf@plt>
```

From here, we see there is a format string bug!

### `search-pattern`
`search-pattern` alters the original `find` command by making it more user-friendly.  `search-pattern` looks across all memory segments in all loaded files for the pattern.
```bash
gef➤  search-pattern "/bin/cat flag.txt"
[+] Searching '/bin/cat flag.txt' in memory
[+] In '/home/joybuzzer/split'(0x601000-0x602000), permission=rw-
  0x601060 - 0x601071  →   "/bin/cat flag.txt" 

gef➤  search-pattern "/bin/sh"
[+] Searching '/bin/sh' in memory
[+] In '/usr/lib/x86_64-linux-gnu/libc.so.6'(0x7ffff7dbd000-0x7ffff7e15000), permission=r--
  0x7ffff7dd8698 - 0x7ffff7dd869f  →   "/bin/sh"
```

You can still specify a memory range to search in:
```bash
gef➤  search-pattern "/bin/cat flag.txt" little 0x600000-0x602000
[+] Searching '/bin/cat flag.txt' in 0x600000-0x602000
[+] In '/home/joybuzzer/Documents/vunrotc/.public/binex/05-rop/split/src/split'(0x600000-0x601000), permission=r--
  0x601060 - 0x601071  →   "/bin/cat flag.txt" 

gef➤  search-pattern "/bin/sh" little libc
[+] Searching '/bin/sh' in libc
[+] In '/usr/lib/x86_64-linux-gnu/libc.so.6'(0x7ffff7dbd000-0x7ffff7e15000), permission=r--
  0x7ffff7dd8698 - 0x7ffff7dd869f  →   "/bin/sh" 
```

{% hint style="info" %}
GEF wants to search loaded libraries for the pattern. Therefore, `search-pattern` can only be used during runtime.
{% endhint %}

### `shellcode`
This command provides a command-line interface for the [Shellstorm Database](http://shell-storm.org/shellcode/).  It allows you to search for shellcode and download it directly into the debugged process.  There are two subcommands: `search` and `get`.

```bash
gef➤  shellcode search linux x86-64
[+] Showing matching shellcodes
[+] Id	Platform	Description
907	Linux/x86-64	Dynamic null-free reverse TCP shell - 65 bytes
905	Linux/x86-64	execveat("/bin//sh") - 29 bytes
896	Linux/x86-64	Add map in /etc/hosts file - 110 bytes
895	Linux/x86-64	Connect Back Shellcode - 139 bytes
894	Linux/x86-64	access() Egghunter - 49 bytes
892	Linux/x86-64	Shutdown - 64 bytes
891	Linux/x86-64	Read password - 105 bytes
890	Linux/x86-64	Password Protected Reverse Shell - 136 bytes
889	Linux/x86-64	Password Protected Bind Shell - 147 bytes
888	Linux/x86-64	Add root - Polymorphic - 273 bytes
884	Linux/x86-64	Bind TCP stager with egghunter - 157 bytes
880	Linux/x86-64	Add user and password with open,write,close - 358 bytes
879	Linux/x86-64	Add user and password with echo cmd - 273 bytes
878	Linux/x86-64	Read /etc/passwd - 82 bytes
877	Linux/x86-64	shutdown -h now - 65 bytes
873	Linux/x86-64	TCP Bind 4444 with password - 173 bytes
871	Linux/x86-64	TCP reverse shell with password - 138 bytes
870	Linux/x86-64	TCP bind shell with password - 175 bytes
867	Linux/x86-64	Reads data from /etc/passwd to /tmp/outfile - 118 bytes
859	Linux/x86-64	shell bind TCP random port - 57 bytes
858	Linux/x86-64	TCP bind shell - 150 bytes
857	Linux/x86-64	Reverse TCP shell - 118 bytes
801	Linux/x86-64	add user with passwd - 189 bytes
683	Linux/x86-64	execve(/sbin/iptables, [/sbin/iptables, -F], NULL) - 49 bytes
806	Linux/x86-64	Execute /bin/sh - 27 bytes
822	Linux/x86-64	bind-shell with netcat - 131 bytes
823	Linux/x86-64	connect back shell with netcat - 109 bytes
815	Linux/x86-64	setreuid(0,0) execve(/bin/ash,NULL,NULL) + XOR - 85 bytes
816	Linux/x86-64	setreuid(0,0) execve(/bin/csh, [/bin/csh, NULL]) + XOR - 87 bytes
817	Linux/x86-64	setreuid(0,0) execve(/bin/ksh, [/bin/ksh, NULL]) + XOR - 87 bytes
818	Linux/x86-64	setreuid(0,0) execve(/bin/zsh, [/bin/zsh, NULL]) + XOR - 87 bytes
78	Linux/x86-64	bindshell port:4444 shellcode - 132 bytes
77	Linux/x86-64	setuid(0) + execve(/bin/sh) 49 bytes
76	Linux/x86-64	execve(/bin/sh, [/bin/sh], NULL) - 33 bytes
603	Linux/x86-64	execve(/bin/sh); - 30 bytes
602	Linux/x86-64	reboot(POWER_OFF) - 19 bytes
605	Linux/x86-64	sethostname() & killall - 33 bytes
[+] Use `shellcode get <id>` to fetch shellcode
```

Use `shellcode get` to get shellcodes by ID and write them to disk.
```bash
gef➤  shellcode get 806
[+] Downloading shellcode id=806
[+] Downloaded, written to disk...
[+] Shellcode written to '/tmp/gef/sc-7yvmnvyp.txt'
```

Inside `gdb`, you can use the `shell` command to spawn a shell without losing your `gdb` session.
```bash
gef➤  shell
$ cat /tmp/gef/sc-7yvmnvyp.txt
...
char code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
...
$ exit
gef➤  
```