# Establishing Connection

Pwntools establishes a standard interface for connecting to binaries, both locally and remotely.  This is accomplished via the `pwnlib.tubes` module.
{% hint style="info" %}
### What is a tube?
A tube is a generic object which can be used to send or receive data.  It is the base class for all connections, and is the primary interface for interacting with a remote process.
{% endhint %}

## Connecting to a Remote Process
Use `remote()` for easy connection to remote processes.
```python
p = remote('vunrotc.cole-ellis.com', 1100)
```

You can also use a listener to connect to a remote process.
```python
l = listen(1100)
r = remote('vunrotc.cole-ellis.com', l.lport)
p = l.wait_for_connection()
```

## Connecting to a Local Process
Use `process()` for easy connection to local processes.
```python
p = process('./win32')
```

## Using GDB with Pwntools
We can use `gdb.debug()` to run a **local** process within `gdb`. This takes a secondary argument, `gdbscript`, which is a string of commands to run in `gdb`.  This is useful for setting breakpoints, etc.
```python
p = gdb.debug('./win32', gdbscript='b *main\nc')
```

People commonly use a separate variable for their `gdbscript` because it's easier to read. Using a separate string allows you to use triple quotes, which makes it easier to write multi-line scripts.
```python
cmds = '''
b *main
c
'''

p = gdb.debug('./win32', gdbscript=cmds)
```
{% hint style="success" %}
This allowed us to write commands without using the newline character.  It also generally makes the code easier to read.
{% endhint %}

We can use `gdb.attach()` to attach to a process. It takes the target to attach to (which, under the hood, is the process ID).
```python
p = process('./win32')
gdb.attach(p)
```