# Mastering Radare2

Radare2 is one of the most powerful debuggers out there. It is a command-line tool that has a rather unintuitive interface, but once you get used to it, it is very powerful. `radare2` is a major step from `gdb` because of the decompilation tools it offers.

`radare2` is especially powerful on 64-bit binaries because it automatically resolves function signatures and strings. This makes it easy to understand the underlying C code of the binary.

{% hint style="warning" %}
### Forewarning

Radare2 is basically the equivalent of using **Vim** instead of another text editor (like Nano). `gdb` is far simpler, but the feature set of radare2 can make it worth your time. It's an amazing tool for reverse engineering and binex if used properly.

If you don't care to learn a new tool, spend the effort to become a master at `gdb`.
{% endhint %}

## Installation

Installation depends on the operating system you are running. The main two operating systems I expect are Kali and Ubuntu Linux. Here is how you install for each:

{% tabs %}
{% tab title="Kali Linux" %}
```nasm
sudo apt install radare2
```
{% endtab %}

{% tab title="Ubuntu Linux" %}
```nasm
sudo snap install radare2
```
{% endtab %}
{% endtabs %}

## Usage

Based on your installation, the running command is slightly different. Here are the two commands:

{% tabs %}
{% tab title="Kali Linux" %}
```nasm
r2 -d -A <binary>
```
{% endtab %}

{% tab title="Ubuntu Linux" %}
```nasm
radare2 -d -A <binary>
```
{% endtab %}
{% endtabs %}

Both commands take the same arguments. The next page will cover the series of flags that are offered by `radare2`. I used the most common ones in the usage examples, but there are many more.
