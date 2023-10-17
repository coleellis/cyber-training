// gcc -o args args.c -no-pie -fno-stack-protector -z execstack -m32

#include <stdio.h>
#include <stdint.h>

void win(int arg)
{
    if (arg != 0xdeadbeef) {
        puts("You lose!");
        return;
    }
    system("cat flag.txt");
}

void read_in()
{
    char buffer[40];
    puts("Good luck winning here!");
    fflush(stdout);
    gets(buffer);
}

void main()
{
    read_in();
}
