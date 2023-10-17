// gcc win.c -o win64 -no-pie -fno-stack-protector -z execstack

#include <stdio.h>
#include <stdlib.h>

void win()
{
	system("cat flag.txt");
}

void read_in()
{
	char buffer[40];
	puts("Can you figure out how to win here?");
	fflush(stdout);
	gets(buffer);
}

int main()
{
	read_in();
	puts("You lose!");
	return 0;
}

void usefulGadgets(unsigned long arg1)
{
    asm volatile ("pop %rdi; ret;");
}

