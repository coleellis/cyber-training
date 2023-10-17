// gcc win.c -o win32 -no-pie -fno-stack-protector -z execstack -m32

#include <stdio.h>

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
