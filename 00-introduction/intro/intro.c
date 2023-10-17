#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STR_SIZE 0x20 

int main(int argc, char* argv[])
{
	char* line = malloc(STR_SIZE * sizeof(char));
	printf("Enter the flag here: ");
	fgets(line, STR_SIZE, stdin);
	
	if (strcmp(line, "flag{welcome_to_runtime}\n") == 0)
		printf("That's the right flag!\n");
	else
		printf("Nope, try again!\n");
	
	return 0;
}
