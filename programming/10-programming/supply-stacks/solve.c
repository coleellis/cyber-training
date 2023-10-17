#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    // open the file
    FILE* fp = fopen("input.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    // prep the input
    char* line = NULL;
    ssize_t read;
    size_t len = 0;

    // read until the newline
    size_t des_line = 0;
    int num_stacks;
    while ((read = getline(&line, &len, fp)) != 1) {
        // our desired line guaranteed starts with a space
        if (line[0] == ' ') {
            char* token = strtok(line, " ");
            while ((token = strtok(NULL, " ")) != NULL && token[0] != 0xd)
               num_stacks = atoi(token);
            break;
        } else {
            ++des_line;
        }
    }
    
    // this resets the file to start reading from the beginning
    fseek(fp, 0, 0);

    // allocate the storage
    char** stacks = malloc(num_stacks * sizeof(char*));
    for (size_t i = 0; i < num_stacks; ++i) {
        stacks[i] = malloc(100 * sizeof(char));
    }
    size_t* size = malloc(num_stacks * sizeof(size_t));

    // now read the first 8 lines and get the data
    size_t line_num = 0;
    while (line_num != des_line) {
        // get the line
        read = getline(&line, &len, fp);

        // read across the line looking for chars
        for (size_t i = 0; i < read; ++i) {
            if (line[i] >= 'A' && line[i] <= 'Z') {
                if (i/4 < num_stacks) {
                    stacks[i/4][size[i/4]++] = line[i];
                } else {
                    printf("Out of bounds error on line %zu\n", line_num);
                    exit(EXIT_FAILURE);
                }
            }
        }

        ++line_num;
    }

    // we put them in backwards, reverse the lists
    for (size_t i = 0; i < num_stacks; ++i) {
        char* rev_stack = malloc(100 * sizeof(char));
        for (size_t j = 0; j <= size[i]; ++j)
            rev_stack[j] = stacks[i][size[i]-j-1];
        free(stacks[i]);
        stacks[i] = rev_stack;
    }

    // push the line twice to get to the right spot
    getline(&line, &len, fp);
    getline(&line, &len, fp);

    // now we need to parse the rest of the lines
    size_t moving, origin, destination;
    while (getline(&line, &len, fp) != -1) {
        strtok(line, " "); // Moving

        size_t moving = atoi(strtok(NULL, " "));
        strtok(NULL, " "); // from

        size_t origin = atoi(strtok(NULL, " ")) - 1;
        strtok(NULL, " "); // to

        size_t destination = atoi(strtok(NULL, " ")) - 1;

        // perform the action
        for (size_t action = 0; action < moving; ++action) {
            stacks[destination][size[destination]++] = stacks[origin][(size[origin]--)-1];
        }
    }

    // get the top stacks
    printf("flag{");
    for (size_t i = 0; i < num_stacks; ++i)
        printf("%c", stacks[i][size[i]-1]);
    printf("}\n");

    // free the memory
    for (size_t i = 0; i < num_stacks; ++i)
        free(stacks[i]);
    free(stacks);
    free(size);
    if (line) free(line);

    return 0;
}