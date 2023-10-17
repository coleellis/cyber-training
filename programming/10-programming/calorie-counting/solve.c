#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int compare(const void* a, const void* b)
{
    return (*(int*)b - *(int*)a);
}

int main(void)
{
    // open the file
    FILE* fp = fopen("input.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    
    char* line = NULL;
    size_t len = 0;
    ssize_t read;

    // initialize array
    int totals[1250] = {0};
    uint16_t i = 0;
    uint32_t sum = 0;

    // read the file till no more lines
    while ((read = getline(&line, &len, fp)) != -1) {
        if (read == 1) { // if blank line, store total
            totals[i] = sum;
            ++i;
            sum = 0;
        } else { // else, add to total
            sum += atoi(line);
        }
    }

    // sort the array
    qsort(totals, i, sizeof(int), compare);

    // print the sum of the top 3
    printf("flag{%d}\n", totals[0] + totals[1] + totals[2]);

    fclose(fp);
    if (line)
        free(line);
    exit(EXIT_SUCCESS);
}
