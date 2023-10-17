#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint32_t part01()
{
    // open file
    FILE* fp = fopen("input.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    // initialize reader variables
    char* line = NULL;
    size_t len = 0;

    // read the file
    uint32_t total_score = 0;
    while (getline(&line, &len, fp) != -1) {
        int enemy = (int)line[0] - 'A';
        int self = (int)line[2] - 'X';

        total_score += (self + 1); // score for self move
        int difference = self - enemy;

        // draw case
        if (difference == 0) {
            total_score += 3;
            continue;
        }

        // win case
        if (difference == 1 || difference == -2) {
            total_score += 6;
            continue;
        }

        // loss case
        if (difference == -1 || difference == 2) {
            total_score += 0;
            continue;
        }

        printf("Bad\n");
    }

    // print the total score
    return total_score;
}

uint32_t part02()
{
    // open file
    FILE* fp = fopen("input.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    // initialize reader variables
    char* line = NULL;
    size_t len = 0;

    // read the file
    uint32_t total_score = 0;
    while (getline(&line, &len, fp) != -1) {
        char enemy = line[0];
        char self = line[2];

        total_score += 3 * ((int)self - 'X'); // score for match result

        if (self == 'X') {
            if (enemy == 'B' || enemy == 'C')
                total_score += ((int)enemy - 'A');
            else if (enemy == 'A')
                total_score += 3;
            else
                printf("Bad 1\n");
        } else if (self == 'Y') { // total score is what enemy put
            total_score += (((int)enemy - 'A') + 1);
        } else if (self == 'Z') {
            if (enemy == 'A' || enemy == 'B')
                total_score += (((int)enemy - 'A') + 2);
            else if (enemy == 'C')
                total_score += 1;
            else
                printf("Bad 2\n");
        } else {
            printf("Bad 3\n");
        }
    }

    return total_score;
}

int main(void)
{
    uint32_t first = part01();
    uint32_t second = part02();

    // print the total score
    printf("flag{%d_%d}\n", first, second);

    return 0;
}