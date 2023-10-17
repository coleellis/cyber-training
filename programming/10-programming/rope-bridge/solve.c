#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Point {
    int x;
    int y;
} Point_default = {0, 0};

struct Vector {
    int x;
    int y;
} Vector_default = {0, 0};

struct Vector build_vector(struct Point head, struct Point tail)
{
    struct Vector* ret = malloc(sizeof(struct Vector));
    ret->x = head.x - tail.x;
    ret->y = head.y - tail.y;
    return *ret;
}

int compare(const void* a, const void* b)
{
    struct Point* first = (struct Point*)a;
    struct Point* second = (struct Point*)b;

    if (first->x < second->x)
        return -1;
    else if (first->x > second->x)
        return 1;
    else {
        if (first->y < second->y)
            return -1;
        if (first->y > second->y)
            return 1;
        else
            return 0;
    }
}

int equal(struct Point a, struct Point b)
{
    return (a.x == b.x && a.y == b.y);
}

struct Point adjust(struct Point head, struct Point tail)
{
    struct Vector distance = build_vector(head, tail);

    // adjust tail location based on vector
    if (distance.x == 2) {
        ++tail.x;
        if (distance.y == 1)
            ++tail.y;
        if (distance.y == -1)
            --tail.y;
    }
    if (distance.x == -2) {
        --tail.x;
        if (distance.y == 1)
            ++tail.y;
        if (distance.y == -1)
            --tail.y;
    }
    if (distance.y == 2) {
        ++tail.y;
        if (distance.x == 1)
            ++tail.x;
        if (distance.x == -1)
            --tail.x;
    }
    if (distance.y == -2) {
        --tail.y;
        if (distance.x == 1)
            ++tail.x;
        if (distance.x == -1)
            --tail.x;
    }

    return tail;
}

int main(void)
{
    FILE* fp = fopen("input.txt", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);

    char* line = NULL;
    size_t len = 0;

    // build the chain
    struct Point* chain = malloc(10 * sizeof(struct Point));
    for (size_t i = 0; i < 10; ++i)
        chain[i] = Point_default;

    // list of points
    struct Point* tail_visits = malloc(20000 * sizeof(struct Point));

    // read the directional changes
    size_t count = 0;
    while (getline(&line, &len, fp) != -1) {
        char dir = strtok(line, " ")[0];
        int times = atoi(strtok(NULL, " "));
        while (times-- > 0) {
            // adjust the head coordinate
            if (dir == 'U')
                ++chain[0].y;
            else if (dir == 'D')
                --chain[0].y;
            else if (dir == 'L')
                --chain[0].x;
            else if (dir == 'R')
                ++chain[0].x;
            else {
                printf("Bad\n");
                exit(EXIT_FAILURE);
            }

            // adjust the links of the chain
            for (size_t i = 0; i < 9; ++i)
                chain[i + 1] = adjust(chain[i], chain[i + 1]);

            // record tail location in list
            tail_visits[count++] = chain[9];
        }
    }

    // sort the list of points
    qsort(tail_visits, count, sizeof(struct Point), compare);

    // count non-duplicates
    size_t visited = 1;
    for (size_t i = 1; i < count; ++i) {
        if (!equal(tail_visits[i], tail_visits[i - 1])) {
            ++visited;
        }
    }

    printf("flag{%zd}\n", visited);

    free(chain);
    free(tail_visits);
    fclose(fp);

    exit(EXIT_SUCCESS);
}
