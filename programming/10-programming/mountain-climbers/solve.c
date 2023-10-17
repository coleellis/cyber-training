#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct node {
    int x, y, steps;
    struct node *next;
} node;

// Global variable declaration
char *map[50];
node *queue, *visited;
int height, width;

// Functions declarations
int BFS(int x, int y);
int inQueue(node *n);
void free_memory(node *list);
int getValue(int x, int y);
node *buildNode(int x, int y, int steps);
void enqueue(node **list, node *n);

int BFS(int x, int y)
{
    // Free memory of the queue and visited
    free_memory(queue);
    free_memory(visited);
    queue = visited = NULL;

    // Create new node
    node *start = buildNode(x, y, 0);

    // Neighbors coordinates
    int dx[] = {1, 0, -1, 0};
    int dy[] = {0, 1, 0, -1};

    // Add starting node to the queue
    queue = start;

    while (queue != NULL)
    {
        // Get data from current node
        int x = queue->x;
        int y = queue->y;
        int value = getValue(x, y);
        int steps = queue->steps;

        // Remove node from the queue
        node *current = queue;
        queue = queue->next;
        current->next = NULL;

        // Add current node to the visited queue
        current->next = visited;
        visited = current;

        // Find neighbors
        for (int i = 0; i < 4; i++) {
            // Get neighbor coordinates
            int nx = x + dx[i];
            int ny = y + dy[i];

            // Check if neighbor is in the map
            if (nx >= 0 && nx < width && ny >= 0 && ny < height) {
                // Check if node is the goal
                if (value >= 24 && map[ny][nx] == 'E')
                    return steps + 1;

                // check if neighbor is movable
                int neighbor_value = getValue(nx, ny);
                if (neighbor_value <= value + 1) {
                    node *n = buildNode(nx, ny, steps + 1);

                    // Check if node is already in the queue
                    if (!inQueue(n))
                        // Add node to the queue
                        enqueue(&queue, n);
                    else
                        free(n);
                }
            }
        }
    }
    return INT_MAX;
}

int inQueue(node *curr)
{
    // Check if node is in the queue
    node *ptr = queue;
    while (ptr != NULL) {
        if (curr->x == ptr->x && curr->y == ptr->y && curr->steps >= ptr->steps)
            return 1;
        ptr = ptr->next;
    }

    // Check if node is in the visited queue
    ptr = visited;
    while (ptr != NULL) {
        if (curr->x == ptr->x && curr->y == ptr->y && curr->steps >= ptr->steps)
            return 1;

        ptr = ptr->next;
    }
    return 0;
}

void free_memory(node *list)
{
    // Free memory of the list
    while (list) {
        node *temp = list;
        list = list->next;
        free(temp);
    }
}

int getValue(int x, int y)
{
    char value = map[y][x];
    switch (value) {
        case 'S':
            return 0;
        case 'E':
            return 25;
        default:
            return value - 'a';
    }
}

node *buildNode(int x, int y, int steps)
{
    node *new_node = malloc(sizeof(node));
    new_node->x = x;
    new_node->y = y;
    new_node->steps = steps;
    new_node->next = NULL;
    return new_node;
}

void enqueue(node **list, node *n)
{
    if (*list == NULL) { // If list is empty
        *list = n;
    } else { // else add node to the end of the list
        node *current = *list;
        while (current->next != NULL)
            current = current->next;

        current->next = n;
    }
}

int main(void)
{
    // Open file for reading
    FILE *file = fopen("input.txt", "r");
    if (file == NULL) {
        printf("Could not open file.\n");
        exit(EXIT_FAILURE);
    }

    // Read data for file
    int index = 0;
    map[index] = malloc(100);
    while (fscanf(file, "%s", map[index]) != EOF) {
        map[++index] = malloc(100);
    }

    // Declare height and width of the heightmap
    height = index;
    width = strlen(map[0]);

    // Find Starting coordinates and calculate shortest path
    int part1 = INT_MAX;
    int part2 = INT_MAX;
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            // part 1 - provided start point
            if (map[y][x] == 'S') {
                if (BFS(x, y) < part1)
                    part1 = BFS(x, y);
            }
            // part 2 - any 'a' start point
            if (map[y][x] == 'a') {
                if (BFS(x, y) < part2)
                    part2 = BFS(x, y);
            }
        }
    }

    // Print results to console
    printf("flag{%d:%d}\n", part1, part2);

    // Free memory
    for (int i = 0; i < index + 1; i++)
        free(map[i]);

    free_memory(visited);
    free_memory(queue);
    fclose(file);
}