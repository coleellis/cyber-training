#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct ArrayItem {
    uint16_t index;
    uint8_t letter;
    uint16_t left;
    uint16_t right;
} node;

int compare(const void* a, const void* b)
{
    node* left = (node*)a;
    node* right = (node*)b;
    return left->index - right->index;
}

void preOrder(char* string, node* nodes, uint16_t index, uint16_t* depth)
{
    // add current to string
    string[(*depth)++] = nodes[index-1].letter;

    // make sure we're not at the end
    if (nodes[index-1].left == 0xffff && nodes[index-1].right == 0xffff)
        return;
    
    // perform the recursive traversal
    if (nodes[index-1].left != 0xffff)
        preOrder(string, nodes, nodes[index-1].left, depth);
    if (nodes[index-1].right != 0xffff)
        preOrder(string, nodes, nodes[index-1].right, depth);
}

int main()
{
    FILE* fp = fopen("data.bin", "rb");
    if (fp == NULL) {
        printf("File not found.\n");
        exit(EXIT_FAILURE);
    }

    node* nodes = malloc(35 * sizeof(node));

    uint32_t num_elements = 0;
    while (1) {
        node e;
        
        uint8_t bytes_read = fread(&e.index, sizeof(e.index), 1, fp);
        if (bytes_read == 0)
            break;
        
        fread(&e.letter, sizeof(e.letter), 1, fp);
        fread(&e.left, sizeof(e.left), 1, fp);
        fread(&e.right, sizeof(e.right), 1, fp);

        nodes[num_elements] = e;
        ++num_elements;
    }

    qsort(nodes, num_elements, sizeof(node), compare);

    char* string = malloc(num_elements * sizeof(char));
    uint16_t* depth = malloc(sizeof(uint16_t));
    *depth = 0;
    preOrder(string, nodes, 0x1, depth);

    printf("%s\n", string);
        
    return 0;
}