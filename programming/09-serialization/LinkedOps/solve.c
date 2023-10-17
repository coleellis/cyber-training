#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct ArrayItem {
    uint8_t letter;
    struct ArrayItem* next;
} node;

void insertNode(node** head, uint16_t loc, char letter) {
    // make a new node
    node* new = malloc(sizeof(node));
    new->letter = letter;
    new->next = NULL;

    // edge case: empty list or inserting beginning
    if (*head == NULL || loc == 0) {
        new->next = *head;
        *head = new;
        return;
    }
    
    // main case: inserting center
    node* current = *head;
    for (uint16_t index = 0; index < loc - 1 && current != NULL; ++index)
        current = current->next;

    if (current == NULL) { // error: beyond edge length
        free(new);
        return;
    }

    // link the nodes
    new->next = current->next;
    current->next = new;
}

void removeNode(node** head, uint16_t loc) {
    if (*head == NULL) return; // list is empty

    if (loc == 0) { // remove from start
        node* toDelete = *head;
        *head = (*head)->next;
        free(toDelete);
        return;
    }
    
    // main case: remove from center
    node* current = *head;
    for (uint16_t index = 0; index < loc - 1 && current != NULL; ++index)
        current = current->next;

    if (current == NULL || current->next == NULL) {
        // error: beyond edge length
        return;
    }

    node* toDelete = current->next;
    current->next = toDelete->next;
    free(toDelete);
}


void printNode(node** head)
{
    printf("flag{");
    for (node* c = *head; c != NULL; c=c->next)
        printf("%c", c->letter);
    printf("}\n");
}

int main()
{
    FILE* fp = fopen("data.bin", "rb");
    if (fp == NULL) {
        printf("Error opening file.\n");
        exit(EXIT_FAILURE);
    }

    node* head = NULL;

    uint16_t num_elements = 0;
    while (1) {
        uint8_t opcode = 0;
        uint16_t bytes_read = fread(&opcode, sizeof(opcode), 1, fp);
        if (bytes_read == 0)
            break;
        
        uint8_t chr;
        uint16_t index;
        if (opcode == 0) { // insert end
            fread(&chr, sizeof(chr), 1, fp);
            insertNode(&head, num_elements, chr);
            ++num_elements;
        } else if (opcode == 1) { // insert front
            fread(&chr, sizeof(chr), 1, fp);
            insertNode(&head, 0, chr);
            ++num_elements;
        } else if (opcode == 2) { // insert index
            fread(&index, sizeof(index), 1, fp);
            fread(&chr, sizeof(chr), 1, fp);
            insertNode(&head, index, chr);
            ++num_elements;
        } else if (opcode == 3) { // remove end
            removeNode(&head, num_elements - 1);
            --num_elements;
        } else if (opcode == 4) { // remove front
            removeNode(&head, 0);
            --num_elements;
        } else if (opcode == 5) { // remove index
            fread(&index, sizeof(index), 1, fp);
            removeNode(&head, index);
            --num_elements;
        } else {
            printf("Bad read: %01x", opcode);
            exit(EXIT_FAILURE);
        }
    }

    printNode(&head);
    return 0;
}