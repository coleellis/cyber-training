#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int isPrime(uint8_t tag)
{
    if (tag < 2) return 0;
    
    for (uint8_t i = 2; i <= tag / 2; ++i)
        if (tag % i == 0) return 0;
    
    return 1;
}

int main()
{
    FILE* fp = fopen("data.bin", "rb");
    if (fp == NULL) {
        printf("Error opening file\n");
        exit(EXIT_FAILURE);
    }

    char* string = malloc(10000 * sizeof(char));

    uint32_t index = 0;
    while (1) {
        uint8_t tag;
        uint8_t length;
        char* value;

        uint8_t bytes = fread(&tag, sizeof(tag), 1, fp);
        if (bytes == 0) break;

        fread(&length, sizeof(length), 1, fp);

        value = malloc(length * sizeof(char));
        fread(value, length, 1, fp);
        
        if (isPrime(tag)) {
            for (uint8_t i = 0; i < length; ++i)
                string[index + i] = value[i];
            index += length;
        }
        free(value);
    }

    uint8_t cps = 8;

    printf("flag{");
    for (uint8_t i = 0; i < cps; ++i)
        printf("%c", string[i]);
    for (uint8_t i = 0; i <= 7; ++i)
        printf("%c", string[strlen(string)/2 - cps/2 + i]);
    for (int16_t i = cps; i > 0; --i)
        printf("%c", string[strlen(string) - i]);
    printf("}\n");

    return 0;
}