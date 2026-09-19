/*
 * vulnerable.c
 * Project #21: Stack-Based Buffer Overflow (Educational)
 *
 * Compile (Linux, protections OFF for learning):
 *   gcc -m32 -fno-stack-protector -z execstack -no-pie vulnerable.c -o vulnerable
 *
 * Compile (Windows 32-bit via MinGW):
 *   i686-w64-mingw32-gcc -fno-stack-protector vulnerable.c -o vulnerable.exe
 *
 * DO NOT deploy this binary anywhere real. Learning only.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];
    /* VULNERABLE: no bounds checking */
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    printf("Input length: %zu\n", strlen(argv[1]));
    vulnerable_function(argv[1]);
    printf("Done!\n");
    return 0;
}