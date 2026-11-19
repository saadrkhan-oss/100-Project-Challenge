#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// BUG 1: Buffer overflow if input > 32 bytes
void check_password(char *input) {
    char buf[32];
    strcpy(buf, input);  // no bounds check
    if (strcmp(buf, "SECRET123") == 0) {
        printf("Access granted!\n");
    } else {
        printf("Access denied.\n");
    }
}

// BUG 2: Integer overflow leading to small allocation
void process_count(unsigned int count) {
    if (count > 0) {
        char *ptr = malloc(count * 4);  // overflow if count > 0x3FFFFFFF
        if (ptr) {
            memset(ptr, 'A', count * 4);
            free(ptr);
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input>\n", argv[0]);
        return 1;
    }

    // Dispatch based on first char
    if (argv[1][0] == 'P') {
        check_password(argv[1] + 1);
    } else if (argv[1][0] == 'C') {
        process_count(atoi(argv[1] + 1));
    } else {
        printf("Unknown command\n");
    }
    return 0;
}
