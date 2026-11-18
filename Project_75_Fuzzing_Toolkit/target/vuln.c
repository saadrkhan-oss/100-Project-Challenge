#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// BUG 1: Heap buffer overflow (type 'H')
void parse_header(char *data, size_t len) {
    char *buf = malloc(16);
    if (len > 0 && data[0] == 'H') {
        memcpy(buf, data + 1, len - 1);  // no bounds check
        buf[len - 1 < 15 ? len - 1 : 15] = 0;
        printf("Header: %s\n", buf);
    }
    free(buf);
}

// BUG 2: Stack buffer overflow (type 'S')
void parse_body(char *data, size_t len) {
    char buf[32];
    if (len > 0 && data[0] == 'S') {
        memcpy(buf, data + 1, len - 1);  // no bounds check
        printf("Body: %s\n", buf);
    }
}

// BUG 3: NULL deref (type 'N')
void parse_footer(char *data, size_t len) {
    if (len > 2 && data[0] == 'N') {
        char *ptr = NULL;
        if (len == 5) {
            *ptr = 'X';  // NULL deref
        }
        printf("Footer: %c\n", data[1]);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    char data[1024];
    size_t len = fread(data, 1, sizeof(data), f);
    fclose(f);
    if (len == 0) return 0;
    switch (data[0]) {
        case 'H': parse_header(data, len); break;
        case 'S': parse_body(data, len); break;
        case 'N': parse_footer(data, len); break;
        default: printf("Unknown: %c\n", data[0]); break;
    }
    return 0;
}
