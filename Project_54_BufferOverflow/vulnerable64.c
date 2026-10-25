#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char shell_string[] = "/bin/sh";

void force_system_import(char *cmd) {
    if (cmd == NULL) {
        system("echo dummy");
    }
}

void vulnerable_function(char *input, size_t len) {
    char buffer[64];
    memcpy(buffer, input, len);
}

int main(int argc, char *argv[]) {
    char input[512];
    memset(input, 0, sizeof(input));
    printf("Enter input: ");
    fflush(stdout);
    ssize_t n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    vulnerable_function(input, n);
    printf("Done!\n");
    return 0;
}
