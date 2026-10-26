#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void force_system_import(char *cmd) {
    if (cmd == NULL) {
        system("echo dummy");
    }
}

void vulnerable_function(char *input) {
    char buffer[128];
    snprintf(buffer, sizeof(buffer), "%s", input);  // safe copy
    printf(buffer);  // ← VULN: format string
    printf("\n");
}

int main(int argc, char *argv[]) {
    char input[256];
    memset(input, 0, sizeof(input));

    // First read: format string payload to overwrite printf@GOT
    printf("Enter exploit: ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin) == NULL) return 1;
    input[strcspn(input, "\n")] = 0;
    vulnerable_function(input);

    // Second read: /bin/sh to trigger system
    memset(input, 0, sizeof(input));
    printf("Enter command: ");
    fflush(stdout);
    if (fgets(input, sizeof(input), stdin) == NULL) return 1;
    input[strcspn(input, "\n")] = 0;
    vulnerable_function(input);  // printf@GOT now points to system

    return 0;
}
