#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void copy_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("%s\n", buffer);
}

void format_input(char *input) {
    char buf[128];
    sprintf(buf, "User: %s", input);
    printf(buf);
}

void get_input() {
    char name[32];
    gets(name);
    printf("Hello %s\n", name);
}

int main(int argc, char **argv) {
    if (argc > 1) copy_input(argv[1]);
    return 0;
}
