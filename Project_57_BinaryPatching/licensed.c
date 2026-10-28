#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int check_license(char *key) {
    if (strcmp(key, "SECRET_KEY_123") == 0) {
        return 1;  // Valid
    }
    return 0;      // Invalid
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <license_key>\n", argv[0]);
        return 1;
    }
    if (check_license(argv[1])) {
        printf("License valid! Full access granted.\n");
    } else {
        printf("Invalid license. Limited access.\n");
    }
    return 0;
}
