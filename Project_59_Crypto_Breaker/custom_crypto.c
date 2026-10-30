#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void encrypt(char *plaintext, char *key, char *ciphertext) {
    int key_len = strlen(key);
    int i;
    for (i = 0; plaintext[i] != '\0'; i++) {
        ciphertext[i] = plaintext[i] ^ key[i % key_len];
    }
    ciphertext[i] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <plaintext> <key>\n", argv[0]);
        return 1;
    }
    char ciphertext[256];
    encrypt(argv[1], argv[2], ciphertext);

    printf("Ciphertext (hex): ");
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        printf("%02x", (unsigned char)ciphertext[i]);
    }
    printf("\n");
    return 0;
}
