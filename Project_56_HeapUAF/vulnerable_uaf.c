#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[64];
    void (*func)(void);
} User;

void admin_func(void) {
    printf("Admin access granted!\n");
    system("/bin/sh");
}

void user_func(void) {
    printf("User access\n");
}

int main(void) {
    User *user = (User *)malloc(sizeof(User));
    if (!user) return 1;

    strcpy(user->name, "Alice");
    user->func = user_func;

    printf("User: %s\n", user->name);
    user->func();

    free(user);

    // UAF + heap spray: reallocate same-size chunk and overwrite func ptr
    char *spray = (char *)malloc(sizeof(User));
    if (spray) {
        memset(spray, 0, sizeof(User));
        // Write admin_func address at offset 64 (where func pointer lives)
        void **func_ptr = (void **)(spray + 64);
        *func_ptr = (void *)admin_func;
    }

    user->func();  // UAF: calls func pointer from freed (now reallocated) memory

    return 0;
}
