#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Custom VM opcodes
#define OP_PUSH 0x01
#define OP_ADD  0x02
#define OP_CMP  0x03
#define OP_JMP  0x04
#define OP_JZ   0x05
#define OP_PRINT 0x06
#define OP_HALT 0xFF

typedef struct {
    int stack[256];
    int sp;
    int pc;
    int flags;
} VM;

void run_vm(unsigned char *code, int len) {
    VM vm = { .sp = 0, .pc = 0, .flags = 0 };
    while (vm.pc < len) {
        unsigned char op = code[vm.pc++];
        switch (op) {
            case OP_PUSH:
                vm.stack[vm.sp++] = code[vm.pc++];
                break;
            case OP_ADD:
                vm.stack[vm.sp-2] += vm.stack[vm.sp-1];
                vm.sp--;
                break;
            case OP_CMP:
                vm.flags = (vm.stack[vm.sp-2] == vm.stack[vm.sp-1]);
                vm.sp -= 2;
                break;
            case OP_JZ:
                if (vm.flags) vm.pc += (signed char)code[vm.pc];
                else vm.pc++;
                break;
            case OP_PRINT:
                printf("%c", vm.stack[--vm.sp]);
                break;
            case OP_HALT:
                return;
        }
    }
}

int main(void) {
    unsigned char code[] = {
        0x01, 'S', 0x06,   // PUSH 'S' PRINT
        0x01, 'E', 0x06,   // PUSH 'E' PRINT
        0x01, 'C', 0x06,   // PUSH 'C' PRINT
        0x01, 'R', 0x06,   // PUSH 'R' PRINT
        0x01, 'E', 0x06,   // PUSH 'E' PRINT
        0x01, 'T', 0x06,   // PUSH 'T' PRINT
        0xFF               // HALT
    };
    run_vm(code, sizeof(code));
    printf("\n");
    return 0;
}
