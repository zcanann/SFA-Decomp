
#include "dolphin/os/__ppc_eabi_init.h"

typedef void (*voidfunctionptr)(void);

extern voidfunctionptr _ctors[];

void __init_cpp(void);

void __init_user(void) {
    __init_cpp();
}

#pragma peephole off
void __init_cpp(void) {
    voidfunctionptr* constructor;

    for (constructor = _ctors; *constructor != 0; constructor++) {
        (*constructor)();
    }
}

#pragma peephole on
void _ExitProcess(void) {
    PPCHalt();
}
