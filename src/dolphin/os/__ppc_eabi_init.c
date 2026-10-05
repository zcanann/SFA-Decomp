
#include "dolphin/os/__ppc_eabi_init.h"
#include <dolphin/PPCArch.h>

typedef void (*voidfunctionptr)(void);

extern voidfunctionptr _ctors[];

void __init_cpp(void);

void __init_user(void) {
    __init_cpp();
}

void __init_cpp(void) {
    voidfunctionptr* constructor;

    for (constructor = _ctors; *constructor != 0; constructor++) {
        (*constructor)();
    }
}

void _ExitProcess(void) {
    PPCHalt();
}
