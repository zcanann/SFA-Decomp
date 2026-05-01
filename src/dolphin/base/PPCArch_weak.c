#include "dolphin.h"

__declspec(weak) asm void PPCMtdec(register u32 newDec) {
    nofralloc
    mtdec r3
    blr
}

__declspec(weak) asm void PPCHalt(void) {
    nofralloc
    sync
loop:
    nop
    li r3, 0
    nop
    b loop
}
