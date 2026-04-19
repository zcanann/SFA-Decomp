#include <dolphin/types.h>

extern s16 lbl_803DDCEC;
extern s16 lbl_803DDCEE;
extern u8 lbl_803DDD00;

asm void* OSPhysicalToCached(register s16 paddr) {
    nofralloc
    sth r3, lbl_803DDCEE(r13)
    blr
}

asm void* OSPhysicalToUncached(register u32 paddr) {
    nofralloc
    lha r3, lbl_803DDCEE(r13)
    blr
}

asm u32 OSCachedToPhysical(register s16 caddr) {
    nofralloc
    sth r3, lbl_803DDCEC(r13)
    blr
}

asm u32 OSUncachedToPhysical(register void* ucaddr) {
    nofralloc
    lha r3, lbl_803DDCEC(r13)
    blr
}

asm void* OSCachedToUncached(register void* caddr) {
    nofralloc
    stb r3, lbl_803DDD00(r13)
    blr
}

asm void* OSUncachedToCached(register void* ucaddr) {
    nofralloc
    lbz r3, lbl_803DDD00(r13)
    blr
}
