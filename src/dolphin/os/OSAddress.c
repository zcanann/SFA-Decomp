#include <dolphin/types.h>

/*
 * Target bytes at this split are not the real OSPhysicalToCached / etc.
 * address-conversion helpers (those live inline as macros in <dolphin/os.h>).
 * The target object appears to be unrelated leftover main-text bytes under
 * SDK-exported names, so this file stays as tiny sdata getter/setter stubs
 * against two s16s and one u8 until the surrounding split is recovered.
 */

extern s16 lbl_803DDCEC;
extern s16 lbl_803DDCEE;
extern u8 lbl_803DDD00;

void OSPhysicalToCached(s16 paddr) {
    lbl_803DDCEE = paddr;
}

s16 OSPhysicalToUncached(void) {
    return lbl_803DDCEE;
}

void OSCachedToPhysical(s16 caddr) {
    lbl_803DDCEC = caddr;
}

s16 OSUncachedToPhysical(void) {
    return lbl_803DDCEC;
}

void OSCachedToUncached(u8 caddr) {
    lbl_803DDD00 = caddr;
}

u8 OSUncachedToCached(void) {
    return lbl_803DDD00;
}
