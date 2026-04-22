#include <dolphin/types.h>

/*
 * Target bytes at this split are not the real OSPhysicalToCached / etc.
 * address-conversion helpers (those live inline as macros in <dolphin/os.h>).
 * The symbols here are 6 tiny sdata getter/setter stubs against two s16s
 * and one u8 — kept to preserve the exact byte image at these addresses.
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
