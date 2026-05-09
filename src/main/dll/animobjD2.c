#include "ghidra_import.h"
#include "main/dll/animobjD2.h"

#pragma peephole off
#pragma scheduling off

extern void *fn_80296118(void *p);
extern void **ObjGroup_GetObjects(int group, int *countOut);
extern f32 Vec_xzDistance(void *a, void *b);
extern int fn_8002178C(f32 dx, f32 dz);
extern int randomGetRange(int lo, int hi);
extern f32 __ieee754_rem_pio2(int angle);
extern f32 fn_8029397C(int angle);
extern int trickyFn_8013b368(void *p1, void *p2, f32 f);
extern void fn_80148B78(const char *fmt, ...);

extern f32 lbl_803E23F8;
extern f32 lbl_803E24D4;
extern f32 lbl_803E2488;
extern const char sTrickyShouldNeverStopCirclingError[];

void *fn_8013EE84(void *obj, void *arg2) {
    void *p_24 = *(void **)((u8 *)arg2 + 0x24);
    void *target;
    void **list;
    int count;
    int i;
    f32 d1, d2, d3;

    if (*(s16 *)((u8 *)p_24 + 0x46) == 0x6a3) {
        return p_24;
    }

    target = fn_80296118(*(void **)((u8 *)arg2 + 0x4));
    if (target == NULL) goto fail;

    list = ObjGroup_GetObjects(3, &count);
    for (i = 0; i < count; i++) {
        if (list[i] == target) {
            d1 = Vec_xzDistance((u8 *)obj + 0x18, (u8 *)target + 0x18);
            d2 = Vec_xzDistance((u8 *)obj + 0x18, (u8 *)*(void **)((u8 *)arg2 + 0x4) + 0x18);
            d3 = Vec_xzDistance((u8 *)target + 0x18, (u8 *)*(void **)((u8 *)arg2 + 0x4) + 0x18);
            if ((d1 + d2) >= lbl_803E23F8 * d3) {
                goto fail;
            }
            return target;
        }
    }
fail:
    return NULL;
}

void fn_8013EF8C(void *p1, void *p2) {
    void *p_24 = *(void **)((u8 *)p2 + 0x24);
    f32 dx = *(f32 *)((u8 *)p_24 + 0x18) - *(f32 *)((u8 *)p1 + 0x18);
    f32 dz = *(f32 *)((u8 *)p_24 + 0x20) - *(f32 *)((u8 *)p1 + 0x20);
    int angle = fn_8002178C(dx, dz);
    s32 delta;
    s32 absDelta;

    if (*(u8 *)((u8 *)p2 + 0xa) == 0) {
        *(s32 *)((u8 *)p2 + 0x700) = randomGetRange(0, 1);
        if (*(s32 *)((u8 *)p2 + 0x700) == 0) {
            *(s32 *)((u8 *)p2 + 0x700) = -1;
        }
        *(s32 *)((u8 *)p2 + 0x704) = angle;
        *(u8 *)((u8 *)p2 + 0xa) = 1;
    }

    delta = angle - (s32)(u16)*(s32 *)((u8 *)p2 + 0x704);
    if (delta > 0x8000) delta -= 0xFFFF;
    if (delta < -0x8000) delta += 0xFFFF;

    absDelta = (delta < 0) ? -delta : delta;
    if (absDelta < 0x2000) {
        *(s32 *)((u8 *)p2 + 0x704) =
            *(s32 *)((u8 *)p2 + 0x704) + (*(s32 *)((u8 *)p2 + 0x700) << 11);
    }

    *(f32 *)((u8 *)p2 + 0x708) =
        *(f32 *)((u8 *)*(void **)((u8 *)p2 + 0x24) + 0x18) -
        lbl_803E24D4 * __ieee754_rem_pio2((u16)*(s32 *)((u8 *)p2 + 0x704));
    *(f32 *)((u8 *)p2 + 0x70c) =
        *(f32 *)((u8 *)*(void **)((u8 *)p2 + 0x24) + 0x1c);
    *(f32 *)((u8 *)p2 + 0x710) =
        *(f32 *)((u8 *)*(void **)((u8 *)p2 + 0x24) + 0x20) -
        lbl_803E24D4 * fn_8029397C((u16)*(s32 *)((u8 *)p2 + 0x704));

    if (trickyFn_8013b368(p1, p2, lbl_803E2488) == 0) {
        fn_80148B78(sTrickyShouldNeverStopCirclingError);
    }
}
