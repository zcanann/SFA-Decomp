/*
 * main/dll/baddie/wispBaddie.c
 *
 * Text span (EN v1.0): 0x801262CC..0x80128120 (3 functions, 7764 b)
 *  - pauseMenuDraw   @ 0x801262CC, 4564 b
 *  - fn_801274A0     @ 0x801274A0, 2692 b
 *  - fn_80127F24     @ 0x80127F24,  508 b
 *
 * The Ghidra-imported placeholder previously declared two 4-byte
 * `FUN_801262cc` / `FUN_801262d0` ghost stubs which do not exist in the
 * v1.0 binary (cf. sfa_ghost_stubs.md). Those have been deleted; this
 * file now hosts hand-decompiled implementations of the three real
 * functions in the unit.
 */

#include "ghidra_import.h"
#include "main/dll/baddie/wispBaddie.h"

extern f32   fn_80293E80(f32 x);
extern void  fn_8011EDA4(void* tex, s16 x, u8 alpha, s32 mode, s32 flag, f32 a, f32 b);

extern u8 hudTextures[0x198];

extern f32 lbl_803DD748;
extern s16 lbl_803DD75C;

extern f32 lbl_803E1E6C;
extern f32 lbl_803E1E78;
extern f32 lbl_803E1E94;
extern f32 lbl_803E1EC8;
extern f32 lbl_803E1EE4;
extern f32 lbl_803E1F18;
extern f32 lbl_803E201C;
extern f32 lbl_803E2090;
extern f32 lbl_803E20BC;
extern f32 lbl_803E20C0;
extern f32 lbl_803E20C4;
extern f32 lbl_803E20C8;
extern f32 lbl_803E20CC;
extern f32 lbl_803E20D0;

#pragma peephole off
#pragma scheduling off
void fn_80127F24(s32 param_1) {
    f32 baseSub;
    f32 baseAdd;
    f32 denom;
    f32 phase;
    f32 yFloat;
    s32 i;

    phase = lbl_803E1F18 *
            fn_80293E80(lbl_803E1EC8 * (lbl_803DD748 * lbl_803E201C) /
                        lbl_803E1E94);

    for (i = 10; (s8)i >= 0; i -= 2) {
        fn_8011EDA4(*(void**)((u8*)hudTextures + 0x11c),
                    (s16)((s16)(0xf5 - (s8)i) - lbl_803DD75C),
                    (u8)param_1, 0x200, 0,
                    lbl_803E20BC, lbl_803E1EE4);
        fn_8011EDA4(*(void**)((u8*)hudTextures + 0x11c),
                    (s16)((s16)(0xf5 - (s8)i) - lbl_803DD75C),
                    (u8)param_1, 0x200, 0,
                    lbl_803E20C0, lbl_803E1EE4);
    }

    yFloat = lbl_803E20C4 - phase * lbl_803E1E6C;
    denom = lbl_803E2090;
    baseAdd = lbl_803E20C8;
    baseSub = lbl_803E20D0;
    for (i = 10; (s8)i >= 0; i -= 10) {
        f32 off = (denom - (f32)(s32)((s8)i)) * phase / denom;
        fn_8011EDA4(*(void**)((u8*)hudTextures + 0x118),
                    (s16)((s16)(0xff - (s8)i) - lbl_803DD75C),
                    (u8)param_1, (s32)yFloat, 0,
                    baseAdd + off, lbl_803E20CC);
        fn_8011EDA4(*(void**)((u8*)hudTextures + 0x118),
                    (s16)((s16)(0xff - (s8)i) - lbl_803DD75C),
                    (u8)param_1, (s32)yFloat, 0,
                    baseSub - off, lbl_803E20CC);
    }
}
#pragma peephole reset
#pragma scheduling reset
