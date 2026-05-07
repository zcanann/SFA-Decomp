#include "ghidra_import.h"
#include "main/dll/newSeqObj.h"

#pragma peephole off
#pragma scheduling off

extern int GameBit_Set(int bit, int value);
extern int Sfx_PlayFromObject(void *obj, int sfxId);
extern void fn_8001FEA8(void);
extern void fn_8015039C(void *p1, void *p2);
extern u32 fn_8014FFB4(void *p1, void *p2, int p3);
extern void fn_8014D08C(void *p1, void *p2, int p3, int p4, f32 f1, int p6);
extern void fn_8014CF7C(void *p1, void *p2, int p3, int p4, f32 f1, f32 f2);
extern void ObjAnim_SetMoveProgress(void *obj, f32 progress);
extern void ObjAnim_SetCurrentMove(void *obj, int move, f32 f1, int p4);

extern u8 lbl_8031DD30[];
extern f32 timeDelta;
extern f32 lbl_803E2740;
extern f32 lbl_803E274C;
extern f32 lbl_803E2768;
extern f32 lbl_803E276C;
extern f32 lbl_803E27A0;
extern f64 lbl_803E2770;

int fn_801504F8(void *p1, void *p2, void *p3, int msgId, int arrIdx, int p6) {
    u8 *table = lbl_8031DD30;
    u8 idx = *(u8 *)((u8 *)p2 + 0x33b);
    u8 *entry = table + 0x143c + idx * 0x28;
    u8 *r31 = *(u8 **)(entry + 0x10);
    int retVal = 0;

    if (idx == 5) {
        *(u32 *)((u8 *)p2 + 0x2e8) |= 0x10;
        return 0;
    }
    if (msgId == 0xe) {
        p6 = p6 * 0xa;
    }
    if ((s32)*(s16 *)((u8 *)p1 + 0xa0) == *(u8 *)(r31 + 0x128)) {
        return 0;
    }
    if (msgId == 0x10) {
        *(u32 *)((u8 *)p2 + 0x2e8) |= 0x28;
        return 0;
    }
    return retVal;
}

void fn_80150EDC(void *p1, void *p2) {
    u8 *table = lbl_8031DD30;
    u8 idx = *(u8 *)((u8 *)p2 + 0x33b);
    u8 *entry = table + idx * 0x28;
    void *r30 = *(void **)(entry + 0x143c);
    void *r29 = *(void **)(entry + 0x1454);
    u8 *r28 = *(u8 **)(entry + 0x1458);

    if (idx == 5 && (*(u32 *)((u8 *)p2 + 0x2dc) & 0x800000) != 0) {
        GameBit_Set(0x1c8, 1);
    }

    if (*(void **)((u8 *)p2 + 0x29c) != NULL &&
        *(s16 *)((u8 *)*(void **)((u8 *)p2 + 0x29c) + 0x44) == 1) {
        fn_8001FEA8();
    }

    fn_8015039C(p1, p2);

    if (*(f32 *)((u8 *)p2 + 0x328) != lbl_803E2740 &&
        *(u16 *)((u8 *)p2 + 0x338) != 0) {
        *(f32 *)((u8 *)p2 + 0x328) = *(f32 *)((u8 *)p2 + 0x328) - timeDelta;
        if (*(f32 *)((u8 *)p2 + 0x328) <= lbl_803E2740) {
            *(f32 *)((u8 *)p2 + 0x328) = lbl_803E2740;
            *(u32 *)((u8 *)p2 + 0x2dc) |= 0x40000000;
            *(u16 *)((u8 *)p2 + 0x338) =
                *(u8 *)(r28 + (*(u16 *)((u8 *)p2 + 0x338) << 4) + 0xa);
        }
    }

    if ((u8)fn_8014FFB4(p1, p2, 0) != 0) {
        return;
    }

    if ((*(u32 *)((u8 *)p2 + 0x2dc) & 0x20000000) != 0 &&
        (*(u32 *)((u8 *)p2 + 0x2e0) & 0x20000000) == 0) {
        Sfx_PlayFromObject(p1, 0x17);
        *(u32 *)((u8 *)p2 + 0x2dc) |= 0x40000000;
    }

    if ((*(u32 *)((u8 *)p2 + 0x2dc) & 0x40000000) != 0) {
        u16 cur338 = *(u16 *)((u8 *)p2 + 0x338);
        if (cur338 != 0) {
            u8 *row = r28 + (cur338 << 4);
            *(u8 *)((u8 *)p2 + 0x2f2) = (u8)*(u32 *)(row + 0xc);
            fn_8014D08C(p1, p2, *(u8 *)(row + 0x8), 0,
                        *(f32 *)(r28 + (cur338 << 4)),
                        (u8)*(u32 *)(row + 0x4));
            ObjAnim_SetMoveProgress(p1,
                *(f32 *)(table + (*(u8 *)(r28 + (*(u16 *)((u8 *)p2 + 0x338) << 4) + 0x8) << 2)));
            *(u16 *)((u8 *)p2 + 0x338) =
                *(u8 *)(r28 + (*(u16 *)((u8 *)p2 + 0x338) << 4) + 0x9);
        } else {
            u16 idx2a0 = *(u16 *)((u8 *)p2 + 0x2a0);
            u8 *row = (u8 *)r29 + idx2a0 * 0xc;
            u8 v8 = *(u8 *)(row + 0x8);
            *(u8 *)((u8 *)p2 + 0x2f2) = 0;
            *(u8 *)((u8 *)p2 + 0x2f3) = 0;
            *(u8 *)((u8 *)p2 + 0x2f4) = 0;
            if (v8 == 0) {
                *(u8 *)((u8 *)p2 + 0x323) = 3;
                ObjAnim_SetCurrentMove(p1, *(u8 *)((u8 *)r30 + 0x2c), lbl_803E2740, 0);
            } else {
                fn_8014D08C(p1, p2, v8, 0,
                            *(f32 *)((u8 *)r29 + idx2a0 * 0xc), 0xb);
                ObjAnim_SetMoveProgress(p1,
                    *(f32 *)(table + (*(u8 *)((u8 *)r29 + (*(u16 *)((u8 *)p2 + 0x2a0)) * 0xc + 0x8) << 2)));
            }
        }
    }

    if ((s32)*(s16 *)((u8 *)p1 + 0xa0) == *(u8 *)((u8 *)r30 + 0x2c)) {
        *(f32 *)((u8 *)p2 + 0x308) =
            *(f32 *)((u8 *)p2 + 0x2fc) *
            (((f32)(s32) * (u16 *)((u8 *)p2 + 0x2a4) /
              *(f32 *)((u8 *)p2 + 0x2a8) / lbl_803E274C) *
             *(f32 *)(table + (*(u8 *)((u8 *)p2 + 0x33b) << 2) + 0x1538));
        if (*(f32 *)((u8 *)p2 + 0x308) < lbl_803E27A0) {
            *(f32 *)((u8 *)p2 + 0x308) = lbl_803E27A0;
        }
    }

    if ((*(u8 *)((u8 *)p2 + 0x323) & 0x10) == 0) {
        void *p_29c = *(void **)((u8 *)p2 + 0x29c);
        f32 f1 = *(f32 *)((u8 *)p_29c + 0xc);
        f32 f2 = *(f32 *)((u8 *)p_29c + 0x14);
        fn_8014CF7C(p1, p2, 0xf, 0, f1, f2);
    }
}
