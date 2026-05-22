

#include "ghidra_import.h"

/* Pattern wrappers. */
int ktrex_stateHandlerA00(void) { return 0x0; }
int drshackle_getExtraSize(void) { return 0x20; }
int drshackle_getObjectTypeId(void) { return 0x0; }
void drshackle_release(void) {}
void drshackle_initialise(void) {}
int hightop_defaultStateHandler(void) { return 0x0; }
void hightop_func15(void) {}
int hightop_func14(void) { return 0x0; }
int hightop_func10(void) { return 0x0; }
int hightop_func0E(void) { return 0x1; }

extern void ObjAnim_SetCurrentMove(int obj, int moveId, f32 t, int unk);
extern u8 framesThisStep;
extern f32 lbl_803E6AA8;
extern f32 lbl_803E6AB4;
extern f32 lbl_803E6AB8;
extern f32 lbl_803E6ABC;
extern f32 lbl_803E6AC0;
extern f32 lbl_803E6AC4;
extern f32 lbl_803E6AC8;

#pragma scheduling off
#pragma peephole off
int hightop_stateHandler08(int obj, u8 *p2) {
    int *state = *(int **)((char *)obj + 0xb8);
    if ((s8)p2[0x27a] != 0) {
        f32 zero;
        *(f32 *)((char *)state + 0xc30) = lbl_803E6AB4;
        zero = lbl_803E6AA8;
        *(f32 *)(p2 + 0x294) = zero;
        *(f32 *)(p2 + 0x284) = zero;
        *(f32 *)(p2 + 0x280) = zero;
        *(f32 *)((char *)obj + 0x24) = zero;
        *(f32 *)((char *)obj + 0x28) = zero;
        *(f32 *)((char *)obj + 0x2c) = zero;
    }
    if ((s8)p2[0x346] != 0) {
        s16 cur = *(s16 *)((char *)obj + 0xa0);
        switch (cur) {
        case 10:
            if (*(f32 *)(p2 + 0x2a0) > lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 5, lbl_803E6AA8, 0);
            } else {
                return 8;
            }
            break;
        case 5:
            if (*(f32 *)((char *)state + 0xc30) < lbl_803E6AA8) {
                ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AB8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6ABC;
            }
            break;
        default:
            ObjAnim_SetCurrentMove(obj, 10, lbl_803E6AA8, 0);
            *(f32 *)(p2 + 0x2a0) = lbl_803E6AC0;
            break;
        }
    }
    if (*(s16 *)((char *)obj + 0xa0) == 10) {
        if (*(f32 *)(p2 + 0x2a0) < lbl_803E6AA8) {
            if (*(f32 *)((char *)obj + 0x98) < lbl_803E6AC4) {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E6AA8, 0);
                *(f32 *)(p2 + 0x2a0) = lbl_803E6AC8;
                return 8;
            }
        }
    }
    *(f32 *)((char *)state + 0xc30) -= (f32)(u32)framesThisStep;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
