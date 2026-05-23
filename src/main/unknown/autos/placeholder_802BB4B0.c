#include "ghidra_import.h"

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E8234;
extern f32 lbl_803E82A4;
extern f32 lbl_803E82A8;
extern f32 lbl_803DE4C4;
extern int lbl_803DB130[];
extern void *gGameUIInterface;
extern void *gMapEventInterface;
extern void *gPlayerInterface;

extern int *Camera_GetCurrentViewSlot(void);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern u32 getButtonsJustPressed(int controller);
extern u32 getButtonsHeld(int controller);
extern void fn_802BB998(int obj, int state, int state2);

/*
 * Empty stub.
 *
 * EN v1.1 Address: 0x802BB4B0, size 4b
 */
void DIMSnowHorn1_hitDetect(void) {}

#pragma peephole off
#pragma scheduling off
#pragma dont_inline on
void fn_802BB4B4(int obj, int a, int slot)
{
    int matchFrame = (slot == -1) ? 1 : ((framesThisStep - 1 - slot) == 0);
    int *viewSlot = Camera_GetCurrentViewSlot();
    int state = *(int *)(obj + 0xb8);

    *(u8 *)(state + 0x354) = 0;
    *(u32 *)state &= ~0x8000;

    if (*(u8 *)(state + 0xa8a) == 2) {
        if (GameBit_Get(0x3e2) != 0) {
            *(s16 *)(state + 0xa88) -= 1;
        } else {
            *(s16 *)(state + 0xa88) = 0x3e8;
        }
        (*(void (**)(int))(*(int *)gGameUIInterface + 0x5c))(*(s16 *)(state + 0xa88));
        if (GameBit_Get(0x3e9) != 0) {
            GameBit_Set(0x3e9, 0);
            *(s16 *)(state + 0xa88) = 0x3e8;
        }
        if (*(s16 *)(state + 0xa88) < 0) {
            *(s16 *)(state + 0xa88) = 0;
            (*(void (**)(void))(*(int *)gMapEventInterface + 0x28))();
        }
        *(f32 *)(state + 0x290) = (f32)(s8)padGetStickX(0);
        *(f32 *)(state + 0x28c) = (f32)(s8)padGetStickY(0);
        *(u32 *)(state + 0x31c) = getButtonsJustPressed(0);
        *(u32 *)(state + 0x318) = getButtonsHeld(0);
        *(s16 *)(state + 0x330) = *(s16 *)viewSlot;
    } else {
        *(f32 *)(state + 0x290) = lbl_803E8234;
        *(f32 *)(state + 0x28c) = lbl_803E8234;
        *(u32 *)(state + 0x31c) = 0;
        *(u32 *)(state + 0x318) = 0;
        *(u16 *)(state + 0x330) = 0;
    }

    *(u32 *)state |= 0x00400000;
    if (matchFrame != 0) {
        *(u32 *)state &= ~0x00400000;
    }

    if (*(s8 *)(state + 0x25f) != 0) {
        *(f32 *)(obj + 0x28) = *(f32 *)(obj + 0x28) - lbl_803E82A4 * (f32)a;
    }

    {
        f32 cur = *(f32 *)(obj + 0x28);
        if (cur < lbl_803E82A8) {
            cur = lbl_803E82A8;
        } else if (cur > lbl_803E8234) {
            cur = lbl_803E8234;
        }
        *(f32 *)(obj + 0x28) = cur;
    }

    (*(void (**)(int, int, f32, f32, int *, f32 *))(*(int *)gPlayerInterface + 0x8))
        (obj, state, timeDelta, timeDelta, lbl_803DB130, &lbl_803DE4C4);
    fn_802BB998(obj, state, state);
}
#pragma dont_inline reset
#pragma scheduling reset
#pragma peephole reset
