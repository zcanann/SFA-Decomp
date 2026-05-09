#include "ghidra_import.h"
#include "main/dll/TREX/TREX_Lazerwall.h"

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void *Obj_GetPlayerObject(void);
extern void ObjHits_DisableObject(int obj);

extern int Stack_IsEmpty(int stack);
extern int Stack_IsFull(int stack);
extern int Stack_Pop(int stack, int *out);
extern int Stack_Push(int stack, int *in);

extern int isGameTimerDisabled(void);
extern void gameTimerStop(void);
extern void hudFn_8011f6f0(int x);
extern void hudFn_8011f38c(int x);

extern undefined4 *lbl_803DCA74;
extern undefined4 *lbl_803DCA9C;
extern undefined4 *lbl_803DCAAC;

extern f32 lbl_803E59DC;
extern f32 lbl_803E59E0;
extern u32 lbl_803E59D0;
extern u32 lbl_803E59D4;

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_801E67BC
 * EN v1.0 Address: 0x801E67BC
 * EN v1.0 Size: 468b
 */
int fn_801E67BC(int arg1, int arg2)
{
    int state;
    int playerObj;
    int hit;
    u32 head[2];
    int popOut;
    int pushKindA;
    int pushKindB;

    head[0] = lbl_803E59D0;
    head[1] = lbl_803E59D4;
    playerObj = (int)Obj_GetPlayerObject();
    state = *(int *)(arg1 + 0xb8);

    if (*(s8 *)(arg2 + 0x27a) != 0) {
        if (Stack_IsEmpty(*(int *)(state + 0x9b0)) != 0) {
            int found = (*(int (**)(u32 *, int, int, f32, f32, f32))(*(int *)*lbl_803DCA9C + 0x14))(
                head, 2, -1,
                *(f32 *)(playerObj + 0xc),
                *(f32 *)(playerObj + 0x10),
                *(f32 *)(playerObj + 0x14));

            if (found != -1) {
                hit = (*(int (**)(void))(*(int *)*lbl_803DCA9C + 0x1c))();
                *(f32 *)(arg1 + 0xc) = *(f32 *)(hit + 0x8);
                *(f32 *)(arg1 + 0x10) = lbl_803E59E0 + *(f32 *)(hit + 0xc);
                *(f32 *)(arg1 + 0x14) = *(f32 *)(hit + 0x10);
                *(s16 *)arg1 = (s16)((s32)*(s8 *)(hit + 0x2c) << 8);
                *(f32 *)(state + 0x9bc) = lbl_803E59E0 + *(f32 *)(hit + 0xc);
                *(s16 *)(state + 0x9ca) = 0;
                *(u8 *)(state + 0x9d3) = *(u8 *)(hit + 0x19);
            }

            if ((s8)*(u8 *)(hit + 0x19) == 0xc) {
                pushKindA = 1;
                if (Stack_IsFull(*(int *)(state + 0x9b0)) == 0) {
                    Stack_Push(*(int *)(state + 0x9b0), &pushKindA);
                }
            } else {
                pushKindB = 2;
                if (Stack_IsFull(*(int *)(state + 0x9b0)) == 0) {
                    Stack_Push(*(int *)(state + 0x9b0), &pushKindB);
                }
            }

            *(f32 *)(arg2 + 0x280) = lbl_803E59DC;
            *(u8 *)(state + 0x9d4) = (u8)(*(u8 *)(state + 0x9d4) | 0x20);
        }
    }

    *(u8 *)(state + 0x9d6) = 0xff;
    if (*(u8 *)(state + 0x9d6) == 0xff) {
        popOut = 0;
        if (Stack_IsEmpty(*(int *)(state + 0x9b0)) == 0) {
            Stack_Pop(*(int *)(state + 0x9b0), &popOut);
        }
        return popOut + 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801E6990
 * EN v1.0 Address: 0x801E6990
 * EN v1.0 Size: 56b
 */
int fn_801E6990(void)
{
    if (GameBit_Get(0x617) != 0) {
        return 6;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801E69C8
 * EN v1.0 Address: 0x801E69C8
 * EN v1.0 Size: 328b
 */
int fn_801E69C8(int arg1)
{
    int state;
    int local10;
    int localC;
    int local8;

    state = *(int *)(arg1 + 0xb8);
    *(u8 *)(arg1 + 0xaf) = (u8)(*(u8 *)(arg1 + 0xaf) | 8);
    *(u8 *)(state + 0x9d6) = 0;
    ObjHits_DisableObject(arg1);

    (*(void (**)(int, int *, int *, int *))(*(int *)*(int *)(*(int *)(state + 0x9b4) + 0x68) + 0x54))(
        *(int *)(state + 0x9b4), &local10, &localC, &local8);

    localC = localC - local10;

    if (isGameTimerDisabled() != 0 || localC >= local8 || local10 != 0) {
        gameTimerStop();
        hudFn_8011f6f0(0);
        GameBit_Set(0x626, 0);

        if (localC >= local8) {
            GameBit_Set(0x624, 1);
        } else {
            GameBit_Set(0x625, 1);
        }

        hudFn_8011f38c(2);

        (*(void (**)(int, int, int))(*(int *)*lbl_803DCAAC + 0x50))(
            (s32)*(s8 *)(arg1 + 0xac), 6, 0);

        (*(void (**)(int, int, int, int, int))(*(int *)*lbl_803DCA74 + 0x4))(0, 0xf3, 0, 0, 0);
    }

    return 0;
}

#pragma peephole reset
#pragma scheduling reset
