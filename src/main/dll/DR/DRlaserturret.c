#include "ghidra_import.h"
#include "main/dll/DR/DRlaserturret.h"

#pragma peephole off
#pragma scheduling off

extern int Sfx_PlayFromObject(int obj, int sfxId);
extern int Stack_IsFull(void *stack);
extern int Stack_Push(void *stack, void *value);
extern void fn_8001469C(void);
extern void gameTimerInit(int, int);
extern int buttonDisable(int, int);
extern int fn_80014B78(int, char *, char *);
extern uint getButtonsJustPressed(int);
extern uint GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int randomGetRange(int lo, int hi);
extern void *Obj_GetPlayerObject(void);
extern void ObjAnim_SetCurrentMove(void *obj, int mode, float val, uint flags);
extern void ObjHits_DisableObject(void *);
extern void ObjHits_EnableObject(void *);
extern int ObjTrigger_IsSet(void *);
extern void *fn_800394AC(void *obj, int idx, int flags);
extern int fn_80065E50(void *obj, float x, float y, float z, void *out, int p5, int p6);
extern void fn_8011F38C(int);
extern void fn_8011F6F0(int);
extern double fn_801E7C4C(void *obj, void *playerObj, int p3);
extern double fn_80293E80(double);
extern int fn_8029689C(void *playerObj);

extern void *lbl_803DCA4C;
extern void *lbl_803DCA54;
extern void *lbl_803DCA74;
extern u8 framesThisStep;
extern f32 timeDelta;
extern s16 lbl_803DC0A0[1];
extern f32 lbl_803DC0A4[3];
extern f32 lbl_803E59DC;
extern f32 lbl_803E59E0;
extern f32 lbl_803E59E4;
extern f32 lbl_803E59E8;
extern f32 lbl_803E59EC;
extern f32 lbl_803E59F0;
extern f32 lbl_803E5A08;
extern f32 lbl_803E5A0C;
extern f32 lbl_803E5A10;
extern f32 lbl_803E5A14;
extern f32 lbl_803E5A18;
extern f32 lbl_803E5A1C;
extern f32 lbl_803E5A20;

/*
 * --INFO--
 *
 * Function: fn_801E6B10
 * EN v1.0 Address: 0x801E6B10
 * EN v1.0 Size: 504b
 */
int fn_801E6B10(void *obj, void *param2)
{
    void *playerObj;
    void *state;
    void *psStack;
    int v;
    int sum;
    int rng;

    playerObj = Obj_GetPlayerObject();
    state = *(void **)((char *)obj + 0xb8);
    *(u8 *)((char *)state + 0x9d6) = 0xff;
    *(f32 *)((char *)param2 + 0x2a0) = lbl_803E59E4;
    if (*(s16 *)((char *)obj + 0xa0) != 0) {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E59DC, 0);
    }
    ObjHits_EnableObject(obj);
    *(u8 *)((char *)obj + 0xaf) = *(u8 *)((char *)obj + 0xaf) & 0xf7;
    if (GameBit_Get(0x617) == 0) {
        v = 1;
        psStack = *(void **)((char *)state + 0x9b0);
        if (Stack_IsFull(psStack) == 0) {
            Stack_Push(psStack, &v);
        }
        return 7;
    }
    fn_801E7C4C(obj, playerObj, 0);
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)state + 0x9b8) *
            (f32)fn_80293E80(
                (double)(lbl_803E59E8 *
                         (f32)((double)(uint)*(u16 *)((char *)state + 0x9ca)) /
                         lbl_803E59EC)) +
        *(f32 *)((char *)state + 0x9bc);
    sum = (uint)*(u16 *)((char *)state + 0x9ca) + (uint)framesThisStep * 0x100;
    if (sum > 0xffff) {
        rng = randomGetRange(0xf, 0x23);
        *(f32 *)((char *)state + 0x9b8) = lbl_803E59F0 * (f32)rng;
    }
    *(u16 *)((char *)state + 0x9ca) = (u16)sum;
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        if (fn_8029689C(playerObj) < 1) {
            rng = randomGetRange(0, 2);
            (**(void (***)(int, void *, int))((char *)*(void **)&lbl_803DCA54 + 0x48))(rng, obj, -1);
            buttonDisable(0, 0x100);
        } else {
            GameBit_Set(0x61d, 1);
            buttonDisable(0, 0x100);
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801E6D08
 * EN v1.0 Address: 0x801E6D08
 * EN v1.0 Size: 1052b
 */
int fn_801E6D08(void *obj, void *param2)
{
    void *playerObj;
    void *state;
    void *psStack;
    int v;
    int sum;
    int rng;
    float fmin;
    float fdist;
    int count;
    int idx;
    void **arr;
    void *out;

    playerObj = Obj_GetPlayerObject();
    state = *(void **)((char *)obj + 0xb8);
    if (*(s8 *)((char *)param2 + 0x27a) != 0) {
        rng = randomGetRange(0x1f4, 0x3e8);
        *(f32 *)((char *)state + 0x9c0) = (f32)rng;
        *(u8 *)((char *)state + 0x9d4) = *(u8 *)((char *)state + 0x9d4) & 0xf7;
    }
    if ((*(u8 *)((char *)state + 0x9d4) & 8) != 0) {
        if (*(s8 *)((char *)param2 + 0x346) != 0) {
            if (*(s16 *)((char *)obj + 0xa0) == 0x11) {
                if (*(f32 *)((char *)param2 + 0x2a0) > lbl_803E59DC) {
                    ObjAnim_SetCurrentMove(obj, 0x12, 0.0f, 0);
                    goto L_DE8;
                }
            }
            if (*(s16 *)((char *)obj + 0xa0) != 0) {
                ObjAnim_SetCurrentMove(obj, 0, lbl_803E59DC, 0);
            }
        L_DE8:
            *(f32 *)((char *)param2 + 0x2a0) = lbl_803E59E4;
            *(u8 *)((char *)state + 0x9d4) = *(u8 *)((char *)state + 0x9d4) & 0xf7;
            rng = randomGetRange(0x1f4, 0x3e8);
            *(f32 *)((char *)state + 0x9c0) = (f32)rng;
        }
    } else {
        if (*(s16 *)((char *)obj + 0xa0) != 0x12 && *(s16 *)((char *)obj + 0xa0) != 0) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E59DC, 0);
            *(f32 *)((char *)param2 + 0x2a0) = lbl_803E59E4;
        }
    }
    *(f32 *)((char *)state + 0x9c0) = *(f32 *)((char *)state + 0x9c0) - timeDelta;
    if (*(f32 *)((char *)state + 0x9c0) <= lbl_803E59DC && (*(u8 *)((char *)state + 0x9d4) & 8) == 0) {
        Sfx_PlayFromObject((int)obj, 0x40d);
        if (*(s16 *)((char *)obj + 0xa0) == 0x12) {
            ObjAnim_SetCurrentMove(obj, 0x11, lbl_803E5A08, 0);
            *(f32 *)((char *)param2 + 0x2a0) = lbl_803E5A0C;
        } else {
            rng = randomGetRange(0, 1);
            ObjAnim_SetCurrentMove(obj, (int)lbl_803DC0A0[rng], lbl_803E59DC, 0);
            *(f32 *)((char *)param2 + 0x2a0) = lbl_803DC0A4[rng];
        }
        *(u8 *)((char *)state + 0x9d4) = *(u8 *)((char *)state + 0x9d4) | 8;
    }
    if (GameBit_Get(0x617) == 0) {
        v = 4;
        psStack = *(void **)((char *)state + 0x9b0);
        if (Stack_IsFull(psStack) == 0) {
            Stack_Push(psStack, &v);
        }
        return 7;
    }
    {
        float t = (float)fn_801E7C4C(obj, playerObj, 0);
        float target;
        if (t > lbl_803E5A18) {
            target = lbl_803E5A14;
        } else {
            target = lbl_803E59DC;
        }
        *(f32 *)((char *)param2 + 0x280) =
            lbl_803E5A10 * (target - *(f32 *)((char *)param2 + 0x280)) * timeDelta +
            *(f32 *)((char *)param2 + 0x280);
        if (*(f32 *)((char *)param2 + 0x280) > lbl_803E5A1C) {
            *(f32 *)((char *)param2 + 0x280) = lbl_803E59DC;
        }
        *(f32 *)((char *)param2 + 0x280) = lbl_803E59DC;
    }
    count = fn_80065E50(obj, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
                        *(f32 *)((char *)obj + 0x14), &arr, 0, 0);
    fmin = lbl_803E5A20;
    if (count > 0) {
        idx = 0;
        do {
            fdist = *(f32 *)*(int *)((char *)arr + idx) - *(f32 *)((char *)obj + 0x10);
            if (fdist < lbl_803E59DC) {
                fdist = -fdist;
            }
            if (fdist < fmin) {
                *(f32 *)((char *)state + 0x9bc) =
                    lbl_803E59E0 + *(f32 *)*(int *)((char *)arr + idx);
                fmin = fdist;
            }
            idx += 4;
            count--;
        } while (count != 0);
    }
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)state + 0x9b8) *
            (f32)fn_80293E80(
                (double)(lbl_803E59E8 *
                         (f32)((double)(uint)*(u16 *)((char *)state + 0x9ca)) /
                         lbl_803E59EC)) +
        *(f32 *)((char *)state + 0x9bc);
    sum = (uint)*(u16 *)((char *)state + 0x9ca) + (uint)framesThisStep * 0x100;
    if (sum > 0xffff) {
        rng = randomGetRange(0xf, 0x23);
        *(f32 *)((char *)state + 0x9b8) = lbl_803E59F0 * (f32)rng;
    }
    *(u16 *)((char *)state + 0x9ca) = (u16)sum;
    if (ObjTrigger_IsSet(obj) != 0) {
        rng = randomGetRange(0, 2);
        (**(void (***)(int, void *, int))((char *)*(void **)&lbl_803DCA54 + 0x48))(rng, obj, -1);
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801E7124
 * EN v1.0 Address: 0x801E7124
 * EN v1.0 Size: 128b
 */
int fn_801E7124(void *obj)
{
    void *state;

    state = *(void **)((char *)obj + 0xb8);
    if (GameBit_Get(0xcef) == 0) {
        return 0;
    }
    if (GameBit_Get(0xad3) != 0) {
        return 2;
    }
    GameBit_Set(0xad3, 1);
    {
        void *target = *(void **)((char *)state + 0x9b4);
        (**(void (***)(void *, int, int))(*(int *)((char *)target + 0x68) + 0x24))(target, 1, 2);
    }
    return 2;
}

/*
 * --INFO--
 *
 * Function: fn_801E71A4
 * EN v1.0 Address: 0x801E71A4
 * EN v1.0 Size: 1096b
 */
int fn_801E71A4(void *obj, void *param2, int dispatch)
{
    void *state;
    char stickHi;
    char stickLo;
    s16 v9d0;
    int rng;
    int btn;
    int slot;

    state = *(void **)((char *)obj + 0xb8);
    if (dispatch == 0x14) {
        fn_80014B78(0, &stickHi, &stickLo);
        if ((s8)stickLo < 0) {
            *(s16 *)((char *)state + 0x9d0) = *(s16 *)((char *)state + 0x9d0) - 1;
            Sfx_PlayFromObject(0, 0xf3);
        } else if ((s8)stickLo > 0) {
            *(s16 *)((char *)state + 0x9d0) = *(s16 *)((char *)state + 0x9d0) + 1;
            Sfx_PlayFromObject(0, 0xf3);
        }
        if (*(s16 *)((char *)state + 0x9d0) > *(s16 *)((char *)state + 0x9c8)) {
            *(s16 *)((char *)state + 0x9d0) = *(s16 *)((char *)state + 0x9c8);
        }
        if (*(s16 *)((char *)state + 0x9d0) > (s16)(*(s16 *)((char *)state + 0x9cc) << 1)) {
            *(s16 *)((char *)state + 0x9d0) = (s16)(*(s16 *)((char *)state + 0x9cc) << 1);
        } else if (*(s16 *)((char *)state + 0x9d0) < (s16)(*(s16 *)((char *)state + 0x9cc) >> 1)) {
            *(s16 *)((char *)state + 0x9d0) = (s16)(*(s16 *)((char *)state + 0x9cc) >> 1);
        }
        v9d0 = *(s16 *)((char *)state + 0x9d0);
        *(int *)fn_800394AC(obj, 8, 0) = (v9d0 - v9d0 / 10 * 10) << 8;
        *(int *)fn_800394AC(obj, 7, 0) = (v9d0 / 10 - v9d0 / 100 * 10) << 8;
        slot = v9d0 / 100;
        if (slot > 9) slot = 9;
        *(int *)fn_800394AC(obj, 6, 0) = slot << 8;
    } else if (dispatch == 0x17) {
        fn_80014B78(0, &stickHi, &stickLo);
        if ((s8)stickLo < 0) {
            *(u8 *)((char *)state + 0x9d5) = *(u8 *)((char *)state + 0x9d5) - 1;
            Sfx_PlayFromObject(0, 0xf3);
        } else if ((s8)stickLo > 0) {
            *(u8 *)((char *)state + 0x9d5) = *(u8 *)((char *)state + 0x9d5) + 1;
            Sfx_PlayFromObject(0, 0xf3);
        }
        if (*(u8 *)((char *)state + 0x9d5) > *(s16 *)((char *)state + 0x9c8)) {
            *(u8 *)((char *)state + 0x9d5) = (u8)*(s16 *)((char *)state + 0x9c8);
        }
        if (*(u8 *)((char *)state + 0x9d5) > 0xa) {
            *(u8 *)((char *)state + 0x9d5) = 0xa;
        } else if (*(u8 *)((char *)state + 0x9d5) < 1) {
            *(u8 *)((char *)state + 0x9d5) = 1;
        }
        {
            u8 v = *(u8 *)((char *)state + 0x9d5);
            *(int *)fn_800394AC(obj, 8, 0) = (v - v / 10 * 10) << 8;
            *(int *)fn_800394AC(obj, 7, 0) = (v / 10 - v / 100 * 10) << 8;
            slot = v / 100;
            if (slot > 9) slot = 9;
            *(int *)fn_800394AC(obj, 6, 0) = slot << 8;
        }
        btn = getButtonsJustPressed(0);
        if ((btn & 0x200) != 0) {
            *(u8 *)((char *)state + 0x9d4) = *(u8 *)((char *)state + 0x9d4) | 0x10;
            (**(void (***)(int, int))((char *)*(void **)&lbl_803DCA4C + 0x8))(0x1e, 1);
            return 1;
        }
    }
    btn = getButtonsJustPressed(0);
    if ((btn & 0x100) == 0) {
        return 0;
    }
    {
        char nudge;
        if (*(s16 *)((char *)state + 0x9d0) < *(s16 *)((char *)state + 0x9ce)) {
            if (*(u8 *)((char *)state + 0x9d2) >= 2) nudge = 2;
            else nudge = 0;
        } else {
            nudge = 1;
        }
        if (dispatch == 0x15) {
            if ((s8)nudge == 1) {
                (**(void (***)(void *))(*(int *)((char *)state + 0x68) + 0x48))(state);
            }
            return ((s8)nudge == 1) ? 1 : 0;
        } else if (dispatch < 0x15) {
            if (dispatch == 0x14) {
                if ((s8)nudge == 0) {
                    *(u8 *)((char *)state + 0x9d2) = *(u8 *)((char *)state + 0x9d2) + 1;
                }
                return ((s8)nudge == 0) ? 1 : 0;
            }
        } else if (dispatch < 0x17) {
            return ((s8)nudge == 2) ? 1 : 0;
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801E75EC
 * EN v1.0 Address: 0x801E75EC
 * EN v1.0 Size: 180b
 */
int fn_801E75EC(void *obj)
{
    void *state;

    state = *(void **)((char *)obj + 0xb8);
    if ((*(u8 *)((char *)state + 0x9d4) & 2) != 0) {
        gameTimerInit(0x11, 0x1e);
        fn_8001469C();
        fn_8011F6F0(1);
        GameBit_Set(0x626, 1);
        (**(void (***)(void *, u8))(*(int *)(*(int *)((char *)state + 0x9b4) + 0x68) + 0x4c))(
            *(void **)((char *)state + 0x9b4), *(u8 *)((char *)state + 0x9d5));
        (**(void (***)(int, int, int, int, int))(*(int *)*(void **)&lbl_803DCA74 + 0x4))(
            0, 0xf5, 0, 0, 0);
    } else {
        fn_8011F38C(0);
    }
    *(u8 *)((char *)state + 0x9d4) = 0;
    return 0;
}

#pragma scheduling reset
#pragma peephole reset
