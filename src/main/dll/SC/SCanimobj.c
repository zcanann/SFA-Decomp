#include "ghidra_import.h"
#include "main/dll/SC/SCanimobj.h"
#include "main/dll/SC/SClantern.h"

#define SFXbaddie_haga_death 700

extern undefined8 FUN_80006824();
extern int ObjHits_GetPriorityHitWithPosition();
extern void ObjLink_DetachChild(int obj, int child);
extern void Obj_FreeObject(int obj);
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003b818();
extern uint FUN_8007f66c();
extern undefined4 FUN_80081120();
extern int fn_801D70D8(int obj, undefined4 p2, int animObj);
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80294be0();
extern uint FUN_80294cb8();
extern undefined4 FUN_802950c8();

extern u32 GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int value);
extern int Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, int obj, f32 *outDistance);
extern void fn_8003ADC4(int obj, int target, void *state, int a, int b, int c);
extern s16 *objModelGetVecFn_800395d8(int obj, int index);
extern s16 Obj_GetYawDeltaToObject(int obj, int target, int flags);
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 moveProgress, int flags);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objAnimFn_80038f38(int obj, int *animState);
extern void characterDoEyeAnims(int obj, void *state);
extern void objAudioFn_800393f8(int obj, void *state, int sfxId, int a, int b, int c);
extern void ObjHits_EnableObject(int obj);
extern int randFn_80080100(int max);

extern s16 lbl_803DC044;
extern s16 lbl_803DDBF0;
extern s16 lbl_803DDBF2;
extern int lbl_803DC038;
extern int lbl_803DC03C;
extern int lbl_803DC040;
extern int lbl_803DC048;
extern int lbl_803DC04C;
extern f64 lbl_803E5490;
extern f32 lbl_803E5460;
extern f32 lbl_803E546C;
extern f32 lbl_803E54A4;
extern f32 lbl_803E54A8;
extern f32 lbl_803E54AC;

/*
 * --INFO--
 *
 * Function: warpstone_update
 * EN v1.0 Address: 0x801D7674
 * EN v1.0 Size: 1164b
 * EN v1.1 Address: 0x801D76A4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void warpstone_update(int obj)
{
    int state;
    int child;
    int advanceResult;
    int target;
    s16 *modelVec;
    s16 yawDelta;
    int moveId;

    state = *(int *)(obj + 0xb8);
    child = *(int *)state;
    if (child != 0) {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(*(int *)state);
        *(int *)state = 0;
    }

    advanceResult = SClantern_advanceAnimEvents(lbl_803E54A4, obj);
    if (*(s16 *)(obj + 0xa0) == 0) {
        if (randFn_80080100(100) != 0) {
            objAudioFn_800393f8(obj, (void *)(state + 0x14), 0xab, -0x100, -1, 0);
        }
        if (randFn_80080100(500) != 0) {
            objAudioFn_800393f8(obj, (void *)(state + 0x14), 0x417, -0x500, -1, 0);
        }
    }

    if (GameBit_Get(0xc7d) != 0) {
        if (randFn_80080100(lbl_803DC038) != 0) {
            *(u8 *)(state + 0xd5) = (*(u8 *)(state + 0xd5) & ~0x40) |
                ((((*(u8 *)(state + 0xd5) >> 6) & 1) == 0) << 6);
        }
        if (((*(u8 *)(state + 0xd5) >> 6) & 1) == 0) {
            *(u8 *)(state + 0xd5) = (*(u8 *)(state + 0xd5) & ~0x40) |
                ((GameBit_Get(0xa45) & 0xff) << 6);
        }
    }

    if (((*(u8 *)(state + 0xd5) >> 6) & 1) != 0) {
        target = Obj_GetPlayerObject();
    } else {
        target = ObjGroup_FindNearestObject(8, obj, 0);
    }

    *(f32 *)(obj + 0x10) += (f32)lbl_803DC040;
    fn_8003ADC4(obj, target, (void *)(state + 0x74), 0x23, 1, lbl_803DC03C);
    modelVec = objModelGetVecFn_800395d8(obj, 0);
    *(f32 *)(obj + 0x10) -= (f32)lbl_803DC040;

    if (modelVec != NULL) {
        modelVec[1] += lbl_803DDBF2;
        modelVec[0] = 0;
        modelVec[0] += lbl_803DC044;
    }

    if (advanceResult != 0) {
        *(u8 *)(state + 0xd5) &= ~0x10;
        yawDelta = Obj_GetYawDeltaToObject(obj, target, 0);
        yawDelta = yawDelta - lbl_803DDBF0;
        if (ABS((s16)(yawDelta - 0x8000)) > 0x18e3) {
            if (yawDelta > 0) {
                if (yawDelta > 0xe38) {
                    moveId = 0x17;
                } else {
                    moveId = 0x16;
                }
            } else if (yawDelta < -0xe38) {
                moveId = 0x19;
            } else {
                moveId = 0x18;
            }
            if (*(s16 *)(obj + 0xa0) != moveId) {
                ObjAnim_SetCurrentMove(obj, moveId, lbl_803E5460, 0);
            }
        } else if (*(s16 *)(obj + 0xa0) != 0) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5460, 0);
            Sfx_StopFromObject(obj, 0x2f1);
        } else if (randFn_80080100(lbl_803DC048) != 0) {
            Sfx_PlayFromObject(obj, 0x416);
            ObjAnim_SetCurrentMove(obj, 0x1b, lbl_803E5460, 0);
        } else if (randFn_80080100(lbl_803DC04C) != 0) {
            Sfx_PlayFromObject(obj, 0x2f1);
            ObjAnim_SetCurrentMove(obj, 0x1a, lbl_803E5460, 0);
        }
    }

    objAnimFn_80038f38(obj, (int *)(state + 0x14));
    characterDoEyeAnims(obj, (void *)(state + 0x44));
    if (GameBit_Get(0x887) == 0) {
        *(u8 *)(state + 0xc) = 0;
    }
    if (((*(u8 *)(state + 0xd5) >> 4) & 1) != 0) {
        return;
    }

    switch (*(s16 *)(obj + 0xa0)) {
    case 0x17:
    case 0x19:
        if (*(f32 *)(obj + 0x98) > lbl_803E546C) {
            Sfx_PlayFromObject(obj, 0x2f1);
            *(u8 *)(state + 0xd5) |= 0x10;
        }
        break;
    case 0x16:
    case 0x18:
        if (*(f32 *)(obj + 0x98) > lbl_803E546C) {
            Sfx_PlayFromObject(obj, SFXbaddie_haga_death);
            *(u8 *)(state + 0xd5) |= 0x10;
        }
        break;
    case 0x1a:
        if (*(f32 *)(obj + 0x98) > lbl_803E54A8) {
            Sfx_PlayFromObject(obj, 0x417);
            *(u8 *)(state + 0xd5) |= 0x10;
        }
        break;
    case 0x1b:
        if (*(f32 *)(obj + 0x98) > lbl_803E54AC) {
            Sfx_PlayFromObject(obj, 0x2f4);
            *(u8 *)(state + 0xd5) |= 0x10;
        }
        break;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: warpstone_release
 * EN v1.0 Address: 0x801D7BA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void warpstone_release(void)
{
}

/*
 * --INFO--
 *
 * Function: warpstone_initialise
 * EN v1.0 Address: 0x801D7BA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void warpstone_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void warpstone_init(int obj, u8 *setup)
{
  int state;
  s16 setupYaw;

  state = *(int *)(obj + 0xb8);
  setupYaw = (s16)(setup[0x1a] << 8);
  *(s16 *)obj = setupYaw;
  *(void **)(obj + 0xbc) = fn_801D70D8;
  *(s16 *)(state + 0xe) = 0x15a;
  *(s16 *)(state + 0x10) = 0x886;
  ObjHits_EnableObject(obj);
  if (GameBit_Get(0x887) != 0 && GameBit_Get(0x15a) != 0) {
    *(u8 *)(state + 0xc) = 1;
  } else {
    *(u8 *)(state + 0xc) = 0;
  }
  GameBit_Set(*(s16 *)(state + 0x10), 0);
  *(int *)state = 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: sh_levelcontrol_getExtraSize
 * EN v1.0 Address: 0x801D7BA8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_levelcontrol_getExtraSize(void)
{
  return 0x14;
}

extern void envFxActFn_800887f8(int);
extern u32 GameBit_Get(int);
extern int GameBit_Set(int, int);
extern void *gGameUIInterface;

#pragma scheduling off
void sh_levelcontrol_free(void)
{
    envFxActFn_800887f8(0);
    if (GameBit_Get(0x13F) == 0) {
        (*(void (***)(void))gGameUIInterface)[0x19]();
    }
    if (GameBit_Get(0x193) != 0) {
        GameBit_Set(0x194, 0);
    }
}
#pragma scheduling reset
