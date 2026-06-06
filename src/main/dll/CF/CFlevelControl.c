#include "main/dll/CF/CFlevelControl.h"
#include "main/dll/CF/CFTreasSharpy.h"
#include "main/objanim.h"

extern void *Obj_GetPlayerObject(void);
extern void *Camera_GetCurrentViewSlot(void);
extern u32 GameBit_Get(int bit);
extern u32 GameBit_Set(int bit, int value);
extern void ObjHits_SetHitVolumeSlot(int obj, int p2, int p3, int p4);
extern int  ObjHits_GetPriorityHit(int obj, undefined4 *outHit, int *outIdx, u32 *outVol);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int  randomGetRange(int lo, int hi);
extern int  objFindTexture(int p1, int p2, int p3);
extern void getLActions(int p1, int p2, int p3, int p4, int p5, int p6);
extern float sqrtf(float x);

extern u8 framesThisStep;
extern f32 timeDelta;
extern void *gObjectTriggerInterface;

extern f64 lbl_803E3DE0;
extern f32 lbl_803E3DE8;
extern f32 lbl_803E3DEC;
extern f32 lbl_803E3DF0;
extern f32 lbl_803E3DF4;
extern f32 lbl_803E3DF8;
extern f32 lbl_803E3DFC;
extern f32 lbl_803E3E00;
extern f32 lbl_803E3E04;
extern f32 lbl_803E3E08;
extern f32 lbl_803E3E0C;
extern f32 lbl_803E3E10;
extern f32 lbl_803E3E14;
extern f64 lbl_803E3E18;
extern f32 lbl_803E3E20;
extern f64 lbl_803E3E28;

/*
 * --INFO--
 *
 * Function: cfccrate_update
 * EN v1.0 Address: 0x8018D8DC
 * EN v1.0 Size: 1992b
 */
#pragma scheduling off
#pragma peephole off
void cfccrate_update(int obj)
{
    CfCcrateState *state; /* r31 = obj->b8 */
    int viewslot;    /* r29 = obj->4c */
    int tmp;
    short id;

    Obj_GetPlayerObject();
    state = *(CfCcrateState **)(obj + 0xb8);
    Camera_GetCurrentViewSlot();
    id = *(short *)(obj + 0x46);
    viewslot = *(int *)(obj + 0x4c);

    switch (id) {
    case 0x7de:
        if (GameBit_Get(state->gameBit) != 0) {
            *(short *)(obj + 0x4) = (short)-(timeDelta * state->oscVelB - (f32)*(short *)(obj + 0x4));
        } else {
            *(short *)(obj + 0x4) = (short)(timeDelta * state->oscVelB + (f32)*(short *)(obj + 0x4));
        }
        break;
    case 0x729:
        if (GameBit_Get(state->gameBit) == 0) {
            *(short *)(obj + 0x2) = *(short *)(obj + 0x2) + framesThisStep * 100;
        }
        break;
    case 0x71b:
        *(u16 *)&state->lingerTimer = state->lingerTimer - framesThisStep;
        ObjHits_SetHitVolumeSlot(obj, 0x13, 1, 0);
        if (state->lingerTimer > 0) {
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - (f32)(lbl_803E3DE0 * (double)timeDelta);
        } else {
            Obj_FreeObject(obj);
        }
        break;
    case 0x6fc:
        if ((GameBit_Get(state->gameBit) != 0) &&
            (*(f32 *)(obj + 0x10) <= lbl_803E3DE8 + *(f32 *)(viewslot + 0xc))) {
            *(f32 *)(obj + 0x10) = lbl_803E3DEC * timeDelta + *(f32 *)(obj + 0x10);
            if (lbl_803E3DE8 + *(f32 *)(viewslot + 0xc) <= *(f32 *)(obj + 0x10)) {
                GameBit_Set(state->gameBit, 0);
            }
        }
        break;
    case 0x6fd:
        if (GameBit_Get(state->gameBit) != 0) {
            *(short *)(obj + 0) = *(short *)(obj + 0) + (s32)(lbl_803E3DF0 * timeDelta);
            *(short *)(obj + 0x4) = *(short *)(obj + 0x4) + (s32)(lbl_803E3DF4 * timeDelta);
        } else {
            *(short *)(obj + 0) = *(short *)(obj + 0) + (s32)(lbl_803E3DF0 * timeDelta);
            *(short *)(obj + 0x4) = *(short *)(obj + 0x4) + (s32)(lbl_803E3DF4 * timeDelta);
        }
        break;
    case 0x6fe:
        if (GameBit_Get(state->gameBit) != 0) {
            *(short *)(obj + 0x2) = *(short *)(obj + 0x2) + (s32)(lbl_803E3DF0 * timeDelta);
            *(short *)(obj + 0x4) = *(short *)(obj + 0x4) + (s32)(lbl_803E3DF4 * timeDelta);
        } else {
            *(short *)(obj + 0x2) = *(short *)(obj + 0x2) + (s32)(lbl_803E3DF0 * timeDelta);
            *(short *)(obj + 0x4) = *(short *)(obj + 0x4) + (s32)(lbl_803E3DF4 * timeDelta);
        }
        break;
    case 0x622: {
        int *p = (int *)objFindTexture(obj, 0, 0);
        if ((p != NULL) && (GameBit_Get(state->gameBit) != 0) && (*p == 0)) {
            Sfx_PlayFromObject(obj, 0x3c4);
            *p = 0x100;
        }
        break;
    }
    case 0x65c:
        break;
    case 0x65d:
        ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E3DF8, timeDelta, NULL);
        break;
    case 0x6b4:
        ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E3DF8, timeDelta, NULL);
        break;
    case 0x708:
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) != 0) {
            GameBit_Set(state->gameBit, 1);
        }
        if (GameBit_Get(state->gameBit) == 0) {
            *(short *)(obj + 0) = *(short *)(obj + 0) + (short)*(s8 *)(viewslot + 0x18) * framesThisStep;
        }
        break;
    case 0x409:
        (**(void(***)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
        break;
    case 0x6be:
        if ((GameBit_Get(state->gameBit2) != 0) && (state->latch3E == 0)) {
            state->latch3E = 1;
            (**(void(***)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(0, obj, -1);
        }
        break;
    case 0x4bf:
        if ((*(f32 *)(obj + 0x10) < lbl_803E3DFC + *(f32 *)(viewslot + 0xc)) &&
            (GameBit_Get(state->gameBit) != 0)) {
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + timeDelta;
        }
        break;
    case 0x828:
        if ((GameBit_Get(state->gameBit2) != 0) && (state->latch3E == 0)) {
            tmp = *(short *)(obj + 0x4) + (s32)(lbl_803E3E00 * timeDelta);
            if (tmp > 0x7fff) {
                state->latch3E = 1;
                *(short *)(obj + 0x4) = 0x7fff;
            } else {
                *(short *)(obj + 0x4) = (short)tmp;
            }
        }
        break;
    case 0x8e:
        state->oscPosA = lbl_803E3E04 * state->oscVelA + state->oscPosA;
        if ((lbl_803E3E08 < state->oscPosA) ||
            (state->oscPosA < lbl_803E3E0C)) {
            state->oscVelA = -state->oscVelA;
        }
        if ((lbl_803E3E10 < state->oscPosB) ||
            (state->oscPosB < lbl_803E3E14)) {
            state->oscVelB = -state->oscVelB;
        }
        state->oscPosB = lbl_803E3E04 * state->oscVelB + state->oscPosB;
        break;
    case 0x10d:
        state->sfxTimer = state->sfxTimer - framesThisStep;
        if (state->sfxTimer < 0) {
            uint r;
            r = randomGetRange(0, state->sfxCount - 1);
            Sfx_PlayFromObject(obj, state->sfxTable[r]);
            *(u16 *)&state->sfxTimer = state->sfxPeriod;
            r = randomGetRange(0, state->sfxPeriod);
            state->sfxTimer = state->sfxTimer + r;
        }
        break;
    case 0x125: {
        f32 fx, fy, fz;
        f32 dist;
        int p;

        *(short *)(obj + 0x4) = (short)(lbl_803E3E18 * ((double)(s32)-(s32)*(short *)(obj + 0x4) - lbl_803E3E28));
        p = (int)Obj_GetPlayerObject();
        fx = *(f32 *)(p + 0x18) - *(f32 *)(obj + 0x18);
        fz = *(f32 *)(p + 0x20) - *(f32 *)(obj + 0x20);
        fy = *(f32 *)(p + 0x1c) - *(f32 *)(obj + 0x1c);
        dist = sqrtf(fy * fy + fx * fx + fz * fz);
        if (dist < lbl_803E3E20) {
            if (state->proximityLatch == 1) {
                state->proximityLatch = 0;
                getLActions(obj, obj, 0x5c, 0, 0, 0);
            }
        } else if ((dist > lbl_803E3E20) && (state->proximityLatch == 0)) {
            state->proximityLatch = 1;
            getLActions(obj, obj, 0x5d, 0, 0, 0);
        }
        break;
    }
    }
}
