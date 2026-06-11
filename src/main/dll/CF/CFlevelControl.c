#include "main/dll/CF/CFlevelControl.h"
#include "main/game_object.h"
#include "main/dll/CF/CFTreasSharpy.h"
#include "main/objanim.h"
#include "main/objseq.h"

typedef struct CfccratePlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x18 - 0x10];
    s8 unk18;
    u8 pad19[0x20 - 0x19];
} CfccratePlacement;


extern void* Obj_GetPlayerObject(void);
extern void* Camera_GetCurrentViewSlot(void);
extern u32 GameBit_Get(int bit);
extern u32 GameBit_Set(int bit, int value);
extern void ObjHits_SetHitVolumeSlot(int obj, int p2, int p3, int p4);
extern int ObjHits_GetPriorityHit(int obj, undefined4* outHit, int* outIdx, u32* outVol);
extern void Obj_FreeObject(int obj);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int randomGetRange(int lo, int hi);
extern int objFindTexture(int p1, int p2, int p3);
extern void getLActions(int p1, int p2, int p3, int p4, int p5, int p6);
extern float sqrtf(float x);

extern u8 framesThisStep;
extern f32 timeDelta;
extern ObjectTriggerInterface** gObjectTriggerInterface;

extern f64 lbl_803E3DE0;
extern const f32 lbl_803E3DE8;
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
void cfccrate_update(int obj)
{
    CfCcrateState* state; /* r31 = obj->b8 */
    int viewslot; /* r29 = obj->4c */
    int cam;
    int tmp;
    short id;

    Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    cam = (int)Camera_GetCurrentViewSlot();
    id = ((GameObject*)obj)->anim.seqId;
    viewslot = *(int*)&((GameObject*)obj)->anim.placementData;

    switch (id)
    {
    case 0x7de:
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.rotZ = (short)-(timeDelta * state->oscVelB - (f32)((GameObject*)obj)->anim.rotZ);
        }
        else
        {
            ((GameObject*)obj)->anim.rotZ = (short)(timeDelta * state->oscVelB + (f32)((GameObject*)obj)->anim.rotZ);
        }
        break;
    case 0x729:
        if (GameBit_Get(state->gameBit) == 0)
        {
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 100;
        }
        break;
    case 0x71b:
        state->lingerTimer -= framesThisStep;
        ObjHits_SetHitVolumeSlot(obj, 0x13, 1, 0);
        if (state->lingerTimer <= 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY = (f32)-(lbl_803E3DE0 * timeDelta - ((GameObject*)obj)->anim.localPosY);
        }
        break;
    case 0x6fc:
        if ((GameBit_Get(state->gameBit) != 0) &&
            (((GameObject*)obj)->anim.localPosY <= lbl_803E3DE8 + ((CfccratePlacement*)viewslot)->unkC))
        {
            ((GameObject*)obj)->anim.localPosY = lbl_803E3DEC * timeDelta + ((GameObject*)obj)->anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY >= lbl_803E3DE8 + ((CfccratePlacement*)viewslot)->unkC)
            {
                GameBit_Set(state->gameBit, 0);
            }
        }
        break;
    case 0x6fd:
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        else
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        break;
    case 0x6fe:
        if (GameBit_Get(state->gameBit) != 0)
        {
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        else
        {
            ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + (s32)(lbl_803E3DF0 * timeDelta);
            ((GameObject*)obj)->anim.rotZ = ((GameObject*)obj)->anim.rotZ + (s32)(lbl_803E3DF4 * timeDelta);
        }
        break;
    case 0x622:
        {
            int* p = (int*)objFindTexture(obj, 0, 0);
            if ((p != NULL) && (GameBit_Get(state->gameBit) != 0) && (*p == 0))
            {
                Sfx_PlayFromObject(obj, 0x3c4);
                *p = 0x100;
            }
            break;
        }
    case 0x65c:
        break;
    case 0x65d:
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E3DF8, timeDelta, NULL);
        break;
    case 0x6b4:
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E3DF8, timeDelta, NULL);
        break;
    case 0x708:
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) != 0)
        {
            GameBit_Set(state->gameBit, 1);
        }
        if (GameBit_Get(state->gameBit) == 0)
        {
            ((GameObject*)obj)->anim.rotX = ((GameObject*)obj)->anim.rotX +
                ((s8*)viewslot)[0x18] * framesThisStep;
        }
        break;
    case 0x409:
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        break;
    case 0x6be:
        if ((GameBit_Get(state->gameBit2) != 0) && (state->latch3E == 0))
        {
            state->latch3E = 1;
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        break;
    case 0x4bf:
        if ((((GameObject*)obj)->anim.localPosY < lbl_803E3DFC + ((CfccratePlacement*)viewslot)->unkC) &&
            (GameBit_Get(state->gameBit) != 0))
        {
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + timeDelta;
        }
        break;
    case 0x828:
        if ((GameBit_Get(state->gameBit2) != 0) && (state->latch3E == 0))
        {
            if (((GameObject*)obj)->anim.rotZ + (tmp = (s32)(lbl_803E3E00 * timeDelta)) > 0x7fff)
            {
                state->latch3E = 1;
                ((GameObject*)obj)->anim.rotZ = 0x7fff;
            }
            else
            {
                ((GameObject*)obj)->anim.rotZ = (short)(((GameObject*)obj)->anim.rotZ + tmp);
            }
        }
        break;
    case 0x8e:
        state->oscPosA = lbl_803E3E04 * state->oscVelA + state->oscPosA;
        if ((state->oscPosA > lbl_803E3E08) ||
            (state->oscPosA < lbl_803E3E0C))
        {
            state->oscVelA = -state->oscVelA;
        }
        if ((state->oscPosB > lbl_803E3E10) ||
            (state->oscPosB < lbl_803E3E14))
        {
            state->oscVelB = -state->oscVelB;
        }
        state->oscPosB = lbl_803E3E04 * state->oscVelB + state->oscPosB;
        break;
    case 0x10d:
        state->sfxTimer -= framesThisStep;
        if (state->sfxTimer < 0)
        {
            uint r;
            int tbl;
            r = randomGetRange(0, state->sfxCount - 1) << 1;
            tbl = *(int volatile*)&state->sfxTable;
            Sfx_PlayFromObject(obj, *(u16*)(tbl + r));
            state->sfxTimer = state->sfxPeriod;
            r = randomGetRange(0, state->sfxPeriod);
            state->sfxTimer = state->sfxTimer + r;
        }
        break;
    case 0x125:
        {
            f32 fx, fy, fz;
            f32 dist;
            int p;

            ((GameObject*)obj)->anim.rotZ = (s16)(lbl_803E3E18 * (double)-(s32)*(s16*)(cam + 4));
            p = (int)Obj_GetPlayerObject();
            fx = *(f32*)(p + 0x18) - ((GameObject*)obj)->anim.worldPosX;
            fz = *(f32*)(p + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
            fy = *(f32*)(p + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
            dist = sqrtf(fy * fy + (fx * fx + fz * fz));
            if (dist < lbl_803E3E20)
            {
                if (state->proximityLatch == 1)
                {
                    state->proximityLatch = 0;
                    getLActions(obj, obj, 0x5c, 0, 0, 0);
                }
            }
            else if ((dist > *(volatile f32*)&lbl_803E3E20) && (state->proximityLatch == 0))
            {
                state->proximityLatch = 1;
                getLActions(obj, obj, 0x5d, 0, 0, 0);
            }
            break;
        }
    }
}
