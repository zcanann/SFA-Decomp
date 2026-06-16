#include "main/audio/sfx_ids.h"
#include "main/dll/crrockfallplacement_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMboulder.h"
#include "main/resource.h"

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

/*
 * Per-object extra state for the magiclight proximity light
 * (magiclight_getExtraSize == 0x14 for non-0x172 types).
 */

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);

/*
 * Per-object extra state for the dll_16C map-event boulder proxy
 * (dll_16C_getExtraSize == 0x24).
 */

STATIC_ASSERT(sizeof(Dll16CState) == 0x24);

/*
 * Per-object extra state for the crrockfall falling rock
 * (crrockfall_getExtraSize == 0x14).
 */

STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

extern undefined4 getLActions();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_DisableObject();

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern f32 lbl_803E53D0;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53F0;

extern void* lbl_803DDB40;
extern f32 lbl_803E4708;
extern void objRenderFn_8003b8f4(f32);
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int** listOut, int p3, int p4);
extern f32 lbl_803E4700;
extern f32 lbl_803E4704;
extern float Vec_distance(float* a, float* b);
extern void warpToMap(int mapId, int flags);
extern void Music_Trigger(int track, int flag);
extern f32 timeDelta;
extern u8 framesThisStep;
extern u8 lbl_803236B8[];
extern f32 lbl_803E4730;
extern void fn_800628CC(int* obj);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void Sfx_PlayFromObject(int* obj, int sfx);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern void spawnExplosion(int* obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern f32 lbl_803E46E8;
extern f32 lbl_803E46EC;
extern f32 lbl_803E46F0;
extern f32 lbl_803E470C;
extern f32 lbl_803E4710;
extern f32 lbl_803E4714;
extern f32 lbl_803E4718;
extern f32 lbl_803E471C;
extern f32 lbl_803E4720;

void FUN_801ac248(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
}

undefined4
FUN_801ad984(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj)
{
    int lookupBase;
    undefined4 in_r9;
    undefined4 in_r10;
    float* state;
    double dist;
    double value;

    if (((GameObject*)obj)->anim.seqId != 0x172)
    {
        state = ((GameObject*)obj)->extra;
        lookupBase = FUN_80017a98();
        dist = (double)FUN_8001771c((float*)(lookupBase + 0x18), (float*)&((GameObject*)obj)->anim.worldPosX);
        value = (double)*state;
        if ((value <= dist) || (*(char*)((int)state + 0xb) != '\0'))
        {
            if (((double)(float)((double)lbl_803E53D0 + value) < dist) &&
                (*(char*)((int)state + 0xb) != '\0'))
            {
                *(u8*)((int)state + 0xb) = 0;
                getLActions(dist, value, param_3, param_4, param_5, param_6, param_7, param_8, obj, obj,
                            (uint) * (ushort*)(state + 2), 0, 0, 0, in_r9, in_r10);
            }
        }
        else
        {
            *(u8*)((int)state + 0xb) = 1;
            getLActions(dist, value, param_3, param_4, param_5, param_6, param_7, param_8, obj, obj,
                        (uint) * (ushort*)((int)state + 6), 0, 0, 0, in_r9, in_r10);
        }
    }
    return 0;
}

void FUN_801adca0(undefined2* dst, undefined2* src, undefined4 param_3, undefined4 param_4,
                  undefined4 param_5, undefined4 param_6, char param_7, int param_8, int param_9)
{
    u8 savedAlpha;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20[5];

    if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8))
    {
        savedAlpha = *(u8*)((int)src + 0x37);
        *(char*)((int)src + 0x37) = (char)param_8;
        (**(code**)(**(int**)(src + 0x34) + 0x10))
            (src, param_3, param_4, param_5, param_6, 0xffffffff);
        *(u8*)((int)src + 0x37) = savedAlpha;
    }
    *(undefined4*)(dst + 0x46) = *(undefined4*)(dst + 0xc);
    *(undefined4*)(dst + 0x48) = *(undefined4*)(dst + 0xe);
    *(undefined4*)(dst + 0x4a) = *(undefined4*)(dst + 0x10);
    *(undefined4*)(dst + 0x40) = *(undefined4*)(dst + 6);
    *(undefined4*)(dst + 0x42) = *(undefined4*)(dst + 8);
    *(undefined4*)(dst + 0x44) = *(undefined4*)(dst + 10);
    (**(code**)(**(int**)(src + 0x34) + 0x28))(src, local_20, &local_24, &local_28);
    *(undefined4*)(dst + 6) = local_20[0];
    *(undefined4*)(dst + 8) = local_24;
    *(undefined4*)(dst + 10) = local_28;
    *dst = *src;
    dst[1] = src[1];
    dst[2] = src[2];
    *(undefined4*)(dst + 0xc) = *(undefined4*)(dst + 6);
    *(undefined4*)(dst + 0xe) = *(undefined4*)(dst + 8);
    *(undefined4*)(dst + 0x10) = *(undefined4*)(dst + 10);
    *(undefined4*)(dst + 0x12) = *(undefined4*)(src + 0x12);
    *(undefined4*)(dst + 0x14) = *(undefined4*)(src + 0x14);
    *(undefined4*)(dst + 0x16) = *(undefined4*)(src + 0x16);
    return;
}

undefined4
FUN_801addec(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, undefined4 param_12, uint* param_13, undefined4 param_14, undefined4 param_15
             , undefined4 param_16)
{
    uint active;
    undefined2* setup;
    undefined4 spawned;
    int modelState;
    int* extra;
    int linkedObj;
    undefined2 uStack_2a;
    undefined4 local_28;
    undefined4 local_24;
    undefined2 local_20;

    extra = ((GameObject*)obj)->extra;
    *(u8*)(extra + 8) = 0xff;
    linkedObj = *extra;
    if (animUpdate->triggerCommand == 3)
    {
        *(u8*)((int)extra + 0x21) = 0xff;
        animUpdate->triggerCommand = 0;
    }
    local_28 = DAT_802c2a88;
    local_24 = DAT_802c2a8c;
    local_20 = DAT_802c2a90;
    if (*(char*)((int)extra + 0x21) != *(char*)((int)extra + 0x22))
    {
        if (*(int*)&((GameObject*)obj)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)obj)->childObjs[0]);
            *(undefined4*)(obj + 200) = 0;
            *(u8*)(obj + 0xeb) = 0;
        }
        active = FUN_80017ae8();
        if ((active & 0xff) == 0)
        {
            *(u8*)((int)extra + 0x22) = 0;
        }
        else
        {
            if (0 < *(char*)((int)extra + 0x21))
            {
                setup = FUN_80017aa4(0x18, (&uStack_2a)[*(char*)((int)extra + 0x21)]);
                param_12 = 0xffffffff;
                param_13 = *(uint**)&((GameObject*)obj)->anim.parent;
                spawned = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, setup,
                                     4, 0xff, 0xffffffff, param_13, param_14, param_15, param_16);
                *(undefined4*)(obj + 200) = spawned;
                *(u8*)(obj + 0xeb) = 1;
            }
            *(u8*)((int)extra + 0x22) = *(u8*)((int)extra + 0x21);
        }
    }
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    if ((linkedObj == 0) || (animUpdate->triggerCommand != 2))
    {
        if ((linkedObj != 0) && (animUpdate->triggerCommand == 1))
        {
            (**(code**)(**(int**)(linkedObj + 0x68) + 0x3c))(linkedObj, 0);
            animUpdate->triggerCommand = 0;
        }
    }
    else
    {
        extra[1] = (int)lbl_803E53F0;
        extra[2] = extra[5];
        extra[3] = extra[6];
        extra[4] = extra[7];
        (**(code**)(**(int**)(linkedObj + 0x68) + 0x3c))(linkedObj, 2);
        FUN_800305f8((double)lbl_803E53E0, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0x100, 1, param_12, param_13, param_14, param_15, param_16);
        modelState = (int)((GameObject*)obj)->anim.modelState;
        if (modelState != 0)
        {
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        animUpdate->hitVolumePair &= ~4;
        animUpdate->triggerCommand = 0;
    }
    if ((linkedObj != 0) && (linkedObj = (**(code**)(**(int**)(linkedObj + 0x68) + 0x38))(linkedObj), linkedObj == 2))
    {
        animUpdate->hitVolumePair &= 0xfffc;
    }
    return 0;
}


#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMapAct((a))

#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY
void crrockfall_free(void)
{
}

void crrockfall_hitDetect(void)
{
}


int crrockfall_getExtraSize(void) { return 0x14; }
int crrockfall_getObjectTypeId(void) { return 0x0; }

void crrockfall_initialise(void) { lbl_803DDB40 = NULL; }

#pragma peephole off
void crrockfall_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    CrRockfallState* inner = ((GameObject*)obj)->extra;
    if (inner->mode != 3 && visible != 0)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4708);
    }
}


#pragma dont_inline on
#pragma scheduling off
f32 fn_801ACCFC(int obj)
{
    CrRockfallState* state = ((GameObject*)obj)->extra;
    int* list;
    int count;
    int i;
    int bestIdx;
    f32 bestDist;
    count = hitDetectFn_80065e50(obj,
                                 ((GameObject*)obj)->anim.localPosX,
                                 ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ,
                                 &list, 0, 0);
    bestDist = lbl_803E4700;
    bestIdx = -1;
    for (i = 0; i < count; i++)
    {
        f32 dy;
        if ((dy = ((GameObject*)obj)->anim.localPosY - *(f32*)list[i]) > lbl_803E4704 && dy < bestDist)
        {
            bestDist = dy;
            bestIdx = i;
        }
    }
    if (bestIdx != -1)
    {
        state->floorFound = 1;
        return *(f32*)list[bestIdx];
    }
    return ((GameObject*)obj)->anim.localPosY;
}
#pragma dont_inline reset


#pragma scheduling on
#pragma peephole on
void crrockfall_release(void)
{
    if (lbl_803DDB40 != NULL)
    {
        Resource_Release(lbl_803DDB40);
    }
    lbl_803DDB40 = NULL;
}

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))

#undef MEVT_TRIGGER
#undef MEVT_SET

/* crrockfall_init: derive the per-rock scale from the placement params, size the
 * capsule hitbox from the sub-object bounds, set up render flags, and pick the
 * state-table variant by object type. */
#pragma scheduling off
#pragma peephole off
void crrockfall_init(int* obj, u8* params)
{
    CrRockfallState* extra = ((GameObject*)obj)->extra;
    int* sub;
    ObjModelState* modelState;

    extra->mode = 0;
    extra->startY = ((GameObject*)obj)->anim.localPosY;
    extra->fallDelay = *(s16*)((char*)params + 0x1e);
    ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
    params[0x1b] / lbl_803E4730;

    sub = *(int**)&((GameObject*)obj)->anim.hitReactState;
    if (sub != NULL)
    {
        f32 scale = ((GameObject*)obj)->anim.rootMotionScale;
        ObjHitbox_SetCapsuleBounds(obj,
                                   (int)((f32)((ObjHitsPriorityState*)sub)->primaryRadius * scale),
                                   (int)((f32)((ObjHitsPriorityState*)sub)->primaryCapsuleOffsetA * scale),
                                   (int)((f32)((ObjHitsPriorityState*)sub)->primaryCapsuleOffsetB * scale));
        ObjHits_DisableObject(obj);
    }

    modelState = ((GameObject*)obj)->anim.modelState;
    if (modelState != NULL)
    {
        modelState->flags |= 0xb0;
        modelState->flags |= 0xc00;
        modelState->overrideWorldPosX = ((GameObject*)obj)->anim.localPosX;
        modelState->overrideWorldPosZ = ((GameObject*)obj)->anim.localPosZ;
        modelState->shadowScale = modelState->shadowScale * ((GameObject*)obj)->anim.rootMotionScale;
    }

    if (((GameObject*)obj)->anim.seqId == 1536)
    {
        extra->cfg = (CrRockfallCfgEntry*)&lbl_803236B8[0xc];
    }
    else
    {
        extra->cfg = (CrRockfallCfgEntry*)lbl_803236B8;
    }
}

/* crrockfall_update: drive the falling-rock state machine - fade-in opacity by
 * height/distance, trigger the fall when the player is in range, integrate the
 * fall, then shatter (sfx + explosion) on impact. */
void crrockfall_update(int* obj)
{
    CrRockfallState* ex = ((GameObject*)obj)->extra;
    int* hitState = *(int**)&((GameObject*)obj)->anim.hitReactState;
    ObjModelState* modelState = ((GameObject*)obj)->anim.modelState;
    int* placement = *(int**)&((GameObject*)obj)->anim.placementData;

    if (lbl_803DDB40 == NULL)
    {
        lbl_803DDB40 = Resource_Acquire(91, 1);
    }

    if (ex->floorFound == 0)
    {
        ex->floorY = fn_801ACCFC((int)obj);
        if (ex->floorFound != 0 && modelState != NULL)
        {
            modelState->overrideWorldPosY = ex->floorY;
            fn_800628CC(obj);
        }
    }
    else
    {
        if (modelState != NULL)
        {
            f32 frac;
            f32 height;
            f32 dist;
            int n;
            int* player;
            frac = (((GameObject*)obj)->anim.localPosY - ex->floorY) /
                (ex->startY - ex->floorY);
            if (frac > lbl_803E4708)
            {
                frac = lbl_803E4708;
            }
            else if (frac < lbl_803E46E8)
            {
                frac = lbl_803E46E8;
            }
            height = (*(f32*)&lbl_803E4708) - frac;
            player = (int*)Obj_GetPlayerObject();
            if (player != NULL)
            {
                dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
                if (dist > lbl_803E470C)
                {
                    dist = lbl_803E470C;
                }
                else if (dist < lbl_803E4710)
                {
                    dist = lbl_803E4710;
                }
            }
            else
            {
                dist = lbl_803E470C;
            }
            dist = (dist - lbl_803E4710) / lbl_803E4714;
            dist = lbl_803E4708 - dist;
            n = (int)(lbl_803E4718 * height) + 0x40;
            modelState->shadowAlpha =
                (int)(((f32)(u32) * (u8*)((char*)obj + 0x37) / lbl_803E471C) *
                    ((f32)n * dist));
        }

        if (((CrrockfallPlacement*)placement)->unk1C == -1 ||
            GameBit_Get(((CrrockfallPlacement*)placement)->unk1C) != 0)
        {
            switch (ex->mode)
            {
            case 0:
                {
                    int cond;
                    int* player = (int*)Obj_GetPlayerObject();
                    if (player == NULL)
                    {
                        cond = 0;
                    }
                    else
                    {
                        int* def = *(int**)&((GameObject*)obj)->anim.placementData;
                        f32 xz = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX,
                                                &((GameObject*)player)->anim.worldPosX);
                        f32 dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                        if (dy < lbl_803E46E8)
                        {
                            dy = lbl_803E46E8;
                        }
                        if (xz < lbl_803E46EC * (f32)(u32)((CrrockfallPlacement*)def)->unk1A &&
                            dy < lbl_803E46F0)
                        {
                            cond = 1;
                        }
                        else
                        {
                            cond = 0;
                        }
                    }
                    if (cond != 0)
                    {
                        s16 timer = ex->fallDelay - framesThisStep;
                        ex->fallDelay = timer;
                        if (timer <= 0)
                        {
                            ex->mode = 1;
                        }
                    }
                    break;
                }
            case 1:
                if (ex->fallStarted == 0)
                {
                    ex->fallStarted = 1;
                    ((GameObject*)obj)->anim.velocityY = lbl_803E46E8;
                    if (((GameObject*)obj)->anim.seqId == 103)
                    {
                        Sfx_PlayFromObject(obj, SFXwp_sexpl2_c);
                    }
                    Sfx_PlayFromObject(obj, SFXmv_blockscrape_lp);
                    ((ObjHitsPriorityState*)hitState)->flags |= 1;
                }
                *(int*)&((ObjHitsPriorityState*)hitState)->objectHitMask = 16;
                *(int*)&((ObjHitsPriorityState*)hitState)->skeletonHitMask = 16;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumeId = 1;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumePriority = 13;
                ((GameObject*)obj)->anim.velocityY =
                    lbl_803E4720 * timeDelta + ((GameObject*)obj)->anim.velocityY;
                ((GameObject*)obj)->anim.localPosY =
                    ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY;
                if (((GameObject*)obj)->anim.localPosY <
                    ex->floorY + ex->cfg->restOffsetY)
                {
                    ((GameObject*)obj)->anim.localPosY =
                        ex->cfg->restOffsetY * ((GameObject*)obj)->anim.rootMotionScale +
                        ex->floorY;
                    ex->mode = 2;
                    if (ex->cfg->landSfx != 0)
                    {
                        Sfx_PlayFromObject(obj, (u16)ex->cfg->landSfx);
                    }
                }
                break;
            case 2:
                *(int*)&((ObjHitsPriorityState*)hitState)->objectHitMask = 16;
                *(int*)&((ObjHitsPriorityState*)hitState)->skeletonHitMask = 16;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumeId = 1;
                *(u8*)&((ObjHitsPriorityState*)hitState)->hitVolumePriority = 13;
                break;
            case 4:
                break;
            }

            if (*(void**)&((ObjHitsPriorityState*)hitState)->lastHitObject != NULL)
            {
                ((ObjHitsPriorityState*)hitState)->flags &= ~1;
                ex->mode = 3;
                Sfx_StopObjectChannel(obj, 8);
                if (((GameObject*)obj)->anim.seqId == 103)
                {
                    Sfx_PlayFromObject(obj, SFXwp_simp1_c);
                }
                else
                {
                    Sfx_PlayFromObject(obj, 955);
                    spawnExplosion(obj, (f32)(u32)((CrrockfallPlacement*)placement)->unk1B,
                                   1, 1, 0, 1, 1, 1, 1);
                }
            }
        }
    }

    {
        f32 z = lbl_803E46E8;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
    }
}
