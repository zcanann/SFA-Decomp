#include "main/audio/sfx_ids.h"
#include "main/dll/blob10_struct.h"
#include "main/dll/crrockfallplacement_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
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

extern undefined4 DAT_802c2a88;
extern undefined4 DAT_802c2a8c;
extern undefined4 DAT_802c2a90;
extern f32 lbl_803E53D0;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53F0;

extern void objRenderFn_8003b8f4(f32);
extern void Obj_FreeObject(int*);
extern void dll_16C_syncSubObjectTransform(void* a, void* b, int c, int d, int e, int f, int g, int h, int i);
extern int objUpdateOpacity(int* obj);
extern void ObjPath_GetPointWorldPosition(int* obj, int idx, f32* x, f32* y, f32* z, int e);
extern f32 lbl_803E4758;
extern float Vec_distance(float* a, float* b);
extern void warpToMap(int mapId, int flags);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
extern f32 lbl_803E4748;
extern u8 lbl_802C2308[];
extern void Music_Trigger(int track, int flag);
extern int* ObjGroup_GetObjects(int group, int* countOut);
extern u8 framesThisStep;
extern f32 lbl_803E474C;
extern f32 lbl_803E475C;
extern f32 lbl_803E4760;
extern f32 lbl_803E4764;

void FUN_801ac248(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
}

undefined4
FUN_801ad984(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9)
{
    int lookupBase;
    undefined4 in_r9;
    undefined4 in_r10;
    float* state;
    double dist;
    double value;

    if (((GameObject*)param_9)->anim.seqId != 0x172)
    {
        state = ((GameObject*)param_9)->extra;
        lookupBase = FUN_80017a98();
        dist = (double)FUN_8001771c((float*)(lookupBase + 0x18), (float*)&((GameObject*)param_9)->anim.worldPosX);
        value = (double)*state;
        if ((value <= dist) || (*(char*)((int)state + 0xb) != '\0'))
        {
            if (((double)(float)((double)lbl_803E53D0 + value) < dist) &&
                (*(char*)((int)state + 0xb) != '\0'))
            {
                *(u8*)((int)state + 0xb) = 0;
                getLActions(dist, value, param_3, param_4, param_5, param_6, param_7, param_8, param_9, param_9,
                            (uint) * (ushort*)(state + 2), 0, 0, 0, in_r9, in_r10);
            }
        }
        else
        {
            *(u8*)((int)state + 0xb) = 1;
            getLActions(dist, value, param_3, param_4, param_5, param_6, param_7, param_8, param_9, param_9,
                        (uint) * (ushort*)((int)state + 6), 0, 0, 0, in_r9, in_r10);
        }
    }
    return 0;
}

void FUN_801adca0(undefined2* param_1, undefined2* param_2, undefined4 param_3, undefined4 param_4,
                  undefined4 param_5, undefined4 param_6, char param_7, int param_8, int param_9)
{
    u8 savedAlpha;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20[5];

    if (((param_9 != 0) && (param_7 != '\0')) && (0 < param_8))
    {
        savedAlpha = *(u8*)((int)param_2 + 0x37);
        *(char*)((int)param_2 + 0x37) = (char)param_8;
        (**(code**)(**(int**)(param_2 + 0x34) + 0x10))
            (param_2, param_3, param_4, param_5, param_6, 0xffffffff);
        *(u8*)((int)param_2 + 0x37) = savedAlpha;
    }
    *(undefined4*)(param_1 + 0x46) = *(undefined4*)(param_1 + 0xc);
    *(undefined4*)(param_1 + 0x48) = *(undefined4*)(param_1 + 0xe);
    *(undefined4*)(param_1 + 0x4a) = *(undefined4*)(param_1 + 0x10);
    *(undefined4*)(param_1 + 0x40) = *(undefined4*)(param_1 + 6);
    *(undefined4*)(param_1 + 0x42) = *(undefined4*)(param_1 + 8);
    *(undefined4*)(param_1 + 0x44) = *(undefined4*)(param_1 + 10);
    (**(code**)(**(int**)(param_2 + 0x34) + 0x28))(param_2, local_20, &local_24, &local_28);
    *(undefined4*)(param_1 + 6) = local_20[0];
    *(undefined4*)(param_1 + 8) = local_24;
    *(undefined4*)(param_1 + 10) = local_28;
    *param_1 = *param_2;
    param_1[1] = param_2[1];
    param_1[2] = param_2[2];
    *(undefined4*)(param_1 + 0xc) = *(undefined4*)(param_1 + 6);
    *(undefined4*)(param_1 + 0xe) = *(undefined4*)(param_1 + 8);
    *(undefined4*)(param_1 + 0x10) = *(undefined4*)(param_1 + 10);
    *(undefined4*)(param_1 + 0x12) = *(undefined4*)(param_2 + 0x12);
    *(undefined4*)(param_1 + 0x14) = *(undefined4*)(param_2 + 0x14);
    *(undefined4*)(param_1 + 0x16) = *(undefined4*)(param_2 + 0x16);
    return;
}

undefined4
FUN_801addec(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* param_11, undefined4 param_12, uint* param_13, undefined4 param_14, undefined4 param_15
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

    extra = ((GameObject*)param_9)->extra;
    *(u8*)(extra + 8) = 0xff;
    linkedObj = *extra;
    if (param_11->triggerCommand == 3)
    {
        *(u8*)((int)extra + 0x21) = 0xff;
        param_11->triggerCommand = 0;
    }
    local_28 = DAT_802c2a88;
    local_24 = DAT_802c2a8c;
    local_20 = DAT_802c2a90;
    if (*(char*)((int)extra + 0x21) != *(char*)((int)extra + 0x22))
    {
        if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
        {
            param_1 = FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                   *(int*)&((GameObject*)param_9)->childObjs[0]);
            *(undefined4*)(param_9 + 200) = 0;
            *(u8*)(param_9 + 0xeb) = 0;
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
                param_13 = *(uint**)&((GameObject*)param_9)->anim.parent;
                spawned = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, setup,
                                     4, 0xff, 0xffffffff, param_13, param_14, param_15, param_16);
                *(undefined4*)(param_9 + 200) = spawned;
                *(u8*)(param_9 + 0xeb) = 1;
            }
            *(u8*)((int)extra + 0x22) = *(u8*)((int)extra + 0x21);
        }
    }
    param_11->hitVolumePair = param_11->activeHitVolumePair;
    if ((linkedObj == 0) || (param_11->triggerCommand != 2))
    {
        if ((linkedObj != 0) && (param_11->triggerCommand == 1))
        {
            (**(code**)(**(int**)(linkedObj + 0x68) + 0x3c))(linkedObj, 0);
            param_11->triggerCommand = 0;
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
                     param_9, 0x100, 1, param_12, param_13, param_14, param_15, param_16);
        modelState = (int)((GameObject*)param_9)->anim.modelState;
        if (modelState != 0)
        {
            ((GameObject*)param_9)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        param_11->hitVolumePair &= ~4;
        param_11->triggerCommand = 0;
    }
    if ((linkedObj != 0) && (linkedObj = (**(code**)(**(int**)(linkedObj + 0x68) + 0x38))(linkedObj), linkedObj == 2))
    {
        param_11->hitVolumePair &= 0xfffc;
    }
    return 0;
}

void imicemountain_free(void);

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))
#define MEVT_QUERY(a)         (*gMapEventInterface)->getMapAct((a))

#undef MEVT_TRIGGER
#undef MEVT_SET
#undef MEVT_QUERY

void dll_16C_release(void)
{
}

void dll_16C_initialise(void)
{
}

int imicemountain_getExtraSize(void);
int dll_16C_getExtraSize(void) { return 0x24; }
int dll_16C_getObjectTypeId(void) { return 0x3; }

void dll_16C_free(int* obj)
{
    int* p = (int*)obj[0xc8 / 4];
    if (p != NULL) Obj_FreeObject(p);
}

void crrockfall_release(void);

#pragma scheduling off
#pragma peephole off
void dll_16C_hitDetect(void* obj)
{
    Dll16CState* extra = ((GameObject*)obj)->extra;
    void* p = extra->linkedObj;
    if (p != NULL)
    {
        if ((*(int (**)(void*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
        {
            dll_16C_syncSubObjectTransform(obj, extra->linkedObj, 0, 0, 0, 0, 0, 0, 0);
        }
    }
}

void dll_16C_render(int* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    Dll16CState* extra;
    int* p;
    int hit;

    if (((GameObject*)obj)->anim.seqId != 883)
    {
        if (GameBit_Get(110) != 0)
        {
            if (GameBit_Get(898) == 0) return;
        }
        extra = ((GameObject*)obj)->extra;
        p = (int*)extra->linkedObj;
        hit = 0;
        if (p != NULL)
        {
            if ((*(int (**)(int*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
            {
                hit = 1;
            }
        }
        if (hit != 0)
        {
            ((GameObject*)obj)->anim.flags |= 8;
            visible = (s8)objUpdateOpacity(p);
            dll_16C_syncSubObjectTransform(obj, p, p1, p2, p3, p4, visible, extra->opacity, 1);
        }
        else
        {
            ((GameObject*)obj)->anim.flags &= ~8;
        }
        if ((s8)visible != 0 && extra->opacity != 0)
        {
            u8 saved = *(u8*)((char*)obj + 0x37);
            if (hit != 0)
            {
                *(u8*)((char*)obj + 0x37) = extra->opacity;
            }
            ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4758);
            ObjPath_GetPointWorldPosition(obj, 1, &extra->pathPointX, &extra->pathPointY, &extra->pathPointZ, 0);
            *(u8*)((char*)obj + 0x37) = saved;
        }
    }
    else
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4758);
    }
}

#pragma peephole on
void dll_16C_init(void* obj, void* arg2)
{
    Dll16CState* extra;
    ((GameObject*)obj)->animEventCallback = (void*)dll_16C_SeqFn;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4000;
        ((GameObject*)obj)->anim.modelState->shadowTintA = 100;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 150;
    }
    extra = ((GameObject*)obj)->extra;
    extra->linkedObj = NULL;
    *(u8*)&extra->subObjIndex = *(u8*)((char*)arg2 + 0x27);
    extra->opacity = 0xff;
}

#define MEVT_TRIGGER(a, b, c) (*gMapEventInterface)->setObjGroupStatus((a), (b), (c))
#define MEVT_SET(a, b)        (*gMapEventInterface)->setMapAct((a), (b))

#undef MEVT_TRIGGER
#undef MEVT_SET

/* dll_16C_SeqFn: per-frame sequence callback - manage the spawned sub-object
 * from a small id table, then run the map-event sub-object state callbacks. */
#pragma peephole off
int dll_16C_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int* p;
    int* extra = ((GameObject*)obj)->extra;
    s16 ids[5];

    ((Dll16CState*)extra)->opacity = 0xff;
    p = (int*)*extra;
    if (animUpdate->triggerCommand == 3)
    {
        ((Dll16CState*)extra)->subObjIndex = -1;
        animUpdate->triggerCommand = 0;
    }
    *(Blob10*)ids = *(Blob10*)lbl_802C2308;

    if (((Dll16CState*)extra)->subObjIndex != ((Dll16CState*)extra)->subObjIndexApplied)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
            ((GameObject*)obj)->childCount = 0;
        }
        if (Obj_IsLoadingLocked())
        {
            s8 idx = ((Dll16CState*)extra)->subObjIndex;
            if (idx > 0)
            {
                *(int*)&((GameObject*)obj)->childObjs[0] =
                    Obj_SetupObject(Obj_AllocObjectSetup(24, ids[idx - 1]), 4, -1, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)obj)->childCount = 1;
            }
            ((Dll16CState*)extra)->subObjIndexApplied = ((Dll16CState*)extra)->subObjIndex;
        }
        else
        {
            ((Dll16CState*)extra)->subObjIndexApplied = 0;
        }
    }

    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;

    if (p != NULL && animUpdate->triggerCommand == 2)
    {
        ((Dll16CState*)extra)->unk04 = lbl_803E4758;
        ((Dll16CState*)extra)->snapX = ((Dll16CState*)extra)->pathPointX;
        ((Dll16CState*)extra)->snapY = ((Dll16CState*)extra)->pathPointY;
        ((Dll16CState*)extra)->snapZ = ((Dll16CState*)extra)->pathPointZ;
        (*(void (**)(int*, int))(**(int**)((char*)p + 0x68) + 0x3c))(p, 2);
        ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 1);
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
        animUpdate->hitVolumePair &= ~4;
        animUpdate->triggerCommand = 0;
    }
    else if (p != NULL && animUpdate->triggerCommand == 1)
    {
        (*(void (**)(int*, int))(**(int**)((char*)p + 0x68) + 0x3c))(p, 0);
        animUpdate->triggerCommand = 0;
    }

    if (p != NULL)
    {
        if ((*(int (**)(int*))(**(int**)((char*)p + 0x68) + 0x38))(p) == 2)
        {
            animUpdate->hitVolumePair &= ~3;
        }
    }
    return 0;
}

/* dll_16C_syncSubObjectTransform: snapshot the map-event sub-object's transform into the boulder
 * extra block, optionally re-issuing a move on the sub-object first. */
void dll_16C_syncSubObjectTransform(void* a, void* b, int c, int d, int e, int f, int g, int h, int i)
{
    if (i != 0 && (s8)g != 0 && h > 0)
    {
        u8 saved = *(u8*)((char*)b + 0x37);
        *(u8*)((char*)b + 0x37) = h;
        (*(void (**)(void*, int, int, int, int, int))(**(int**)&((GameObject*)b)->anim.dll + 0x10))(b, c, d, e, f, -1);
        *(u8*)((char*)b + 0x37) = saved;
    }
    ((GameObject*)a)->anim.previousWorldPosX = ((GameObject*)a)->anim.worldPosX;
    ((GameObject*)a)->anim.previousWorldPosY = ((GameObject*)a)->anim.worldPosY;
    ((GameObject*)a)->anim.previousWorldPosZ = ((GameObject*)a)->anim.worldPosZ;
    ((GameObject*)a)->anim.previousLocalPosX = ((GameObject*)a)->anim.localPosX;
    ((GameObject*)a)->anim.previousLocalPosY = ((GameObject*)a)->anim.localPosY;
    ((GameObject*)a)->anim.previousLocalPosZ = ((GameObject*)a)->anim.localPosZ;
    {
        f32 x, y, z;
        (*(void (**)(void*, f32*, f32*, f32*))(**(int**)&((GameObject*)b)->anim.dll + 0x28))(b, &x, &y, &z);
        ((GameObject*)a)->anim.localPosX = x;
        ((GameObject*)a)->anim.localPosY = y;
        ((GameObject*)a)->anim.localPosZ = z;
    }
    ((GameObject*)a)->anim.rotX = ((GameObject*)b)->anim.rotX;
    ((GameObject*)a)->anim.rotY = ((GameObject*)b)->anim.rotY;
    ((GameObject*)a)->anim.rotZ = ((GameObject*)b)->anim.rotZ;
    ((GameObject*)a)->anim.worldPosX = ((GameObject*)a)->anim.localPosX;
    ((GameObject*)a)->anim.worldPosY = ((GameObject*)a)->anim.localPosY;
    ((GameObject*)a)->anim.worldPosZ = ((GameObject*)a)->anim.localPosZ;
    ((GameObject*)a)->anim.velocityX = ((GameObject*)b)->anim.velocityX;
    ((GameObject*)a)->anim.velocityY = ((GameObject*)b)->anim.velocityY;
    ((GameObject*)a)->anim.velocityZ = ((GameObject*)b)->anim.velocityZ;
}

/* dll_16C_update: re-link the spawned sub-object, then while active/visible run
 * its move and fade opacity by distance to the player. */
void dll_16C_update(int* obj)
{
    Dll16CState* extra = ((GameObject*)obj)->extra;
    s16 ids[5];

    *(Blob10*)ids = *(Blob10*)lbl_802C2308;
    if (extra->subObjIndex != extra->subObjIndexApplied)
    {
        if (((GameObject*)obj)->childObjs[0] != NULL)
        {
            Obj_FreeObject(((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
            ((GameObject*)obj)->childCount = 0;
        }
        if (Obj_IsLoadingLocked())
        {
            s8 idx = extra->subObjIndex;
            if (idx > 0)
            {
                *(int*)&((GameObject*)obj)->childObjs[0] =
                    Obj_SetupObject(Obj_AllocObjectSetup(24, ids[idx - 1]), 4, -1, -1,
                                    *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)obj)->childCount = 1;
            }
            extra->subObjIndexApplied = extra->subObjIndex;
        }
        else
        {
            extra->subObjIndexApplied = 0;
        }
    }

    if (extra->linkedObj == NULL)
    {
        int* objs;
        int count;
        int i;
        int sel;
        objs = ObjGroup_GetObjects(10, &count);
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 365:
        case 883:
        default:
            sel = 364;
            break;
        case 368:
            sel = 367;
            break;
        }
        for (i = 0; i < count; i++)
        {
            if (sel == *(s16*)((char*)objs[i] + 0x46))
            {
                extra->linkedObj = (void*)objs[i];
                i = count;
            }
        }
    }

    if (((GameObject*)obj)->anim.seqId == 883 || GameBit_Get(0x3a2) != 0)
    {
        int* sub = (int*)extra->linkedObj;
        f32 blend;
        f32 a, b;
        if (((GameObject*)obj)->anim.currentMove != 0x100)
        {
            ObjAnim_SetCurrentMove((int)obj, 0x100, lbl_803E4748, 0);
        }
        (*(void (**)(int*, f32*))(**(int**)((char*)sub + 0x68) + 0x44))(sub, &blend);
        blend = lbl_803E474C;
        (*(void (**)(int*, f32*, f32*))(**(int**)((char*)sub + 0x68) + 0x40))(sub, &a, &b);
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, blend, (f32)(u32)framesThisStep, NULL);
        if (extra->linkedObj != NULL)
        {
            f32 t;
            int* player = (int*)Obj_GetPlayerObject();
            t = Vec_distance((f32*)((char*)extra->linkedObj + 0x18), &((GameObject*)player)->anim.worldPosX);
            t = (t - lbl_803E475C) / lbl_803E4760;
            if (t < lbl_803E4748)
            {
                t = lbl_803E4748;
            }
            else if (t > lbl_803E4758)
            {
                t = lbl_803E4758;
            }
            extra->opacity = (int)(lbl_803E4764 * (lbl_803E4758 - t));
            if (((GameObject*)obj)->anim.modelState != NULL)
            {
                ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
        else
        {
            extra->opacity = 0xff;
            if (((GameObject*)obj)->anim.modelState != NULL)
            {
                ((GameObject*)obj)->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_FADE_OUT;
            }
        }
    }
}
