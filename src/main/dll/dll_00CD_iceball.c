#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"

extern undefined8 FUN_80003494();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006a54();
extern undefined4 FUN_80017698();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined8 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3a58;
extern f32 lbl_803E3A60;
extern f32 lbl_803E3A64;
extern f32 lbl_803E3A68;
extern f32 lbl_803E3A6C;
extern f32 lbl_803E3A70;
extern f32 lbl_803E3A74;
extern f32 lbl_803E3A78;
extern f32 lbl_803E3A7C;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B80;
extern f32 lbl_803E3B88;
extern f32 lbl_803E3B8C;
extern f32 lbl_803E3B90;
extern f32 lbl_803E3B94;

extern int objMove(int obj, f32 vx, f32 vy, f32 vz);
extern int getTrickyObject(void);
extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern f32 lbl_803E2E54;
extern f32 lbl_803E2E58;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E2E50;
extern void Camera_DisableViewYOffset(void);

undefined4
FUN_8015e0d0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int state)
{
    float val;
    float* extraData;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 msgResult;

    val = lbl_803E3A60;
    if (*(char*)(state + 0x27b) == '\0')
    {
        if (*(char*)(state + 0x346) != '\0')
        {
            msgResult = ObjMsg_SendToObjects(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0, 3,
                                         param_9, 0xe0000, param_9, in_r8, in_r9, in_r10);
            if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
            {
                FUN_80017ac8(msgResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
                return 0;
            }
            return 4;
        }
    }
    else
    {
        extraData = *(float**)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
        *extraData = lbl_803E3A60;
        extraData[1] = val;
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, state, 6);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
    }
    return 0;
}

int fn_8015E210(int* obj, GroundBaddieState* state);

undefined4
FUN_8015e2e0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float val;
    int player;
    int extra;
    double startVal;

    extra = *(int*)&((GameObject*)param_9)->extra;
    *(undefined*)(param_10 + 0x34d) = 3;
    *(float*)(param_10 + 0x2a0) = lbl_803E3A64;
    val = lbl_803E3A60;
    startVal = (double)lbl_803E3A60;
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    *(float*)(param_10 + 0x284) = val;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8(startVal, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9, 1, 0, param_12,
                     param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if ((*(byte*)(param_10 + 0x356) & 1) == 0)
    {
        player = FUN_80017a98();
        if (*(short*)(player + 0x46) == 0)
        {
            FUN_80006824(param_9, SFXfox_treadwater322);
        }
        else
        {
            FUN_80006824(param_9, SFXfoot_metal_run_2);
        }
        FUN_80006824(param_9, SFXdoor_unlocked);
        FUN_80006824(param_9, SFXfoxcom_find);
        *(byte*)(param_10 + 0x356) = *(byte*)(param_10 + 0x356) | 1;
    }
    if (((*(byte*)(param_10 + 0x356) & 2) == 0) && (lbl_803E3A68 < ((GameObject*)param_9)->anim.currentMoveProgress))
    {
        FUN_80006824(param_9, SFXdoor_creak);
        *(byte*)(param_10 + 0x356) = *(byte*)(param_10 + 0x356) | 2;
        (**(code**)(*DAT_803dd738 + 0x4c))(param_9, (int)*(short*)(extra + 0x3f0), 0xffffffff, 0);
    }
    return 0;
}

undefined4
FUN_8015e488(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objList;
    uint other;
    int target;
    int objIdx;
    int objCount;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        objList = FUN_80017b00(&objIdx, &objCount);
        for (; objIdx < objCount; objIdx = objIdx + 1)
        {
            other = *(uint*)(objList + objIdx * 4);
            if ((other != param_9) && (*(short*)(other + 0x46) == 0x306))
            {
                (**(code**)(**(int**)(other + 0x68) + 0x24))(other, 0x81, 0);
            }
        }
        objList = FUN_80017a98();
        target = *(int*)(objList + 200);
        objList = FUN_80017a98();
        target = (**(code**)(**(int**)(target + 0x68) + 0x44))(target);
        if (target == 0)
        {
            if (*(short*)(objList + 0x46) == 0)
            {
                FUN_80006824(param_9, SFXfox_treadwater322);
            }
            else
            {
                FUN_80006824(param_9, SFXfoot_metal_run_2);
            }
        }
        else if (*(short*)(objList + 0x46) == 0)
        {
            FUN_80006824(param_9, SFXmv_ropecreak22);
        }
        else
        {
            FUN_80006824(param_9, SFXfoot_metal_run_2);
        }
        FUN_80006824(param_9, SFXfoxcom_stay);
    }
    *(undefined*)(param_10 + 0x34d) = 3;
    *(float*)(param_10 + 0x2a0) = lbl_803E3A6C;
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    return 0;
}

int fn_8015DC04(int obj, GroundBaddieState* p);

undefined4
FUN_8015e678(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objList;
    uint other;
    int vtable;
    int extra;
    int objIdx;
    int objCount;

    extra = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    vtable = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        objList = FUN_80017b00(&objIdx, &objCount);
        for (; objIdx < objCount; objIdx = objIdx + 1)
        {
            other = *(uint*)(objList + objIdx * 4);
            if ((other != param_9) && (*(short*)(other + 0x46) == 0x306))
            {
                vtable = **(int**)(other + 0x68);
                (**(code**)(vtable + 0x24))(other, 0x81, 0);
            }
        }
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, vtable, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        extra = *(int*)(extra + 0x40c);
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        *(byte*)(extra + 8) = *(byte*)(extra + 8) | 1;
        FUN_80006824(param_9, SFXfoxcom_heel);
    }
    return 0;
}

undefined4
FUN_8015e88c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 noTarget;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    noTarget = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, noTarget, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    return 0;
}

undefined4
FUN_8015e9f4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objList;
    int other;
    uint roll;
    int vtable;
    int extra;
    int objIdx;
    int objCount[5];

    extra = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    vtable = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairPriority = 10;
    (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        objList = FUN_80017b00(&objIdx, objCount);
        for (; objIdx < objCount[0]; objIdx = objIdx + 1)
        {
            other = *(int*)(objList + objIdx * 4);
            if ((other != param_9) && (*(short*)(other + 0x46) == 0x306))
            {
                vtable = **(int**)(other + 0x68);
                (**(code**)(vtable + 0x24))(other, 0x81, 0);
            }
        }
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, vtable, param_13, param_14, param_15, param_16);
                *(undefined*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, vtable, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
        *(undefined*)(param_10 + 0x34d) = 1;
        *(float*)(param_10 + 0x2a0) =
            lbl_803E3A74 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e3a58) /
            lbl_803E3A78;
    }
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    return 0;
}

void fn_8015EB6C(int obj, int p2, int p3);

undefined4
FUN_8015ec98(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int subObj;
    int extra;

    extra = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (lbl_803E3A7C < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        subObj = *(int*)(extra + 0x40c);
        *(byte*)(subObj + 8) = *(byte*)(subObj + 8) | 2;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_DisableObject(param_9);
        *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
        *(float*)(param_10 + 0x280) = lbl_803E3A60;
    }
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        FUN_80017698((int)*(short*)(extra + 0x3f4), 0);
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        *(undefined2*)(extra + 0x402) = 0;
        if ((*(byte*)(subObj + 9) & 2) == 0)
        {
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
                resetHitboxMode | 8;
        }
    }
    return 0;
}

void fn_8015ED1C(int p1, int p2, int p3);

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015FBEC(int obj)
{
    extern void Camera_EnableViewYOffset(void);
    extern void CameraShake_SetAllMagnitudes(f32);
    extern f32 lbl_803E2E50;
    s16 mode = ((GameObject*)obj)->anim.seqId;
    int i;

    if (mode == 715)
    {
        for (i = 0; i < 25; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 834, NULL, 1, -1, NULL);
        }
    }
    else if (mode == 100 || mode == 778)
    {
        for (i = 0; i < 25; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 836, NULL, 1, -1, NULL);
        }
    }

    Sfx_PlayFromObject(obj, SFXkr_impact3);
    Camera_EnableViewYOffset();
    CameraShake_SetAllMagnitudes(lbl_803E2E50);
}
#pragma dont_inline reset

static inline u8 scarab_isObjectInList(void* o)
{
    extern int*ObjList_GetObjects(int* startIndex, int* objectCount);
    int i;
    int count;
    int* objs = ObjList_GetObjects(&i, &count);
    while (i < count)
    {
        if (o == (void*)objs[i++])
        {
            return 1;
        }
    }
    return 0;
}

void fn_8015FCCC(int obj)
{
    extern void Camera_EnableViewYOffset(void);
    extern void CameraShake_SetAllMagnitudes(f32);
    extern f32 lbl_803E2E50;
    s16 type;
    int n;

    Camera_EnableViewYOffset();
    CameraShake_SetAllMagnitudes(lbl_803E2E50);
    Sfx_PlayFromObject(obj, SFXkr_impact3);
    type = ((GameObject*)obj)->anim.seqId;
    if (type == 0x2cb)
    {
        if (((GameObject*)obj)->ownerObj != NULL)
        {
            if (scarab_isObjectInList(((GameObject*)obj)->ownerObj))
            {
                (*(void (**)(void*, int))(**(int**)(*(int*)&((GameObject*)obj)->ownerObj + 0x68) + 0x20))(
                    ((GameObject*)obj)->ownerObj, 0x80);
            }
        }
        for (n = 0; n < 25; n++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 832, NULL, 1, -1, NULL);
        }
    }
    else if (type == 100)
    {
        if (((GameObject*)obj)->ownerObj != NULL)
        {
            if (scarab_isObjectInList(((GameObject*)obj)->ownerObj))
            {
                (*(void (**)(void*, int))(**(int**)(*(int*)&((GameObject*)obj)->ownerObj + 0x68) + 0x24))(
                    ((GameObject*)obj)->ownerObj, 0x80);
            }
        }
        for (n = 0; n < 25; n++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
    else if (type == 0x30a)
    {
        if (((GameObject*)obj)->ownerObj != NULL)
        {
            if (scarab_isObjectInList(((GameObject*)obj)->ownerObj))
            {
                (*(void (**)(void*, int, int))(**(int**)(*(int*)&((GameObject*)obj)->ownerObj + 0x68) + 0x24))(
                    ((GameObject*)obj)->ownerObj, 0x80, 0);
            }
        }
        for (n = 0; n < 25; n++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
}

void iceball_update(undefined2* obj, int unused)
{
    int p;

    p = (int)obj;
    *(int*)(p + 0xf4) = (s32)((f32)(s32) * (int*)(p + 0xf4) - timeDelta);
    if (*(int*)(p + 0xf4) < 0)
    {
        Obj_FreeObject((int*)p);
        return;
    }
    if (((GameObject*)p)->anim.alpha == 0)
    {
        return;
    }
    *(float*)(p + 0x28) = *(float*)(p + 0x28) - lbl_803E2E54 * timeDelta;
    *(float*)(p + 0x28) = *(float*)(p + 0x28) * lbl_803E2E58;
    *(s16*)(p + 0) += 910;
    *(s16*)(p + 4) += 910;
    *(s16*)(p + 2) += 910;
    objMove(p, *(float*)(p + 0x24) * timeDelta, *(float*)(p + 0x28) * timeDelta,
            *(float*)(p + 0x2c) * timeDelta);
    ObjHits_SetHitVolumeSlot(p, 10, 1, 0);
    ObjHitbox_SetSphereRadius(p, 5);
    ObjHits_EnableObject(p);
    if ((*(ObjHitsPriorityState**)(p + 0x54))->lastHitObject != 0 &&
        ((*(ObjHitsPriorityState**)(p + 0x54))->lastHitObject == Obj_GetPlayerObject() ||
            (*(ObjHitsPriorityState**)(p + 0x54))->lastHitObject == getTrickyObject()))
    {
        fn_8015FCCC(p);
        ((GameObject*)p)->anim.alpha = 0;
        *(int*)(p + 0xf4) = 120;
        (*(ObjHitsPriorityState**)(p + 0x54))->flags &= ~1;
    }
    else if ((*(ObjHitsPriorityState**)(p + 0x54))->contactFlags != 0)
    {
        fn_8015FBEC(p);
        ((GameObject*)p)->anim.alpha = 0;
        *(int*)(p + 0xf4) = 120;
        (*(ObjHitsPriorityState**)(p + 0x54))->flags &= ~1;
    }
}

int fn_801601C4(int obj, GroundBaddieState* p);

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void FUN_8016043c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

undefined4
FUN_80160798(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10)
{
    float val;
    int extra;
    undefined8 copyResult;

    extra = *(int*)&((GameObject*)param_9)->extra;
    if (*(int*)(param_10 + 0x2d0) == 0)
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 0);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 1);
        val = lbl_803E3B00;
        *(float*)(param_10 + 0x290) = lbl_803E3B00;
        *(float*)(param_10 + 0x28c) = val;
        FUN_80003494(extra + 0x35c, param_9 + 0xc, 0xc);
        copyResult = FUN_80003494(extra + 0x368, *(int*)(param_10 + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(copyResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        if ((*(float*)(param_10 + 0x2c0) < lbl_803E3B04) && (*(char*)(extra + 0x405) == '\x02'))
        {
            return 5;
        }
        if (*(char*)(extra + 0x381) == '\0')
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(extra + 0x374), (double)*(float*)(extra + 0x37c),
             (double)lbl_803E3B00, (double)lbl_803E3B00, (double)lbl_803E3B08, param_9,
             param_10);
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(extra + 0x374), (double)*(float*)(extra + 0x37c),
             (double)lbl_803E3B0C, (double)lbl_803E3B10, (double)lbl_803E3B08, param_9,
             param_10);
        }
    }
    return 0;
}

undefined4
FUN_80160aa4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int player;
    undefined4 result;

    if (*(char*)(param_10 + 0x27b) == '\0')
    {
        player = FUN_80017a98();
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, player, 0xe0000,
                            param_9, 0, param_13, param_14, param_15, param_16);
        if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
            result = 0;
        }
        else
        {
            result = 4;
        }
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 3);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        (*(ObjHitsPriorityState**)&((GameObject*)param_9)->anim.hitReactState)->flags &= ~1;
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
        result = 0;
    }
    return result;
}

undefined4
FUN_80160cd0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 sound;

    sound = *(undefined4*)(param_9 + 0xb8);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B00, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x25f) = 1;
    *(undefined2*)(param_9 + 4) = *(undefined2*)(param_10 + 0x19e);
    *(undefined2*)(param_9 + 2) = *(undefined2*)(param_10 + 0x19c);
    (**(code**)(*DAT_803dd738 + 0x10))
        ((double)lbl_803E3B24, (double)lbl_803E3B28, param_9, param_10, sound);
    *(float*)(param_10 + 0x2a0) = lbl_803E3B2C * *(float*)(param_10 + 0x280);
    return 0;
}

void FUN_80161130(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    undefined4 extra;
    undefined8 removeResult;

    extra = *(undefined4*)&((GameObject*)param_9)->extra;
    removeResult = ObjGroup_RemoveObject(param_9, 3);
    if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
    {
        FUN_80017ac8(removeResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)param_9)->childObjs[0]);
        *(undefined4*)&((GameObject*)param_9)->childObjs[0] = 0;
    }
    (**(code**)(*DAT_803dd738 + 0x40))(param_9, extra, 1);
    return;
}

undefined4
FUN_801615d4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             int param_10)
{
    undefined4 result;

    if (*(char*)(param_10 + 0x27b) != '\0')
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 8);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        param_1 = ObjHits_DisableObject(param_9);
        *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode |
            8;
    }
    if (((GameObject*)param_9)->anim.alpha == 0)
    {
        if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
            result = 0;
        }
        else
        {
            result = 6;
        }
    }
    else
    {
        result = 0;
    }
    return result;
}

undefined4
FUN_80161c08(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int extra;

    extra = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B80;
    if ((*(uint*)(param_10 + 0x314) & 0x200) != 0)
    {
        FUN_80006824(param_9, SFXdoor_creak);
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & 0xfffffdff;
        (**(code**)(*DAT_803dd738 + 0x4c))(param_9, (int)*(short*)(extra + 0x3f0), 0xffffffff, 1);
    }
    return 0;
}

undefined4
FUN_80161ea0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    uint roll;
    int angle;
    undefined4 result;
    int subObj;
    double dist;
    float aX;
    float aY;
    float aZ;
    float bX;
    float bY;
    float bZ[2];
    uint dir;

    subObj = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    ((ObjHitsPriorityState*)*(int*)&((GameObject*)param_9)->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)*(int*)&((GameObject*)param_9)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    roll = randomGetRange(0, 100);
    if ((int)roll < 0x32)
    {
        if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 1, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
    }
    else if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 4, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    dir = *(char*)(subObj + 0x45) * -2 + 1U ^ 0x80000000;
    bZ[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(subObj + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)dir),
        *(int*)(subObj + 0x38), subObj + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(subObj + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(subObj + 0x48))
        {
            *(float*)(subObj + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(subObj + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(subObj + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(subObj + 0x48) - lbl_803E3B94), *(int*)(subObj + 0x38), &aX,
     &aY, &aZ);
    (**(code**)(**(int**)(*(int*)(subObj + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(subObj + 0x48)), *(int*)(subObj + 0x38), &bX,
     &bY, bZ);
    aX = aX - bX;
    aY = aY - bY;
    aZ = aZ - bZ[0];
    dist = FUN_80293900((double)(aX * aX + aZ * aZ));
    aX = (float)dist;
    angle = FUN_80017730();
    ((GameObject*)param_9)->anim.rotY = (short)angle * ((short)((int)*(char*)(subObj + 0x45) << 1) + -1);
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        result = 0;
    }
    else
    {
        result = 5;
    }
    return result;
}

void dll_CA_release_nop(void);

void chukchuk_free(void);

void chukchuk_hitDetect(void);

void chukchuk_release(void);

void chukchuk_initialise(void);

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

void chukchuk_init(u8* obj, u8* params);
void iceball_hitDetect(void)
{
}

void iceball_release(void)
{
}

void iceball_initialise(void)
{
}

void dll_CB_func0B_nop(void);

int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void) { return 0x2; }
int iceball_getObjectTypeId(void) { return 0x0; }
int fn_8016052C(void);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#pragma scheduling off
#pragma peephole off
void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E2E50);
}

void iceball_free(void) { Camera_DisableViewYOffset(); }

void fn_8015F5B0(short* obj);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj)
{
    char* p = (char*)obj;
    *(int*)(p + 0xf4) = 0xb4;
    ObjHits_DisableObject((int)p);
    ((GameObject*)p)->anim.alpha = 0xff;
}

int fn_8016050C(int p1, u8* obj);

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};

/* scarab_updateProximityGate: scarab AI proximity gate. If no current target, dispatches
 * vtable[5](obj, state, 0) and returns 1. Else (unless state mode 6 means
 * already engaged) reads the angle from the obj to the target; when within
 * a +/-90? wedge the planar distance term is the constant lbl_803E2EB0,
 * otherwise it's sqrtf(dx*dx + dz*dz) - lbl_803E2EB4. The signed magnitude
 * drives three threshold checks against lbl_803E2EBC/EC0/EC4 that issue
 * vtable[5] calls with mode 6 (close), 1 (medium-out), or 1 (close-in)
 * depending on the current mode at (*(u8 *)&state->baddie.controlMode) and the latch byte at
 * state->baddie.moveDone. When mode == 1, picks one of two scalars (lbl_803E2EC8 or
 * lbl_803E2ECC) for (*(u8 *)&state->baddie.moveSpeed). Returns 0. */
