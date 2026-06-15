#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/scarab.h"
#include "main/objtexture.h"

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
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
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

extern int Obj_GetPlayerObject(void);
extern f32 timeDelta;
extern uint GameBit_Get(int eventId);
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E2E30;
extern void objRenderFn_8003b8f4(f32);
extern void GameBit_Set(int eventId, int value);
extern f32 sqrtf(f32);

undefined4
FUN_8015e0d0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj
             , int state)
{
    float zero;
    float* vec;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 msgResult;

    zero = lbl_803E3A60;
    if (*(char*)(state + 0x27b) == '\0')
    {
        if (*(char*)(state + 0x346) != '\0')
        {
            msgResult = ObjMsg_SendToObjects(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0, 3,
                                         obj, 0xe0000, obj, in_r8, in_r9, in_r10);
            if (*(int*)&((GameObject*)obj)->anim.placementData == 0)
            {
                FUN_80017ac8(msgResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj);
                return 0;
            }
            return 4;
        }
    }
    else
    {
        vec = *(float**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
        *vec = lbl_803E3A60;
        vec[1] = zero;
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 6);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        ObjHits_DisableObject(obj);
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode |
            8;
    }
    return 0;
}

int fn_8015E210(int* obj, GroundBaddieState* state);

undefined4
FUN_8015e2e0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float zero;
    int player;
    int extra;
    double zeroD;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(undefined*)(state + 0x34d) = 3;
    *(float*)(state + 0x2a0) = lbl_803E3A64;
    zero = lbl_803E3A60;
    zeroD = (double)lbl_803E3A60;
    *(float*)(state + 0x280) = lbl_803E3A60;
    *(float*)(state + 0x284) = zero;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8(zeroD, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj, 1, 0, param_12,
                     param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if ((*(byte*)(state + 0x356) & 1) == 0)
    {
        player = FUN_80017a98();
        if (*(short*)(player + 0x46) == 0)
        {
            FUN_80006824(obj, SFXfox_treadwater322);
        }
        else
        {
            FUN_80006824(obj, SFXfoot_metal_run_2);
        }
        FUN_80006824(obj, SFXdoor_unlocked);
        FUN_80006824(obj, SFXfoxcom_find);
        *(byte*)(state + 0x356) = *(byte*)(state + 0x356) | 1;
    }
    if (((*(byte*)(state + 0x356) & 2) == 0) && (lbl_803E3A68 < ((GameObject*)obj)->anim.currentMoveProgress))
    {
        FUN_80006824(obj, SFXdoor_creak);
        *(byte*)(state + 0x356) = *(byte*)(state + 0x356) | 2;
        (**(code**)(*DAT_803dd738 + 0x4c))(obj, (int)*(short*)(extra + 0x3f0), 0xffffffff, 0);
    }
    return 0;
}

undefined4
FUN_8015e488(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objList;
    uint other;
    int onGround;
    int objIdx;
    int objCount;

    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        objList = FUN_80017b00(&objIdx, &objCount);
        for (; objIdx < objCount; objIdx = objIdx + 1)
        {
            other = *(uint*)(objList + objIdx * 4);
            if ((other != obj) && (*(short*)(other + 0x46) == 0x306))
            {
                (**(code**)(**(int**)(other + 0x68) + 0x24))(other, 0x81, 0);
            }
        }
        objList = FUN_80017a98();
        onGround = *(int*)(objList + 200);
        objList = FUN_80017a98();
        onGround = (**(code**)(**(int**)(onGround + 0x68) + 0x44))(onGround);
        if (onGround == 0)
        {
            if (*(short*)(objList + 0x46) == 0)
            {
                FUN_80006824(obj, SFXfox_treadwater322);
            }
            else
            {
                FUN_80006824(obj, SFXfoot_metal_run_2);
            }
        }
        else if (*(short*)(objList + 0x46) == 0)
        {
            FUN_80006824(obj, SFXmv_ropecreak22);
        }
        else
        {
            FUN_80006824(obj, SFXfoot_metal_run_2);
        }
        FUN_80006824(obj, SFXfoxcom_stay);
    }
    *(undefined*)(state + 0x34d) = 3;
    *(float*)(state + 0x2a0) = lbl_803E3A6C;
    *(float*)(state + 0x280) = lbl_803E3A60;
    return 0;
}

int fn_8015DC04(int obj, GroundBaddieState* p);

undefined4
FUN_8015e678(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objList;
    uint other;
    int vtbl;
    int extra;
    int objIdx;
    int objCount;
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    vtbl = -1;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        objList = FUN_80017b00(&objIdx, &objCount);
        for (; objIdx < objCount; objIdx = objIdx + 1)
        {
            other = *(uint*)(objList + objIdx * 4);
            if ((other != obj) && (*(short*)(other + 0x46) == 0x306))
            {
                vtbl = **(int**)(other + 0x68);
                (**(code**)(vtbl + 0x24))(other, 0x81, 0);
            }
        }
    }
    *(float*)(state + 0x2a0) = lbl_803E3A70;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 10, 0, vtbl, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    if ((*(uint*)(state + 0x314) & 1) != 0)
    {
        extra = *(int*)(extra + 0x40c);
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & ~1;
        *(byte*)(extra + 8) = *(byte*)(extra + 8) | 1;
        FUN_80006824(obj, SFXfoxcom_heel);
    }
    return 0;
}

undefined4
FUN_8015e88c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 noVtbl;
    ObjHitsPriorityState* hitState;

    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    noVtbl = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    *(float*)(state + 0x2a0) = lbl_803E3A70;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 5, 0, noVtbl, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    return 0;
}

undefined4
FUN_8015e9f4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objList;
    int other;
    uint roll;
    int vtbl;
    int extra;
    int objIdx;
    int objCount[5];
    ObjHitsPriorityState* hitState;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    vtbl = -1;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        objList = FUN_80017b00(&objIdx, objCount);
        for (; objIdx < objCount[0]; objIdx = objIdx + 1)
        {
            other = *(int*)(objList + objIdx * 4);
            if ((other != obj) && (*(short*)(other + 0x46) == 0x306))
            {
                vtbl = **(int**)(other + 0x68);
                (**(code**)(vtbl + 0x24))(other, 0x81, 0);
            }
        }
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 7, 0, vtbl, param_13, param_14, param_15, param_16);
                *(undefined*)(state + 0x346) = 0;
            }
        }
        else if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 6, 0, vtbl, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E3A74 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(extra + 0x406)) - DOUBLE_803e3a58) /
            lbl_803E3A78;
    }
    *(float*)(state + 0x280) = lbl_803E3A60;
    return 0;
}

void fn_8015EB6C(int obj, int p2, int p3);

undefined4
FUN_8015ec98(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int light;
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (lbl_803E3A7C < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        light = *(int*)(extra + 0x40c);
        *(byte*)(light + 8) = *(byte*)(light + 8) | 2;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_DisableObject(obj);
        *(float*)(state + 0x2a0) = lbl_803E3A70;
        *(float*)(state + 0x280) = lbl_803E3A60;
    }
    if (*(char*)(state + 0x346) != '\0')
    {
        FUN_80017698((int)*(short*)(extra + 0x3f4), 0);
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        *(undefined2*)(extra + 0x402) = 0;
        if ((*(byte*)(light + 9) & 2) == 0)
        {
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.
                resetHitboxMode | 8;
        }
    }
    return 0;
}

void fn_8015ED1C(int p1, int p2, int p3);

#pragma scheduling off
#pragma peephole off
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

void fn_8015FCCC(int obj);


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
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state)
{
    float c;
    int extra;
    undefined8 mtx;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(int*)(state + 0x2d0) == 0)
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 0);
        *(undefined*)(state + 0x346) = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 1);
        c = lbl_803E3B00;
        *(float*)(state + 0x290) = lbl_803E3B00;
        *(float*)(state + 0x28c) = c;
        FUN_80003494(extra + 0x35c, obj + 0xc, 0xc);
        mtx = FUN_80003494(extra + 0x368, *(int*)(state + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(mtx, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        if ((*(float*)(state + 0x2c0) < lbl_803E3B04) && (*(char*)(extra + 0x405) == '\x02'))
        {
            return 5;
        }
        if (*(char*)(extra + 0x381) == '\0')
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(extra + 0x374), (double)*(float*)(extra + 0x37c),
             (double)lbl_803E3B00, (double)lbl_803E3B00, (double)lbl_803E3B08, obj,
             state);
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(extra + 0x374), (double)*(float*)(extra + 0x37c),
             (double)lbl_803E3B0C, (double)lbl_803E3B10, (double)lbl_803E3B08, obj,
             state);
        }
    }
    return 0;
}

undefined4
FUN_80160aa4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj
             , int state, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    int player;
    undefined4 result;
    ObjHitsPriorityState* hitState;

    if (*(char*)(state + 0x27b) == '\0')
    {
        player = FUN_80017a98();
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, player, 0xe0000,
                            obj, 0, param_13, param_14, param_15, param_16);
        if (*(int*)&((GameObject*)obj)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj);
            result = 0;
        }
        else
        {
            result = 4;
        }
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 3);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode |
            8;
        result = 0;
    }
    return result;
}

undefined4
FUN_80160cd0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 animId;

    animId = *(undefined4*)(obj + 0xb8);
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B00, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x25f) = 1;
    *(undefined2*)(obj + 4) = *(undefined2*)(state + 0x19e);
    *(undefined2*)(obj + 2) = *(undefined2*)(state + 0x19c);
    (**(code**)(*DAT_803dd738 + 0x10))
        ((double)lbl_803E3B24, (double)lbl_803E3B28, obj, state, animId);
    *(float*)(state + 0x2a0) = lbl_803E3B2C * *(float*)(state + 0x280);
    return 0;
}

void FUN_80161130(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int obj)
{
    undefined4 extra;
    undefined8 grpResult;

    extra = *(undefined4*)&((GameObject*)obj)->extra;
    grpResult = ObjGroup_RemoveObject(obj, 3);
    if (*(int*)&((GameObject*)obj)->childObjs[0] != 0)
    {
        FUN_80017ac8(grpResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)obj)->childObjs[0]);
        *(undefined4*)&((GameObject*)obj)->childObjs[0] = 0;
    }
    (**(code**)(*DAT_803dd738 + 0x40))(obj, extra, 1);
    return;
}

undefined4
FUN_801615d4(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj,
             int state)
{
    undefined4 result;

    if (*(char*)(state + 0x27b) != '\0')
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 8);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        param_1 = ObjHits_DisableObject(obj);
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode |
            8;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        if (*(int*)&((GameObject*)obj)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj);
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
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(float*)(state + 0x2a0) = lbl_803E3B80;
    if ((*(uint*)(state + 0x314) & 0x200) != 0)
    {
        FUN_80006824(obj, SFXdoor_creak);
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & 0xfffffdff;
        (**(code**)(*DAT_803dd738 + 0x4c))(obj, (int)*(short*)(extra + 0x3f0), 0xffffffff, 1);
    }
    return 0;
}

undefined4
FUN_80161ea0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    uint roll;
    int angleStep;
    undefined4 result;
    int light;
    double dist;
    ObjHitsPriorityState* hitState;
    float aX;
    float aY;
    float aZ;
    float bX;
    float bY;
    float bZ[2];
    uint flip;

    light = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 9;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    roll = randomGetRange(0, 100);
    if ((int)roll < 0x32)
    {
        if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 1, 0, param_12, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
    }
    else if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 4, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(float*)(state + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, obj, state, 1);
    flip = *(char*)(light + 0x45) * -2 + 1U ^ 0x80000000;
    bZ[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(light + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(state + 0x280) *
             (f32)(s32)flip),
        *(int*)(light + 0x38), light + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(light + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(light + 0x48))
        {
            *(float*)(light + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(light + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(light + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(light + 0x48) - lbl_803E3B94), *(int*)(light + 0x38), &aX,
     &aY, &aZ);
    (**(code**)(**(int**)(*(int*)(light + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(light + 0x48)), *(int*)(light + 0x38), &bX,
     &bY, bZ);
    aX = aX - bX;
    aY = aY - bY;
    aZ = aZ - bZ[0];
    dist = FUN_80293900((double)(aX * aX + aZ * aZ));
    aX = (float)dist;
    angleStep = FUN_80017730();
    ((GameObject*)obj)->anim.rotY = (short)angleStep * ((short)((int)*(char*)(light + 0x45) << 1) + -1);
    if (*(char*)(state + 0x346) == '\0')
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

void chukchuk_free(void)
{
}

void chukchuk_hitDetect(void)
{
}

void chukchuk_release(void)
{
}

void chukchuk_initialise(void)
{
}

/*
 * Per-object extra state for the ChukChuk ice-spitter
 * (chukchuk_getExtraSize == 0x18).
 */

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

#pragma scheduling off
#pragma peephole off
void chukchuk_init(u8* obj, u8* params)
{
    ChukChukState* sub = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
    sub->gameBit = *(s16*)(params + 0x18);
    if (sub->gameBit != -1 && GameBit_Get(sub->gameBit) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        sub->flags = (u8)(sub->flags | 0x2);
    }
    else
    {
        sub->triggerDistance = (u16)(params[0x29] << 3);
        sub->unk08 = *(s16*)(params + 0x22);
        sub->hitsLeft = params[0x32];
        sub->arcHalfAngle = (u16)((s8)params[0x28] * 0xb6);
        sub->attackChance = params[0x2f];
        sub->aimHeightY = params[0x27];
        *(s16*)obj = (s16)((s8)params[0x2a] << 8);
    }
}
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

int chukchuk_getExtraSize(void) { return 0x18; }
int chukchuk_getObjectTypeId(void) { return 0x0; }
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E2E30);
}

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void fn_8015F5B0(short* obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int Obj_AllocObjectSetup(int size, int id);
    extern u8*Obj_SetupObject(int setup, int a, int b, int c, int d);
    extern int Obj_GetPlayerObject(void);
    extern f32 lbl_803E2E20;
    extern f32 lbl_803E2E24;
    ChukChukState* sub;
    int setup;
    u8* o;
    int pl;
    f32 sc;

    sub = ((GameObject*)obj)->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(36, 1307);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = lbl_803E2E20 + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s8*)(setup + 4) = 1;
        *(s8*)(setup + 5) = 4;
        *(u8*)(setup + 7) = 0xff;
        o = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            pl = Obj_GetPlayerObject();
            ((GameObject*)o)->anim.velocityX = (*(f32*)(pl + 0xc) - ((GameObject*)obj)->anim.localPosX) / (sc =
                lbl_803E2E24);
            ((GameObject*)o)->anim.velocityY =
                ((*(f32*)(pl + 0x10) + (f32)(u32)
            sub->aimHeightY
            )
            -((GameObject*)obj)->anim.localPosY
            )
            /
            sc;
            ((GameObject*)o)->anim.velocityZ = (*(f32*)(pl + 0x14) - ((GameObject*)obj)->anim.localPosZ) / sc;
        }
    }
}

void chukchuk_update(short* obj)
{
    extern void objParticleFn_80099d84(f32, short*, int, f32, int);
    extern int Obj_GetPlayerObject(void);
    extern int getAngle(f32 deltaX, f32 deltaZ);
    extern f32 sqrtf(f32);
    extern void GameBit_Set(int bit, int val);
    extern void fn_8015F5B0(short* obj);
    extern u8 lbl_8031FF80[];
    extern f32 timeDelta;
    extern f32 lbl_803E2E30;
    extern f32 lbl_803E2E34;
    extern f32 lbl_803E2E38;
    extern f32 lbl_803E2E3C;
    extern f32 lbl_803E2E40;
    ChukChukState* v;
    u16 di;
    int pl;
    ObjTextureRuntimeSlot* tex;
    int ang;
    int r;
    f32 ph;
    f32 lim;
    f32 nv;
    f32 dx;
    f32 dz;
    struct
    {
        int c;
        int b;
        int a;
        f32 d[3];
    } stk;

    v = ((GameObject*)obj)->extra;
    if (v->steamTimer != lbl_803E2E34)
    {
        v->steamTimer -= timeDelta;
        objParticleFn_80099d84(lbl_803E2E30, obj, 1, v->steamTimer / lbl_803E2E38, 0);
        if (v->steamTimer <= *(f32*)&lbl_803E2E34)
        {
            v->steamTimer = lbl_803E2E34;
        }
    }
    if ((v->flags & 2) == 0)
    {
        tex = objFindTexture((void*)obj, 0, 0);
        if (v->glowPhase < lbl_803E2E3C)
        {
            if ((int)v->glowPhase == 10)
            {
                v->flags |= 1;
            }
            tex->textureId = lbl_8031FF80[(int)v->glowPhase] << 8;
            lim = lbl_803E2E3C;
            nv = v->glowPhase + lbl_803E2E30;
            v->glowPhase = nv;
            if (lim == nv)
            {
                v->glowPhase = (f32)(int)
                randomGetRange(16, 245);
            }
        }
        else
        {
            if (lbl_803E2E40 - v->glowPhase >= timeDelta)
            {
                v->glowPhase = v->glowPhase + timeDelta;
            }
            else
            {
                v->glowPhase = lbl_803E2E34;
            }
            tex->textureId = 0;
        }
        pl = Obj_GetPlayerObject();
        dx = *(f32*)(pl + 0xc) - ((GameObject*)obj)->anim.localPosX;
        dz = *(f32*)(pl + 0x14) - ((GameObject*)obj)->anim.localPosZ;
        di = sqrtf(dx * dx + dz * dz);
        if (di < v->triggerDistance)
        {
            if (v->prevDistance >= v->triggerDistance)
            {
                v->flags = 5;
                v->glowPhase = lbl_803E2E34;
            }
            if ((v->flags & 5) != 0)
            {
                stk.d[0] = *(f32*)(pl + 0x18) - ((GameObject*)obj)->anim.worldPosX;
                stk.d[1] = *(f32*)(pl + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
                stk.d[2] = *(f32*)(pl + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
                ang = getAngle(stk.d[0], stk.d[2]) & 0xffff;
                ang -= *obj & 0xffff;
                if (ang > 0x8000)
                {
                    ang -= 0xffff;
                }
                if (ang < -0x8000)
                {
                    ang += 0xffff;
                }
                if (((u32)ang & 0xffff) < v->arcHalfAngle ||
                    ((u32)ang & 0xffff) > ((0xffff - v->arcHalfAngle) & 0xffff))
                {
                    r = randomGetRange(0, 99);
                    if (r < v->attackChance || (v->flags & 4) != 0)
                    {
                        Sfx_PlayFromObject(obj, SFXkr_impact1);
                        fn_8015F5B0(obj);
                    }
                    else
                    {
                        Sfx_PlayFromObject(obj, SFXkr_impact2);
                    }
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXkr_impact2);
                }
            }
        }
        else if ((v->flags & 1) != 0)
        {
            Sfx_PlayFromObject(obj, SFXkr_impact2);
        }
        v->prevDistance = di;
        if (ObjHits_GetPriorityHit(obj, &stk.a, &stk.b, &stk.c) == 14)
        {
            v->hitsLeft -= 1;
            if (v->hitsLeft < 1)
            {
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= 0x4000;
                v->flags |= 2;
                Sfx_PlayFromObject(obj, SFXkr_impact3);
                GameBit_Set(v->gameBit, 1);
                v->steamTimer = lbl_803E2E38;
                Sfx_PlayFromObject(obj, SFXfoot_ice_run_4);
            }
        }
        v->flags &= ~5;
    }
}

#pragma scheduling on
#pragma peephole on
void chukchuk_setScale(int obj, int v)
{
    switch ((u8)v)
    {
    case 0x80:
        Sfx_PlayFromObject(obj, SFXkr_jump1);
        break;
    }
}

void iceball_init(void* obj);

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
