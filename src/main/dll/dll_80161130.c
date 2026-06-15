#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"

typedef struct GrimbleState
{
    u8 pad0[0x38 - 0x0];
    s32 unk38;
    u8 pad3C[0x45 - 0x3C];
    s8 unk45;
    u8 pad46[0x48 - 0x46];
    f32 unk48;
    u8 pad4C[0x58 - 0x4C];
    s16 unk58;
    u8 pad5A[0x60 - 0x5A];
} GrimbleState;

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

extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern int getAngle(f32 a, f32 b);
extern void GameBit_Set(int eventId, int value);
extern undefined4* gBaddieControlInterface;
extern undefined4* gPlayerInterface;
extern f32 lbl_803E2EB8;
extern f32 lbl_803E2EE8;
extern void* lbl_803AC5D0[];
extern f32 sqrtf(f32);
extern f32 lbl_803E2EB0;
extern f32 lbl_803E2EB4;
extern f32 lbl_803E2EBC;
extern f32 lbl_803E2EC0;
extern f32 lbl_803E2EC4;
extern f32 lbl_803E2EC8;
extern f32 lbl_803E2ECC;

undefined4
FUN_8015e0d0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint objId
             , int state)
{
    float val;
    float* hitData;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 msg;

    val = lbl_803E3A60;
    if (*(char*)(state + 0x27b) == '\0')
    {
        if (*(char*)(state + 0x346) != '\0')
        {
            msg = ObjMsg_SendToObjects(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0, 3,
                                         objId, 0xe0000, objId, in_r8, in_r9, in_r10);
            if (*(int*)&((GameObject*)objId)->anim.placementData == 0)
            {
                FUN_80017ac8(msg, param_2, param_3, param_4, param_5, param_6, param_7, param_8, objId);
                return 0;
            }
            return 4;
        }
    }
    else
    {
        hitData = *(float**)(*(int*)&((GameObject*)objId)->extra + 0x40c);
        *hitData = lbl_803E3A60;
        hitData[1] = val;
        (**(code**)(*DAT_803dd70c + 0x14))(objId, state, 6);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        ObjHits_DisableObject(objId);
        *(byte*)&((GameObject*)objId)->anim.resetHitboxMode = *(byte*)&((GameObject*)objId)->anim.resetHitboxMode |
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
    int player;
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
        player = *(int*)(objList + 200);
        objList = FUN_80017a98();
        player = (**(code**)(**(int**)(player + 0x68) + 0x44))(player);
        if (player == 0)
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
    undefined4 vtbl;
    ObjHitsPriorityState* hitState;

    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    vtbl = 0xffffffff;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    *(float*)(state + 0x2a0) = lbl_803E3A70;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 5, 0, vtbl, param_13, param_14, param_15, param_16);
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
    int control;
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
        control = *(int*)(extra + 0x40c);
        *(byte*)(control + 8) = *(byte*)(control + 8) | 2;
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
        if ((*(byte*)(control + 9) & 2) == 0)
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
    float val;
    int extra;
    undefined8 ret;

    extra = *(int*)&((GameObject*)obj)->extra;
    if (*(int*)(state + 0x2d0) == 0)
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 0);
        *(undefined*)(state + 0x346) = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 1);
        val = lbl_803E3B00;
        *(float*)(state + 0x290) = lbl_803E3B00;
        *(float*)(state + 0x28c) = val;
        FUN_80003494(extra + 0x35c, obj + 0xc, 0xc);
        ret = FUN_80003494(extra + 0x368, *(int*)(state + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(ret, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
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
    undefined4 ret;
    ObjHitsPriorityState* hitState;

    if (*(char*)(state + 0x27b) == '\0')
    {
        player = FUN_80017a98();
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, player, 0xe0000,
                            obj, 0, param_13, param_14, param_15, param_16);
        if (*(int*)&((GameObject*)obj)->anim.placementData == 0)
        {
            FUN_80017ac8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, obj);
            ret = 0;
        }
        else
        {
            ret = 4;
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
        ret = 0;
    }
    return ret;
}

undefined4
FUN_80160cd0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 modelData;

    modelData = *(undefined4*)(obj + 0xb8);
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
        ((double)lbl_803E3B24, (double)lbl_803E3B28, obj, state, modelData);
    *(float*)(state + 0x2a0) = lbl_803E3B2C * *(float*)(state + 0x280);
    return 0;
}

void FUN_80161130(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int obj)
{
    undefined4 extra;
    undefined8 ret;

    extra = *(undefined4*)&((GameObject*)obj)->extra;
    ret = ObjGroup_RemoveObject(obj, 3);
    if (*(int*)&((GameObject*)obj)->childObjs[0] != 0)
    {
        FUN_80017ac8(ret, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
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
    undefined4 ret;

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
            ret = 0;
        }
        else
        {
            ret = 6;
        }
    }
    else
    {
        ret = 0;
    }
    return ret;
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
    int angle;
    undefined4 ret;
    int hit;
    double dist;
    ObjHitsPriorityState* hitState;
    float aX;
    float aY;
    float aZ;
    float bX;
    float bY;
    float bZ[2];
    uint flip;

    hit = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
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
    flip = *(char*)(hit + 0x45) * -2 + 1U ^ 0x80000000;
    bZ[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(hit + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(state + 0x280) *
             (f32)(s32)flip),
        *(int*)(hit + 0x38), hit + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(hit + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(hit + 0x48))
        {
            *(float*)(hit + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(hit + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(hit + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(hit + 0x48) - lbl_803E3B94), *(int*)(hit + 0x38), &aX,
     &aY, &aZ);
    (**(code**)(**(int**)(*(int*)(hit + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(hit + 0x48)), *(int*)(hit + 0x38), &bX,
     &bY, bZ);
    aX = aX - bX;
    aY = aY - bY;
    aZ = aZ - bZ[0];
    dist = FUN_80293900((double)(aX * aX + aZ * aZ));
    aX = (float)dist;
    angle = FUN_80017730();
    ((GameObject*)obj)->anim.rotY = (short)angle * ((short)((int)*(char*)(hit + 0x45) << 1) + -1);
    if (*(char*)(state + 0x346) == '\0')
    {
        ret = 0;
    }
    else
    {
        ret = 5;
    }
    return ret;
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
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj);

#pragma peephole off
int grimble_stateHandlerB03(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1) return 5;
    return 1;
}

int fn_8015E00C(int p1, u8* obj);

#pragma scheduling off
int grimble_stateHandlerB05(int* obj, u8* obj2)
{
    GroundBaddieState* x = ((GameObject*)obj)->extra;
    if ((s8)obj2[0x27b] != 0)
    {
        x->unk405 = 0;
        GameBit_Set(x->gameBitB, 0);
        GameBit_Set(x->gameBitA, 1);
    }
    return 0;
}

int fn_801603E8(int* obj, u8* obj2);

int grimble_stateHandlerA08(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2EB8, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = lbl_803E2EE8;
    if ((*(int*)&state->baddie.eventFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        *(int*)&state->baddie.eventFlags &= ~0x200;
        ((void(*)(int*, int, int, int))((void**)*gBaddieControlInterface)[19])(obj, sub->unk3F0, -1, 1);
    }
    return 0;
}

int fn_8016032C(int* obj, GroundBaddieState* state);

int grimble_stateHandlerB04(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 8);
        *(int*)&state->baddie.targetObj = 0;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        ObjHits_DisableObject((int)obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        if (*(void**)&((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        return 6;
    }
    return 0;
}

int grimble_stateHandlerB01(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 9);
    }
    if ((s8)state->baddie.moveDone != 0)
    {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerB00(int obj, GroundBaddieState* p)
{
    extern f32 timeDelta;
    extern f64 lbl_803E2ED8;
    extern f32 lbl_803E2ED0;
    extern f32 lbl_803E2ED4;
    u16 a;
    u16 b;
    u16 c;

    if (*(void**)&p->baddie.targetObj != NULL && p->baddie.controlMode != 2)
    {
        if ((f32)p->baddie.unk32E > lbl_803E2ED0 * timeDelta)
        {
            (*(void (**)(int, int, int, u16*, u16*, u16*))((char*)*gBaddieControlInterface + 0x14))(
                obj, *(int*)&p->baddie.targetObj, 16, &a, &b, &c);
            if (a < 4 || a > 11)
            {
                return 3;
            }
            (*(void (**)(int, u8*, int))((char*)*gPlayerInterface + 0x14))(obj, (u8*)p, 2);
            p->baddie.moveSpeed = lbl_803E2ED4;
            *(s8*)&p->baddie.moveDone = 0;
        }
    }
    return 0;
}

int grimble_stateHandlerA09(int obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EB8;
    extern f32 lbl_803E2EE0;
    extern f32 lbl_803E2EE4;
    GroundBaddieState* sub;
    f32 spd;

    sub = ((GameObject*)obj)->extra;
    *(s8*)&p->baddie.unk34D = 0;
    p->baddie.moveSpeed = lbl_803E2EE0;
    spd = lbl_803E2EB8;
    p->baddie.animSpeedA = spd;
    p->baddie.animSpeedB = spd;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        Sfx_PlayFromObject(obj, SFXsc_death02);
        if (*(char*)&p->baddie.moveJustStartedA != '\0')
        {
            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2EB8, 0);
            *(s8*)&p->baddie.moveDone = 0;
        }
        p->baddie.moveSpeed = lbl_803E2EE4;
        *(s8*)&p->baddie.moveDone = 0;
        ((GameObject*)obj)->anim.alpha = 0xff;
        sub->flags400 |= 0x100;
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA06(int obj, GroundBaddieState* p, f32 spd)
{
    extern f32 sqrtf(f32);
    extern int getAngle(f32 a, f32 b);
    extern int randomGetRange(int min, int max);
    extern f32 lbl_803E2EB8;
    extern f32 lbl_803E2EF0;
    extern f32 lbl_803E2EF4;
    extern f32 lbl_803E2EF8;
    extern f32 lbl_803E2EFC;
    extern f64 lbl_803E2ED8;
    int hit;
    ObjHitsPriorityState* hitState;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->hitVolumePriority = 9;
    hitState->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (randomGetRange(0, 100) < 50)
    {
        if (*(char*)&p->baddie.moveJustStartedA != '\0')
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E2EB8, 0);
            *(s8*)&p->baddie.moveDone = 0;
        }
    }
    else if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 4, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(short*, u8*, f32, int))((char*)*gPlayerInterface + 0x20))((short*)obj, (u8*)p, spd, 1);
    (*(void (**)(void*, void*, f32))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) + 0x28))(
        *(void**)&((GrimbleState*)hit)->unk38, (void*)(hit + 0x48),
        p->baddie.animSpeedA * (f32)(1 - (((GrimbleState*)hit)->unk45 << 1)));
    if (((GrimbleState*)hit)->unk48 < lbl_803E2EF4)
    {
        ((GrimbleState*)hit)->unk48 = lbl_803E2EF4;
    }
    else if (((GrimbleState*)hit)->unk48 > lbl_803E2EF8)
    {
        ((GrimbleState*)hit)->unk48 = lbl_803E2EF8;
    }
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, ((GrimbleState*)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, lbl_803E2EFC + ((GrimbleState*)hit)->unk48, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, (f32)d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleState*)hit)->unk45 << 1) - 1);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 5;
    }
    return 0;
}

int grimble_stateHandlerA07(short* obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EB8;
    extern f32 lbl_803E2EEC;
    int hit;
    s16 yaw;
    int diff;
    f32 spd;

    hit = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        Sfx_PlayFromObject(obj, SFXsc_attack04);
    }
    p->baddie.moveSpeed = lbl_803E2EEC;
    yaw = ((GrimbleState*)hit)->unk58;
    diff = *obj - (yaw & 0xffff);
    if (diff > 0x8000)
    {
        diff -= 0xffff;
    }
    if (diff < -0x8000)
    {
        diff += 0xffff;
    }
    *obj = yaw;
    if (diff > 0x3ffc || diff < -0x3ffc)
    {
        *obj += 0x8000;
    }
    spd = lbl_803E2EB8;
    p->baddie.animSpeedA = spd;
    p->baddie.animSpeedB = spd;
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA05(short* obj, GroundBaddieState* p)
{
    extern f32 sqrtf(f32);
    extern int getAngle(f32 a, f32 b);
    extern f32 lbl_803E2EB8;
    extern f32 lbl_803E2EF0;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, ((GrimbleState*)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, lbl_803E2EFC + ((GrimbleState*)hit)->unk48, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, (f32)d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleState*)hit)->unk45 << 1) - 1);
    }
    return 0;
}

int grimble_stateHandlerA04(short* obj, GroundBaddieState* p)
{
    extern f32 sqrtf(f32);
    extern int getAngle(f32 a, f32 b);
    extern f32 lbl_803E2EB8;
    extern f32 lbl_803E2EF0;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, ((GrimbleState*)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, lbl_803E2EFC + ((GrimbleState*)hit)->unk48, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, (f32)d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleState*)hit)->unk45 << 1) - 1);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 6;
    }
    return 0;
}

int grimble_stateHandlerA03(short* obj, GroundBaddieState* p)
{
    extern f32 sqrtf(f32);
    extern int getAngle(f32 a, f32 b);
    extern f32 lbl_803E2EB8;
    extern f32 lbl_803E2EE4;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EE4;
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, ((GrimbleState*)hit)->unk48 - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleState*)hit)->unk38 + 0x68) +
        0x24))(
        *(void**)&((GrimbleState*)hit)->unk38, lbl_803E2EFC + ((GrimbleState*)hit)->unk48, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, (f32)d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleState*)hit)->unk45 << 1) - 1);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 1;
    }
    return 0;
}

void dll_CB_free(int* obj);

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
int scarab_updateProximityGate(int* obj, GroundBaddieState* state)
{
    int* target;
    f32 dx;
    f32 dz;
    f32 magAbs;
    u32 rel;

    target = *(int**)&state->baddie.targetObj;
    if (target == NULL)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        return 1;
    }
    if (state->baddie.controlMode != 6)
    {
        dx = ((GameObject*)obj)->anim.localPosX - *(f32*)((char*)target + 0xc);
        dz = ((GameObject*)obj)->anim.localPosZ - *(f32*)((char*)target + 0x14);
        rel = (getAngle(dx, dz) - *(s16*)obj) & 0xffff;
        if (rel > 0x4000 && rel < 0xc000)
        {
            dx = lbl_803E2EB0;
        }
        else
        {
            dx = sqrtf(dx * dx + dz * dz) - lbl_803E2EB4;
        }
        magAbs = dx < lbl_803E2EB8 ? -dx : dx;
        if (magAbs < lbl_803E2EBC)
        {
            if (state->baddie.controlMode == 1 ||
                (state->baddie.controlMode == 5 && (s8)state->baddie.moveDone != 0))
            {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 6);
                goto
                post;
            }
        }
        if (state->baddie.controlMode == 1) goto
        post;
        if (dx > lbl_803E2EC0)
        {
            if (state->baddie.controlMode != 4 &&
                (state->baddie.controlMode != 5 || (s8)state->baddie.moveDone != 0))
            {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
            }
        }
        if (dx < lbl_803E2EC4)
        {
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
        }
        post
        :
        if (state->baddie.controlMode == 1)
        {
            state->baddie.moveSpeed = (dx > lbl_803E2EB8) ? lbl_803E2EC8 : lbl_803E2ECC;
        }
    }
    return 0;
}
