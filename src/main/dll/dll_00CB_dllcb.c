#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/dll/rom_curve_interface.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"

typedef struct DllCBPlacement
{
    u8 pad0[0x4 - 0x0];
    s8 unk4;
    s8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x24 - 0x14];
    s16 unk24;
    u8 pad26[0x2C - 0x26];
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllCBPlacement;

typedef struct DllCBState
{
    f32 unk0;
    f32 unk4;
    u8 pad8[0x3DC - 0x8];
    void* unk3DC;
    s32 unk3E0;
    u8 pad3E4[0x3F6 - 0x3E4];
    s16 gameBitId;
    u8 pad3F8[0x3FE - 0x3F8];
    u16 unk3FE;
    u16 unk400;
    u8 pad402[0x405 - 0x402];
    s8 unk405;
    u8 pad406[0x408 - 0x406];
} DllCBState;

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

undefined4
FUN_8015e0d0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10)
{
    float zero;
    float* vel;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    undefined8 msg;

    zero = lbl_803E3A60;
    if (*(char*)(param_10 + 0x27b) == '\0')
    {
        if (*(char*)(param_10 + 0x346) != '\0')
        {
            msg = ObjMsg_SendToObjects(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0, 3,
                                         param_9, 0xe0000, param_9, in_r8, in_r9, in_r10);
            if (*(int*)&((GameObject*)param_9)->anim.placementData == 0)
            {
                FUN_80017ac8(msg, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9);
                return 0;
            }
            return 4;
        }
    }
    else
    {
        vel = *(float**)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
        *vel = lbl_803E3A60;
        vel[1] = zero;
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 6);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
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
    float zero;
    int player;
    int sub;
    double zerod;

    sub = *(int*)&((GameObject*)param_9)->extra;
    *(undefined*)(param_10 + 0x34d) = 3;
    *(float*)(param_10 + 0x2a0) = lbl_803E3A64;
    zero = lbl_803E3A60;
    zerod = (double)lbl_803E3A60;
    *(float*)(param_10 + 0x280) = lbl_803E3A60;
    *(float*)(param_10 + 0x284) = zero;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8(zerod, param_2, param_3, param_4, param_5, param_6, param_7, param_8, param_9, 1, 0, param_12,
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
        (**(code**)(*DAT_803dd738 + 0x4c))(param_9, (int)*(short*)(sub + 0x3f0), 0xffffffff, 0);
    }
    return 0;
}

undefined4
FUN_8015e488(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objs;
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
        objs = FUN_80017b00(&objIdx, &objCount);
        for (; objIdx < objCount; objIdx = objIdx + 1)
        {
            other = *(uint*)(objs + objIdx * 4);
            if ((other != param_9) && (*(short*)(other + 0x46) == 0x306))
            {
                (**(code**)(**(int**)(other + 0x68) + 0x24))(other, 0x81, 0);
            }
        }
        objs = FUN_80017a98();
        target = *(int*)(objs + 200);
        objs = FUN_80017a98();
        target = (**(code**)(**(int**)(target + 0x68) + 0x44))(target);
        if (target == 0)
        {
            if (*(short*)(objs + 0x46) == 0)
            {
                FUN_80006824(param_9, SFXfox_treadwater322);
            }
            else
            {
                FUN_80006824(param_9, SFXfoot_metal_run_2);
            }
        }
        else if (*(short*)(objs + 0x46) == 0)
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
    int objs;
    uint other;
    int hitVtbl;
    int sub;
    int objIdx;
    int objCount;
    ObjHitsPriorityState* hitState;

    sub = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    hitVtbl = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        objs = FUN_80017b00(&objIdx, &objCount);
        for (; objIdx < objCount; objIdx = objIdx + 1)
        {
            other = *(uint*)(objs + objIdx * 4);
            if ((other != param_9) && (*(short*)(other + 0x46) == 0x306))
            {
                hitVtbl = **(int**)(other + 0x68);
                (**(code**)(hitVtbl + 0x24))(other, 0x81, 0);
            }
        }
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, hitVtbl, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        sub = *(int*)(sub + 0x40c);
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        *(byte*)(sub + 8) = *(byte*)(sub + 8) | 1;
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
    undefined4 hitVtbl;
    ObjHitsPriorityState* hitState;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    hitVtbl = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, hitVtbl, param_13, param_14, param_15, param_16);
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
    int objs;
    int other;
    uint roll;
    int hitVtbl;
    int sub;
    int objIdx;
    int objCount[5];
    ObjHitsPriorityState* hitState;

    sub = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    hitVtbl = -1;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(param_9);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        objs = FUN_80017b00(&objIdx, objCount);
        for (; objIdx < objCount[0]; objIdx = objIdx + 1)
        {
            other = *(int*)(objs + objIdx * 4);
            if ((other != param_9) && (*(short*)(other + 0x46) == 0x306))
            {
                hitVtbl = **(int**)(other + 0x68);
                (**(code**)(hitVtbl + 0x24))(other, 0x81, 0);
            }
        }
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, hitVtbl, param_13, param_14, param_15, param_16);
                *(undefined*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, hitVtbl, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
        *(undefined*)(param_10 + 0x34d) = 1;
        *(float*)(param_10 + 0x2a0) =
            lbl_803E3A74 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(sub + 0x406)) - DOUBLE_803e3a58) /
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
    int unaff_r29;
    int sub;

    sub = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (lbl_803E3A7C < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        unaff_r29 = *(int*)(sub + 0x40c);
        *(byte*)(unaff_r29 + 8) = *(byte*)(unaff_r29 + 8) | 2;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_DisableObject(param_9);
        *(float*)(param_10 + 0x2a0) = lbl_803E3A70;
        *(float*)(param_10 + 0x280) = lbl_803E3A60;
    }
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        FUN_80017698((int)*(short*)(sub + 0x3f4), 0);
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined4*)(param_10 + 0x2d0) = 0;
        *(undefined*)(param_10 + 0x25f) = 0;
        *(undefined*)(param_10 + 0x349) = 0;
        *(undefined2*)(sub + 0x402) = 0;
        if ((*(byte*)(unaff_r29 + 9) & 2) == 0)
        {
            *(byte*)&((GameObject*)param_9)->anim.resetHitboxMode = *(byte*)&((GameObject*)param_9)->anim.
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

extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;

void iceball_update(undefined2* param_1, int param_2);

int fn_801601C4(int obj, GroundBaddieState* p)
{
    extern void*memcpy(void* dst, const void* src, int n);
    extern void voxmaps_updateRoutePath(char* a, char* b);
    extern f32 lbl_803E2E68;
    extern f32 lbl_803E2E6C;
    extern f32 lbl_803E2E70;
    extern f32 lbl_803E2E74;
    extern f32 lbl_803E2E78;
    GroundBaddieState* sub;
    char* wp;
    f32 z;

    sub = ((GameObject*)obj)->extra;
    if (*(void**)&p->baddie.targetObj != NULL)
    {
        (*gPlayerInterface)->setState((void*)obj, p, 1);
        wp = (char*)sub->route35C;
        z = lbl_803E2E68;
        p->baddie.moveInputX = z;
        p->baddie.moveInputZ = z;
        memcpy(wp, (void*)&((GameObject*)obj)->anim.localPosX, 12);
        memcpy((void*)(sub->route35C + 0xc), (void*)(*(int*)&p->baddie.targetObj + 0xc), 12);
        voxmaps_updateRoutePath(wp, (char*)(sub->route35C + 0x28));
        if (p->baddie.targetDistance < lbl_803E2E6C && sub->unk405 == 2)
        {
            return 5;
        }
        if (*(u8*)(wp + 0x25) == 0)
        {
            (*gPlayerInterface)->moveTowardPoint((void*)obj, p, *(f32*)(wp + 0x18), *(f32*)(wp + 0x20),
                                                 lbl_803E2E68, *(f32*)&lbl_803E2E68, lbl_803E2E70);
        }
        else
        {
            (*gPlayerInterface)->moveTowardPoint((void*)obj, p, *(f32*)(wp + 0x18), *(f32*)(wp + 0x20),
                                                 lbl_803E2E74, lbl_803E2E78, lbl_803E2E70);
        }
    }
    else
    {
        (*gPlayerInterface)->setState((void*)obj, p, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    return 0;
}

int fn_8016043C(int obj, GroundBaddieState* p)
{
    extern int Obj_GetPlayerObject(void);
    extern void ObjMsg_SendToObject(int target, int msg, int from, int a);
    extern void Obj_FreeObject(int* obj);
    ObjHitsPriorityState* hitState;

    if (*(char*)&p->baddie.moveJustStartedB != '\0')
    {
        (*gPlayerInterface)->setState((void*)obj, p, 3);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    else
    {
        ObjMsg_SendToObject(Obj_GetPlayerObject(), 0xe0000, obj, 0);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject((int*)obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

#pragma dont_inline on
void fn_801606F0(int obj, void* p2, int sub, GroundBaddieState* p)
{
    extern int* gBaddieControlInterface;
    extern void* lbl_803AC5D0[];
    extern void* lbl_803AC5E8[];
    extern f32 timeDelta;
    extern f32 lbl_803E2E9C;
    int setup;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    *(s8*)&p->baddie.moveDone = 1;
    if ((*(int (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
        obj, (u8*)p, (f32)(u32) * (u16*)(sub + 0x3fe), 1) != 0)
    {
        *(int*)&p->baddie.targetObj = *(int*)(sub + 0x3e0);
        *(s8*)&p->baddie.hasTarget = 0;
        if (*(char*)(setup + 0x2e) != -1)
        {
            if (p2 != NULL)
            {
                (*gObjectTriggerInterface)->yield((ObjSeqState*)p2, *(s16*)(setup + 0x24));
            }
            *(s8*)(sub + 0x405) = 1;
        }
        else
        {
            *(int*)&p->baddie.targetObj = 0;
        }
    }
    (*(void (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, (u8*)p,
                                                                              lbl_803E2E9C, 1);
    *(int*)(sub + 0x3e0) = *(int*)&((GameObject*)obj)->pendingParentObj;
    *(int*)&((GameObject*)obj)->pendingParentObj = 0;
    (*gPlayerInterface)->update((void*)obj, p, timeDelta, timeDelta, lbl_803AC5E8, lbl_803AC5D0);
    *(int*)&((GameObject*)obj)->pendingParentObj = *(int*)(sub + 0x3e0);
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_8016083C(int* obj, GroundBaddieState* sub, GroundBaddieState* p)
{
    extern void characterDoEyeAnims(int* obj, u8* a);
    extern f32 sqrtf(f32);
    extern int Obj_GetPlayerObject(void);
    extern int* gBaddieControlInterface;
    extern u8 lbl_80320008[];
    extern u8 lbl_80320080[];
    char* o;
    int t;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        *(int*)(*(int*)&((GameObject*)obj)->childObjs[0] + 0x30) = *(int*)&((GameObject*)obj)->anim.parent;
    }
    o = *(char**)&p->baddie.targetObj;
    if (o != NULL)
    {
        d.x = ((GameObject*)o)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = ((GameObject*)o)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = ((GameObject*)o)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        p->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }
    characterDoEyeAnims(obj, sub->route35C + 0x50);
    if ((sub->configFlags & 1) == 0)
    {
        (*(void (**)(int*, u8*, u8*, int, int, int, int))(*(int*)gBaddieControlInterface + 0x3c))(
            obj, (u8*)p, (u8*)&sub->flags400, 2, 3, sub->unk3FC, sub->unk3FA);
    }
    (*(void (**)(int*, u8*, u8*, int, u8*, int, int, int))(*(int*)gBaddieControlInterface +
        0x54))(
        obj, (u8*)p, sub->route35C, sub->gameBitB, &sub->unk405, 0, 0, 0);
    t = (*(int (**)(int*, u8*, u8*, int, u8*, u8*, int, int))(*(int*)gBaddieControlInterface +
        0x50))(
        obj, (u8*)p, sub->route35C, sub->gameBitB, lbl_80320008, lbl_80320080, 1, 0);
    if (t >= 4)
    {
        *(s8*)&sub->unk405 = 2;
        *(int*)&p->baddie.targetObj = Obj_GetPlayerObject();
    }
}
#pragma dont_inline reset

int dll_CB_seqFn(short* obj, int p2, u8* e)
{
    extern u32 GameBit_Get(int bit);
    extern int Curve_AdvanceAlongPath(int* p, f32 t);
    extern int getAngle(f32 a, f32 b);
    extern int* gBaddieControlInterface;
    extern void* lbl_803AC5D0[];
    extern void* lbl_803AC5E8[];
    extern f32 lbl_803E2E8C;
    extern f32 lbl_803E2E98;
    extern f32 lbl_803E2E9C;
    int setup;
    int* path;
    int sub;

    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        return 0;
    }
    if (((GameObject*)obj)->seqIndex != -1)
    {
        if ((*(int (**)(short*, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, sub, 1) ==
            0)
        {
            return 1;
        }
        fn_8016083C((int*)obj, (GroundBaddieState*)sub, (GroundBaddieState*)sub);
        if (((DllCBState*)sub)->gameBitId != -1 && GameBit_Get(((DllCBState*)sub)->gameBitId) != 0)
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)e, ((DllCBPlacement*)setup)->unk2C);
            ((DllCBState*)sub)->gameBitId = -1;
        }
        switch (*(u8*)&((DllCBState*)sub)->unk405)
        {
        case 2:
            *(s16*)(e + 0x6e) = 0;
            fn_801606F0((int)obj, e, sub, (GroundBaddieState*)sub);
            if (*(u8*)&((DllCBState*)sub)->unk405 == 1)
            {
                ((GroundBaddieState*)sub)->baddie.substate = 5;
                (*gPlayerInterface)->update(obj, (void*)sub, lbl_803E2E8C, *(f32*)&lbl_803E2E8C,
                                            lbl_803AC5E8, lbl_803AC5D0);
                *(s8*)(e + 0x56) = 0;
            }
            break;
        case 1:
            if ((*(int (**)(short*, u8*, int, void*, void*, int))(*(int*)gBaddieControlInterface +
                0x34))(
                obj, e, sub, lbl_803AC5E8, lbl_803AC5D0, 0) != 0)
            {
                (*(void (**)(short*, int, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(obj, sub, lbl_803E2E9C, 1);
            }
            break;
        case 0:
        default:
            *(s16*)(e + 0x6e) = -1;
            *(s16*)(e + 0x6e) &= ~0x40;
            path = *(int**)&((DllCBState*)sub)->unk3DC;
            if ((((DllCBState*)sub)->unk400 & 8) != 0)
            {
                if ((Curve_AdvanceAlongPath(path, ((GroundBaddieState*)sub)->baddie.animSpeedA) != 0 || path[4] != 0) &&
                    (*gRomCurveInterface)->goNextPoint(path) != 0)
                {
                    ((DllCBState*)sub)->unk400 &= ~8;
                }
                ((GroundBaddieState*)sub)->baddie.animSpeedA = lbl_803E2E98;
                ((GameObject*)obj)->anim.rotX = getAngle(*(f32*)((char*)path + 0x74), *(f32*)((char*)path + 0x7c)) +
                    0x8000;
                ((GameObject*)obj)->anim.rotY = getAngle(*(f32*)((char*)path + 0x7c), *(f32*)((char*)path + 0x78)) +
                    0x4000;
                ((GameObject*)obj)->anim.rotZ = getAngle(*(f32*)((char*)path + 0x78), *(f32*)((char*)path + 0x74)) +
                    0x4000;
                ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)path + 0x68);
                ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)path + 0x6c);
                ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)path + 0x70);
            }
            break;
        }
    }
    if (((GameObject*)obj)->seqIndex == -1)
    {
        ((DllCBState*)sub)->unk400 |= 2;
        return 0;
    }
    return *(u8*)&((DllCBState*)sub)->unk405 != 0;
}

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
    float zero;
    int sub;
    undefined8 copyResult;

    sub = *(int*)&((GameObject*)param_9)->extra;
    if (*(int*)(param_10 + 0x2d0) == 0)
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 0);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(param_9, param_10, 1);
        zero = lbl_803E3B00;
        *(float*)(param_10 + 0x290) = lbl_803E3B00;
        *(float*)(param_10 + 0x28c) = zero;
        FUN_80003494(sub + 0x35c, param_9 + 0xc, 0xc);
        copyResult = FUN_80003494(sub + 0x368, *(int*)(param_10 + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(copyResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        if ((*(float*)(param_10 + 0x2c0) < lbl_803E3B04) && (*(char*)(sub + 0x405) == '\x02'))
        {
            return 5;
        }
        if (*(char*)(sub + 0x381) == '\0')
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(sub + 0x374), (double)*(float*)(sub + 0x37c),
             (double)lbl_803E3B00, (double)lbl_803E3B00, (double)lbl_803E3B08, param_9,
             param_10);
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(sub + 0x374), (double)*(float*)(sub + 0x37c),
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
    ObjHitsPriorityState* hitState;

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
        hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
        hitState->flags &= ~1;
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
    undefined4 model;

    model = *(undefined4*)(param_9 + 0xb8);
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
        ((double)lbl_803E3B24, (double)lbl_803E3B28, param_9, param_10, model);
    *(float*)(param_10 + 0x2a0) = lbl_803E3B2C * *(float*)(param_10 + 0x280);
    return 0;
}

void FUN_80161130(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    undefined4 sub;
    undefined8 removeResult;

    sub = *(undefined4*)&((GameObject*)param_9)->extra;
    removeResult = ObjGroup_RemoveObject(param_9, 3);
    if (*(int*)&((GameObject*)param_9)->childObjs[0] != 0)
    {
        FUN_80017ac8(removeResult, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)param_9)->childObjs[0]);
        *(undefined4*)&((GameObject*)param_9)->childObjs[0] = 0;
    }
    (**(code**)(*DAT_803dd738 + 0x40))(param_9, sub, 1);
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
    int sub;

    sub = *(int*)&((GameObject*)param_9)->extra;
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
        (**(code**)(*DAT_803dd738 + 0x4c))(param_9, (int)*(short*)(sub + 0x3f0), 0xffffffff, 1);
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
    int part;
    double dist;
    ObjHitsPriorityState* hitState;
    float aX;
    float aY;
    float aZ;
    float bX;
    float bY;
    float bZ[2];
    uint flip;

    part = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    hitState->hitVolumePriority = 9;
    hitState->hitVolumeId = 1;
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
    flip = *(char*)(part + 0x45) * -2 + 1U ^ 0x80000000;
    bZ[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(part + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)flip),
        *(int*)(part + 0x38), part + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(part + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(part + 0x48))
        {
            *(float*)(part + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(part + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(part + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(part + 0x48) - lbl_803E3B94), *(int*)(part + 0x38), &aX,
     &aY, &aZ);
    (**(code**)(**(int**)(*(int*)(part + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(part + 0x48)), *(int*)(part + 0x38), &bX,
     &bY, bZ);
    aX = aX - bX;
    aY = aY - bY;
    aZ = aZ - bZ[0];
    dist = FUN_80293900((double)(aX * aX + aZ * aZ));
    aX = (float)dist;
    angle = FUN_80017730();
    ((GameObject*)param_9)->anim.rotY = (short)angle * ((short)((int)*(char*)(part + 0x45) << 1) + -1);
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

extern uint GameBit_Get(int eventId);

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

void dll_CB_func0B_nop(void)
{
}

void dll_CB_release_nop(void)
{
}

extern f32 lbl_803E2EA8;

#pragma scheduling off
#pragma peephole off
void dll_CB_init(int* obj, u8* params, int extra)
{
    extern int* gBaddieControlInterface;
    GroundBaddieState* sub;
    u8 flags;

    sub = ((GameObject*)obj)->extra;
    flags = 0x16;
    if (extra != 0) flags |= 1;
    if ((params[0x2b] & 1) == 0) flags |= 8;
    ((GameObject*)obj)->anim.rotY = (s16)((s8)params[0x28] << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((s8)params[0x27] << 8);
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*(int*)gBaddieControlInterface)[22])(
        obj, params, (u8*)sub, 4, 6, 0x82, flags, lbl_803E2EA8);
    ((GameObject*)obj)->animEventCallback = (void*)dll_CB_seqFn;
    (*gPlayerInterface)->setState(obj, sub, 0);
    sub->baddie.substate = 0;
    if (sub->aggroRange < 0x32)
    {
        sub->aggroRange = 0x32;
    }
}

extern int Curve_AdvanceAlongPath(int* p, f32 t);
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E2E98;

void dll_CB_update(int* obj)
{
    extern int* gBaddieControlInterface;
    int* path;
    GroundBaddieState* sub;
    u8* def;

    sub = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0) return;
    if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((DllCBPlacement*)def)->posX;
        ((GameObject*)obj)->anim.localPosY = ((DllCBPlacement*)def)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((DllCBPlacement*)def)->posZ;
        ((GameObject*)obj)->unkF8 = 1;
        return;
    }
    if ((sub->flags400 & 2) != 0)
    {
        ((void(*)(int*, u8*, u8*, s16, u8*, int, int, int, int))((int**)*(int**)gBaddieControlInterface)[10])(
            obj, (u8*)sub, sub->route35C, sub->gameBitB, &sub->unk405, 0, 0, 0, 1);
        sub->flags400 = (u16)(sub->flags400 & ~2);
    }
    if (((int(*)(int*, u8*, int))((int**)*(int**)gBaddieControlInterface)[12])(obj, (u8*)sub, 1) == 0) return;
    fn_8016083C(obj, sub, sub);
    path = *(int**)&sub->path;
    if ((sub->flags400 & 8) == 0) return;
    if (Curve_AdvanceAlongPath(path, sub->baddie.animSpeedA) != 0 || path[4] != 0)
    {
        if ((*gRomCurveInterface)->goNextPoint(path) != 0)
        {
            sub->flags400 = (u16)(sub->flags400 & ~8);
        }
    }
    sub->baddie.animSpeedA = lbl_803E2E98;
    *(s16*)obj = (s16)(getAngle(*(f32*)((char*)path + 0x74), *(f32*)((char*)path + 0x7c)) + 0x8000);
    ((GameObject*)obj)->anim.rotY = (s16)(getAngle(*(f32*)((char*)path + 0x7c), *(f32*)((char*)path + 0x78)) + 0x4000);
    ((GameObject*)obj)->anim.rotZ = (s16)(getAngle(*(f32*)((char*)path + 0x78), *(f32*)((char*)path + 0x74)) + 0x4000);
    ((GameObject*)obj)->anim.localPosX = *(f32*)((char*)path + 0x68);
    ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)path + 0x6c);
    ((GameObject*)obj)->anim.localPosZ = *(f32*)((char*)path + 0x70);
}

int dll_CE_getExtraSize_ret_1052(void);
int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);
int fn_8016052C(void) { return 0x6; }
int dll_CB_getExtraSize_ret_1040(void) { return 0x410; }
int dll_CB_getObjectTypeId(void) { return 0x14b; }

s16 dll_CE_setScale(int* obj);
s16 dll_CB_setScale(int* obj) { return *(s16*)((char*)((int**)obj)[0xb8 / 4] + 0x274); }

extern void objRenderFn_8003b8f4(f32);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj);

#pragma scheduling on
int fn_8016050C(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1) return 3;
    return 6;
}

int grimble_stateHandlerB03(int p1, u8* obj);

extern void GameBit_Set(int eventId, int value);

extern undefined4* gBaddieControlInterface;

#pragma scheduling off
int fn_801603E8(int* obj, u8* obj2)
{
    GroundBaddieState* x = ((GameObject*)obj)->extra;
    if ((s8)obj2[0x27b] != 0)
    {
        (*(code*)((char*)(*gBaddieControlInterface) + 0x4c))(obj, x->unk3F0, -1, 0);
    }
    return 0;
}

extern u8 lbl_803AC5E8[];
#pragma peephole on
void dll_CB_hitDetect(int* obj)
{
    void* a = ((GameObject*)obj)->extra;
    (*gPlayerInterface)->updateVelocityState(obj, a, lbl_803AC5E8);
}

extern f32 lbl_803E2E8C;
#pragma scheduling on
#pragma peephole off
void dll_CB_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            objRenderFn_8003b8f4(lbl_803E2E8C);
            break;
        }
    }
}

extern f32 lbl_803E2E68;
#pragma scheduling off
#pragma peephole on
int fn_801605A8(short* out, u8* obj)
{
    f32 f = lbl_803E2E68;
    *(f32*)(obj + 0x280) = f;
    *(f32*)(obj + 0x284) = f;
    *(s8*)(obj + 0x25f) = 1;
    out[2] = *(s16*)(obj + 0x19e);
    out[1] = *(s16*)(obj + 0x19c);
    return 0;
}

int fn_80160690(short* out, u8* obj)
{
    f32 f = lbl_803E2E68;
    *(f32*)(obj + 0x280) = f;
    *(f32*)(obj + 0x284) = f;
    *(f32*)(obj + 0x2a0) = f;
    *(s8*)(obj + 0x25f) = 1;
    out[2] = *(s16*)(obj + 0x19e);
    out[1] = *(s16*)(obj + 0x19c);
    (*gPlayerInterface)->rotateTowardTarget(out, obj, 5);
    return 0;
}

extern u8 framesThisStep;

extern f32 lbl_803E2E7C;
extern f64 lbl_803E2E80;
extern f32 lbl_803E2E88;

#pragma peephole off
int fn_8016032C(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        (*gPlayerInterface)->setState(obj, state, 0);
        fz = lbl_803E2E7C;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E2E80)
    {
        f32 fz = lbl_803E2E68;
        ((GameObject*)obj)->anim.velocityY = fz;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedC = fz;
        return 6;
    }
    {
        f32 d = lbl_803E2E88;
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY / d;
        state->baddie.animSpeedA = state->baddie.animSpeedA / d;
        state->baddie.animSpeedC = state->baddie.animSpeedC / d;
    }
    return 0;
}

int fn_8015E520(int* obj, GroundBaddieState* state);

extern void* lbl_803AC5D0[];
extern int fn_801605D4(int* obj, GroundBaddieState* def);
int fn_80160534(int* obj);

extern f32 lbl_803E2E90;
extern f32 lbl_803E2E94;

int fn_801605D4(int* obj, GroundBaddieState* def)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    if ((s8)def->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2E68, 0);
        *(s8*)&def->baddie.moveDone = 0;
    }
    *(s8*)&def->baddie.physicsActive = 1;
    ((GameObject*)obj)->anim.rotZ = def->baddie.spawnRotZ;
    ((GameObject*)obj)->anim.rotY = def->baddie.spawnRotY;
    ((void(*)(int*, u8*, int*, f32, f32))((void**)*gBaddieControlInterface)[4])(
        obj, (u8*)def, (int*)state, lbl_803E2E8C, lbl_803E2E90);
    def->baddie.moveSpeed = lbl_803E2E94 * def->baddie.animSpeedA;
    return 0;
}

void dll_CB_initialise(void)
{
    ((void**)lbl_803AC5E8)[0] = (void*)fn_80160690;
    ((void**)lbl_803AC5E8)[1] = (void*)fn_801605D4;
    ((void**)lbl_803AC5E8)[2] = (void*)fn_801605A8;
    ((void**)lbl_803AC5E8)[3] = (void*)fn_80160534;
    lbl_803AC5D0[0] = (void*)fn_8016052C;
    lbl_803AC5D0[1] = (void*)fn_8016050C;
    lbl_803AC5D0[2] = (void*)fn_8016043C;
    lbl_803AC5D0[3] = (void*)fn_801603E8;
    lbl_803AC5D0[4] = (void*)fn_8016032C;
    lbl_803AC5D0[5] = (void*)fn_801601C4;
}

#pragma peephole on
int fn_80160534(int* obj)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    u8 step;
    if (((GameObject*)obj)->anim.alpha >= (step = framesThisStep))
    {
        ((GameObject*)obj)->anim.alpha = ((GameObject*)obj)->anim.alpha - step;
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = 0;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        GameBit_Set(sub->gameBitB, 0);
        GameBit_Set(sub->gameBitA, 1);
    }
    return 0;
}

int grimble_stateHandlerB01(int* obj, GroundBaddieState* state);

#pragma peephole off
void dll_CB_free(int* obj)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    {
        int* sub = ((GameObject*)obj)->childObjs[0];
        if (sub != NULL)
        {
            Obj_FreeObject(sub);
            ((GameObject*)obj)->childObjs[0] = NULL;
        }
    }
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int*)state, 1);
}

void dll_CE_free(int* obj);

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

extern f32 sqrtf(f32);

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
