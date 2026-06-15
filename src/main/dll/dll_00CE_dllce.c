#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/sky_interface.h"

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

int fn_8015E3A0(int obj, int p2)
{
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
    extern void ObjHits_RegisterActiveHitVolumeObject(int);
    extern int*ObjList_GetObjects(int*, int*);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DD8;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int count;
    int idx;

    if ((s32)(s8) * (u8*)(p2 + 0x27a) != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);

    if ((s32)(s8) * (u8*)(p2 + 0x27a) != 0)
    {
        int* objs = ObjList_GetObjects(&idx, &count);
        while (idx < count)
        {
            int o = objs[idx];
            if ((void*)o != (void*)obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(int (**)(int, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(o, 129, 0);
            }
            idx++;
        }
    }

    *(f32*)(p2 + 0x2a0) = lbl_803E2DD8;

    if ((s32)(s8) * (u8*)(p2 + 0x27a) != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 10, lbl_803E2DC8, 0);
        *(u8*)(p2 + 0x346) = 0;
    }
    *(u8*)(p2 + 0x34d) = 1;

    if ((*(u32*)(p2 + 0x314) & 0x1) != 0U)
    {
        int child = *(int*)&sub->control;
        *(u32*)(p2 + 0x314) = *(u32*)(p2 + 0x314) & ~0x1;
        *(u8*)(child + 0x8) = (u8)(*(u8*)(child + 0x8) | 0x1);
        Sfx_PlayFromObject(obj, SFXfoxcom_heel);
    }
    return 0;
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015e0d0(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj
             , int state)
{
    float zero;
    float* vel;
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
        vel = *(float**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
        *vel = lbl_803E3A60;
        vel[1] = zero;
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

#pragma scheduling off
#pragma peephole off
int fn_8015E210(int* obj, GroundBaddieState* state)
{
    extern int*ObjList_GetObjects(int* startIndex, int* objectCount);
    extern void*Obj_GetPlayerObject(void);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DD4;
    int* objs;
    int count;
    int i;
    int* playerChild;
    int* player;
    int result;

    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2DC8, 0);
        *(s8*)&state->baddie.moveDone = 0;
    }
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != (void*)obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(void (**)(void*, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(
                    o, 129, 0);
            }
        }
        playerChild = *(int**)((char*)Obj_GetPlayerObject() + 0xc8);
        player = (int*)Obj_GetPlayerObject();
        result = (**(int (**)(int*))(*(int*)(*(int*)&((GameObject*)playerChild)->anim.dll) + 0x44))(playerChild);
        if (result != 0)
        {
            if (((GameObject*)player)->anim.seqId != 0)
            {
                Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXmv_ropecreak22);
            }
        }
        else
        {
            if (((GameObject*)player)->anim.seqId != 0)
            {
                Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXfox_treadwater322);
            }
        }
        Sfx_PlayFromObject(obj, SFXfoxcom_stay);
    }
    *(s8*)&state->baddie.unk34D = 3;
    state->baddie.moveSpeed = lbl_803E2DD4;
    state->baddie.animSpeedA = lbl_803E2DC8;
    return 0;
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015e2e0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float zero;
    int player;
    int sub;
    double zeroD;

    sub = *(int*)&((GameObject*)obj)->extra;
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
        (**(code**)(*DAT_803dd738 + 0x4c))(obj, (int)*(short*)(sub + 0x3f0), 0xffffffff, 0);
    }
    return 0;
}

undefined4
FUN_8015e488(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objs;
    uint other;
    int player;
    int i;
    int count;

    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        objs = FUN_80017b00(&i, &count);
        for (; i < count; i = i + 1)
        {
            other = *(uint*)(objs + i * 4);
            if ((other != obj) && (*(short*)(other + 0x46) == 0x306))
            {
                (**(code**)(**(int**)(other + 0x68) + 0x24))(other, 0x81, 0);
            }
        }
        objs = FUN_80017a98();
        player = *(int*)(objs + 200);
        objs = FUN_80017a98();
        player = (**(code**)(**(int**)(player + 0x68) + 0x44))(player);
        if (player == 0)
        {
            if (*(short*)(objs + 0x46) == 0)
            {
                FUN_80006824(obj, SFXfox_treadwater322);
            }
            else
            {
                FUN_80006824(obj, SFXfoot_metal_run_2);
            }
        }
        else if (*(short*)(objs + 0x46) == 0)
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

#pragma scheduling off
#pragma peephole off
int fn_8015DC04(int obj, GroundBaddieState* p)
{
    extern int*ObjList_GetObjects(int* startIndex, int* objectCount);
    extern int randomGetRange(int min, int max);
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f64 lbl_803E2DC0;
    int count;
    int i;
    GroundBaddieState* sub;
    u8* hit;
    int maxr;
    int four;
    int* objs;
    int r;
    int rnd;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&p->baddie.moveDone != '\0' || *(char*)&p->baddie.moveJustStartedB != '\0')
    {
        hit = *(u8**)&sub->control;
        r = (*(int (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
            obj, (u8*)p, (f32)(u32)sub->aggroRange, 1);
        if (r != 0)
        {
            hit[9] &= ~2;
            return 5;
        }
        four = 0;
        maxr = 0;
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != (void*)obj && ((GameObject*)o)->anim.seqId == 774)
            {
                int v = (*(int (**)(void*, int))(**(int**)&((GameObject*)o)->anim.dll + 0x20))(o, 0);
                if (v > maxr)
                {
                    maxr = v;
                }
                if (v == 4)
                {
                    four++;
                }
            }
        }
        rnd = randomGetRange(0, sub->aggression);
        if (maxr >= 5 || (hit[9] & 1) != 0)
        {
            if ((sub->configFlags & 2) != 0)
            {
                hit[9] |= 1;
            }
            (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 4);
        }
        else if (rnd > 32)
        {
            if (four > 1)
            {
                (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 2);
            }
            else
            {
                (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 4);
            }
        }
        else if (rnd > 16)
        {
            (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 2);
        }
        else
        {
            (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 3);
        }
    }
    return 0;
}

#pragma dont_inline on
void fn_8015DAE8(void)
{
    extern void* gMediumBasketStateHandlersB[];
    extern void* gMediumBasketStateHandlersA[];
    extern int mediumbasket_updateOpenHitState();
    extern int mediumbasket_updateOpenState();
    extern int mediumbasket_updateHideResetState();
    extern int mediumbasket_updateImpactHitState();
    extern int mediumbasket_updateSpinState();
    extern int mediumbasket_stateHandlerA05();
    extern int mediumbasket_stateHandlerA06();
    extern int mediumbasket_updateHeightBlendState();
    extern int mediumbasket_updateControlMove5State();
    extern int mediumbasket_updateCommDownState();
    extern int mediumbasket_updateDropState();
    extern int mediumbasket_stateHandlerA0B();
    extern int mediumbasket_updateContactHitState();
    extern int mediumbasket_updateLandingState();
    extern int mediumbasket_checkTargetState();
    extern int mediumbasket_stateHandlerB01();
    extern int mediumbasket_stateHandlerB02();
    extern int mediumbasket_stateHandlerB03();
    extern int mediumbasket_stateHandlerB04();
    extern int mediumbasket_stateHandlerB05();
    extern int mediumbasket_stateHandlerB06();
    extern int mediumbasket_stateHandlerB07();

    gMediumBasketStateHandlersA[0] = (void*)mediumbasket_updateOpenHitState;
    gMediumBasketStateHandlersA[1] = (void*)mediumbasket_updateOpenState;
    gMediumBasketStateHandlersA[2] = (void*)mediumbasket_updateHideResetState;
    gMediumBasketStateHandlersA[3] = (void*)mediumbasket_updateImpactHitState;
    gMediumBasketStateHandlersA[4] = (void*)mediumbasket_updateSpinState;
    gMediumBasketStateHandlersA[5] = (void*)mediumbasket_stateHandlerA05;
    gMediumBasketStateHandlersA[6] = (void*)mediumbasket_stateHandlerA06;
    gMediumBasketStateHandlersA[7] = (void*)mediumbasket_updateHeightBlendState;
    gMediumBasketStateHandlersA[8] = (void*)mediumbasket_updateControlMove5State;
    gMediumBasketStateHandlersA[9] = (void*)mediumbasket_updateCommDownState;
    gMediumBasketStateHandlersA[10] = (void*)mediumbasket_updateDropState;
    gMediumBasketStateHandlersA[11] = (void*)mediumbasket_stateHandlerA0B;
    gMediumBasketStateHandlersA[12] = (void*)mediumbasket_updateContactHitState;
    gMediumBasketStateHandlersA[13] = (void*)mediumbasket_updateLandingState;
    gMediumBasketStateHandlersB[0] = (void*)mediumbasket_checkTargetState;
    gMediumBasketStateHandlersB[1] = (void*)mediumbasket_stateHandlerB01;
    gMediumBasketStateHandlersB[2] = (void*)mediumbasket_stateHandlerB02;
    gMediumBasketStateHandlersB[3] = (void*)mediumbasket_stateHandlerB03;
    gMediumBasketStateHandlersB[4] = (void*)mediumbasket_stateHandlerB04;
    gMediumBasketStateHandlersB[5] = (void*)mediumbasket_stateHandlerB05;
    gMediumBasketStateHandlersB[6] = (void*)mediumbasket_stateHandlerB06;
    gMediumBasketStateHandlersB[7] = (void*)mediumbasket_stateHandlerB07;
}
#pragma dont_inline reset

void dll_CA_init(int obj, u8* p, int flags);

int fn_8015E5DC(short* obj, GroundBaddieState* p)
{
    extern int*ObjList_GetObjects(int* startIndex, int* objectCount);
    extern int randomGetRange(int min, int max);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DDC;
    extern f32 lbl_803E2DE0;
    int count;
    int i;
    GroundBaddieState* sub;
    int* objs;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != (void*)obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(void (**)(void*, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(
                    o, 129, 0);
            }
        }
        if (randomGetRange(0, 1) != 0)
        {
            if (*(char*)&p->baddie.moveJustStartedA != '\0')
            {
                ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2DC8, 0);
                *(s8*)&p->baddie.moveDone = 0;
            }
        }
        else
        {
            if (*(char*)&p->baddie.moveJustStartedA != '\0')
            {
                ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2DC8, 0);
                *(s8*)&p->baddie.moveDone = 0;
            }
        }
        *(s8*)&p->baddie.unk34D = 1;
        p->baddie.moveSpeed = lbl_803E2DDC + (f32)(u32)
        sub->aggression / lbl_803E2DE0;
    }
    p->baddie.animSpeedA = lbl_803E2DC8;
    return 0;
}

int fn_8015DF20(int obj, GroundBaddieState* p)
{
    extern int* gPlayerInterface;
    extern void Obj_FreeObject(int* obj);
    extern f32 lbl_803E2DC8;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    f32* v;
    f32 z;

    if (*(char*)&p->baddie.moveJustStartedB != '\0')
    {
        v = *(f32**)&sub->control;
        z = lbl_803E2DC8;
        v[0] = z;
        v[1] = z;
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 6);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    }
    else if (*(char*)&p->baddie.moveDone != '\0')
    {
        ObjMsg_SendToObjects(0, 3, obj, 0xe0000, obj);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject((int*)obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int fn_8015E0C8(int obj, GroundBaddieState* p)
{
    extern int Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern int* gBaddieControlInterface;
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DCC;
    extern f32 lbl_803E2DD0;
    GroundBaddieState* sub;
    f32 spd;

    sub = ((GameObject*)obj)->extra;
    *(s8*)&p->baddie.unk34D = 3;
    p->baddie.moveSpeed = lbl_803E2DCC;
    spd = lbl_803E2DC8;
    p->baddie.animSpeedA = spd;
    p->baddie.animSpeedB = spd;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 1, spd, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if ((p->baddie.moveEventFlags & 1) == 0)
    {
        if (*(s16*)(Obj_GetPlayerObject() + 0x46) != 0)
        {
            Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXfox_treadwater322);
        }
        Sfx_PlayFromObject(obj, SFXdoor_unlocked);
        Sfx_PlayFromObject(obj, SFXfoxcom_find);
        p->baddie.moveEventFlags |= 1;
    }
    if ((p->baddie.moveEventFlags & 2) == 0 && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2DD0)
    {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        p->baddie.moveEventFlags |= 2;
        (*(void (**)(int, int, int, int))(*(int*)gBaddieControlInterface + 0x4c))(
            obj, sub->unk3F0, -1, 0);
    }
    return 0;
}

int fn_8015E798(int obj, GroundBaddieState* p)
{
    extern void GameBit_Set(int bit, int val);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DD8;
    extern f32 lbl_803E2DE4;
    GroundBaddieState* sub;
    u8* hit;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E2DC8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2DE4)
    {
        hit = *(u8**)&sub->control;
        hit[8] |= 2;
    }
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjHits_DisableObject(obj);
        p->baddie.moveSpeed = lbl_803E2DD8;
        p->baddie.animSpeedA = lbl_803E2DC8;
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        GameBit_Set(sub->gameBitB, 0);
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        sub->targetState = 0;
        if ((hit[9] & 2) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
    }
    return 0;
}

int fn_8015E8BC(int obj, GroundBaddieState* p)
{
    extern void GameBit_Set(int bit, int val);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DE8;
    extern f32 lbl_803E2DEC;
    extern f32 lbl_803E2DF0;
    GroundBaddieState* sub;
    u8* hit;
    int flags;

    sub = ((GameObject*)obj)->extra;
    hit = *(u8**)&sub->control;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 11, lbl_803E2DC8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        *(s8*)&p->baddie.physicsActive = 1;
        GameBit_Set(sub->gameBitB, 1);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        ((GameObject*)obj)->anim.alpha = 0xff;
        *(s8*)&p->baddie.unk34D = 1;
        p->baddie.moveSpeed =
            lbl_803E2DE8 + (f32)(u32)
        sub->aggression / lbl_803E2DEC;
        ObjHits_EnableObject(obj);
    }
    else
    {
        ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        sub->targetState = 1;
    }
    flags = p->baddie.eventFlags;
    if ((flags & 0x200) != 0)
    {
        p->baddie.eventFlags = flags & ~0x200;
        hit[8] |= 4;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2DF0)
    {
        hit[8] |= 2;
    }
    return 0;
}

void fn_8015EA48(int obj, GroundBaddieState* state)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int Obj_AllocObjectSetup(int size, int id);
    extern u8*Obj_SetupObject(int setup, int a, int b, int c, int d);
    extern f64 lbl_803E2DC0;
    extern f32 lbl_803E2DF4;
    extern f32 lbl_803E2DF8;
    extern f32 lbl_803E2DFC;
    f32 dur;
    f32 t;
    int setup;
    u8* o;

    if (Obj_IsLoadingLocked() == 0)
    {
        setup = Obj_AllocObjectSetup(36, 778);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = lbl_803E2DF4 + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s8*)(setup + 4) = 1;
        *(s8*)(setup + 5) = 1;
        *(u8*)(setup + 6) = 0xff;
        *(u8*)(setup + 7) = 0xff;
        o = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            t = state->baddie.targetDistance / (f32)(u32)
            state->aggroRange;
            dur = lbl_803E2DF8 * t;
            ((GameObject*)o)->anim.velocityX =
                (*(f32*)(*(int*)&state->baddie.targetObj + 0xc) - ((GameObject*)obj)->anim.localPosX) / dur;
            ((GameObject*)o)->anim.velocityY =
            ((lbl_803E2DFC * t + *(f32*)(*(int*)&state->baddie.targetObj + 0x10)) - ((GameObject*)obj)->anim.
                localPosY) / dur;
            ((GameObject*)o)->anim.velocityZ =
                (*(f32*)(*(int*)&state->baddie.targetObj + 0x14) - ((GameObject*)obj)->anim.localPosZ) / dur;
            *(int*)&((GameObject*)o)->ownerObj = obj;
        }
    }
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015e678(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int objs;
    uint other;
    int otherVtbl;
    int sub;
    int i;
    int count;
    ObjHitsPriorityState* hitState;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    otherVtbl = -1;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        objs = FUN_80017b00(&i, &count);
        for (; i < count; i = i + 1)
        {
            other = *(uint*)(objs + i * 4);
            if ((other != obj) && (*(short*)(other + 0x46) == 0x306))
            {
                otherVtbl = **(int**)(other + 0x68);
                (**(code**)(otherVtbl + 0x24))(other, 0x81, 0);
            }
        }
    }
    *(float*)(state + 0x2a0) = lbl_803E3A70;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 10, 0, otherVtbl, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    *(undefined*)(state + 0x34d) = 1;
    if ((*(uint*)(state + 0x314) & 1) != 0)
    {
        sub = *(int*)(sub + 0x40c);
        *(uint*)(state + 0x314) = *(uint*)(state + 0x314) & ~1;
        *(byte*)(sub + 8) = *(byte*)(sub + 8) | 1;
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
    int objs;
    int other;
    uint roll;
    int otherVtbl;
    int sub;
    int i;
    int count[5];
    ObjHitsPriorityState* hitState;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    otherVtbl = -1;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->objectPairPriority = 10;
    hitState->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)(state + 0x27a) != '\0')
    {
        objs = FUN_80017b00(&i, count);
        for (; i < count[0]; i = i + 1)
        {
            other = *(int*)(objs + i * 4);
            if ((other != obj) && (*(short*)(other + 0x46) == 0x306))
            {
                otherVtbl = **(int**)(other + 0x68);
                (**(code**)(otherVtbl + 0x24))(other, 0x81, 0);
            }
        }
        roll = randomGetRange(0, 1);
        if (roll == 0)
        {
            if (*(char*)(state + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             obj, 7, 0, otherVtbl, param_13, param_14, param_15, param_16);
                *(undefined*)(state + 0x346) = 0;
            }
        }
        else if (*(char*)(state + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         obj, 6, 0, otherVtbl, param_13, param_14, param_15, param_16);
            *(undefined*)(state + 0x346) = 0;
        }
        *(undefined*)(state + 0x34d) = 1;
        *(float*)(state + 0x2a0) =
            lbl_803E3A74 +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(sub + 0x406)) - DOUBLE_803e3a58) /
            lbl_803E3A78;
    }
    *(float*)(state + 0x280) = lbl_803E3A60;
    return 0;
}

#pragma scheduling off
#pragma peephole off
void fn_8015EB6C(int obj, int p2, int p3)
{
    extern int* gBaddieControlInterface;
    extern void*Obj_GetPlayerObject(void);
    extern f32 sqrtf(f32);
    extern f32 timeDelta;
    extern f32 lbl_803E2DEC;
    extern f32 lbl_803E2E00;
    int sub = *(int*)(p2 + 0x40c);
    char* r;

    r = (char*)(**(int (**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
        obj, p3, (f32)(u32) * (u16*)(p2 + 0x3fe), 0x8000);

    if (r != NULL && (*(u8*)(p2 + 0x404) & 0x4) == 0)
    {
        int v = -1;
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x28))(
            obj, p3, p2 + 0x35c, (s32) * (s16*)(p2 + 0x3f4), 0, 0, 0, 8, v);
        *(int*)(p3 + 0x2d0) = (int)r;
        *(u8*)(p3 + 0x349) = 0;
        *(s16*)(p2 + 0x402) = 1;
    }
    else
    {
        void* player = Obj_GetPlayerObject();
        f32 dist;
        struct
        {
            f32 x, y, z;
        } d;
        f32* dp = &d.x;
        if (player != NULL)
        {
            d.x = *(f32*)((int)player + 0x18) - ((GameObject*)obj)->anim.worldPosX;
            d.y = *(f32*)((int)player + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
            d.z = *(f32*)((int)player + 0x20) - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
        }
        else
        {
            dist = lbl_803E2DEC;
        }
        if (*(f32*)(sub + 0) > *(f32*)(sub + 4))
        {
            if (dist < lbl_803E2E00)
            {
                Sfx_PlayFromObject(obj, SFXfoxcom_gogetit);
                *(f32*)(sub + 4) += (f32)(s32)
                randomGetRange(50, 250);
            }
        }
        *(f32*)(sub + 0) += timeDelta;
    }
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_8015ec98(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, int state,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int unaff_r29;
    int sub;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (*(char*)(state + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 0xe, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(state + 0x346) = 0;
    }
    if (lbl_803E3A7C < ((GameObject*)obj)->anim.currentMoveProgress)
    {
        unaff_r29 = *(int*)(sub + 0x40c);
        *(byte*)(unaff_r29 + 8) = *(byte*)(unaff_r29 + 8) | 2;
    }
    if (*(char*)(state + 0x27a) != '\0')
    {
        ObjHits_DisableObject(obj);
        *(float*)(state + 0x2a0) = lbl_803E3A70;
        *(float*)(state + 0x280) = lbl_803E3A60;
    }
    if (*(char*)(state + 0x346) != '\0')
    {
        FUN_80017698((int)*(short*)(sub + 0x3f4), 0);
        FUN_800305f8((double)lbl_803E3A60, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     obj, 8, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined4*)(state + 0x2d0) = 0;
        *(undefined*)(state + 0x25f) = 0;
        *(undefined*)(state + 0x349) = 0;
        *(undefined2*)(sub + 0x402) = 0;
        if ((*(byte*)(unaff_r29 + 9) & 2) == 0)
        {
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.
                resetHitboxMode | 8;
        }
    }
    return 0;
}

#pragma scheduling off
#pragma peephole off
void fn_8015ED1C(int p1, int p2, int p3)
{
    extern int* gBaddieControlInterface;
    extern void*Obj_GetPlayerObject(void);
    extern f32 sqrtf(f32);
    extern u8 lbl_8031FEA8[];
    extern u8 lbl_8031FF20[];
    extern u8 lbl_803AC580[];
    void* player;
    char* t;
    int r;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    player = Obj_GetPlayerObject();
    t = *(char**)(p3 + 0x2d0);
    if (t != NULL)
    {
        d.x = *(f32*)(t + 0x18) - ((GameObject*)p1)->anim.worldPosX;
        d.y = *(f32*)(t + 0x1c) - ((GameObject*)p1)->anim.worldPosY;
        d.z = *(f32*)(t + 0x20) - ((GameObject*)p1)->anim.worldPosZ;
        *(f32*)(p3 + 0x2c0) = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }

    if ((*(u8*)(p2 + 0x404) & 0x20) == 0)
    {
        (**(void (**)(int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x3c))(
            p1, p3, p2 + 0x400, 2, 3, (s32) * (s16*)(p2 + 0x3fa), (s32) * (s16*)(p2 + 0x3fc));
    }

    (**(void (**)(int, int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x54))(
        p1, p3, p2 + 0x35c, (s32) * (s16*)(p2 + 0x3f4), 0, 0, 0, 8);

    r = (int)
    (**(int (**)(int, int, int, int, u8*, u8*, int, u8*))((char*)(*gBaddieControlInterface) + 0x50))(
        p1, p3, p2 + 0x35c, (s32) * (s16*)(p2 + 0x3f4), lbl_8031FEA8, lbl_8031FF20, 1, lbl_803AC580);

    if (r != 0)
    {
        void* pc8 = ((GameObject*)player)->childObjs[0];
        (*(void (**)(void*))(**(int**)((char*)pc8 + 0x68) + 0x50))(pc8);
    }
}

void dll_CE_func0B(int obj, int v)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern int* gPlayerInterface;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    GroundBaddieState* sub2 = (GroundBaddieState*)(int)sub;

    switch ((u8)v)
    {
    case 0x80:
        *(u8*)(*(int*)&sub->control + 9) |= 2;
        Sfx_PlayFromObject(obj, SFXfoxcom_flame);
        (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, (int)sub2, 1);
        sub2->baddie.substate = 4;
        *(s8*)&sub2->baddie.moveJustStartedB = 1;
        break;
    case 0x81:
        sub->configFlags &= ~4;
        break;
    }
}

void dll_CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    extern void fn_8003B5E0(int, int, int, int);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2E10;
    GroundBaddieState* sub = ((GameObject*)p1)->extra;
    f32 t;

    if (visible == 0 || ((GameObject*)p1)->unkF4 != 0 || sub->targetState == 0)
    {
        return;
    }
    t = sub->unk3E8;
    if (t != lbl_803E2DC8)
    {
        fn_8003B5E0(200, 0, 0, (int)t);
    }
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5,
                                                                   lbl_803E2E10);
}

void dll_CE_init(int obj, u8* p, int flags)
{
    extern int randomGetRange(int min, int max);
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2E14;
    GroundBaddieState* sub;
    u8 mode;
    f32* v;

    sub = ((GameObject*)obj)->extra;
    mode = 6;
    if (flags != 0)
    {
        mode |= 1;
    }
    if ((*(u8*)(p + 0x2b) & 0x20) == 0)
    {
        mode |= 8;
    }
    (*(void (**)(int, u8*, int, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, p, (int)sub, 7, 6, 0x102, mode, lbl_803E2E14);
    ((GameObject*)obj)->animEventCallback = NULL;
    v = *(f32**)&sub->control;
    *v = (f32)(int)
    randomGetRange(10, 300);
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, (int)sub, 0);
    sub->baddie.substate = 0;
    *(s8*)&sub->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
}

void dll_CE_update(int obj, int p2, int p3)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void fn_8015ED1C(int p1, int p2, int p3);
    extern void fn_8015EB6C(int obj, int p2, int p3);
    extern void fn_8015EA48(int obj, u8* p);
    extern int* gBaddieControlInterface;
    extern MapEventInterface** gMapEventInterface;
    extern int* gPlayerInterface;
    extern void* lbl_803AC5B0[];
    extern void* lbl_803AC598[];
    extern f32 timeDelta;
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2E14;
    extern f32 lbl_803E2E18;
    GroundBaddieState* sub;
    int setup;
    u8* hit;
    int n;
    f32 sunTime;

    sub = ((GameObject*)obj)->extra;
    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((sub->baddie.substate != 3 || (sub->configFlags & 1) != 0) &&
            (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
        {
            (*(void (**)(int, int, int, int, int, int, int, f32))(*(int*)gBaddieControlInterface +
                0x58))(
                obj, setup, (int)sub, 7, 6, 0x102, 0x26, lbl_803E2E14);
            sub->targetState = 0;
            Sfx_PlayFromObject(obj, SFXfoxcom_find);
            ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0x10);
            *(s8*)&sub->baddie.moveDone = 0;
            ((GameObject*)obj)->anim.alpha = 0xff;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
    }
    else if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        (*gObjectTriggerInterface)->runSequence(*(s8*)(setup + 0x2e), (void*)obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
    }
    else
    {
        if ((*(int (**)(int, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, (int)sub, 0) == 0)
        {
            sub->targetState = 0;
        }
        else if ((sub->configFlags & 0x10) != 0 &&
            (*gSkyInterface)->getSunPosition(&sunTime) == 0)
        {
            sub->targetState = 0;
        }
        else
        {
            fn_8015ED1C(obj, (int)sub, (int)sub);
            if (sub->targetState == 0)
            {
                fn_8015EB6C(obj, (int)sub, (int)sub);
            }
            else
            {
                hit = *(u8**)&sub->control;
                if ((hit[8] & 1) != 0)
                {
                    fn_8015EA48(obj, (u8*)sub);
                }
                if ((hit[8] & 2) != 0)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x345, NULL, 1, -1, NULL);
                }
                if ((hit[8] & 4) != 0)
                {
                    n = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x343, NULL, 1, -1, NULL);
                        n++;
                    }
                    while (n < 10);
                }
                hit[8] = 0;
                (*(void (**)(int, int, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(
                    obj, (int)sub, lbl_803E2DC8, -1);
                (*(void (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, (int)sub, timeDelta,
                    4);
                sub->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
                *(int*)&((GameObject*)obj)->pendingParentObj = 0;
                (*(void (**)(int, int, f32, f32, void*, void*))(*(int*)gPlayerInterface + 8))(
                    obj, (int)sub, timeDelta, timeDelta, lbl_803AC5B0, lbl_803AC598);
                *(int*)&((GameObject*)obj)->pendingParentObj = sub->savedObjC0;
            }
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY - lbl_803E2E18;
        }
    }
}

#pragma dont_inline on
void fn_8015FBEC(int obj);
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

void fn_8015FCCC(int obj);

extern int Obj_GetPlayerObject(void);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;


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
    float zero;
    int sub;
    undefined8 result;

    sub = *(int*)&((GameObject*)obj)->extra;
    if (*(int*)(state + 0x2d0) == 0)
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 0);
        *(undefined*)(state + 0x346) = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd70c + 0x14))(obj, state, 1);
        zero = lbl_803E3B00;
        *(float*)(state + 0x290) = lbl_803E3B00;
        *(float*)(state + 0x28c) = zero;
        FUN_80003494(sub + 0x35c, obj + 0xc, 0xc);
        result = FUN_80003494(sub + 0x368, *(int*)(state + 0x2d0) + 0xc, 0xc);
        FUN_80006a54(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        if ((*(float*)(state + 0x2c0) < lbl_803E3B04) && (*(char*)(sub + 0x405) == '\x02'))
        {
            return 5;
        }
        if (*(char*)(sub + 0x381) == '\0')
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(sub + 0x374), (double)*(float*)(sub + 0x37c),
             (double)lbl_803E3B00, (double)lbl_803E3B00, (double)lbl_803E3B08, obj,
             state);
        }
        else
        {
            (**(code**)(*DAT_803dd70c + 0x1c))
            ((double)*(float*)(sub + 0x374), (double)*(float*)(sub + 0x37c),
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
    undefined4 child;

    child = *(undefined4*)(obj + 0xb8);
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
        ((double)lbl_803E3B24, (double)lbl_803E3B28, obj, state, child);
    *(float*)(state + 0x2a0) = lbl_803E3B2C * *(float*)(state + 0x280);
    return 0;
}

void FUN_80161130(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int obj)
{
    undefined4 sub;
    undefined8 result;

    sub = *(undefined4*)&((GameObject*)obj)->extra;
    result = ObjGroup_RemoveObject(obj, 3);
    if (*(int*)&((GameObject*)obj)->childObjs[0] != 0)
    {
        FUN_80017ac8(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     *(int*)&((GameObject*)obj)->childObjs[0]);
        *(undefined4*)&((GameObject*)obj)->childObjs[0] = 0;
    }
    (**(code**)(*DAT_803dd738 + 0x40))(obj, sub, 1);
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
    int sub;

    sub = *(int*)&((GameObject*)obj)->extra;
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
        (**(code**)(*DAT_803dd738 + 0x4c))(obj, (int)*(short*)(sub + 0x3f0), 0xffffffff, 1);
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
    undefined4 result;
    int sub;
    double mag;
    ObjHitsPriorityState* hitState;
    float aX;
    float aY;
    float aZ;
    float bX;
    float bY;
    float bZ[2];
    uint dir;

    sub = *(int*)(*(int*)&((GameObject*)obj)->extra + 0x40c);
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
    dir = *(char*)(sub + 0x45) * -2 + 1U ^ 0x80000000;
    bZ[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(sub + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(state + 0x280) *
             (f32)(s32)dir),
        *(int*)(sub + 0x38), sub + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(sub + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(sub + 0x48))
        {
            *(float*)(sub + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(sub + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(sub + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(sub + 0x48) - lbl_803E3B94), *(int*)(sub + 0x38), &aX,
     &aY, &aZ);
    (**(code**)(**(int**)(*(int*)(sub + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(sub + 0x48)), *(int*)(sub + 0x38), &bX,
     &bY, bZ);
    aX = aX - bX;
    aY = aY - bY;
    aZ = aZ - bZ[0];
    mag = FUN_80293900((double)(aX * aX + aZ * aZ));
    aX = (float)mag;
    angle = FUN_80017730();
    ((GameObject*)obj)->anim.rotY = (short)angle * ((short)((int)*(char*)(sub + 0x45) << 1) + -1);
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

void dll_CE_hitDetect_nop(void)
{
}

void dll_CE_release_nop(void)
{
}

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

int dll_CE_getExtraSize_ret_1052(void) { return 0x41c; }
int dll_CE_getObjectTypeId(void) { return 0x49; }
int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

s16 dll_CE_setScale(int* obj) { return *(s16*)((char*)((int**)obj)[0xb8 / 4] + 0x274); }
s16 dll_CB_setScale(int* obj);

extern void objRenderFn_8003b8f4(f32);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj);

#pragma peephole off
int fn_8015E00C(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1) return 3;
    if ((s8)obj[0x346] != 0) return 6;
    return 0;
}

extern void GameBit_Set(int eventId, int value);

extern undefined4* gBaddieControlInterface;

extern undefined4* gPlayerInterface;

extern f32 lbl_803E2DC8;

#pragma scheduling off
int fn_8015DE50(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
        {
            f32* p = *(f32**)&sub->control;
            fz = lbl_803E2DC8;
            p[0] = fz;
            p[1] = fz;
        }
    }
    return 0;
}

int fn_8015DEB4(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub;
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        sub = ((GameObject*)obj)->extra;
        sub->unk405 = 0;
        if (sub->gameBitB != -1)
        {
            GameBit_Set(sub->gameBitB, 0);
        }
        if (sub->gameBitA != -1)
        {
            GameBit_Set(sub->gameBitA, 1);
        }
    }
    return 0;
}

int fn_8015E044(int* obj, GroundBaddieState* state)
{
    if (*(int**)&state->baddie.targetObj != NULL)
    {
        if ((s8)state->baddie.moveJustStartedB != 0)
        {
            f32 fz = lbl_803E2DC8;
            state->baddie.animSpeedB = fz;
            state->baddie.animSpeedA = fz;
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        }
        if ((s8)state->baddie.moveDone != 0)
        {
            return 6;
        }
    }
    return 0;
}

extern f32 lbl_803E2DD8;

int fn_8015E520(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    state->baddie.moveSpeed = lbl_803E2DD8;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2DC8, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.unk34D = 1;
    return 0;
}


extern void* lbl_803AC5B0[];
extern void* lbl_803AC598[];

void dll_CE_initialise(void)
{
    lbl_803AC5B0[0] = (void*)fn_8015E8BC;
    lbl_803AC5B0[1] = (void*)fn_8015E798;
    lbl_803AC5B0[2] = (void*)fn_8015E5DC;
    lbl_803AC5B0[3] = (void*)fn_8015E520;
    lbl_803AC5B0[4] = (void*)fn_8015E3A0;
    lbl_803AC5B0[5] = (void*)fn_8015E210;
    lbl_803AC5B0[6] = (void*)fn_8015E0C8;
    lbl_803AC598[0] = (void*)fn_8015E044;
    lbl_803AC598[1] = (void*)fn_8015E00C;
    lbl_803AC598[2] = (void*)fn_8015DF20;
    lbl_803AC598[3] = (void*)fn_8015DEB4;
    lbl_803AC598[4] = (void*)fn_8015DE50;
    lbl_803AC598[5] = (void*)fn_8015DC04;
}


void dll_CE_free(int* obj)
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
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int*)state, 32);
}

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
