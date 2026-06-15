#include "main/game_object.h"
#include "main/dll/grimble_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/barrel.h"
#include "main/dll/scarab.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"

extern undefined4 FUN_80006824();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800305f8();
extern void* ObjGroup_GetObjects();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3b70;
extern f64 DOUBLE_803e3ba8;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B88;
extern f32 lbl_803E3B8C;
extern f32 lbl_803E3B90;
extern f32 lbl_803E3B94;
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
extern f32 lbl_803E3BA0;
extern f32 lbl_803E3BA4;
extern f32 lbl_803E3BB0;
extern f32 lbl_803E3BB4;

extern void objRenderFn_8003b8f4(f32);
extern void* gGrimbleStateHandlersA[11];
extern void* gGrimbleStateHandlersB[6];
int grimble_animEventCallback(void);







extern f32 lbl_803E2F30;
extern uint GameBit_Get(int eventId);
extern undefined4 ObjHits_DisableObject();
extern void getTrickyObject(void);
extern void* ObjList_FindObjectById(int id);
extern f32 timeDelta;
extern f32 lbl_803E2F34;
extern f32 lbl_803E2F38;
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);

undefined4
FUN_801620c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int randVal;
    undefined4 result;
    int model;
    double dist;
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];

    model = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(model + 0x48) - lbl_803E3B94), *(int*)(model + 0x38), &p0x,
     &p0y, &p0z);
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(model + 0x48)), *(int*)(model + 0x38), &p1x,
     &p1y, p1z);
    p0x = p0x - p1x;
    p0y = p0y - p1y;
    p0z = p0z - p1z[0];
    dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
    p0x = (float)dist;
    randVal = FUN_80017730();
    *(short*)(param_9 + 2) = (short)randVal * ((short)((int)*(char*)(model + 0x45) << 1) + -1);
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        result = 0;
    }
    else
    {
        result = 6;
    }
    return result;
}

undefined4
FUN_80162450(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float speed;
    uint cntlz;
    int randVal;
    undefined4 result;
    int model;
    double dist;
    ushort hitInfo;
    u8 hitPad[2];
    ushort hitType[2];
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];
    uint dir;
    undefined8 tmp;

    model = *(int*)(*(int*)(param_9 + 0x5c) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 3, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 9);
    dir = *(char*)(model + 0x45) * -2 + 1U ^ 0x80000000;
    p1z[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)dir),
        *(int*)(model + 0x38), model + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(model + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(model + 0x48))
        {
            *(float*)(model + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(model + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(model + 0x48) - lbl_803E3B94), *(int*)(model + 0x38), &p0x,
     &p0y, &p0z);
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(model + 0x48)), *(int*)(model + 0x38), &p1x,
     &p1y, p1z);
    p0x = p0x - p1x;
    p0y = p0y - p1y;
    p0z = p0z - p1z[0];
    dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
    p0x = (float)dist;
    randVal = FUN_80017730();
    dir = (int)(short)((short)randVal * ((short)((int)*(char*)(model + 0x45) << 1) + -1)) ^
        0x80000000;
    p1z[1] = 176.0;
    randVal = (int)
    (-(lbl_803E3B98 * *(float*)(param_9 + 0x4c) - lbl_803E3B54) *
        (f32)(s32)
    dir
    )
    ;
    tmp = (double)(longlong)randVal;
    param_9[1] = (short)randVal;
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        result = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd738 + 0x14))
            (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, hitType, hitPad, &hitInfo);
        *(char*)(model + 0x45) = '\x01' - *(char*)(model + 0x45);
        cntlz = countLeadingZeros((int)*(char*)(model + 0x45));
        *param_9 = *(short*)(model + 0x58) + (short)((cntlz >> 5) << 0xf);
        cntlz = randomGetRange(0x32, 100);
        speed = (float)((double)CONCAT44(0x43300000, *(char*)(model + 0x45) * 2 - 1U ^ 0x80000000) -
            DOUBLE_803e3b70) * ((f32)(s32)(cntlz) / lbl_803E3B9C);
        if ((hitType[0] < 4) || (0xb < hitType[0]))
        {
            cntlz = (uint)hitInfo;
            if (cntlz < 0x1f5)
            {
                tmp = (double)CONCAT44(0x43300000, cntlz);
                speed = speed * (lbl_803E3B54 + (float)(tmp - DOUBLE_803e3ba8) / lbl_803E3BA0);
            }
            else
            {
                tmp = (double)CONCAT44(0x43300000, cntlz);
                speed = speed * (lbl_803E3B54 + (float)(tmp - DOUBLE_803e3ba8) / lbl_803E3B9C);
            }
        }
        *(float*)(model + 0x54) = *(float*)(model + 0x48) - speed;
        speed = lbl_803E3B54;
        if (lbl_803E3B54 < *(float*)(model + 0x54))
        {
            speed = *(float*)(model + 0x54);
        }
        *(float*)(model + 0x54) = speed;
        speed = lbl_803E3BA4;
        if (*(float*)(model + 0x54) < lbl_803E3BA4)
        {
            speed = *(float*)(model + 0x54);
        }
        *(float*)(model + 0x54) = speed;
        result = 4;
    }
    return result;
}

undefined4
FUN_801628c4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    bool clamped;
    undefined4 result;
    int randVal;
    int model;
    double dist;
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];
    uint dir;

    model = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 0);
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        FUN_80006824(param_9, SFXsc_death01);
    }
    dir = *(char*)(model + 0x45) * -2 + 1U ^ 0x80000000;
    p1z[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x28))
        ((double)(lbl_803E3BB0 *
             *(float*)(param_10 + 0x2a0) *
             (f32)(s32)dir),
        *(int*)(model + 0x38), model + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(model + 0x48))
    {
        if (*(float*)(model + 0x48) <= lbl_803E3B90)
        {
            clamped = false;
        }
        else
        {
            *(float*)(model + 0x48) = lbl_803E3B90;
            clamped = true;
        }
    }
    else
    {
        *(float*)(model + 0x48) = lbl_803E3B8C;
        clamped = true;
    }
    if (clamped)
    {
        result = 7;
    }
    else
    {
        (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
        ((double)(*(float*)(model + 0x48) - lbl_803E3B94), *(int*)(model + 0x38), &p0x,
         &p0y, &p0z);
        (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
        ((double)(lbl_803E3B94 + *(float*)(model + 0x48)), *(int*)(model + 0x38), &p1x,
         &p1y, p1z);
        p0x = p0x - p1x;
        p0y = p0y - p1y;
        p0z = p0z - p1z[0];
        dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
        p0x = (float)dist;
        randVal = FUN_80017730();
        *(short*)(param_9 + 2) = (short)randVal * ((short)((int)*(char*)(model + 0x45) << 1) + -1);
        result = 0;
    }
    return result;
}

undefined4
FUN_80162b78(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 result;
    int randVal;
    int model;
    double dist;
    ushort hitInfo;
    u8 hitPad[2];
    ushort hitType[2];
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];
    uint dir;

    model = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    dir = *(char*)(model + 0x45) * -2 + 1U ^ 0x80000000;
    p1z[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)dir),
        *(int*)(model + 0x38), model + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(model + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(model + 0x48))
        {
            *(float*)(model + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(model + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(*DAT_803dd738 + 0x14))
        (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, hitType, hitPad, &hitInfo);
    if ((((hitType[0] < 4) || (0xb < hitType[0])) || (hitInfo < 0x191)) ||
        ((*(float*)(model + 0x48) <= lbl_803E3B98 || (lbl_803E3BB4 <= *(float*)(model + 0x48)))))
    {
        if (((int)*(char*)(model + 0x45) ==
            ((uint)(byte)((*(float*)(model + 0x54) <= *(float*)(model + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char*)(param_10 + 0x346) == '\0'))
        {
            if ((*(uint*)(param_10 + 0x314) & 1) != 0)
            {
                *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
                FUN_80006824(param_9, SFXsc_death01);
            }
            (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
            ((double)(*(float*)(model + 0x48) - lbl_803E3B94), *(int*)(model + 0x38),
             &p0x, &p0y, &p0z);
            (**(code**)(**(int**)(*(int*)(model + 0x38) + 0x68) + 0x24))
            ((double)(lbl_803E3B94 + *(float*)(model + 0x48)), *(int*)(model + 0x38),
             &p1x, &p1y, p1z);
            p0x = p0x - p1x;
            p0y = p0y - p1y;
            p0z = p0z - p1z[0];
            dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
            p0x = (float)dist;
            randVal = FUN_80017730();
            *(short*)(param_9 + 2) = (short)randVal * ((short)((int)*(char*)(model + 0x45) << 1) + -1);
            result = 0;
        }
        else
        {
            result = 3;
        }
    }
    else
    {
        result = 3;
    }
    return result;
}


void cannonclaw_free(void)
{
}

void cannonclaw_hitDetect(void)
{
}

int cannonclaw_getExtraSize(void) { return 0x0; }
int cannonclaw_getObjectTypeId(void) { return 0x0; }

#pragma dont_inline on
#pragma scheduling off
void grimble_initialiseStateHandlerTables(void)
{
    gGrimbleStateHandlersA[0] = (void*)grimble_stateHandlerA00;
    gGrimbleStateHandlersA[1] = (void*)grimble_stateHandlerA01;
    gGrimbleStateHandlersA[2] = (void*)grimble_stateHandlerA02;
    gGrimbleStateHandlersA[3] = (void*)grimble_stateHandlerA03;
    gGrimbleStateHandlersA[4] = (void*)grimble_stateHandlerA04;
    gGrimbleStateHandlersA[5] = (void*)grimble_stateHandlerA05;
    gGrimbleStateHandlersA[6] = (void*)grimble_stateHandlerA06;
    gGrimbleStateHandlersA[7] = (void*)grimble_stateHandlerA07;
    gGrimbleStateHandlersA[8] = (void*)grimble_stateHandlerA08;
    gGrimbleStateHandlersA[9] = (void*)grimble_stateHandlerA09;
    gGrimbleStateHandlersB[0] = (void*)grimble_stateHandlerB00;
    gGrimbleStateHandlersB[1] = (void*)grimble_stateHandlerB01;
    gGrimbleStateHandlersB[2] = (void*)scarab_updateProximityGate;
    gGrimbleStateHandlersB[3] = (void*)grimble_stateHandlerB03;
    gGrimbleStateHandlersB[4] = (void*)grimble_stateHandlerB04;
    gGrimbleStateHandlersB[5] = (void*)grimble_stateHandlerB05;
}
#pragma dont_inline reset



#pragma peephole off
void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E2F30);
            break;
        default:
            break;
        }
    }
}

ObjectDescriptor gGrimbleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)grimble_initialise,
    (ObjectDescriptorCallback)grimble_release,
    0,
    (ObjectDescriptorCallback)grimble_init,
    (ObjectDescriptorCallback)grimble_update,
    (ObjectDescriptorCallback)grimble_hitDetect,
    (ObjectDescriptorCallback)grimble_render,
    (ObjectDescriptorCallback)grimble_free,
    (ObjectDescriptorCallback)grimble_getObjectTypeId,
    grimble_getExtraSize,
};

/* segment pragma-stack balance (re-split): */

/* Actual cannonclaw_update is 188b -- trigger-once cannon-arm awakener.
 * The 668b "Ghidra body" was misattributed; replaced with the right one. */

void cannonclaw_update(u8* obj)
{
    u8* trickyState;
    getTrickyObject();
    trickyState = (u8*)ObjList_FindObjectById(0x1723);
    if (((GameObject*)obj)->unkF4 != 0) return;
    if (((GameObject*)obj)->anim.currentMove != 0x208)
    {
        ObjAnim_SetCurrentMove((int)obj, 0x208, lbl_803E2F34, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E2F38, timeDelta, NULL);
    if (trickyState == NULL) return;
    if (GameBit_Get(*(s16*)(*(u8**)(trickyState + 0x4c) + 0x1a)) == 0) return;
    ((GameObject*)obj)->unkF4 = 1;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 0x8);
    ObjHits_DisableObject(obj);
}

void cannonclaw_release(void)
{
}

void cannonclaw_initialise(void)
{
}

void tumbleweedbush_free(void);

void tumbleweedbush_hitDetect(void);

void tumbleweedbush_release(void);

void tumbleweedbush_initialise(void);

void tumbleweedbush_init(u8* obj, u8* params, int param3);

int tumbleweedbush_getExtraSize(void);
int tumbleweedbush_getObjectTypeId(void);

void tumbleweedbush_update(int* obj);

void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void cannonclaw_init(s16* dst, void* src)
{
    s8 v = *((s8*)src + 0x28);
    s16 t = v << 8;
    *dst = t;
}

/* tumbleweedbush_findNearestActive: scan all type-0x31 objects, pick the closest one whose
 * obj->_46 == 0x3fb and obj->_b8->_278 > 1 (by vec3f_distanceSquared from
 * the supplied position vector). Returns NULL if no match. */
extern void* ObjGroup_GetObjects(int type, int* outCount);

void* tumbleweedbush_findNearestActive(f32* p_pos);

/* tumbleweedbush_setScale: scan the sub-array at obj->_b8 (sub[0x50] entries
 * of 4 bytes each), zeroing every slot whose +0xc word matches `match`. */
void tumbleweedbush_setScale(u8* obj, void* match);

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)tumbleweedbush_initialise,
        (ObjectDescriptorCallback)tumbleweedbush_release,
        0,
        (ObjectDescriptorCallback)tumbleweedbush_init,
        (ObjectDescriptorCallback)tumbleweedbush_update,
        (ObjectDescriptorCallback)tumbleweedbush_hitDetect,
        (ObjectDescriptorCallback)tumbleweedbush_render,
        (ObjectDescriptorCallback)tumbleweedbush_free,
        (ObjectDescriptorCallback)tumbleweedbush_getObjectTypeId,
        tumbleweedbush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_setScale,
    },
    0,
};
