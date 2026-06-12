#include "main/game_object.h"
#include "main/dll/grimble_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/barrel.h"
#include "main/dll/scarab.h"
#include "main/mapEventTypes.h"





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

/*
 * --INFO--
 *
 * Function: grimble_stateHandlerA02
 * EN v1.0 Address: 0x80161F0C
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x80161FA4
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void objRenderFn_8003b8f4(f32);
extern void* gGrimbleStateHandlersA[11];
extern void* gGrimbleStateHandlersB[6];
int grimble_animEventCallback(void);


#pragma scheduling off
#pragma peephole off
int grimble_stateHandlerA02(int obj, char* state, f32 arg);

int grimble_stateHandlerA01(int obj, char* state, f32 arg);

int grimble_stateHandlerA00(int obj, char* state, f32 arg);


void grimble_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void grimble_update(int obj);

void grimble_init(int obj, int p2, int p3);

/*
 * --INFO--
 *
 * Function: FUN_801620c0
 * EN v1.0 Address: 0x801620C0
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x801620F0
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
FUN_801620c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    undefined4 uVar2;
    int iVar3;
    double dVar4;
    float local_28;
    float local_24;
    float local_20;
    float local_1c;
    float local_18;
    float local_14[2];

    iVar3 = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(iVar3 + 0x48) - lbl_803E3B94), *(int*)(iVar3 + 0x38), &local_28,
     &local_24, &local_20);
    (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(iVar3 + 0x48)), *(int*)(iVar3 + 0x38), &local_1c,
     &local_18, local_14);
    local_28 = local_28 - local_1c;
    local_24 = local_24 - local_18;
    local_20 = local_20 - local_14[0];
    dVar4 = FUN_80293900((double)(local_28 * local_28 + local_20 * local_20));
    local_28 = (float)dVar4;
    iVar1 = FUN_80017730();
    *(short*)(param_9 + 2) = (short)iVar1 * ((short)((int)*(char*)(iVar3 + 0x45) << 1) + -1);
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        uVar2 = 0;
    }
    else
    {
        uVar2 = 6;
    }
    return uVar2;
}


/*
 * --INFO--
 *
 * Function: FUN_80162450
 * EN v1.0 Address: 0x80162450
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x801623B8
 * EN v1.1 Size: 968b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80162450(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    uint uVar2;
    int iVar3;
    undefined4 uVar4;
    int iVar5;
    double dVar6;
    ushort local_58;
    u8 auStack_56[2];
    ushort local_54[2];
    float local_50;
    float local_4c;
    float local_48;
    float local_44;
    float local_40;
    float local_3c[2];
    uint uStack_34;
    undefined8 local_30;

    iVar5 = *(int*)(*(int*)(param_9 + 0x5c) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 3, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 9);
    uStack_34 = *(char*)(iVar5 + 0x45) * -2 + 1U ^ 0x80000000;
    local_3c[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar5 + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)uStack_34),
        *(int*)(iVar5 + 0x38), iVar5 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar5 + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(iVar5 + 0x48))
        {
            *(float*)(iVar5 + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(iVar5 + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(iVar5 + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(iVar5 + 0x48) - lbl_803E3B94), *(int*)(iVar5 + 0x38), &local_50,
     &local_4c, &local_48);
    (**(code**)(**(int**)(*(int*)(iVar5 + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(iVar5 + 0x48)), *(int*)(iVar5 + 0x38), &local_44,
     &local_40, local_3c);
    local_50 = local_50 - local_44;
    local_4c = local_4c - local_40;
    local_48 = local_48 - local_3c[0];
    dVar6 = FUN_80293900((double)(local_50 * local_50 + local_48 * local_48));
    local_50 = (float)dVar6;
    iVar3 = FUN_80017730();
    uStack_34 = (int)(short)((short)iVar3 * ((short)((int)*(char*)(iVar5 + 0x45) << 1) + -1)) ^
        0x80000000;
    local_3c[1] = 176.0;
    iVar3 = (int)
    (-(lbl_803E3B98 * *(float*)(param_9 + 0x4c) - lbl_803E3B54) *
        (f32)(s32)
    uStack_34
    )
    ;
    local_30 = (double)(longlong)iVar3;
    param_9[1] = (short)iVar3;
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        uVar4 = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd738 + 0x14))
            (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, local_54, auStack_56, &local_58);
        *(char*)(iVar5 + 0x45) = '\x01' - *(char*)(iVar5 + 0x45);
        uVar2 = countLeadingZeros((int)*(char*)(iVar5 + 0x45));
        *param_9 = *(short*)(iVar5 + 0x58) + (short)((uVar2 >> 5) << 0xf);
        uVar2 = randomGetRange(0x32, 100);
        fVar1 = (float)((double)CONCAT44(0x43300000, *(char*)(iVar5 + 0x45) * 2 - 1U ^ 0x80000000) -
            DOUBLE_803e3b70) * ((f32)(s32)(uVar2) / lbl_803E3B9C);
        if ((local_54[0] < 4) || (0xb < local_54[0]))
        {
            uVar2 = (uint)local_58;
            if (uVar2 < 0x1f5)
            {
                local_30 = (double)CONCAT44(0x43300000, uVar2);
                fVar1 = fVar1 * (lbl_803E3B54 + (float)(local_30 - DOUBLE_803e3ba8) / lbl_803E3BA0);
            }
            else
            {
                local_30 = (double)CONCAT44(0x43300000, uVar2);
                fVar1 = fVar1 * (lbl_803E3B54 + (float)(local_30 - DOUBLE_803e3ba8) / lbl_803E3B9C);
            }
        }
        *(float*)(iVar5 + 0x54) = *(float*)(iVar5 + 0x48) - fVar1;
        fVar1 = lbl_803E3B54;
        if (lbl_803E3B54 < *(float*)(iVar5 + 0x54))
        {
            fVar1 = *(float*)(iVar5 + 0x54);
        }
        *(float*)(iVar5 + 0x54) = fVar1;
        fVar1 = lbl_803E3BA4;
        if (*(float*)(iVar5 + 0x54) < lbl_803E3BA4)
        {
            fVar1 = *(float*)(iVar5 + 0x54);
        }
        *(float*)(iVar5 + 0x54) = fVar1;
        uVar4 = 4;
    }
    return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_801628c4
 * EN v1.0 Address: 0x801628C4
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x80162780
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801628c4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    bool bVar1;
    undefined4 uVar2;
    int iVar3;
    int iVar4;
    double dVar5;
    float local_48;
    float local_44;
    float local_40;
    float local_3c;
    float local_38;
    float local_34[2];
    uint uStack_2c;

    iVar4 = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
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
    uStack_2c = *(char*)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
    local_34[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x28))
        ((double)(lbl_803E3BB0 *
             *(float*)(param_10 + 0x2a0) *
             (f32)(s32)uStack_2c),
        *(int*)(iVar4 + 0x38), iVar4 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar4 + 0x48))
    {
        if (*(float*)(iVar4 + 0x48) <= lbl_803E3B90)
        {
            bVar1 = false;
        }
        else
        {
            *(float*)(iVar4 + 0x48) = lbl_803E3B90;
            bVar1 = true;
        }
    }
    else
    {
        *(float*)(iVar4 + 0x48) = lbl_803E3B8C;
        bVar1 = true;
    }
    if (bVar1)
    {
        uVar2 = 7;
    }
    else
    {
        (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x24))
        ((double)(*(float*)(iVar4 + 0x48) - lbl_803E3B94), *(int*)(iVar4 + 0x38), &local_48,
         &local_44, &local_40);
        (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x24))
        ((double)(lbl_803E3B94 + *(float*)(iVar4 + 0x48)), *(int*)(iVar4 + 0x38), &local_3c,
         &local_38, local_34);
        local_48 = local_48 - local_3c;
        local_44 = local_44 - local_38;
        local_40 = local_40 - local_34[0];
        dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
        local_48 = (float)dVar5;
        iVar3 = FUN_80017730();
        *(short*)(param_9 + 2) = (short)iVar3 * ((short)((int)*(char*)(iVar4 + 0x45) << 1) + -1);
        uVar2 = 0;
    }
    return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80162b78
 * EN v1.0 Address: 0x80162B78
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x801629C4
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80162b78(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;
    int iVar2;
    int iVar3;
    double dVar4;
    ushort local_48;
    u8 auStack_46[2];
    ushort local_44[2];
    float local_40;
    float local_3c;
    float local_38;
    float local_34;
    float local_30;
    float local_2c[2];
    uint uStack_24;

    iVar3 = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    uStack_24 = *(char*)(iVar3 + 0x45) * -2 + 1U ^ 0x80000000;
    local_2c[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)uStack_24),
        *(int*)(iVar3 + 0x38), iVar3 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar3 + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(iVar3 + 0x48))
        {
            *(float*)(iVar3 + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(iVar3 + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(*DAT_803dd738 + 0x14))
        (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, local_44, auStack_46, &local_48);
    if ((((local_44[0] < 4) || (0xb < local_44[0])) || (local_48 < 0x191)) ||
        ((*(float*)(iVar3 + 0x48) <= lbl_803E3B98 || (lbl_803E3BB4 <= *(float*)(iVar3 + 0x48)))))
    {
        if (((int)*(char*)(iVar3 + 0x45) ==
            ((uint)(byte)((*(float*)(iVar3 + 0x54) <= *(float*)(iVar3 + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char*)(param_10 + 0x346) == '\0'))
        {
            if ((*(uint*)(param_10 + 0x314) & 1) != 0)
            {
                *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
                FUN_80006824(param_9, SFXsc_death01);
            }
            (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(*(float*)(iVar3 + 0x48) - lbl_803E3B94), *(int*)(iVar3 + 0x38),
             &local_40, &local_3c, &local_38);
            (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(lbl_803E3B94 + *(float*)(iVar3 + 0x48)), *(int*)(iVar3 + 0x38),
             &local_34, &local_30, local_2c);
            local_40 = local_40 - local_34;
            local_3c = local_3c - local_30;
            local_38 = local_38 - local_2c[0];
            dVar4 = FUN_80293900((double)(local_40 * local_40 + local_38 * local_38));
            local_40 = (float)dVar4;
            iVar2 = FUN_80017730();
            *(short*)(param_9 + 2) = (short)iVar2 * ((short)((int)*(char*)(iVar3 + 0x45) << 1) + -1);
            uVar1 = 0;
        }
        else
        {
            uVar1 = 3;
        }
    }
    else
    {
        uVar1 = 3;
    }
    return uVar1;
}


/*
 * --INFO--
 *
 * Function: cannonclaw_release
 * EN v1.0 Address: 0x801631C0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80162F5C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */
void grimble_release(void);

void cannonclaw_free(void)
{
}

void cannonclaw_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int grimble_animEventCallback(void);
int grimble_getExtraSize(void);
int grimble_getObjectTypeId(void);
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
void grimble_initialise(void);

extern f32 lbl_803E2F30;

#pragma peephole off
void grimble_free(int obj);

void grimble_hitDetect(int obj);

void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        if (((GameObject*)obj)->unkF4 == 0)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E2F30);
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
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

/* === moved from main/dll/ladders.c [801630EC-801631C8) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/objanim.h"



extern uint GameBit_Get(int eventId);
extern undefined4 ObjHits_DisableObject();


/*
 * --INFO--
 *
 * Function: cannonclaw_update
 * EN v1.0 Address: 0x801630EC
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x801630F0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Actual cannonclaw_update is 188b -- trigger-once cannon-arm awakener.
 * The 668b "Ghidra body" was misattributed; replaced with the right one. */
extern void getTrickyObject(void);
extern void* ObjList_FindObjectById(int id);
extern f32 timeDelta;
extern f32 lbl_803E2F34;
extern f32 lbl_803E2F38;

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


/*
 * --INFO--
 *
 * Function: FUN_801633b0
 * EN v1.0 Address: 0x801633B0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80163554
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801638bc
 * EN v1.0 Address: 0x801638BC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801639B8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801638e4
 * EN v1.0 Address: 0x801638E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801639EC
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801638e8
 * EN v1.0 Address: 0x801638E8
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x80163B9C
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
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

/* 8b "li r3, N; blr" returners. */
int tumbleweedbush_getExtraSize(void);
int tumbleweedbush_getObjectTypeId(void);



void tumbleweedbush_update(int* obj);

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */

void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* byte-to-short shift8 pattern. */
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
extern f32 vec3f_distanceSquared(f32 * p1, f32 * p2);

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
#pragma scheduling reset
#pragma peephole reset
