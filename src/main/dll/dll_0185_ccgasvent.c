#include "main/dll/DIM/dimlogfire.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"











extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803ad590;
extern undefined4 DAT_803ad598;
extern undefined4 DAT_803ad59c;
extern undefined4 DAT_803ad5a0;
extern undefined4 DAT_803ad5a4;
extern EffectInterface** gPartfxInterface;
extern f32 lbl_803DC074;
extern f32 lbl_803E5248;
extern f32 lbl_803E524C;

/*
 * --INFO--
 *
 * Function: FUN_801a8f88
 * EN v1.0 Address: 0x801A8F88
 * EN v1.0 Size: 836b
 * EN v1.1 Address: 0x801A9044
 * EN v1.1 Size: 944b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801a8f88(void)
{
    int iVar1;
    uint uVar2;
    short* psVar3;

    iVar1 = FUN_80286840();
    psVar3 = *(short**)(iVar1 + 0xb8);
    if (((int)*psVar3 == 0xffffffff) || (uVar2 = GameBit_Get((int)*psVar3), uVar2 != 0))
    {
        *(float*)(psVar3 + 0x14) = *(float*)(psVar3 + 0x14) - lbl_803DC074;
        if (*(float*)(psVar3 + 0x14) < lbl_803E5248)
        {
            *(float*)(psVar3 + 0xc) = lbl_803E524C;
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[1], (uint)(ushort)psVar3[1]);
            *(float*)(psVar3 + 0xe) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[3], (uint)(ushort)psVar3[3]);
            *(float*)(psVar3 + 0x10) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(-(uint)(ushort)psVar3[2], (uint)(ushort)psVar3[2]);
            *(float*)(psVar3 + 0x12) =
                (f32)(s32)(uVar2);
            FUN_80017748((ushort*)(psVar3 + 4), (float*)(psVar3 + 0xe));
            *(float*)(psVar3 + 0xe) = *(float*)(psVar3 + 0xe) + *(float*)(iVar1 + 0xc);
            *(float*)(psVar3 + 0x10) = *(float*)(psVar3 + 0x10) + *(float*)(iVar1 + 0x10);
            *(float*)(psVar3 + 0x12) = *(float*)(psVar3 + 0x12) + *(float*)(iVar1 + 0x14);
            uVar2 = randomGetRange(100, 200);
            *(float*)(psVar3 + 0x14) =
                (f32)(s32)(uVar2);
            uVar2 = randomGetRange(0x32, 100);
            *(float*)(psVar3 + 0x16) =
                (f32)(s32)(uVar2);
        }
        *(float*)(psVar3 + 0x16) = *(float*)(psVar3 + 0x16) - lbl_803DC074;
        if (lbl_803E5248 < *(float*)(psVar3 + 0x16))
        {
            (*gPartfxInterface)->spawnObject((void*)iVar1, 0x71f, psVar3 + 8, 0x200001, -1, NULL);
        }
        DAT_803ad598 = lbl_803E524C;
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[1], (uint)(ushort)psVar3[1]);
        DAT_803ad59c = (f32)(s32)(uVar2);
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[3], (uint)(ushort)psVar3[3]);
        DAT_803ad5a0 = (f32)(s32)(uVar2);
        uVar2 = randomGetRange(-(uint)(ushort)psVar3[2], (uint)(ushort)psVar3[2]);
        DAT_803ad5a4 = (f32)(s32)(uVar2);
        FUN_80017748((ushort*)(psVar3 + 4), &DAT_803ad59c);
        DAT_803ad59c = DAT_803ad59c + *(float*)(iVar1 + 0xc);
        DAT_803ad5a0 = DAT_803ad5a0 + *(float*)(iVar1 + 0x10);
        DAT_803ad5a4 = DAT_803ad5a4 + *(float*)(iVar1 + 0x14);
        (*gPartfxInterface)->spawnObject((void*)iVar1, 0x720, &DAT_803ad590, 0x200001, -1, NULL);
    }
    FUN_8028688c();
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801a9408
 * EN v1.0 Address: 0x801A9408
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x801A953C
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801a9408(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9,
             ObjAnimUpdateState* animUpdate)
{
    byte bVar1;
    undefined2* puVar2;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int iVar3;
    int iVar4;
    undefined8 uVar5;

    for (iVar3 = 0; iVar3 < (int)(uint)animUpdate->eventCount; iVar3 = iVar3 + 1)
    {
        bVar1 = animUpdate->eventIds[iVar3];
        if (bVar1 == 2)
        {
            iVar4 = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (iVar4 != 0)
            {
                uVar5 = ObjLink_DetachChild(param_9, iVar4);
                param_1 = FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
            }
            *(undefined4*)(param_9 + 0xf8) = 0xffffffff;
        }
        else if ((bVar1 < 2) && (bVar1 != 0))
        {
            *(undefined4*)(param_9 + 0xf8) = 0x30b;
            iVar4 = *(int*)&((GameObject*)param_9)->childObjs[0];
            if (iVar4 != 0)
            {
                uVar5 = ObjLink_DetachChild(param_9, iVar4);
                param_1 = FUN_80017ac8(uVar5, param_2, param_3, param_4, param_5, param_6, param_7, param_8, iVar4);
            }
            puVar2 = FUN_80017aa4(0x20, (short)*(undefined4*)(param_9 + 0xf8));
            iVar4 = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, puVar2, 4,
                                 ((GameObject*)param_9)->anim.mapEventSlot, 0xffffffff,
                                 *(uint**)&((GameObject*)param_9)->anim.parent,
                                 in_r8, in_r9, in_r10);
            param_1 = ObjLink_AttachChild(param_9, iVar4, 0);
        }
    }
    return 0;
}


/* Trivial 4b 0-arg blr leaves. */
void animsharpclaw_hitDetect(void);







#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
void ccgasvent_render(void)
{
}

/* 8b "li r3, N; blr" returners. */
int animsharpclaw_getExtraSize(void);
int ccgasvent_getExtraSize(void) { return 0x1; }
int ccgasventcontrol_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
#pragma peephole off

#pragma peephole reset

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
void ccgasvent_free(int x) { ObjGroup_RemoveObject(x, 0x3f); }
#pragma scheduling reset

/* call(x, N) wrappers. */
#pragma scheduling off
void ccgasvent_init(int x) { ObjGroup_AddObject(x, 0x3f); }
#pragma scheduling reset

/* MoonSeedPlantingSpot_SeqFn: leaf flag-set on obj's extra struct, returns 0. */
extern void disableHeavyFog(void);
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MoonSeedPlantingSpot_SeqFn(int obj);
#pragma peephole reset
#pragma scheduling reset

/* CCGasVentControl_SeqFn: trampoline to CCGasVentControlFn_801a9fd0 passing (obj, obj->extra), returns 0. */
#pragma scheduling off
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma scheduling reset

extern f32 lbl_803E4610;
extern f32 lbl_803E4614;

#pragma scheduling off
#pragma peephole off
void ccgasvent_update(int* obj)
{
    f32 dist = lbl_803E4610;
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x1c0) != 0)
    {
        ObjGroup_FindNearestObject(5, (uint)obj, &dist);
        switch (state[0])
        {
        case 0:
            if (dist >= lbl_803E4614)
            {
                state[0] = 1;
            }
            break;
        case 1:
            if (dist < lbl_803E4614)
            {
                state[0] = 0;
            }
            else
            {
                (*gPartfxInterface)->spawnObject(obj, 0x3df, NULL, 0, -1, NULL);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int MoonSeedPlantingSpot_setScale(int* obj, int arg);
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
