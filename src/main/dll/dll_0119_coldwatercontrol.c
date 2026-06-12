#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/dll/CF/CFBaby.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern void* Obj_GetPlayerObject(void);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

extern f32 timeDelta;
extern f32 lbl_803E3B68;
extern f32 lbl_803E3B6C;
extern int fn_80295C40(int obj);
extern void Obj_FreeObject(int obj);

undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;
    char cVar2;
    int iVar3;
    int iVar4;
    int iVar5;
    int iVar6;
    int iVar7;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 uVar8;

    iVar6 = *(int*)&((GameObject*)param_9)->anim.placementData;
    iVar5 = *(int*)&((GameObject*)param_9)->extra;
    iVar7 = 0;
    iVar4 = (int)animUpdate;
    do
    {
        if ((int)(uint)animUpdate->eventCount <= iVar7)
        {
            return 0;
        }
        switch (animUpdate->eventIds[iVar7])
        {
        case 2:
        case 0x65:
            iVar4 = *(int*)(iVar6 + 0x14);
            if (iVar4 == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x26);
                FUN_80042bec(uVar1, 0);
                uVar1 = FUN_80044404(0xb);
                FUN_80042bec(uVar1, 1);
            }
            else if (iVar4 < 0x49f5a)
            {
                if (iVar4 == 0x451b9)
                {
                    cVar2 = (*gMapEventInterface)->getMode(0xd);
                    param_1 = extraout_f1;
                    if (cVar2 == '\x02')
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        iVar4 = 1;
                        FUN_80042b9c(0, 0, 1);
                        uVar1 = FUN_80044404(0xb);
                        FUN_80042bec(uVar1, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        iVar4 = 1;
                        FUN_80042b9c(0, 0, 1);
                        uVar1 = FUN_80044404(0x29);
                        FUN_80042bec(uVar1, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < iVar4) || (iVar4 != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    iVar4 = 1;
                    FUN_80042b9c(0, 0, 1);
                    uVar1 = FUN_80044404(0x29);
                    FUN_80042bec(uVar1, 0);
                }
            }
            else if (iVar4 == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x41);
                FUN_80042bec(uVar1, 0);
                uVar1 = FUN_80044404(0xb);
                FUN_80042bec(uVar1, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                uVar1 = FUN_80044404(0x29);
                FUN_80042bec(uVar1, 0);
            }
            break;
        case 3:
        case 100:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x49f5a)
            {
                iVar4 = 0;
                param_12 = (int)*gMapEventInterface;
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (iVar3 < 0x49f5a)
            {
                if (iVar3 == 0x451b9)
                {
                    cVar2 = (*gMapEventInterface)->getMode(0xd);
                    param_1 = extraout_f1_00;
                    if (cVar2 == '\x02')
                    {
                        uVar8 = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setAnimEvent(0xd, 10, 0);
                        (*gMapEventInterface)->setAnimEvent(0xd, 0xb, 0);
                        iVar4 = 0;
                        param_12 = (int)*gMapEventInterface;
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((iVar3 < 0x451b9) && (iVar3 == 0x43775))
                {
                    iVar4 = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (iVar3 == 0x4cd65)
            {
                iVar4 = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x451b9)
            {
                cVar2 = (*gMapEventInterface)->getMode(0xd);
                param_1 = extraout_f1_01;
                if (cVar2 == '\x02')
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (iVar3 < 0x451b9)
            {
                if (iVar3 == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (iVar3 == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x451b9)
            {
                cVar2 = (*gMapEventInterface)->getMode(0xd);
                param_1 = extraout_f1_02;
                if (cVar2 == '\x02')
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (iVar3 < 0x451b9)
            {
                if (iVar3 == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (iVar3 == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            iVar3 = *(int*)(iVar6 + 0x14);
            if (iVar3 == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', iVar4, param_12, param_13, param_14, param_15, param_16);
            }
            else if (iVar3 < 0x49f5a)
            {
                if ((iVar3 == 0x451b9) &&
                    (cVar2 = (*gMapEventInterface)->getMode(0xd), param_1 = extraout_f1_03,
                        cVar2 == '\x02'))
                {
                    iVar4 = (int)*gMapEventInterface;
                    uVar8 = (**(code**)(iVar4 + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', iVar4, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (iVar3 == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', iVar4
                             , param_12, param_13, param_14, param_15, param_16);
                iVar4 = (int)*gMapEventInterface;
                param_1 = (**(code**)(iVar4 + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(iVar5 + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(iVar5 + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(iVar5 + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(iVar5 + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(iVar5 + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(iVar5 + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(iVar5 + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(iVar5 + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(iVar5 + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(iVar5 + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(iVar5 + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            iVar3 = *(int*)(iVar5 + 0x10);
            if (iVar3 != 0)
            {
                *(ushort*)(iVar3 + 6) = *(ushort*)(iVar3 + 6) & 0xbfff;
            }
            break;
        case 0x19:
            iVar3 = *(int*)(iVar5 + 0x10);
            if (iVar3 != 0)
            {
                *(ushort*)(iVar3 + 6) = *(ushort*)(iVar3 + 6) | 0x4000;
            }
        }
        iVar7 = iVar7 + 1;
    }
    while (true);
}

void flammablevine_release(void);

int coldwatercontrol_getExtraSize(void) { return 0x8; }
int infopoint_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void coldwatercontrol_update(int obj)
{
    u8* state;

    state = ((GameObject*)obj)->extra;
    if (GameBit_Get(0x1bf) != 0 && GameBit_Get(0x1bd) == 0)
    {
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        GameBit_Set(0x1bd, 1);
        return;
    }

    if (*(void**)(state + 4) != NULL)
    {
        if (fn_80295C40(*(int*)(state + 4)) != 0)
        {
            if (lbl_803E3B68 == *(f32*)state)
            {
                ObjHits_RecordObjectHit(*(int*)(state + 4), obj, 0x1c, 0, 1);
            }

            *(f32*)state = *(f32*)state + timeDelta;
            if (*(f32*)state > lbl_803E3B6C)
            {
                ObjHits_RecordObjectHit(*(int*)(state + 4), obj, 0x1c, 1, 1);
                *(f32*)state = *(f32*)state - lbl_803E3B6C;
            }
        }
        else
        {
            *(f32*)state = lbl_803E3B68;
        }
    }
    else
    {
        *(int*)(state + 4) = (int)Obj_GetPlayerObject();
    }
}

#pragma scheduling on
void coldwatercontrol_init(int obj)
{
    int* p = ((int**)obj)[0xb8 / 4];
    *(f32*)p = lbl_803E3B68;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
}

void landed_arwing_free(int obj);

#pragma dont_inline on
#pragma dont_inline reset
