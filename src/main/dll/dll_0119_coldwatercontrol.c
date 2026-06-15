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
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

extern f32 timeDelta;
extern f32 lbl_803E3B68;
extern f32 lbl_803E3B6C;
extern int fn_80295C40(int obj);

undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 eventHandle;
    char mapAct;
    int mapId;
    int scratch;
    int state;
    int def;
    int eventIndex;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 uVar8;

    def = *(int*)&((GameObject*)param_9)->anim.placementData;
    state = *(int*)&((GameObject*)param_9)->extra;
    eventIndex = 0;
    scratch = (int)animUpdate;
    do
    {
        if ((int)(uint)animUpdate->eventCount <= eventIndex)
        {
            return 0;
        }
        switch (animUpdate->eventIds[eventIndex])
        {
        case 2:
        case 0x65:
            scratch = *(int*)(def + 0x14);
            if (scratch == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                eventHandle = FUN_80044404(0x26);
                FUN_80042bec(eventHandle, 0);
                eventHandle = FUN_80044404(0xb);
                FUN_80042bec(eventHandle, 1);
            }
            else if (scratch < 0x49f5a)
            {
                if (scratch == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1;
                    if (mapAct == '\x02')
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        scratch = 1;
                        FUN_80042b9c(0, 0, 1);
                        eventHandle = FUN_80044404(0xb);
                        FUN_80042bec(eventHandle, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        scratch = 1;
                        FUN_80042b9c(0, 0, 1);
                        eventHandle = FUN_80044404(0x29);
                        FUN_80042bec(eventHandle, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < scratch) || (scratch != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    scratch = 1;
                    FUN_80042b9c(0, 0, 1);
                    eventHandle = FUN_80044404(0x29);
                    FUN_80042bec(eventHandle, 0);
                }
            }
            else if (scratch == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                eventHandle = FUN_80044404(0x41);
                FUN_80042bec(eventHandle, 0);
                eventHandle = FUN_80044404(0xb);
                FUN_80042bec(eventHandle, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                eventHandle = FUN_80044404(0x29);
                FUN_80042bec(eventHandle, 0);
            }
            break;
        case 3:
        case 100:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x49f5a)
            {
                scratch = 0;
                param_12 = (int)*gMapEventInterface;
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (mapId < 0x49f5a)
            {
                if (mapId == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1_00;
                    if (mapAct == '\x02')
                    {
                        uVar8 = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 0);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 0);
                        scratch = 0;
                        param_12 = (int)*gMapEventInterface;
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((mapId < 0x451b9) && (mapId == 0x43775))
                {
                    scratch = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (mapId == 0x4cd65)
            {
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_01;
                if (mapAct == '\x02')
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (mapId < 0x451b9)
            {
                if (mapId == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (mapId == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_02;
                if (mapAct == '\x02')
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (mapId < 0x451b9)
            {
                if (mapId == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (mapId == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', scratch, param_12, param_13, param_14, param_15, param_16);
            }
            else if (mapId < 0x49f5a)
            {
                if ((mapId == 0x451b9) &&
                    (mapAct = (*gMapEventInterface)->getMapAct(0xd), param_1 = extraout_f1_03,
                        mapAct == '\x02'))
                {
                    scratch = (int)*gMapEventInterface;
                    uVar8 = (**(code**)(scratch + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', scratch, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (mapId == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', scratch
                             , param_12, param_13, param_14, param_15, param_16);
                scratch = (int)*gMapEventInterface;
                param_1 = (**(code**)(scratch + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(state + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(state + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(state + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(state + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(state + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(state + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(state + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(state + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(state + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(state + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(state + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(state + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(state + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(state + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            mapId = *(int*)(state + 0x10);
            if (mapId != 0)
            {
                *(ushort*)(mapId + 6) = *(ushort*)(mapId + 6) & 0xbfff;
            }
            break;
        case 0x19:
            mapId = *(int*)(state + 0x10);
            if (mapId != 0)
            {
                *(ushort*)(mapId + 6) = *(ushort*)(mapId + 6) | 0x4000;
            }
        }
        eventIndex = eventIndex + 1;
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
