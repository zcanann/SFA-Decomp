#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/CF/CFBaby.h"

typedef struct FallLaddersObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FallLaddersObjectDef;

extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B58;
extern f32 lbl_803E3B5C;

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

void Fall_Ladders_render(void)
{
}

void Fall_Ladders_hitDetect(void)
{
}

void Fall_Ladders_release(void)
{
}

void Fall_Ladders_initialise(void)
{
}

void infopoint_free(void);

int Fall_Ladders_SeqFn(void) { return 0x0; }
int Fall_Ladders_getExtraSize(void) { return 0xc; }
int Fall_Ladders_getObjectTypeId(void) { return 0x0; }
int coldwatercontrol_getExtraSize(void);

typedef struct FallLaddersState
{
    f32 restYOffset;
    s16 lowerGameBit;
    s16 upperGameBit;
    u8 motionState;
    u8 playStartSound;
    s16 delay;
} FallLaddersState;

void Fall_Ladders_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void coldwatercontrol_init(int obj);

#pragma scheduling off
#pragma peephole off
void Fall_Ladders_update(int obj)
{
    int def;
    FallLaddersState* state;
    f32 speed;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 0x548)
    {
        if (GameBit_Get(state->upperGameBit) != 0 && GameBit_Get(state->lowerGameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        if (GameBit_Get(state->upperGameBit) == 0 && GameBit_Get(state->lowerGameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
    }
    else if (state->delay != 0)
    {
        state->delay -= (s16)timeDelta;
        if (state->delay <= 0)
        {
            state->motionState = 1;
            if (state->playStartSound != 0)
            {
                Sfx_PlayFromObject(obj, 0x4bc);
                state->playStartSound = 0;
            }
            state->delay = 0;
        }
    }
    else
    {
        if ((s8)state->motionState == 0 && GameBit_Get(state->upperGameBit) != 0)
        {
            state->delay = 10;
        }
        if ((s8)state->motionState == 1 && ((GameObject*)obj)->anim.localPosY >= ((ObjPlacement*)def)->posY)
        {
            ((GameObject*)obj)->anim.velocityY -= lbl_803E3B50;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->
                anim.localPosY;
            if (((GameObject*)obj)->anim.localPosY <= ((ObjPlacement*)def)->posY)
            {
                ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY;
                ((GameObject*)obj)->anim.velocityY = lbl_803E3B54 * -((GameObject*)obj)->anim.velocityY;
                speed = ((GameObject*)obj)->anim.velocityY;
                speed = (speed >= lbl_803E3B58) ? speed : -speed;
                if (speed < lbl_803E3B5C)
                {
                    state->motionState = 2;
                }
            }
        }
    }
}

void Fall_Ladders_init(int* obj, s8* def)
{
    s16* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32) * (s8*)((char*)def + 0x18) << 8);
    state[3] = ((FallLaddersObjectDef*)def)->unk20;
    state[2] = ((FallLaddersObjectDef*)def)->unk1E;
    *(f32*)state = (f32)(s32)((FallLaddersObjectDef*)def)->unk1A;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ((GameObject*)obj)->animEventCallback = (void*)Fall_Ladders_SeqFn;
    ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)def)->posY + *(f32*)state;
    Obj_SetActiveModelIndex(obj, (s32) * (s8*)((char*)def + 0x19));
    ((FallLaddersState*)state)->motionState = 0;
    if (GameBit_Get(state[3]) == 0)
    {
        ((FallLaddersState*)state)->playStartSound = 1;
    }
}
