#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/dll/CF/CFBaby.h"

typedef struct InfopointObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    u8 pad1A[0x1B - 0x1A];
    u8 unk1B;
    s16 unk1C;
    u8 unk1E;
    u8 unk1F;
} InfopointObjectDef;

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

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3B70;
extern void buttonDisable(int p1, int mask);
extern int textureLoadAsset(int id);
extern int* gameTextGet(int id);
extern int lbl_803219A0[];
extern int lbl_80321990[];

void infopoint_hitDetect(void)
{
}

undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 actionId;
    char mapAct;
    int objId;
    int tmp;
    int extra;
    int placement;
    int i;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 f1tmp;

    placement = *(int*)&((GameObject*)param_9)->anim.placementData;
    extra = *(int*)&((GameObject*)param_9)->extra;
    i = 0;
    tmp = (int)animUpdate;
    do
    {
        if ((int)(uint)animUpdate->eventCount <= i)
        {
            return 0;
        }
        switch (animUpdate->eventIds[i])
        {
        case 2:
        case 0x65:
            tmp = *(int*)(placement + 0x14);
            if (tmp == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                tmp = 1;
                FUN_80042b9c(0, 0, 1);
                actionId = FUN_80044404(0x26);
                FUN_80042bec(actionId, 0);
                actionId = FUN_80044404(0xb);
                FUN_80042bec(actionId, 1);
            }
            else if (tmp < 0x49f5a)
            {
                if (tmp == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1;
                    if (mapAct == '\x02')
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        tmp = 1;
                        FUN_80042b9c(0, 0, 1);
                        actionId = FUN_80044404(0xb);
                        FUN_80042bec(actionId, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        tmp = 1;
                        FUN_80042b9c(0, 0, 1);
                        actionId = FUN_80044404(0x29);
                        FUN_80042bec(actionId, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < tmp) || (tmp != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    tmp = 1;
                    FUN_80042b9c(0, 0, 1);
                    actionId = FUN_80044404(0x29);
                    FUN_80042bec(actionId, 0);
                }
            }
            else if (tmp == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                tmp = 1;
                FUN_80042b9c(0, 0, 1);
                actionId = FUN_80044404(0x41);
                FUN_80042bec(actionId, 0);
                actionId = FUN_80044404(0xb);
                FUN_80042bec(actionId, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                tmp = 1;
                FUN_80042b9c(0, 0, 1);
                actionId = FUN_80044404(0x29);
                FUN_80042bec(actionId, 0);
            }
            break;
        case 3:
        case 100:
            objId = *(int*)(placement + 0x14);
            if (objId == 0x49f5a)
            {
                tmp = 0;
                param_12 = (int)*gMapEventInterface;
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (objId < 0x49f5a)
            {
                if (objId == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1_00;
                    if (mapAct == '\x02')
                    {
                        f1tmp = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(f1tmp, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 0);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 0);
                        tmp = 0;
                        param_12 = (int)*gMapEventInterface;
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((objId < 0x451b9) && (objId == 0x43775))
                {
                    tmp = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (objId == 0x4cd65)
            {
                tmp = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            objId = *(int*)(placement + 0x14);
            if (objId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_01;
                if (mapAct == '\x02')
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (objId < 0x451b9)
            {
                if (objId == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (objId == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            objId = *(int*)(placement + 0x14);
            if (objId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_02;
                if (mapAct == '\x02')
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (objId < 0x451b9)
            {
                if (objId == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (objId == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            objId = *(int*)(placement + 0x14);
            if (objId == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', tmp, param_12, param_13, param_14, param_15, param_16);
            }
            else if (objId < 0x49f5a)
            {
                if ((objId == 0x451b9) &&
                    (mapAct = (*gMapEventInterface)->getMapAct(0xd), param_1 = extraout_f1_03,
                        mapAct == '\x02'))
                {
                    tmp = (int)*gMapEventInterface;
                    f1tmp = (**(code**)(tmp + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(f1tmp, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', tmp, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (objId == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', tmp
                             , param_12, param_13, param_14, param_15, param_16);
                tmp = (int)*gMapEventInterface;
                param_1 = (**(code**)(tmp + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(extra + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(extra + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(extra + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(extra + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(extra + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(extra + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(extra + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(extra + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(extra + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(extra + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(extra + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(extra + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(extra + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(extra + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            objId = *(int*)(extra + 0x10);
            if (objId != 0)
            {
                *(ushort*)(objId + 6) = *(ushort*)(objId + 6) & 0xbfff;
            }
            break;
        case 0x19:
            objId = *(int*)(extra + 0x10);
            if (objId != 0)
            {
                *(ushort*)(objId + 6) = *(ushort*)(objId + 6) | 0x4000;
            }
        }
        i = i + 1;
    }
    while (true);
}

void flammablevine_release(void);

void infopoint_free(void)
{
}

void infopoint_release(void)
{
}

void infopoint_initialise(void)
{
}

void decoration11a_free(void);

int infopoint_getExtraSize(void) { return 0x20; }
int infopoint_getObjectTypeId(void) { return 0x0; }
int decoration11a_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3B70);
}

void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void infopoint_update(int obj)
{
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
    {
        buttonDisable(0, 0x100);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
}

void landed_arwing_init(int obj, int param);

#pragma dont_inline on
#pragma dont_inline reset

int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    s16* inner = ((GameObject*)obj)->extra;
    int i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1: inner[0xb] = (s16)0xff;
            break;
        case 2: inner[0xb] = 0;
            break;
        case 3: break;
        case 4: break;
        }
    }
    return 0;
}

void dll_109_free(int obj);

void infopoint_init(int* obj, u8* def)
{
    u8* state = ((GameObject*)obj)->extra;
    int* txt;
    ((GameObject*)obj)->animEventCallback = (void*)InfoPoint_SeqFn;
    if (*(void**)lbl_803219A0 == NULL)
    {
        *(int*)lbl_803219A0 = textureLoadAsset(616);
    }
    *(int*)(state + 8) = (int)lbl_80321990;
    txt = gameTextGet(((InfopointObjectDef*)def)->unk18);
    *(int*)(state + 4) = **(int**)((char*)txt + 8);
    *(int*)(state + 0xc) = 100;
    *(int*)state = (int)txt;
    *(s16*)obj = (s16)((s32) * (u8*)((char*)def + 0x1c) << 8);
    *(int*)(state + 0x18) = 2;
    *(u8*)(state + 0x10) = ((InfopointObjectDef*)def)->unk1B;
    *(s16*)(state + 0x16) = 0;
    ((GameObject*)obj)->objectFlags |= 0x2000;
}
