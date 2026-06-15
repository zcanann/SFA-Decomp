#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEvent.h"
#include "main/dll/CF/CFBaby.h"

typedef struct FlammablevineObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FlammablevineObjectDef;

typedef struct FlammablevinePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    u16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} FlammablevinePlacement;

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
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

undefined4
#pragma scheduling on
#pragma peephole on
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, undefined4 param_10
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

    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    extra = *(int*)&((GameObject*)obj)->extra;
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

void flammablevine_release(void)
{
}

void flammablevine_initialise(void)
{
}

void dll_109_hitDetect_nop(void);

int flammablevine_getExtraSize(void) { return 0x14; }
int flammablevine_getObjectTypeId(void) { return 0x0; }
int dll_109_getExtraSize_ret_16(void);

extern f32 timeDelta;
extern void Sfx_PlayFromObject(int obj, int sfxId);

extern f32 lbl_803E3AF8;
extern f32 lbl_803E3AFC;
extern f32 lbl_803E3B00;
extern f32 lbl_803E3B04;
extern f32 lbl_803E3B08;
extern f32 lbl_803E3B0C;
extern f32 lbl_803E3B10;
extern f32 lbl_803E3B14;
extern f32 lbl_803E3B18;
extern f32 lbl_803E3B1C;
extern f32 lbl_803E3B20;
extern f32 lbl_803E3B24;
extern f32 lbl_803E3B28;
extern f32 lbl_803E3B2C;
extern f32 lbl_803E3B30;
extern f32 lbl_803E3B34;
extern void objRenderFn_8003b8f4(f32);
extern void Obj_RemoveFromUpdateList(int obj);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern void fn_80098B18(int obj, f32 scale, int type, int a, int b, int c);
extern int cMenuGetSelectedItem(void);
extern void* getTrickyObject(void);

#pragma scheduling off
#pragma peephole off
void flammablevine_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3AF8);
}

void infopoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void flammablevine_free(int x) { ObjGroup_RemoveObject(x, 0x31); }

void flammablevine_hitDetect(int obj)
{
    u8* state;
    u8* def;
    int hitObj;

    state = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if ((state[0] & 3) == 0)
    {
        if (ObjHits_GetPriorityHit(obj, 0, 0, &hitObj) == 0x1a)
        {
            if (((FlammablevinePlacement*)def)->unk1E != -1)
            {
                GameBit_Set(((FlammablevinePlacement*)def)->unk1E, 1);
                Sfx_PlayFromObject(0, 0x409);
            }
            *(f32*)(state + 4) = lbl_803E3AFC;
            state[0] = state[0] | 1;
        }
    }
}

void flammablevine_init(int obj, int def)
{
    u8* state;
    f32 scale;

    state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, 0x31);
    *(s16*)obj = (s16)((s8) * (u8*)(def + 0x18) << 8);

    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3B20 * ((f32)((FlammablevineObjectDef*)def)->unk1A /
        lbl_803E3B24);
    if (((GameObject*)obj)->anim.rootMotionScale <= *(f32*)&lbl_803E3B28)
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3B28;
    }

    scale = ((GameObject*)obj)->anim.rootMotionScale;
    ObjHitbox_SetCapsuleBounds(
        obj,
        (s16)(lbl_803E3B2C * scale),
        0,
        (s16)(lbl_803E3B30 * scale));
    *(f32*)(state + 0x10) = lbl_803E3B34;
    ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)((ObjAnimComponent*)obj, lbl_803E3B00);

    if (((FlammablevineObjectDef*)def)->unk1E != -1 && GameBit_Get(((FlammablevineObjectDef*)def)->unk1E) != 0)
    {
        Obj_RemoveFromUpdateList(obj);
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.alpha = 0;
        state[0] = state[0] | 2;
    }

    state[1] = *(u8*)(def + 0x19);
    if (state[1] == 1)
    {
        ObjHits_MarkObjectPositionDirty(obj);
    }
}

void flammablevine_update(int obj)
{
    u8* state;
    u8* def;
    void* tricky;
    u8 canUse;
    f32 burnTimer;
    f32 zero;
    int pulseStyle;
    u32 fadeAlpha;

    state = ((GameObject*)obj)->extra;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    tricky = getTrickyObject();

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8;
    if (((FlammablevinePlacement*)def)->unk20 == -1)
    {
        goto can_use_vine;
    }
    if (GameBit_Get(((FlammablevinePlacement*)def)->unk20) == 0)
    {
        goto cant_use_vine;
    }
    if (tricky == NULL)
    {
        goto cant_use_vine;
    }
    if (GameBit_Get(0x245) == 0)
    {
        goto cant_use_vine;
    }
can_use_vine:
    canUse = 1;
    goto checked_vine_use;
cant_use_vine:
    canUse = 0;
checked_vine_use:

    if ((state[0] & 3) == 0)
    {
        if (state[1] == 0)
        {
            ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
        }
        ObjHits_EnableObject(obj);

        if (((GameObject*)obj)->anim.seqId == 0x102)
        {
            if (cMenuGetSelectedItem() == -1)
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0;
            }
            else
            {
                ((GameObject*)obj)->anim.modelInstance->hitVolumes[0].priority = 0x10;
            }
        }

        if (tricky != NULL && canUse != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8;
            if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
            {
                ((void (*)(void*, int, int, int))(*(int*)(*(int*)(*(int*)((u8*)tricky + 0x68)) + 0x28)))(
                    tricky, obj, 1, 4);
            }
        }
    }

    burnTimer = *(f32*)(state + 4);
    zero = lbl_803E3B00;
    if (burnTimer > zero)
    {
        *(f32*)(state + 4) = burnTimer - timeDelta;
        if (*(f32*)(state + 4) <= zero)
        {
            ((GameObject*)obj)->anim.alpha = 0;
            *(f32*)(state + 4) = zero;
            state[0] = state[0] & ~1;
            state[0] = state[0] | 2;
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
        }
    }

    if ((state[0] & 1) != 0)
    {
        if (*(f32*)(state + 4) < lbl_803E3B04)
        {
            *(f32*)(state + 0x10) = lbl_803E3AF8;
        }
        else
        {
            *(f32*)(state + 0x10) = lbl_803E3AF8 - ((*(f32*)(state + 4) - lbl_803E3B04) / lbl_803E3B04);
        }

        if (*(f32*)(state + 4) < lbl_803E3B08 && *(f32*)(state + 4) > lbl_803E3B04)
        {
            ((int (*)(ObjAnimComponent*, f32))ObjAnim_SetMoveProgress)(
                (ObjAnimComponent*)obj,
                lbl_803E3AF8 - ((*(f32*)(state + 4) - lbl_803E3B04) / lbl_803E3B0C));
        }

        if (*(f32*)(state + 4) < lbl_803E3B10)
        {
            if (*(f32*)(state + 4) < lbl_803E3B04)
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
            else
            {
                fadeAlpha = (u8)(lbl_803E3B14 * ((*(f32*)(state + 4) - lbl_803E3B04) / lbl_803E3B18));
                ((GameObject*)obj)->anim.alpha = fadeAlpha;
            }
        }

        *(f32*)(state + 0xc) = *(f32*)(state + 0xc) - timeDelta;
        if (*(f32*)(state + 0xc) <= lbl_803E3B00)
        {
            pulseStyle = 3;
            *(f32*)(state + 0xc) = *(f32*)(state + 0xc) + lbl_803E3AF8;
        }
        else
        {
            pulseStyle = 0;
        }
        fn_80098B18(obj, lbl_803E3B1C * (*(f32*)(state + 0x10) * ((GameObject*)obj)->anim.rootMotionScale), 3, 0,
                    pulseStyle, 0);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXmv_liftloop);
    }
}

void Fall_Ladders_free(int obj);

#pragma dont_inline on
#pragma dont_inline reset
