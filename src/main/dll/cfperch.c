#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/cfperch.h"

typedef struct SmallbasketObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 unk19;
    s16 unk1A;
    f32 unk1C;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    f32 unk24;
} SmallbasketObjectDef;


#define SMALLBASKET_LINKED_ID_BASE 0x40000
#define SMALLBASKET_ROB_WAVE_DIRECT_ID 0x66
#define SMALLBASKET_ROB_WAVE_ID_65D0 0x65d0
#define SMALLBASKET_ROB_WAVE_ID_65D2 0x65d2
#define SMALLBASKET_ROB_WAVE_ID_65D5 0x65d5
#define SMALLBASKET_ROB_WAVE_ID_65D6 0x65d6
#define SMALLBASKET_ROB_WAVE_ID_65D7 0x65d7
#define GAMEBIT_SFX_MUTE 0xa71

extern undefined8 FUN_80006824();
extern uint FUN_80006ba0();
extern undefined4 FUN_80006ba8();
extern uint FUN_80006c00();
extern double FUN_80017708();
extern undefined4 FUN_8001771c();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 FUN_80081120();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_80181b50();
extern undefined4 FUN_801816f8();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();
extern uint FUN_80294bec();
extern byte FUN_80294c20();
extern uint FUN_80294ce8();
extern uint FUN_80294cf0();
extern uint FUN_80294db4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803de740;
extern f64 DOUBLE_803e4600;
extern f64 DOUBLE_803e4638;
extern f32 lbl_803DC074;
extern f32 lbl_803E45C8;
extern f32 lbl_803E45D0;
extern f32 lbl_803E45E8;
extern f32 lbl_803E45F0;
extern f32 lbl_803E460C;
extern f32 lbl_803E4610;
extern f32 lbl_803E4614;
extern f32 lbl_803E4618;
extern f32 lbl_803E461C;
extern f32 lbl_803E4620;
extern f32 lbl_803E4624;
extern f32 lbl_803E4628;
extern f32 lbl_803E462C;
extern f32 lbl_803E4630;

extern void* Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern int GameBit_Get(int id);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern f32 lbl_803E39AC;
extern f64 lbl_803E39B0;
extern f32 lbl_803E39B8;
extern f32 lbl_803E39BC;
extern f32 lbl_803E39C0;
extern f32 lbl_803E39C4;
extern f64 lbl_803E39C8;

f32 fn_80183204(int obj)
{
    u8* state = ((GameObject*)obj)->extra;
    return lbl_803E39AC - (f32)(u32)
    state[0x13] / (f32)(u32)
    state[0x28];
}

extern void ObjGroup_AddObject(int obj, int group);
extern void* lbl_803DDAC0;

void smallbasket_init(int obj, int def);

void fn_80183250(int obj, int def)
{
    int state31;
    int player;
    f32 oldVel;
    int sum;
    u32 adj;
    u32 v;
    f32 limit;

    state31 = *(int*)&((GameObject*)obj)->anim.placementData;
    player = (int)Obj_GetPlayerObject();
    if ((*(u16*)(*(int*)&((GameObject*)obj)->anim.parent + 0xb0) & 0x1000) != 0)
    {
        ((GameObject*)obj)->anim.localPosX = *(f32*)(def + 0x24);
        ((GameObject*)obj)->anim.velocityX = 0.0f;
    }
    else
    {
        oldVel = ((GameObject*)obj)->anim.velocityX;
        sum = *(s16*)(*(int*)&((GameObject*)obj)->anim.parent + 0x4) + *(u16*)(def + 0x20);
        ((GameObject*)obj)->anim.velocityX = -(f32)sum / *(f32*)(def + 0x1c);
        if ((oldVel <= 0.0f && ((GameObject*)obj)->anim.velocityX >= 0.0f) ||
            (oldVel >= 0.0f && ((GameObject*)obj)->anim.velocityX <= 0.0f))
        {
            v = *(u32*)(state31 + 0x14);
            adj = v - SMALLBASKET_LINKED_ID_BASE;
            if ((adj == SMALLBASKET_ROB_WAVE_ID_65D7) ||
                ((adj - SMALLBASKET_ROB_WAVE_ID_65D5) <=
                    (SMALLBASKET_ROB_WAVE_ID_65D6 - SMALLBASKET_ROB_WAVE_ID_65D5)) ||
                (v == SMALLBASKET_ROB_WAVE_DIRECT_ID) || (adj == SMALLBASKET_ROB_WAVE_ID_65D0) ||
                (adj == SMALLBASKET_ROB_WAVE_ID_65D2))
            {
                if (Vec_distance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) <
                    lbl_803E39BC)
                {
                    if ((u32)GameBit_Get(GAMEBIT_SFX_MUTE) == 0)
                    {
                        Sfx_PlayFromObject(obj, SFXfend_rob_wave);
                    }
                }
            }
        }
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + ((GameObject*)obj)->anim.velocityX;
        if (((GameObject*)obj)->anim.localPosX > (limit = lbl_803E39C0 + *(f32*)(def + 0x24)))
        {
            ((GameObject*)obj)->anim.localPosX = limit;
        }
        else
        {
            limit = *(f32*)(def + 0x24) - lbl_803E39C4;
            if (((GameObject*)obj)->anim.localPosX < limit)
            {
                ((GameObject*)obj)->anim.localPosX = limit;
            }
        }
    }
}

extern void ObjHits_ClearHitVolumes(int obj);
extern void ObjHits_SetHitVolumeSlot(int obj, int volumeIdx, int hitType, int extra);
extern void ObjHits_SyncObjectPositionIfDirty(int obj);
extern u32 buttonGetDisabled(int pad);
extern u32 getButtonsJustPressed(int pad);
extern void buttonDisable(int pad, int mask);
extern int ObjTrigger_IsSet(int obj);
extern int playerIsDisguised(int player);
extern u32 playerGetStateFlag310(int player);
extern void setAButtonIcon(int icon);
extern int fn_80295BF0(int player);
extern int fn_8029669C(int player);
extern int fn_802966B4(int player);
extern void vecRotateZXY(void* p, void* v);
extern void ObjMsg_SendToObject(int target, int msg, int obj, u32 value);
extern void fn_801816F8(int obj, int player, int state);
extern void fn_801814D0(int obj, int player, int state);
extern void fn_801821FC(int obj);
extern f32 getXZDistance(f32 * a, f32 * b);
extern u8 framesThisStep;
extern f32 timeDelta;
extern int* gSHthorntailAnimationInterface;
extern f32 lbl_803E3930;
extern f32 lbl_803E3934;
extern f32 lbl_803E3938;
extern f32 lbl_803E3950;
extern f32 lbl_803E3958;
extern f64 lbl_803E3968;
extern f32 lbl_803E3974;
extern f32 lbl_803E3978;
extern f32 lbl_803E397C;
extern f32 lbl_803E3980;
extern f32 lbl_803E3984;
extern f32 lbl_803E3988;
extern f32 lbl_803E398C;
extern f32 lbl_803E3990;
extern f32 lbl_803E3994;
extern f32 lbl_803E3998;
extern f64 lbl_803E39A0;

typedef struct
{
    s16 h0;
    s16 h1;
    s16 h2;
    f32 fx;
    f32 fy;
    f32 fz;
    f32 fw;
} BasketMathArgs;

/*
 * --INFO--
 *
 * Function: smallbasket_update
 * EN v1.0 Address: 0x801826E8
 * EN v1.0 Size: 2476b
 */
