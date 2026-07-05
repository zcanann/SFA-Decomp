/*
 * mmplevelcontrol (DLL 0x17E) - Moon Mountain Pass level controller.
 *
 * A singleton manager object that drives the area's environment. init
 * unlocks the map, primes the fog/heat-haze countdown (lbl_803DDB28) and
 * fires the area music cues. update selects the sky/weather environment
 * fx set from gamebits (0xD47 / 0xF33) and the player's current map cell,
 * runs the heat-haze text + countdown, and latches two scripted gamebit
 * events via SCGameBitLatch_Update. The sequence callback
 * (MMP_LevelControl_SeqFn) layers extra env fx on top in response to anim
 * events.
 */

#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/gamebits.h"
#include "main/lightmap.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/music_trigger_ids.h"
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void Music_Trigger(int id, int arg);

extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);

#define MMPLEVELCONTROL_OBJFLAG_HIDDEN 0x4000
#define MMPLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000




extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int setBit, int textId);


extern f32 timeDelta;
extern f32 lbl_803E44C0;
extern f32 lbl_803E44C4;
extern f32 lbl_803E44C8;
extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;

void MMP_levelcontrol_update(int obj);

void MMP_levelcontrol_hitDetect(void)
{
}

int MMP_levelcontrol_getExtraSize(void) { return 0x0; }
int MMP_levelcontrol_getObjectTypeId(void) { return 0x0; }

void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E44C4);
}

void MMP_levelcontrol_free(int obj)
{
    lbl_803DDB28 = lbl_803E44C0;
    lbl_803DDB2C = 0;
    Music_Trigger(MUSICTRIG_WLC_Puzzle, 0);
}

int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int Obj_GetPlayerObject(void);
    int player;
    int i;

    player = Obj_GetPlayerObject();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            getEnvfxAct(obj, player, 0x13b, 0);
            break;
        case 2:
            getEnvfxAct(obj, player, 0x138, 0);
            break;
        }
    }
    MMP_levelcontrol_update(obj);
    return 0;
}

#pragma peephole on
void MMP_levelcontrol_update(int obj)
{
    extern void* Obj_GetPlayerObject(void);
    int playerForMap;
    int playerForFx;

    playerForMap = (int)Obj_GetPlayerObject();
    playerForFx = (int)Obj_GetPlayerObject();

    if (lbl_803DDB28 > lbl_803E44C0)
    {
        gameTextShow(0x34f);
        {
            f32 t = lbl_803DDB28 - timeDelta;
            lbl_803DDB28 = t;
            if (t < lbl_803E44C0)
            {
                lbl_803DDB28 = lbl_803E44C0;
            }
        }
    }

    if (((GameObject*)obj)->unkF4 != 0)
    {
        envFxActFn_800887f8(0);
        if (GameBit_Get(0xd47) != 0)
        {
            skyFn_80088c94(7, 1);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x234, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x235, 0);
            }
            else
            {
                getEnvfxAct(obj, playerForFx, 0x13a, 0);
                getEnvfxAct(obj, playerForFx, 0x234, 0);
                getEnvfxAct(obj, playerForFx, 0x235, 0);
            }
            ((GameObject*)obj)->unkF8 = 0;
        }
        else if (GameBit_Get(0xf33) != 0)
        {
            skyFn_80088c94(7, 1);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x10c, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x10d, 0);
            }
            else
            {
                getEnvfxAct(obj, playerForFx, 0x13a, 0);
                getEnvfxAct(obj, playerForFx, 0x10c, 0);
                getEnvfxAct(obj, playerForFx, 0x10d, 0);
            }
            ((GameObject*)obj)->unkF8 = 1;
        }
        else if (coordsToMapCell(((GameObject*)playerForMap)->anim.localPosX, ((GameObject*)playerForMap)->anim.localPosZ) == 0x12)
        {
            skyFn_80088c94(7, 0);
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(obj, playerForFx, 0x13a, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x138, 0);
                getEnvfxActImmediately(obj, playerForFx, 0x139, 0);
            }
            else
            {
                getEnvfxAct(obj, playerForFx, 0x13a, 0);
                getEnvfxAct(obj, playerForFx, 0x138, 0);
                getEnvfxAct(obj, playerForFx, 0x139, 0);
            }
            ((GameObject*)obj)->unkF8 = 0;
        }
        Music_Trigger(MUSICTRIG_Barrels, 1);
        ((GameObject*)obj)->unkF4 = 0;
    }

    if (((GameObject*)obj)->unkF8 != 0 && GameBit_Get(0xf33) == 0)
    {
        skyFn_80088c94(7, 0);
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x138, 0);
        getEnvfxAct(obj, playerForFx, 0x139, 0);
        ((GameObject*)obj)->unkF8 = 0;
    }
    else if (((GameObject*)obj)->unkF8 == 0 && GameBit_Get(0xf33) != 0)
    {
        skyFn_80088c94(7, 1);
        getEnvfxAct(obj, playerForFx, 0x13a, 0);
        getEnvfxAct(obj, playerForFx, 0x10c, 0);
        getEnvfxAct(obj, playerForFx, 0x10d, 0);
        ((GameObject*)obj)->unkF8 = 1;
    }

    SCGameBitLatch_Update(&lbl_803DDB2C, 1, -1, -1, 0x389, 0xd5);
    SCGameBitLatch_Update(&lbl_803DDB2C, 2, -1, -1, 0xcbb, 0xc4);
}

void MMP_levelcontrol_release(void)
{
}

void MMP_levelcontrol_initialise(void)
{
}

#pragma peephole off
void MMP_levelcontrol_init(int obj)
{

    ((GameObject*)obj)->objectFlags |= (MMPLEVELCONTROL_OBJFLAG_HIDDEN | MMPLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED);
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    *(u32*)&((GameObject*)obj)->unkF8 = GameBit_Get(0xF33);
    ((GameObject*)obj)->animEventCallback = MMP_LevelControl_SeqFn;
    unlockLevel(mapGetDirIdx(0x12), 0, 0);
    lbl_803DDB28 = lbl_803E44C8;
    lbl_803DDB2C = 0;
    Music_Trigger(MUSICTRIG_wind_ambi, 0);
    Music_Trigger(MUSICTRIG_mammoth_walk_db, 0);
    Music_Trigger(MUSICTRIG_LVF_Tracking_f2, 0);
    Music_Trigger(MUSICTRIG_CRF_Swim, 0);
    Music_Trigger(MUSICTRIG_cldrnr_walkabout, 0);
    GameBit_Set(0xDCF, 0);
}
