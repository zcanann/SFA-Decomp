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
#include "main/audio/music_api.h"
#include "main/object_render_legacy.h"
#include "main/object_api.h"
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
#include "main/objanim_update.h"
#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/dll/savegame_load_api.h"
#include "main/gametext.h"
#include "main/map_load.h"
#include "main/pi_dolphin_api.h"
#include "main/sky_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/MMP/dll_017E_mmplevelcontrol.h"

#define MMPLEVELCONTROL_OBJFLAG_HIDDEN             0x4000
#define MMPLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000

/* env-effect ids for the area weather/sky sets (index-style; roles opaque).
   A/B layered by anim seq event; C is shared across all three update state
   gates; D/E in the 0xd47 gate; F/G in the 0xf33 gate; B/H in the map-cell gate. */
#define MMPLEVELCONTROL_ENVFX_A 0x13b
#define MMPLEVELCONTROL_ENVFX_B 0x138
#define MMPLEVELCONTROL_ENVFX_C 0x13a
#define MMPLEVELCONTROL_ENVFX_D 0x234
#define MMPLEVELCONTROL_ENVFX_E 0x235
#define MMPLEVELCONTROL_ENVFX_F 0x10c
#define MMPLEVELCONTROL_ENVFX_G 0x10d
#define MMPLEVELCONTROL_ENVFX_H 0x139

extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;

extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit, int setBit,
                                  int textId);

int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int player;
    int i;

    player = (int)Obj_GetPlayerObject();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            getEnvfxAct(obj, player, MMPLEVELCONTROL_ENVFX_A, 0);
            break;
        case 2:
            getEnvfxAct(obj, player, MMPLEVELCONTROL_ENVFX_B, 0);
            break;
        }
    }
    MMP_levelcontrol_update((GameObject*)(obj));
    return 0;
}

int MMP_levelcontrol_getExtraSize(void)
{
    return 0x0;
}
int MMP_levelcontrol_getObjectTypeId(void)
{
    return 0x0;
}

void MMP_levelcontrol_free(int obj)
{
    lbl_803DDB28 = 0.0f;
    lbl_803DDB2C = 0;
    Music_Trigger(MUSICTRIG_WLC_Puzzle, 0);
}

void MMP_levelcontrol_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void MMP_levelcontrol_hitDetect(void)
{
}

void MMP_levelcontrol_update(GameObject* obj)
{
    int playerForMap;
    int playerForFx;

    playerForMap = (int)Obj_GetPlayerObject();
    playerForFx = (int)Obj_GetPlayerObject();

    if (lbl_803DDB28 > 0.0f)
    {
        gameTextShow(0x34f);
        {
            f32 t = lbl_803DDB28 - timeDelta;
            lbl_803DDB28 = t;
            if (t < 0.0f)
            {
                lbl_803DDB28 = 0.0f;
            }
        }
    }

    if ((obj)->unkF4 != 0)
    {
        envFxActFn_800887f8(0);
        if (mainGetBit(0xd47) != 0)
        {
            skyFn_80088c94(7, 1);
            if ((obj)->unkF4 == 2)
            {
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_D, 0);
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_E, 0);
            }
            else
            {
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_D, 0);
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_E, 0);
            }
            (obj)->unkF8 = 0;
        }
        else if (mainGetBit(0xf33) != 0)
        {
            skyFn_80088c94(7, 1);
            if ((obj)->unkF4 == 2)
            {
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_F, 0);
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_G, 0);
            }
            else
            {
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_F, 0);
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_G, 0);
            }
            (obj)->unkF8 = 1;
        }
        else if (coordsToMapCell(((GameObject*)playerForMap)->anim.localPosX,
                                 ((GameObject*)playerForMap)->anim.localPosZ) == 0x12)
        {
            skyFn_80088c94(7, 0);
            if ((obj)->unkF4 == 2)
            {
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_B, 0);
                getEnvfxActImmediately((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_H, 0);
            }
            else
            {
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_B, 0);
                getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_H, 0);
            }
            (obj)->unkF8 = 0;
        }
        Music_Trigger(MUSICTRIG_Barrels, 1);
        (obj)->unkF4 = 0;
    }

    if ((obj)->unkF8 != 0 && mainGetBit(0xf33) == 0)
    {
        skyFn_80088c94(7, 0);
        getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
        getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_B, 0);
        getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_H, 0);
        (obj)->unkF8 = 0;
    }
    else if ((obj)->unkF8 == 0 && mainGetBit(0xf33) != 0)
    {
        skyFn_80088c94(7, 1);
        getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_C, 0);
        getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_F, 0);
        getEnvfxAct((int)obj, playerForFx, MMPLEVELCONTROL_ENVFX_G, 0);
        (obj)->unkF8 = 1;
    }

    SCGameBitLatch_Update(&lbl_803DDB2C, 1, -1, -1, 0x389, 0xd5);
    SCGameBitLatch_Update(&lbl_803DDB2C, 2, -1, -1, 0xcbb, 0xc4);
}

void MMP_levelcontrol_init(GameObject* obj)
{

    obj->objectFlags |= (MMPLEVELCONTROL_OBJFLAG_HIDDEN | MMPLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED);
    if (getSaveGameLoadStatus() != 0)
    {
        obj->unkF4 = 2;
    }
    else
    {
        obj->unkF4 = 1;
    }
    *(u32*)&obj->unkF8 = mainGetBit(0xF33);
    obj->animEventCallback = MMP_LevelControl_SeqFn;
    unlockLevel(mapGetDirIdx(0x12), 0, 0);
    lbl_803DDB28 = 300.0f;
    lbl_803DDB2C = 0;
    Music_Trigger(MUSICTRIG_wind_ambi, 0);
    Music_Trigger(MUSICTRIG_mammoth_walk_db, 0);
    Music_Trigger(MUSICTRIG_LVF_Tracking_f2, 0);
    Music_Trigger(MUSICTRIG_CRF_Swim, 0);
    Music_Trigger(MUSICTRIG_cldrnr_walkabout, 0);
    mainSetBits(0xDCF, 0);
}

void MMP_levelcontrol_release(void)
{
}

void MMP_levelcontrol_initialise(void)
{
}
