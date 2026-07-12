/*
 * nwshlevcon (DLL 0x198) - the SnowHorn level controller for SnowHorn
 * Wastes (map 'nwastes', 0x0A; "sh" = SnowHorn).
 *
 * Drives the area's intro: on init it unlocks the connecting level
 * (map 0x28), starts ambient music track 6 and arms its setup game
 * bits, then counts a one-frame delay (unkF4) before restoring the sky
 * and environment fx. Its trigger sequence hands the player an item and
 * opens the next batch of object groups / map act. On free it stops the
 * music and clears its progress bit.
 */
#include "main/dll/dll_0198_nwshlevcon.h"
#include "main/objprint_dolphin.h"
#include "main/render.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"

#define NWSH_LEVCON_MAP_SHRINE 0xb /* Krazoa shrine map triggered on activation */

#define NWSH_LEVCON_ENVFX_A 0xd1
#define NWSH_LEVCON_ENVFX_B 0xd6
#define NWSH_LEVCON_ENVFX_C 0x222

extern f32 lbl_803E5150;

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void Music_Trigger(int id, int arg);
extern int mapGetDirIdx(int idx);
extern void skyFn_80088c94(int flags, int mode);
extern void objSetAnimStateFlags(void* player, int a, int b);

int NWSH_levcon_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    void* player;
    int i;

    player = Obj_GetPlayerObject();
    if (player != 0)
    {
        for (i = 0; i < animUpdate->eventCount; i++)
        {
            switch (animUpdate->eventIds[i])
            {
            case 1:
                objSetAnimStateFlags(player, 0x10, 1);
                mainSetBits(GAMEBIT_ITEM_Spirit6_Got, 1);
                (*gMapEventInterface)->setObjGroupStatus(NWSH_LEVCON_MAP_SHRINE, 4, 1);
                (*gMapEventInterface)->setObjGroupStatus(NWSH_LEVCON_MAP_SHRINE, 0x1d, 1);
                (*gMapEventInterface)->setObjGroupStatus(NWSH_LEVCON_MAP_SHRINE, 0x1e, 1);
                (*gMapEventInterface)->setObjGroupStatus(NWSH_LEVCON_MAP_SHRINE, 0x1f, 1);
                (*gMapEventInterface)->setMapAct(NWSH_LEVCON_MAP_SHRINE, 6);
                break;
            default:
                break;
            }
        }
    }
    return 0;
}

int nwsh_levcon_getExtraSize(void)
{
    return 0x0;
}
int nwsh_levcon_getObjectTypeId(void)
{
    return 0x0;
}

void nwsh_levcon_free(int obj)
{
    Music_Trigger(MUSICTRIG_ewt_chase, 0);
    mainSetBits(GAMEBIT_SETPIECE_ACTIVE, 0);
}

void nwsh_levcon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E5150);
}

void nwsh_levcon_hitDetect(void)
{
}

void nwsh_levcon_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxActInt(0, 0, NWSH_LEVCON_ENVFX_A, 0);
            getEnvfxActInt(0, 0, NWSH_LEVCON_ENVFX_B, 0);
            getEnvfxActInt(0, 0, NWSH_LEVCON_ENVFX_C, 0);
        }
    }
}

void nwsh_levcon_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = NWSH_levcon_SeqFn;
    unlockLevel(mapGetDirIdx(0x28), 1, 0);
    Music_Trigger(MUSICTRIG_ewt_chase, 1);
    ((GameObject*)obj)->unkF4 = 1;
    mainSetBits(GAMEBIT_K6_Entered, 1);
    mainSetBits(GAMEBIT_SETPIECE_ACTIVE, 1);
}

void nwsh_levcon_release(void)
{
}

void nwsh_levcon_initialise(void)
{
}
