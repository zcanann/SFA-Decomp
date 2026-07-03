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
#include "main/game_object.h"
#include "main/mapEventTypes.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/music_trigger_ids.h"
extern f32 lbl_803E5150;
extern void objRenderFn_8003b8f4(f32);
extern void Music_Trigger(int id, int arg);
extern int mapGetDirIdx(int idx);
extern int unlockLevel(s32 val, int idx, int flag);
extern void skyFn_80088c94(int flags, int mode);
extern int getEnvfxAct(int a, int b, u16 idx, int d);

extern void fn_80296518(void* player, int a, int b);

void nwsh_levcon_hitDetect(void)
{
}

void nwsh_levcon_release(void)
{
}

void nwsh_levcon_initialise(void)
{
}

int nwsh_levcon_getExtraSize(void) { return 0x0; }
int nwsh_levcon_getObjectTypeId(void) { return 0x0; }

void nwsh_levcon_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5150);
}

void nwsh_levcon_free(int obj)
{
    Music_Trigger(MUSICTRIG_ewt_chase, 0);
    GameBit_Set(0xefd, 0);
}

void nwsh_levcon_update(int* obj)
{
    if (((GameObject*)obj)->unkF4 != 0)
    {
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - 1;
        if (((GameObject*)obj)->unkF4 == 0)
        {
            skyFn_80088c94(7, 1);
            getEnvfxAct(0, 0, 0xd1, 0);
            getEnvfxAct(0, 0, 0xd6, 0);
            getEnvfxAct(0, 0, 0x222, 0);
        }
    }
}

void nwsh_levcon_init(int* obj)
{
    ((GameObject*)obj)->animEventCallback = NWSH_levcon_SeqFn;
    unlockLevel(mapGetDirIdx(0x28), 1, 0);
    Music_Trigger(MUSICTRIG_ewt_chase, 1);
    ((GameObject*)obj)->unkF4 = 1;
    GameBit_Set(0xea2, 1);
    GameBit_Set(0xefd, 1);
}

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
                fn_80296518(player, 0x10, 1);
                GameBit_Set(0x174, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 4, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 0x1d, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 0x1e, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xb, 0x1f, 1);
                (*gMapEventInterface)->setMapAct(0xb, 6);
                break;
            default:
                break;
            }
        }
    }
    return 0;
}
