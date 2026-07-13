/*
 * DLL fragment [801AC01C-801AC160) — World Map HUD enter/leave handlers,
 * called from the IM ice-mountain object (dll_0169). Each handler queries
 * the player object's vtable[0x48] mode via playerGetFocusObject(Obj_GetPlayerObject())
 * and writes a HUD-state byte (5 = world-map shown, 6 = hidden) into the
 * object's extra-state block while toggling the world-map HUD and the
 * associated game bits.
 *   fn_801AC01C: enter — clears the 0x3a3/0x3a2 request bits, locks level
 *     0x17, shows/hides the HUD and sets 0x37b or 0xce.
 *   fn_801AC108: leave — only acts when request bit 0x3a3 is set; clears the
 *     request bits, sets 0x4e5, enables object group 1, sets 0x379 or 0xcb.
 */
#include "main/game_object.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/game_ui_interface.h"
#include "main/gameplay_runtime.h"
#include "main/mapEventTypes.h"
#include "main/gamebit_ids.h"
#include "main/dll/player_api.h"


#define PLAYER_VTABLE_GET_MODE 0x48

#define HUD_STATE_WORLDMAP 5
#define HUD_STATE_HIDDEN 6

#pragma scheduling off
void fn_801AC01C(GameObject *obj)
{
    int state = *(int*)&(obj)->extra;
    int mode;
    void* player;

    mainSetBits(GAMEBIT_IM_BikeRelated03A3, 0);
    mainSetBits(GAMEBIT_IM_BikeRelated03A2, 0);
    player = playerGetFocusObject(Obj_GetPlayerObject());
    if (player != 0)
    {
        mode = (*(int (**)(int))(*(int*)(*(int*)&((GameObject*)player)->anim.dll) + PLAYER_VTABLE_GET_MODE))((int)player);
    }
    else
    {
        mode = 0;
    }
    lockLevel(mapGetDirIdx(0x17), 1);
    if (mode == 1)
    {
        (*gGameUIInterface)->setShowWorldMapHud(1);
        *(u8*)state = HUD_STATE_WORLDMAP;
        mainSetBits(GAMEBIT_IMRelated037B, 1);
    }
    else
    {
        *(u8*)state = HUD_STATE_HIDDEN;
        mainSetBits(GAMEBIT_IMRelated00CE, 1);
    }
    mainSetBits(GAMEBIT_IM_BikeRelated0378, 0);
    mainSetBits(GAMEBIT_IM_BikeRelated03B9, 0);
}

void fn_801AC108(GameObject *obj, int extra)
{
    int mode;
    void* player;

    (*gGameUIInterface)->setShowWorldMapHud(0);
    if (mainGetBit(GAMEBIT_IM_BikeRelated03A3) != 0)
    {
        mainSetBits(GAMEBIT_IM_BikeRelated03A3, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated03A2, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated0378, 0);
        mainSetBits(GAMEBIT_IM_BikeRelated03B9, 0);
        player = playerGetFocusObject(Obj_GetPlayerObject());
        if (player != 0)
        {
            mode = (*(int (**)(int))(*(int*)(*(int*)&((GameObject*)player)->anim.dll) + PLAYER_VTABLE_GET_MODE))((int)player);
        }
        else
        {
            mode = 0;
        }
        mainSetBits(GAMEBIT_IM_DoneRace, 1);
        (*gMapEventInterface)->setObjGroupStatus((obj)->anim.mapEventSlot, 1, 1);
        if (mode == 1)
        {
            (*gGameUIInterface)->setShowWorldMapHud(1);
            *(u8*)extra = HUD_STATE_WORLDMAP;
            mainSetBits(GAMEBIT_IM_BikeRelated0379, 1);
        }
        else
        {
            *(u8*)extra = HUD_STATE_HIDDEN;
            mainSetBits(0xcb, 1);
        }
    }
}
