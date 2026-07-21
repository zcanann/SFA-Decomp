/*
 * DragonRock Palace level controller (DLL 0x229; "DFP_LevelControl").
 * Drives the spell-puzzle level state: a per-mode countdown timer, RNG
 * seeding of the puzzle solution table when its map-act reset flag is
 * raised, and gamebit-driven progression
 * (1504/1505/1507/1508/1589/3671) plus level unlocks and music triggers.
 */
#include "main/dll/dfp_types.h"
#include "main/audio/music_api.h"
#include "main/map_load.h"
#include "main/object_api.h"
#include "main/game_object.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/dll/player_api.h"
#include "main/mapEventTypes.h"
#include "main/audio/sfx_ids.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/lightmap_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/DF/dll_0229_dfplevelcontrol.h"

s16 gDFPLevelControlMapAct1Timer = 0x82;
u8 gDFPLevelControlResetMapAct1 = 1;
u8 gDFPLevelControlResetMapAct2 = 1;

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

#define DFPLEVELCONTROL_OBJGROUP 0x9

#define DFPLEVELCONTROL_OBJFLAG_HIDDEN 0x4000

/* repels the player away from this object and applies status damage (arg = status type) */
#define DFPLEVELCONTROL_MSG_PLAYER_HIT 0x60005

void DFP_LevelControl_updateMapAct2(GameObject* obj)
{
    DfpLevelControlState* state = (obj)->extra;
    GameObject* player;
    s16 i;

    player = Obj_GetPlayerObject();
    if (gDFPLevelControlResetMapAct2 != 0)
    {
        mainSetBits(GAMEBIT_STAFF_ABILITY_FIRE_BLASTER, 1);
        mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);
        for (i = 0; i < 9; i++)
        {
            gDFPLevelControlPuzzleValues[i] = (s16)randomGetRange(1, 4);
        }
        mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
        state->timer = 0;
        gDFPLevelControlResetMapAct2 = 0;
    }
    if (mainGetBit(0x5e3) == 0 && mainGetBit(0x5e0) != 0 && mainGetBit(0x5e1) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_espk2_c);
        mainSetBits(0x5e3, 1);
    }
    if (mainGetBit(0x792) == 0 && mainGetBit(0xb8c) != 0 && mainGetBit(0xb8c) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_espk2_c);
        mainSetBits(0x792, 1);
    }
    if (mainGetBit(0xe58) == 0)
    {
        if (mainGetBit(0x635) != 0 && state->sfxLatch == 0)
        {
            Sfx_PlayFromObject(0, SFXTRIG_dn_boar1_c_1c4);
            for (i = 0; i < 9; i++)
            {
                gDFPLevelControlPuzzleValues[i] = (s16)randomGetRange(1, 4);
            }
            mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 1);
            state->sfxLatch = 1;
        }
        else
        {
            if (mainGetBit(0x635) == 0 && state->sfxLatch == 1)
            {
                state->sfxLatch = 0;
                mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
            }
        }
        if (mainGetBit(0x5e5) != 0)
        {
            state->timer = 300;
            ObjMsg_SendToObject(player, DFPLEVELCONTROL_MSG_PLAYER_HIT, obj, 0);
        }
    }
    if (mainGetBit(0x7a1) != 0)
    {
        if ((u8)(*gMapEventInterface)->getObjGroupStatus((obj)->anim.mapEventSlot, 6) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus((obj)->anim.mapEventSlot, 6, 1);
        }
    }
}

void DFP_LevelControl_updateMapAct1(GameObject* obj)
{
    DfpLevelControlState* state;
    GameObject* player;

    state = (obj)->extra;
    player = Obj_GetPlayerObject();
    if (gDFPLevelControlResetMapAct1 != 0)
    {
        s16 i;
        gDFPLevelControlPuzzleValues[6] = 0;
        gDFPLevelControlPuzzleValues[7] = 0;
        gDFPLevelControlPuzzleValues[8] = 0;
        for (i = 0; i < 6; i++)
        {
            gDFPLevelControlPuzzleValues[i] = (s16)randomGetRange(1, 4);
        }
        mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
        state->timer = 0;
        gDFPLevelControlResetMapAct1 = 0;
    }
    if (mainGetBit(1507) == 0)
    {
        if (mainGetBit(1504) != 0 && mainGetBit(1505) != 0)
        {
            mainSetBits(1507, 1);
        }
    }
    if (mainGetBit(3671) == 0)
    {
        if (mainGetBit(1589) != 0 && state->sfxLatch == 0)
        {
            s16 i;
            Sfx_PlayFromObject(0, SFXTRIG_statue_wave);
            for (i = 0; i < 6; i++)
            {
                gDFPLevelControlPuzzleValues[i] = (s16)randomGetRange(1, 4);
            }
            mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 1);
            state->sfxLatch = 1;
        }
        else if (mainGetBit(1589) == 0 && state->sfxLatch == 1)
        {
            state->sfxLatch = 0;
            mainSetBits(GAMEBIT_DRBOT_SpellPuzzleActive, 0);
        }
        if (mainGetBit(1509) != 0)
        {
            state->timer = 300;
            ObjMsg_SendToObject(player, DFPLEVELCONTROL_MSG_PLAYER_HIT, obj, 1);
        }
    }
}

int DFP_LevelControl_sequenceCallback(GameObject* obj)
{
    DfpLevelControlState* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    s16 timer = state->timer;
    if (timer > 0)
    {
        state->timer -= (s16)timeDelta;
        fn_802960E8(player, 0x51e);
    }
    return 0;
}

void DFP_LevelControl_copyPuzzleValues(int unused, u8* out)
{
    int i;
    for (i = 0; (s16)i < 9; i += 3)
    {
        out[(s16)i] = gDFPLevelControlPuzzleValues[i];
        out[(s16)(i + 1)] = gDFPLevelControlPuzzleValues[i + 1];
        out[(s16)(i + 2)] = gDFPLevelControlPuzzleValues[i + 2];
    }
}

int DFP_LevelControl_getExtraSize(void)
{
    return sizeof(DfpLevelControlState);
}
int DFP_LevelControl_getObjectTypeId(void)
{
    return 0x0;
}

void DFP_LevelControl_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, DFPLEVELCONTROL_OBJGROUP);
}

void DFP_LevelControl_render(void)
{
}

void DFP_LevelControl_hitDetect(void)
{
}

void DFP_LevelControl_update(GameObject* obj)
{

    DfpLevelControlState* state = (obj)->extra;
    GameObject* player;
    u8 b1;
    u8 b2;
    u8 b3;
    int mode;

    player = Obj_GetPlayerObject();
    b1 = mainGetBit(0xd5d);
    b2 = mainGetBit(0xd59);
    b3 = mainGetBit(0xd5a);
    if ((b1 != 0 && ((u32)state->flags07 >> 7 & 1) == 0) || (b2 != 0 && ((u32)state->flags07 >> 6 & 1) == 0) ||
        (b3 != 0 && ((u32)state->flags07 >> 5 & 1) == 0))
    {
        Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
    }
    ((DfpFlags7*)&state->flags07)->b80 = b1;
    ((DfpFlags7*)&state->flags07)->b40 = b2;
    ((DfpFlags7*)&state->flags07)->b20 = b3;
    if (mainGetBit(0x5e8) == 0 && mainGetBit(0x5ee) != 0 && mainGetBit(0x5ef) != 0)
    {
        mainSetBits(0x5e8, 1);
    }
    coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
    mode = (*gMapEventInterface)->getMapAct((obj)->anim.mapEventSlot);
    switch (mode)
    {
    case 1:
        if (gDFPLevelControlMapAct1Timer != 0)
        {
            gDFPLevelControlMapAct1Timer -= (s16)timeDelta;
            if (gDFPLevelControlMapAct1Timer <= 0)
            {
                gDFPLevelControlMapAct1Timer = 0;
            }
        }
        DFP_LevelControl_updateMapAct1(obj);
        break;
    case 2:
        DFP_LevelControl_updateMapAct2(obj);
        break;
    case 3:
        break;
    }
    SCGameBitLatch_Update((SCGameBitLatchState*)state->gameBitLatches, 2, -1, -1, 0xdce, 0x95);
    SCGameBitLatch_UpdateInverted((SCGameBitLatchState*)state->gameBitLatches, 4, -1, -1, 0xdce, 0x37);
    SCGameBitLatch_UpdateInverted((SCGameBitLatchState*)state->gameBitLatches, 1, -1, -1, 0xdce, 0xe4);
    mainSetBits(0xdcf, 0);
}

void DFP_LevelControl_init(GameObject* obj, DfpLevelControlPlacement* placement)
{

    DfpLevelControlState* state = (obj)->extra;
    int mode;
    ObjGroup_AddObject((int)obj, DFPLEVELCONTROL_OBJGROUP);
    ((DfpFlags7*)&state->flags07)->b80 = mainGetBit(0xd5d);
    ((DfpFlags7*)&state->flags07)->b40 = mainGetBit(0xd59);
    ((DfpFlags7*)&state->flags07)->b20 = mainGetBit(0xd5a);
    (obj)->animEventCallback = (void*)DFP_LevelControl_sequenceCallback;
    state->mode = 1;
    mode = placement->mode;
    if (mode != 0 && mode <= 2)
    {
        state->mode = mode;
    }
    (*gMapEventInterface)->getMapAct((obj)->anim.mapEventSlot);
    unlockLevel(0, 0, 1);
    (obj)->objectFlags = (obj)->objectFlags | DFPLEVELCONTROL_OBJFLAG_HIDDEN;
    if ((obj)->anim.mapEventSlot == 0x15)
    {
        mainSetBits(0xdce, 0);
    }
    if ((u32)mainGetBit(0xdce) != 0)
    {
        Music_Trigger(MUSICTRIG_blizzard, 0);
        Music_Trigger(MUSICTRIG_trex_hit, 0);
    }
}

void DFP_LevelControl_release(void)
{
}

void DFP_LevelControl_initialise(void)
{
    s16* p = gDFPLevelControlPuzzleValues;
    p[0] = 1;
    p[1] = 2;
    p[2] = 3;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8] = 0;
}
