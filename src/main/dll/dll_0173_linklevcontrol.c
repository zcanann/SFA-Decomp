/*
 * linklevcontrol (DLL 0x0173) - per-area level-control object for the
 * LinkLevel maps. One instance lives in each map-event area cell; the
 * object's anim.mapEventSlot identifies which cell (0x45..0x49).
 *
 * link_levcontrol_update tracks the player's current map cell (via
 * coordsToMapCell on the player world XZ): on first entry to this
 * object's cell it runs the one-shot enter effects (sky / env-fx /
 * music cues), and while the player stays in the cell it drives the
 * looping area music. The cell's music selection branches on sky sun
 * position and a couple of story game bits, edge-latched through the
 * object's musicTrack field and a SCGameBitLatch record.
 *
 * The unit's own object descriptor (gLINKLevControlObjDescriptor,
 * .data:0x80323AD0) and its area-effect table (lbl_803239F0) live in the
 * unowned .data gap (auto_07_803236D0); this TU carries no data sections,
 * matching the retail object.
 */
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/object_api.h"
#include "main/audio/music_api.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/object_descriptor.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/dll/savegame_load_api.h"
#include "main/sky_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/dll/dll_0173_linklevcontrol.h"

#define LINKLEVCONTROL_OBJFLAG_HIDDEN 0x4000

/* Area cells handled by this controller (GameObject::anim.mapEventSlot). */
enum
{
    AREA_CELL_45 = 0x45,
    AREA_CELL_46 = 0x46,
    AREA_CELL_47 = 0x47,
    AREA_CELL_48 = 0x48,
    AREA_CELL_49 = 0x49
};

/* unkF4 records how the object was spawned: fresh start vs loaded save. */
enum
{
    LEVCON_SAVE_STATUS_FRESH = 1,
    LEVCON_SAVE_STATUS_LOADED = 2
};

/* env-effect ids activated on entering AREA_CELL_45 (index-style; roles opaque) */
#define LINKLEVCONTROL_ENVFX_A 0x13e
#define LINKLEVCONTROL_ENVFX_B 0x140
#define LINKLEVCONTROL_ENVFX_C 0x13f

u8 lbl_803239F0[224] = {
    0x01, 0xB3, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x01, 0xB3, 0x01, 0xB6, 0x01, 0xB9, 0x01, 0xB9,
    0x01, 0xB3, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x01, 0xB6, 0x01, 0xB9,
    0x01, 0xB9, 0x01, 0xB9, 0x01, 0xB3, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61,
    0x01, 0xB3, 0x00, 0x61, 0x00, 0x61, 0x00, 0x61, 0x01, 0xB2, 0x00, 0x5F, 0x00, 0x5F, 0x00, 0x5F,
    0x01, 0xB2, 0x01, 0xB5, 0x01, 0xB8, 0x01, 0xB8, 0x01, 0xB2, 0x00, 0x5F, 0x00, 0x5F, 0x00, 0x5F,
    0x00, 0x5F, 0x00, 0x5F, 0x01, 0xB5, 0x01, 0xB8, 0x01, 0xB8, 0x01, 0xB8, 0x01, 0xB2, 0x00, 0x5F,
    0x00, 0x5F, 0x00, 0x5F, 0x00, 0x5F, 0x00, 0x5F, 0x01, 0xB2, 0x00, 0x5F, 0x00, 0x5F, 0x00, 0x5F,
    0x01, 0xB4, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0xB4, 0x01, 0xB7, 0x01, 0xBA, 0x01, 0xBA,
    0x01, 0xB4, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x01, 0xB7, 0x01, 0xBA,
    0x01, 0xBA, 0x01, 0xBA, 0x01, 0xB4, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60,
    0x01, 0xB4, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xA8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0xA8, 0xFF, 0xFF, 0x01, 0xA8, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

extern void fn_80088870(u8* a, u8* b, u8* c, u8* d);

#pragma dont_inline on
void link_levcontrol_updateAreaMusic(int* obj)
{
    LinkLevControlState* state = ((GameObject*)obj)->extra;
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case AREA_CELL_47:
        if ((*gSkyInterface)->getSunPosition(0) != 0)
        {
            if (state->musicTrack != 0x2d)
            {
                state->musicTrack = 0x2d;
                Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
            }
        }
        else
        {
            if (state->musicTrack != 0x33)
            {
                state->musicTrack = 0x33;
                Music_Trigger(MUSICTRIG_KP_Text, 1);
            }
        }
        break;
    case AREA_CELL_48:
        if (mainGetBit(0xe1e) == 0)
        {
            if (mainGetBit(0xb72) != 0)
            {
                if (state->musicTrack != 0x95)
                {
                    state->musicTrack = 0x95;
                    Music_Trigger(MUSICTRIG_mmpassalien, 1);
                }
            }
            else if ((*gSkyInterface)->getSunPosition(0) != 0)
            {
                if (state->musicTrack != 0x2d)
                {
                    state->musicTrack = 0x2d;
                    Music_Trigger(MUSICTRIG_PU1_Mysterious, 1);
                }
            }
            else
            {
                if (state->musicTrack != 0x33)
                {
                    state->musicTrack = 0x33;
                    Music_Trigger(MUSICTRIG_KP_Text, 1);
                }
            }
        }
        SCGameBitLatch_Update((SCGameBitLatchState*)&state->latch, 1, -1, -1, 0xe1e, 0x36);
        break;
    }
}

void link_levcontrol_applyEnterAreaEffects(int* obj)
{
    u8* tbl = lbl_803239F0;
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case AREA_CELL_47:
        fn_80088870(tbl + 0x38, tbl, tbl + 0x70, tbl + 0xa8);
        if (((GameObject*)obj)->unkF4 == LEVCON_SAVE_STATUS_LOADED)
        {
            envFxActFn_800887f8(0x3f);
        }
        else
        {
            envFxActFn_800887f8(0x1f);
        }
        Music_Trigger(MUSICTRIG_cldrnr_walkabout, 0);
        Music_Trigger(MUSICTRIG_CRF_Swim, 0);
        Music_Trigger(MUSICTRIG_wind_ambi, 0);
        Music_Trigger(MUSICTRIG_mammoth_walk_db, 0);
        Music_Trigger(MUSICTRIG_LVF_Tracking_f2, 0);
        break;
    case AREA_CELL_45:
        skyFn_80088c94(7, 0);
        envFxActFn_800887f8(0);
        getEnvfxActInt(0, 0, LINKLEVCONTROL_ENVFX_A, 0);
        getEnvfxActInt(0, 0, LINKLEVCONTROL_ENVFX_B, 0);
        getEnvfxActInt(0, 0, LINKLEVCONTROL_ENVFX_C, 0);
        Music_Trigger(MUSICTRIG_underwater, 1);
        break;
    case AREA_CELL_49:
        Music_Trigger(MUSICTRIG_Teleport, 1);
        break;
    case AREA_CELL_48:
        Music_Trigger(MUSICTRIG_Arwing_Crash, 0);
        break;
    case AREA_CELL_46:
        Music_Trigger(MUSICTRIG_ice_race, 0);
        Music_Trigger(MUSICTRIG_citytombs, 1);
        break;
    }
}
#pragma dont_inline reset

int link_levcontrol_getExtraSize(void)
{
    return sizeof(LinkLevControlState);
}

void link_levcontrol_free(GameObject* obj)
{
    switch ((s32)obj->anim.mapEventSlot)
    {
    case AREA_CELL_45:
        Music_Trigger(MUSICTRIG_underwater, 0);
        break;
    case AREA_CELL_48:
    case AREA_CELL_49:
        Music_Trigger(MUSICTRIG_Teleport, 0);
        break;
    }
}

void link_levcontrol_update(int* obj)
{
    LinkLevControlState* state = ((GameObject*)obj)->extra;
    GameObject* player = Obj_GetPlayerObject();
    if (player == NULL)
        return;

    if ((s32)state->areaCell != (s32)((GameObject*)obj)->anim.mapEventSlot)
    {
        if ((s32)((GameObject*)obj)->anim.mapEventSlot ==
            coordsToMapCell(player->anim.localPosX, player->anim.localPosZ))
        {
            link_levcontrol_applyEnterAreaEffects(obj);
        }
        else
        {
            return;
        }
    }
    if ((s32)((GameObject*)obj)->anim.mapEventSlot ==
        coordsToMapCell(player->anim.localPosX, player->anim.localPosZ))
    {
        link_levcontrol_updateAreaMusic(obj);
    }
    state->areaCell = coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
}

void link_levcontrol_init(int* obj)
{
    LinkLevControlState* state = ((GameObject*)obj)->extra;
    state->areaCell = -1;
    state->unk04 = -1;
    state->musicTrack = -1;
    ((GameObject*)obj)->objectFlags |= LINKLEVCONTROL_OBJFLAG_HIDDEN;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = LEVCON_SAVE_STATUS_LOADED;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = LEVCON_SAVE_STATUS_FRESH;
    }
}

ObjectDescriptor gLINKLevControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)link_levcontrol_init,
    (ObjectDescriptorCallback)link_levcontrol_update,
    0,
    0,
    (ObjectDescriptorCallback)link_levcontrol_free,
    0,
    link_levcontrol_getExtraSize,
};
