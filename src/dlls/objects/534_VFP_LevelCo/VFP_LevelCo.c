/*
 * vfplevelcontrol (DLL 0x216, VFP_LevelControl) - the master controller
 * object for the Volcano Force Point Temple ("VFP") level.
 *
 * It owns the level-wide bookkeeping that has no single visible object:
 *  - a one-shot environment/sky transition on the first update tick
 *    (envfx 0x10c..0x10e + skySetLightIndex), gated by a global game bit;
 *  - per-map-event-state logic (the map-act value 0..3 returned by the
 *    map-event interface), each state counting down the shared timer
 *    gVfpLevelControlTimer and rolling up groups of progress bits into summary
 *    bits;
 *  - the spell-tablet ordered-sequence puzzle (VFP_LevelControl_updateSpellTabletPuzzle), which
 *    requires the four step bits to light in order and grants the
 *    "sequence done" bit when all four are set;
 *  - two music latches driven through GameBitLatch_Update.
 */
#include "main/audio/music_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/lightmap_api.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/objtype.h"
#include "main/rcp_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "main/sky_api.h"
#include "sys/objects.h"
#include "main/dll/VF/dll_0216_vfplevelcontrol.h"

int gVfpLevelControlTimer = 0x82;

#define VFPLEVELCONTROL_OBJGROUP 9

/* Ordered spell-tablet sequence: the four step bits must light in this
   array order (advanced by VFP_LevelControl_updateSpellTabletPuzzle); lighting them out of order
   resets the puzzle. SEQUENCE_DONE is granted once all four are set. */
enum
{
    GAMEBIT_VFP_SEQ_STEP_0 = 0xe1a,
    GAMEBIT_VFP_SEQ_STEP_1 = 0xe19,
    GAMEBIT_VFP_SEQ_STEP_2 = 0xe17,
    GAMEBIT_VFP_SEQ_STEP_3 = 0xe18,
    GAMEBIT_VFP_SEQ_DONE = 0xe1b
};

/* the level's intro environment transition (run once) */
#define GAMEBIT_VFP_SKY_PENDING 0xd72 /* request the day sky swap, cleared after */
#define VFP_ENVFX_INTRO_0       0x10c
#define VFP_ENVFX_INTRO_1       0x10d
#define VFP_ENVFX_INTRO_2       0x10e

#define GAMEBIT_VFP_LATCH 0xdcf /* music-latch bit shared by both latches */
#define VFP_MUSIC_A       0xe1
#define VFP_MUSIC_B       0x96

#define VFP_TIMER_INIT 0x82


/* Advance the ordered spell-tablet puzzle. The four step bits must be
   set in array order; the next-expected bit advances the step, any
   later bit lighting early resets the whole puzzle. */
void VFP_LevelControl_updateSpellTabletPuzzle(GameObject* obj)
{
    s16* p;
    VfpLevelControlState* state = obj->extra;
    s16 bits[4];
    s16 i;

    if (state->latch.fields.sequenceStep < 4)
    {
        bits[0] = mainGetBit(GAMEBIT_VFP_SEQ_STEP_0);
        bits[1] = mainGetBit(GAMEBIT_VFP_SEQ_STEP_1);
        bits[2] = mainGetBit(GAMEBIT_VFP_SEQ_STEP_2);
        bits[3] = mainGetBit(GAMEBIT_VFP_SEQ_STEP_3);
        i = state->latch.fields.sequenceStep;
        p = &bits[i];
        for (; i < 4; i++)
        {
            if (i == state->latch.fields.sequenceStep)
            {
                if (*p != 0)
                {
                    state->latch.fields.sequenceStep++;
                    if (state->latch.fields.sequenceStep == 4)
                    {
                        mainSetBits(GAMEBIT_VFP_SEQ_DONE, 1);
                    }
                }
            }
            else if (*p != 0)
            {
                state->latch.fields.sequenceStep = 0;
                mainSetBits(GAMEBIT_VFP_SEQ_STEP_0, 0);
                mainSetBits(GAMEBIT_VFP_SEQ_STEP_1, 0);
                mainSetBits(GAMEBIT_VFP_SEQ_STEP_2, 0);
                mainSetBits(GAMEBIT_VFP_SEQ_STEP_3, 0);
                break;
            }
            p++;
        }
    }
}

int VFP_LevelControl_getExtraSize(void)
{
    return 0x1c;
}

int VFP_LevelControl_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_LevelControl_free(GameObject* obj)
{
    Rcp_DisableHeatEffect();
    objFreeObjectType(obj, VFPLEVELCONTROL_OBJGROUP);
    Music_Trigger(VFP_MUSIC_A, 0);
}

void VFP_LevelControl_render(void)
{
}

void VFP_LevelControl_hitDetect(void)
{
}

void VFP_LevelControl_update(GameObject* obj)
{
    VfpLevelControlState* state = (obj)->extra;
    GameObject* player = Obj_GetPlayerObject();
    u8 mapEventState;

    if ((obj)->userData1 == 0 && mainGetBit(GAMEBIT_VFP_EnvironmentRelated0EF6) == 0u)
    {
        if (mainGetBit(GAMEBIT_VFP_SKY_PENDING) != 0u)
        {
            getEnvfxActImmediately(obj, obj, VFP_ENVFX_INTRO_0, 0);
            getEnvfxActImmediately(obj, obj, VFP_ENVFX_INTRO_1, 0);
            getEnvfxActImmediately(obj, obj, VFP_ENVFX_INTRO_2, 0);
            skySetLightIndex(1, 0.0f);
            mainSetBits(GAMEBIT_VFP_SKY_PENDING, 0);
        }
        (obj)->userData1 = 1;
    }

    coordsToMapCell(player->anim.localPosX, player->anim.localPosZ);
    mapEventState = (*gMapEventInterface)->getMapAct((obj)->anim.mapEventSlot);
    switch (mapEventState)
    {
    case 0:
        break;
    case 1:
        if (gVfpLevelControlTimer != 0)
        {
            gVfpLevelControlTimer -= (s16)(int)timeDelta;
            if (gVfpLevelControlTimer <= 0)
            {
                gVfpLevelControlTimer = 0;
            }
        }
        Obj_GetPlayerObject();
        if (mainGetBit(0x4ec) == 0u && mainGetBit(0x9b1) != 0u && mainGetBit(0x9b2) != 0u)
        {
            mainSetBits(0x4ec, 1);
        }
        if (mainGetBit(0xd6d) != 0u && mainGetBit(0xd6e) != 0u && mainGetBit(0xd6f) != 0u && mainGetBit(0xd70) != 0u)
        {
            mainSetBits(0xcfb, 1);
        }
        break;
    case 2:
        if (gVfpLevelControlTimer != 0)
        {
            gVfpLevelControlTimer -= (s16)(int)timeDelta;
            if (gVfpLevelControlTimer <= 0)
            {
                gVfpLevelControlTimer = 0;
            }
        }
        VFP_LevelControl_updateSpellTabletPuzzle(obj);
        break;
    case 3:
        if (gVfpLevelControlTimer != 0)
        {
            gVfpLevelControlTimer -= (s16)(int)timeDelta;
            if (gVfpLevelControlTimer <= 0)
            {
                gVfpLevelControlTimer = 0;
            }
        }
        Obj_GetPlayerObject();
        break;
    }

    GameBitLatch_Update((GameBitLatchState*)state->latch.raw, 1, -1, -1, GAMEBIT_VFP_MusicLatch,
                        VFP_MUSIC_A);
    GameBitLatch_Update((GameBitLatchState*)state->latch.raw, 2, -1, -1, GAMEBIT_VFP_MusicLatch,
                        VFP_MUSIC_B);
}

void VFP_LevelControl_init(GameObject* obj, VfpLevelControlSetup* setup)
{
    VfpLevelControlState* state = obj->extra;
    objAddObjectType(obj, VFPLEVELCONTROL_OBJGROUP);
    state->unk02[0] = 0;
    state->unk02[1] = 0;
    state->unk02[2] = 0;
    state->unk02[3] = 0;
    state->unk02[4] = 0;
    state->unk02[5] = 0;
    state->areaMode = 1;
    if (setup->areaMode != 0 && setup->areaMode <= 2)
    {
        state->areaMode = setup->areaMode;
    }
    gVfpLevelControlTimer = VFP_TIMER_INIT;
    (*gMapEventInterface)->getMapAct(obj->anim.mapEventSlot);
    state->unk02[4] = 0;
    state->unk02[5] = 0;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    Rcp_EnableHeatEffect();
    mainSetBits(GAMEBIT_VFP_MusicLatch, 1);
    unlockLevel(0, 0, 1);
    if (mainGetBit(GAMEBIT_VFP_SEQ_DONE) != 0)
    {
        state->latch.fields.sequenceStep = 4;
    }
    else
    {
        mainSetBits(GAMEBIT_VFP_SEQ_STEP_0, 0);
        mainSetBits(GAMEBIT_VFP_SEQ_STEP_1, 0);
        mainSetBits(GAMEBIT_VFP_SEQ_STEP_2, 0);
        mainSetBits(GAMEBIT_VFP_SEQ_STEP_3, 0);
    }
}

void VFP_LevelControl_release(void)
{
}

void VFP_LevelControl_initialise(void)
{
    gVfpLevelControlTimer = VFP_TIMER_INIT;
}

ObjectDescriptor gVFP_LevelControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)VFP_LevelControl_initialise,
    (ObjectDescriptorCallback)VFP_LevelControl_release,
    0,
    (ObjectDescriptorCallback)VFP_LevelControl_init,
    (ObjectDescriptorCallback)VFP_LevelControl_update,
    (ObjectDescriptorCallback)VFP_LevelControl_hitDetect,
    (ObjectDescriptorCallback)VFP_LevelControl_render,
    (ObjectDescriptorCallback)VFP_LevelControl_free,
    (ObjectDescriptorCallback)VFP_LevelControl_getObjectTypeId,
    VFP_LevelControl_getExtraSize,
};
