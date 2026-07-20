/* DLL 0x011E (magiccavebottom) - Magic Cave bottom area objects [0x8018ADB4-0x8018AFC8). */
#include "main/dll/dll_011E_magiccavebottom.h"
#include "main/objseq.h"
#include "main/objprint_render_api.h"
#include "main/sky_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/obj_trigger.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/tricky_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/object_descriptor.h"


#define MAGICCAVEBOTTOM_GAMEBIT_ACTIVE 0xefb /* bottom-area loaded/active latch */
#define MAGICCAVE_GAMEBIT_WARP_READY 0x91e   /* handoff to top: perform warp sequence */
#define MAGICCAVE_GAMEBIT_WARP_DEST 0x1b8    /* warp destination map index */

/* Env-fx ids seeded on area setup (getEnvfxAct 3rd arg) */
#define MAGICCAVEBOTTOM_ENVFX_A 0x2c
#define MAGICCAVEBOTTOM_ENVFX_B 0x2d

/* MagicCaveBottom_update sequence state machine (state byte at extra[0]) */
#define MAGICCAVEBOTTOM_STATE_SETUP 0     /* latch active, seed env fx, run intro seq */
#define MAGICCAVEBOTTOM_STATE_START_MUSIC 1 /* kick off the adventure music */
#define MAGICCAVEBOTTOM_STATE_IDLE 2      /* show prompt, wait for the player trigger */
#define MAGICCAVEBOTTOM_STATE_WARP 3      /* latch warp-ready and warp to the destination */

int MagicCaveBottom_getExtraSize(void)
{
    return sizeof(MagicCaveBottomState);
}

void MagicCaveBottom_free(GameObject* obj)
{
    (void)obj;
    mainSetBits(MAGICCAVEBOTTOM_GAMEBIT_ACTIVE, 0);
    Music_Trigger(MUSICTRIG_PU3_Adventure, 0);
}

void MagicCaveBottom_update(GameObject* obj)
{
    MagicCaveBottomSetup* setup;
    MagicCaveBottomState* state;

    setup = (MagicCaveBottomSetup*)obj->anim.placementData;
    state = obj->extra;

    obj->anim.rotX = (s16)((s32)setup->rotation << 8);
    switch (state->phase)
    {
    case MAGICCAVEBOTTOM_STATE_SETUP:
        mainSetBits(MAGICCAVEBOTTOM_GAMEBIT_ACTIVE, 1);
        envFxActFn_800887f8(0);
        getEnvfxAct(obj, obj, MAGICCAVEBOTTOM_ENVFX_A, 0);
        getEnvfxAct(obj, obj, MAGICCAVEBOTTOM_ENVFX_B, 0);
        state->phase = MAGICCAVEBOTTOM_STATE_START_MUSIC;
        if (setup->sequenceBank != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        }
        else
        {
            (*gObjectTriggerInterface)->runSequence(2, obj, -1);
        }
        break;
    case MAGICCAVEBOTTOM_STATE_START_MUSIC:
        Music_Trigger(MUSICTRIG_PU3_Adventure, 1);
        state->phase = MAGICCAVEBOTTOM_STATE_IDLE;
        break;
    case MAGICCAVEBOTTOM_STATE_IDLE:
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0)
        {
            setAButtonIcon(0x19);
        }
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            state->phase = MAGICCAVEBOTTOM_STATE_WARP;
            if (setup->sequenceBank != 0)
            {
                (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(3, obj, -1);
            }
        }
        else
        {
            objRenderFn_80041018(obj);
        }
        break;
    case MAGICCAVEBOTTOM_STATE_WARP:
        mainSetBits(MAGICCAVE_GAMEBIT_WARP_READY, 1);
        warpToMap(mainGetBit(MAGICCAVE_GAMEBIT_WARP_DEST), 0);
        break;
    }
}

ObjectDescriptor gMagicCaveBottomObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    0,
    (ObjectDescriptorCallback)MagicCaveBottom_update,
    0,
    0,
    (ObjectDescriptorCallback)MagicCaveBottom_free,
    0,
    MagicCaveBottom_getExtraSize,
};
