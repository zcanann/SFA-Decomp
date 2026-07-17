/*
 * Shared GroundBaddie whirlpool-group helpers.
 *
 * These three utilities sit at the head of the dll_00CA carve but are their own
 * translation unit: the carve holds two u32 conversion biases (0x803E2CE0 here,
 * 0x803E2D68 in icebaddie) and repeats 60.0f / 0.01f / 1.0f, neither of which a
 * single TU does. They are called by the generic enemy DLL (dll_00C9) as well as
 * by icebaddie.
 */
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/frame_timing.h"
#include "main/objprint_api.h"
#include "main/object.h"
#include "main/object_render_legacy.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/objanim.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/dll/baddie_control_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/obj_placement.h"
#include "main/mapEventTypes.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "string.h"
#include "main/gamebits.h"
#include "main/dll/dll_00CA_icebaddie.h"
#include "main/camera.h"
#include "main/obj_path.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_00CD_iceball.h"
#include "main/voxmaps.h"

#define ICEBADDIE_OBJGROUP_SECONDARY 80
#define ICEBADDIE_HIT_VOLUME_SLOT    10

extern void renderWhirlpool(void);
extern void ObjGroup_AddObject(int obj, int group);
extern void ObjGroup_RemoveObject(int obj, int group);

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs reset
#pragma fp_contract reset
void iceBaddie_enterWhirlpoolGroup(GameObject* obj, GroundBaddieState* state)
{
    ObjHitsPriorityState* hitState;

    if (state->baddie.inWhirlpoolGroup == 0)
    {
        ObjGroup_AddObject((int)obj, ICEBADDIE_OBJGROUP_SECONDARY);
        state->baddie.inWhirlpoolGroup = 1;
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, ICEBADDIE_HIT_VOLUME_SLOT, 1, 0);
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    (obj)->anim.rotX -= 256;
}

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs reset
#pragma fp_contract reset
void iceBaddie_leaveWhirlpoolGroup(GameObject* obj, GroundBaddieState* state)
{
    if (state->baddie.inWhirlpoolGroup != 0)
    {
        ObjGroup_RemoveObject((int)obj, ICEBADDIE_OBJGROUP_SECONDARY);
        state->baddie.inWhirlpoolGroup = 0;
    }
    *(u16*)obj = (float)(int)(obj)->anim.rotX - 256.0f * timeDelta;
}

#pragma scheduling off
#pragma peephole on
#pragma opt_common_subs reset
#pragma fp_contract reset
void baddie_initWhirlpoolState(int* obj, GroundBaddieState* state)
{
    f32 fz;
    state->baddie.speedScale = 60.0f;
    *(char*)&state->baddie.inWhirlpoolGroup = state->baddie.unk2A8;
    state->baddie.unk2A8 = 160.0f;
    state->baddie.unk2E4 = 0x42001;
    state->baddie.unk308 = 0.01f;
    state->baddie.animDeltaScale = 0.006f;
    state->baddie.unk304 = 0.95f;
    state->baddie.unk320 = 0;
    fz = 1.0f;
    *(f32*)&state->baddie.eventFlags = fz;
    state->baddie.unk321 = 5;
    state->baddie.unk318 = fz;
    state->baddie.unk322 = 7;
    state->baddie.unk31C = fz;
    state->baddie.seqEntryIndex = 1;
    state->baddie.inWhirlpoolGroup = 0;
    ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel((GameObject*)obj), renderWhirlpool);
}

