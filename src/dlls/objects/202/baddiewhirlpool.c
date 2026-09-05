#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/baddie_state.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/pad_api.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/baddie_frozen.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_api.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "dlls/objects/225_WispBaddie.h"
#include "main/trig_float_helpers.h"
#include "main/obj_link.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dolphin/mtx.h"
#include "main/dll/mikaladon.h"
#include "main/dll/magicPlant.h"
#include "main/dll/kooshy.h"
#include "main/dll/weevil.h"
#include "main/trig.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster_api.h"
#include "main/track_bbox_api.h"
#include "main/sky_interface.h"
#include "main/dll/duster.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "main/dll/duster_wb.h"
#include "main/obj_query.h"
#include "main/dll/hoodedzyck.h"
#include "main/camera_interface.h"
#include "main/model_light.h"
#include "main/dll/firecrawler.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/snowworm.h"
#include "main/dll/baddiewhirlpool.h"
#include "track/intersect_whirlpool_api.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

#define ICEBADDIE_OBJGROUP_SECONDARY 80
#define ICEBADDIE_HIT_VOLUME_SLOT    10


void whirlpool_updateWhileFrozen(GameObject* wpad0, u8* wpad1, GameObject* attacker, int wpad3, int wpad4, int wpad5,
                                 Vec* wpad6, int wpad7)
{
}

void iceBaddie_enterWhirlpoolGroup(GameObject* obj, EnemyState* state)
{
    ObjHitsPriorityState* hitState;

    if (state->userData2 == 0)
    {
        objAddObjectType(obj, ICEBADDIE_OBJGROUP_SECONDARY);
        state->userData2 = 1;
    }
    ObjHits_SetHitVolumeSlot(&obj->anim, ICEBADDIE_HIT_VOLUME_SLOT, 1, 0);
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    (obj)->anim.rotX -= 256;
}

void iceBaddie_leaveWhirlpoolGroup(GameObject* obj, EnemyState* state)
{
    if (state->userData2 != 0)
    {
        objFreeObjectType(obj, ICEBADDIE_OBJGROUP_SECONDARY);
        state->userData2 = 0;
    }
    *(u16*)obj = (float)(int)(obj)->anim.rotX - 256.0f * timeDelta;
}

void baddie_initWhirlpoolState(int* obj, EnemyState* state)
{
    f32 fz;
    state->sightRange = 60.0f;
    *(char*)&state->userData2 = state->aggroRange;
    state->aggroRange = 160.0f;
    state->flags2E4 = 0x42001;
    state->animPlaySpeed = 0.01f;
    state->gravity = 0.006f;
    state->drag = 0.95f;
    state->moveId0 = 0;
    fz = 1.0f;
    state->moveSpeedScale0 = fz;
    state->moveId1 = 5;
    state->moveSpeedScale1 = fz;
    state->moveId2 = 7;
    state->moveSpeedScale2 = fz;
    state->userData1 = 1;
    state->userData2 = 0;
    ObjModel_SetRenderCallback((u8*)Obj_GetActiveModel((GameObject*)obj), renderWhirlpool);
}
