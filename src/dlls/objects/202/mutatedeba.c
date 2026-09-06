#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
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

/* Baddie-family animation data shared with the sequence-driver TUs. */

void mutatedEbaPlayMoveSfx(GameObject* obj, EnemyState* state);

u8 gDusterEbaMoveTable[] = {
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x03, 0x03, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3E, 0xCC, 0xCC, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
    0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x07, 0x07, 0x07, 0x00, 0x40, 0x80, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x08, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    0x07, 0x07, 0x07, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x00, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x06, 0x05, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x07, 0x07, 0x07, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x08, 0x08,
    0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
};

void mutatedEbaPlayMoveSfx(GameObject* obj, EnemyState* state)
{
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 5:
        if (state->animEventMask != 0)
        {
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_rach_bite);
        }
        break;
    case 6:
        if (state->animEventMask != 0)
        {
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_rach_bite);
        }
        break;
    case 7:
        if (state->animEventMask != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < 0.15f)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_rach_bite);
            }
            else
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_kooshy_death);
            }
        }
        break;
    case 8:
        if (state->animEventMask != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < 0.25f)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_kooshy_hit);
            }
            else if (((GameObject*)obj)->anim.currentMoveProgress < 0.75f)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_rach_call1);
            }
            else
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_kooshy_death);
            }
        }
        break;
    }
    return;
}

void mutatedEbaUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int eventKind, int wpad0, int wpad1,
                                 Vec* wpad2, int wpad3)
{
    int move;

    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x20;
        }
        else
        {
            if ((((move = ((GameObject*)obj)->anim.currentMove) == 0) || (move == 1)) || (move == 3) || (move == 4))
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_mv_ladderslide16_250);
                ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x10;
            }
            else
            {
                baddieSetMove((GameObject*)obj, state, 4, 1.0f, 0, 0);
                ((EnemyState*)state)->userData1 = 0;
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_kooshy_call);
                ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 8;
            }
        }
    }
    return;
}

void mutatedEbaUpdateEngaged(GameObject* obj, void* state)
{
    int tblOff;

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    if (((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0) &&
        (((EnemyState*)state)->userData1 <= 1))
    {
        ((EnemyState*)state)->userData1 = 1;
        ((EnemyState*)state)->controlFlags = ((EnemyState*)state)->controlFlags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ((EnemyState*)state)->userData1 += 1;
        if (((EnemyState*)state)->userData1 > 10)
        {
            ((EnemyState*)state)->userData1 = 3;
        }
        if (((EnemyState*)state)->turnOctant < 4)
        {
            tblOff = (u32)((EnemyState*)state)->userData1 * 0xc;
            baddieSetMove((GameObject*)obj, state, gDusterEbaMoveTable[tblOff + 8],
                        *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
        }
        else
        {
            tblOff = (u32)((EnemyState*)state)->userData1 * 0xc;
            baddieSetMove((GameObject*)obj, state, gDusterEbaMoveTable[tblOff + 9],
                        *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
        }
    }
    mutatedEbaPlayMoveSfx(obj, (EnemyState*)state);
    return;
}

void mutatedEbaUpdateIdle(GameObject* obj, void* state)
{
    int tblOff;
    u32 phase;

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        phase = ((EnemyState*)state)->userData1;
        if (phase == 0)
        {
            ((EnemyState*)state)->userData1 += 1;
        }
        else if (phase >= 2)
        {
            ((EnemyState*)state)->userData1 = 0;
        }
        tblOff = (u32)((EnemyState*)state)->userData1 * 0xc;
        baddieSetMove((GameObject*)obj, state, gDusterEbaMoveTable[tblOff + 8],
                    *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
    }
    mutatedEbaPlayMoveSfx(obj, (EnemyState*)state);
    return;
}

void mutatedEbaInit(u32 unused, int state)
{
    float fa;

    ((EnemyState*)state)->sightRange = 60.0f;
    ((EnemyState*)state)->flags2E4 = 0x46001;
    ((EnemyState*)state)->animPlaySpeed = 0.01f;
    ((EnemyState*)state)->gravity = 0.006f;
    ((EnemyState*)state)->drag = 0.95f;
    ((EnemyState*)state)->moveId0 = 0;
    fa = 1.0f;
    ((EnemyState*)state)->moveSpeedScale0 = 1.0f;
    ((EnemyState*)state)->moveId1 = 4;
    ((EnemyState*)state)->moveSpeedScale1 = fa;
    ((EnemyState*)state)->moveId2 = 3;
    ((EnemyState*)state)->moveSpeedScale2 = fa;
    ((EnemyState*)state)->userData1 = 1;
    ((EnemyState*)state)->current = 0xa;
    return;
}
