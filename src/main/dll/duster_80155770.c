#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/object.h"
#include "main/obj_placement.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/sky_interface.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/objfsa.h"
#include "main/frame_timing.h"
#include "main/dll/player_api.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster.h"
#include "main/dll/dll_00D8_pinponspike_arc_api.h"


/* object-type id of the pollen-spit projectile spawned by spittingEbaSpawnPollen
 * (see file docblock). */
#define DUSTER_CHILD_OBJ_POLLEN_SPIT 0x47b
#define DUSTER_HIT_VOLUME_SLOT       10


extern f32 gDusterWallProbeOffsets[];
extern u8 gDusterEbaMoveTable[];

void rachnopUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind, int wpad0, int wpad1, void* wpad2, int wpad3)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else if (eventKind != 0x11)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_lash_254);
        ((BaddieState*)state)->hitCounter = 0;
    }
    return;
}

void rachnopUpdateIdle(int* obj, int state)
{
    int cond;

    if (((BaddieState*)state)->userData1 == 0)
    {
        rachnopFindWallPlane(obj, state);
    }
    else
    {
        if ((((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1) &&
            (cond = fn_80295CBC((GameObject*)(*(int*)&((BaddieState*)state)->trackedObj)), cond != 0))
        {
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
        }
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_id_253);
            Baddie_SetMove((int)obj, state, 2, gWallPlaneOne, 0, 0);
        }
    }
    return;
}

void rachnopUpdateApproach(int* obj, int state)
{
    int cond;

    if (((BaddieState*)state)->userData1 == 0)
    {
        rachnopFindWallPlane(obj, state);
    }
    else if ((((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1) &&
             (cond = fn_80295CBC((GameObject*)(*(int*)&((BaddieState*)state)->trackedObj)), cond != 0))
    {
        fireflyLanternSteerTowardTarget((short*)obj, state, 0x19, (double)(0.5f));
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            Baddie_SetMove((int)obj, state, 0, (0.5f), 0, 0);
            Sfx_PlayFromObject((u32)obj, SFXTRIG_id_252);
        }
    }
    else
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
    }
    return;
}

void rachnopUpdateAttack(int* obj, int state)
{
    short move;
    int cond;
    u16 outIds[2];
    float outVec[3];

    if (((BaddieState*)state)->userData1 == 0)
    {
        rachnopFindWallPlane(obj, state);
    }
    else if ((((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1) &&
             (cond = fn_80295CBC((GameObject*)(*(int*)&((BaddieState*)state)->trackedObj)), cond != 0))
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DUSTER_HIT_VOLUME_SLOT, 1, 0);
        move = ((GameObject*)obj)->anim.currentMove;
        if (move == 3)
        {
            fireflyLanternSteerTowardTarget((short*)obj, state, 0x19, (double)gWallPlaneZero);
        }
        else if ((move == 0) || (move == 1))
        {
            fireflyLanternSteerTowardTarget((short*)obj, state, 0x19, (double)0.5f);
        }
        fireflyLanternGetTargetAngleAndDistance((int)obj, state, outIds, outVec);
        if (((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0) ||
            ((outIds[0] < 0x5dc && (((GameObject*)obj)->anim.currentMove != 1))))
        {
            if (outIds[0] < 0x5dc)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_251);
                Baddie_SetMove((int)obj, state, 1, 0.5f, 0, 0);
            }
            else
            {
                Baddie_SetMove((int)obj, state, 3, 0.5f, 0, 0);
            }
        }
    }
    else
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
    }
    return;
}

void rachnopInit(u32 unused, int state)
{
    float fa;
    float fb;

    ((BaddieState*)state)->speedScale = (25.0f);
    *(u32*)&((BaddieState*)state)->unk2E4 = 1;
    fa = (0.1f);
    ((BaddieState*)state)->unk308 = (0.1f);
    ((BaddieState*)state)->animDeltaScale = fa;
    ((BaddieState*)state)->unk304 = (0.97f);
    ((BaddieState*)state)->unk320 = 0;
    fb = 1.5f;
    *(float*)&((BaddieState*)state)->eventFlags = 1.5f;
    ((BaddieState*)state)->unk321 = 4;
    fa = gWallPlaneOne;
    ((BaddieState*)state)->unk318 = gWallPlaneOne;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fb;
    ((DusterState*)state)->phaseTimer = gWallPlaneZero;
    ((BaddieState*)state)->userData1 = 0;
    ((BaddieState*)state)->userData2 = 0;
    ((BaddieState*)state)->pathStep = fa;
    return;
}
