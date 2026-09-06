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

#define GROUND_BADDIE_PI 3.14159274f
#define GROUND_BADDIE_ANGLE_UNIT_SCALE 32768.0f
#define GROUND_BADDIE_PUSH_RADIUS 50.0f
#define GROUND_BADDIE_PUSH_MAX_DEPTH -20.0f


/* gcRobotPatrol (mikaladon_update): periodically dropped object; parented back to
 * the dropper via +0xC4 and announced with SFX 0x249. */

typedef struct
{
    f32 animSpeed; /* 0x0 */
    u32 sequenceDriven; /* 0x4 */
    u8 anim;       /* 0x8 */
    u8 next;       /* 0x9 */
    u8 alt;        /* 0xa */
    u8 flagB;      /* 0xb */
} Seq11ERow;

extern Seq11ERow gSeq11EStateTable[];

void guardClaw_update(GameObject* obj, u8* state);

void guardClaw_init(GameObject* obj, u8* state);

void groundBaddiePushPlayerOut(GameObject* obj, u8* state)
{
    GameObject* player;
    ObjPlacement* setup;
    f32 dy;
    f32 px0;
    f32 pz0;
    f32 sinA;
    f32 cosA;
    f32 base;
    f32 depth;
    f32 f2v;
    f32 dx;
    f32 dz;

    player = Obj_GetPlayerObject();
    setup = obj->anim.placement;
    dy = player->anim.localPosY - obj->anim.localPosY;
    dy = (dy >= 0.0f) ? dy : -dy;
    if (dy > GROUND_BADDIE_PUSH_RADIUS)
    {
        return;
    }
    px0 = setup->posX - GROUND_BADDIE_PUSH_RADIUS * mathSinf(GROUND_BADDIE_PI *
                                                             (f32)obj->anim.rotX /
                                                             GROUND_BADDIE_ANGLE_UNIT_SCALE);
    pz0 = setup->posZ - GROUND_BADDIE_PUSH_RADIUS * mathCosf(GROUND_BADDIE_PI *
                                                             (f32)obj->anim.rotX /
                                                             GROUND_BADDIE_ANGLE_UNIT_SCALE);
    dx = player->anim.worldPosX - px0;
    dz = player->anim.worldPosZ - pz0;
    if (sqrtf(dx * dx + dz * dz) < ((EnemyState*)state)->sightRange)
    {
        sinA = mathSinf(GROUND_BADDIE_PI * (f32)obj->anim.rotX / GROUND_BADDIE_ANGLE_UNIT_SCALE);
        cosA = mathCosf(GROUND_BADDIE_PI * (f32)obj->anim.rotX / GROUND_BADDIE_ANGLE_UNIT_SCALE);
        base = -(sinA * (px0 - sinA) + cosA * (pz0 - cosA));
        depth = base + (sinA * player->anim.previousWorldPosX + cosA * player->anim.previousWorldPosZ);
        f2v = base + (sinA * player->anim.worldPosX + cosA * player->anim.worldPosZ);
        if (f2v > 0.0f)
        {
            if (!(depth >= GROUND_BADDIE_PUSH_MAX_DEPTH))
            {
                return;
            }
            player->anim.worldPosX = player->anim.worldPosX - sinA * depth;
            player->anim.worldPosZ = player->anim.worldPosZ - cosA * depth;
            Obj_TransformWorldPointToLocal(player->anim.worldPosX, player->anim.worldPosY, player->anim.worldPosZ,
                                           &player->anim.localPosX, &player->anim.localPosY, &player->anim.localPosZ,
                                           player->anim.parent);
        }
    }
}

void guardClawUpdateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int wpad1, int wpad2, int wpad3,
                                Vec* wpad4, int wpad5)
{
    Sfx_PlayFromObject(obj, SFXTRIG_wp_pole1_c_23);
    ((EnemyState*)state)->flags2E8 |= 0x10;
}

void guardClaw_update(GameObject* obj, u8* state)
{
    GroundBaddiePlacement* def = *(GroundBaddiePlacement**)&(obj)->anim.placementData;
    u32 flags;

    if (((EnemyState*)state)->userData1 == 2 && mainGetBit(def->gameBitD) == 0)
    {
        (obj)->anim.resetHitboxFlags =
            (u8)((obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        if ((obj)->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED)
        {
            groundBaddieHandlePaidTrigger(obj, state);
        }
    }
    else
    {
        (obj)->anim.resetHitboxFlags =
            (u8)((obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
    }
    flags = ((EnemyState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_JUST_TRIGGERED)
    {
        if (gSeq11EStateTable[((EnemyState*)state)->userData1].sequenceDriven != 0)
        {
            ((EnemyState*)state)->controlFlags = flags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
        }
    }
    flags = ((EnemyState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_SEQUENCE_DRIVEN)
    {
        int anim;
        u8* animTbl;

        if (((EnemyState*)state)->userData1 == 0)
        {
            if (flags & 0x20000000)
            {
                if (mainGetBit(def->gameBitD) != 0)
                {
                    ((EnemyState*)state)->userData1 = gSeq11EStateTable[((EnemyState*)state)->userData1].alt;
                }
                else
                {
                    ((EnemyState*)state)->userData1 = gSeq11EStateTable[((EnemyState*)state)->userData1].next;
                }
            }
        }
        else if (((EnemyState*)state)->userData1 == 2)
        {
            if (mainGetBit(def->gameBitD) != 0 || !(((EnemyState*)state)->controlFlags & 0x20000000))
            {
                ((EnemyState*)state)->userData1 = gSeq11EStateTable[((EnemyState*)state)->userData1].next;
            }
        }
        else if (((EnemyState*)state)->userData1 == 3)
        {
            if (mainGetBit(def->gameBitD) != 0)
            {
                ((EnemyState*)state)->userData1 = gSeq11EStateTable[((EnemyState*)state)->userData1].alt;
            }
            else
            {
                ((EnemyState*)state)->userData1 = gSeq11EStateTable[((EnemyState*)state)->userData1].next;
            }
        }
        else
        {
            ((EnemyState*)state)->userData1 = gSeq11EStateTable[((EnemyState*)state)->userData1].next;
        }
        anim = (obj)->anim.currentMove;
        if (anim != (animTbl = (u8*)gSeq11EStateTable + 8)[((EnemyState*)state)->userData1 * 12])
        {
            if (animTbl[((EnemyState*)state)->userData1 * 12] != 0 &&
                animTbl[((EnemyState*)state)->userData1 * 12] != 4)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_eggsnatch_carry3);
            }
            baddieSetMove(
                obj, state, animTbl[((EnemyState*)state)->userData1 * 12],
                *(f32*)((u8*)gSeq11EStateTable + ((EnemyState*)state)->userData1 * 12), 0, 0xf);
        }
    }
    if (gSeq11EStateTable[((EnemyState*)state)->userData1].flagB != 0)
    {
        groundBaddiePushPlayerOut(obj, state);
    }
}

void guardClaw_init(GameObject* obj, u8* state)
{
    GroundBaddiePlacement* sub = *(GroundBaddiePlacement**)&(obj)->anim.placementData;
    f32 fz;
    ((EnemyState*)state)->sightRange = 200.0f;
    ((EnemyState*)state)->aggroRange = 300.0f;
    ((EnemyState*)state)->flags2E4 = 1;
    ((EnemyState*)state)->flags2E4 |= 0xC80;
    ((EnemyState*)state)->animPlaySpeed = 0.0055555557f;
    ((EnemyState*)state)->gravity = 0.17f;
    ((EnemyState*)state)->drag = 0.97f;
    ((EnemyState*)state)->moveId0 = 0;
    fz = 1.0f;
    ((EnemyState*)state)->moveSpeedScale0 = fz;
    ((EnemyState*)state)->moveId1 = 0;
    ((EnemyState*)state)->moveSpeedScale1 = fz;
    ((EnemyState*)state)->moveId2 = 0;
    ((EnemyState*)state)->moveSpeedScale2 = fz;
    if (sub->sequenceId != -1)
    {
        ((EnemyState*)state)->controlFlags |= 1;
    }
    (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
}

Seq11ERow gSeq11EStateTable[6] = {
    {3.0f, 0x1, 0, 1, 4, 1}, {2.0f, 0x0, 1, 2, 2, 1}, {3.0f, 0x1, 2, 3, 3, 1},
    {2.0f, 0x0, 7, 0, 4, 1}, {2.0f, 0x0, 3, 5, 5, 0}, {3.5f, 0x1, 4, 5, 5, 0},
};
