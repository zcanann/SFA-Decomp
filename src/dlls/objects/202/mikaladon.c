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

#define SEQOBJ11E_GCROBOT_DROP_OBJ 0x6b5

/* guardClaw_update: state-table driver: walks the 12-byte gSeq11EStateTable state
 * rows, advancing on GameBit + sequence flags and kicking the matching anim. */

const f32 gMikaladonZero[] = {0.0f};

const f32 gMikaladonDefaultPeriod[] = {60.0f};

enum MikaladonVerticalPhase
{
    MIKALADON_PHASE_ORBIT = 0,
    MIKALADON_PHASE_DESCEND = 1,
    MIKALADON_PHASE_ASCEND = 2
};

#define MIKALADON_ORBIT_ANGLE_SPEED     75.0f
#define MIKALADON_TRIGGER_RADIUS_SCALE  1.3f
#define MIKALADON_DESCENT_SPEED         0.5f
#define MIKALADON_DESCENT_DISTANCE      500.0f
#define MIKALADON_ASCENT_SPEED          1.5f
#define MIKALADON_DROP_INTERVAL         100
#define MIKALADON_DROP_HEIGHT_OFFSET    5.0f
#define MIKALADON_AMBIENT_SFX_MIN_DELAY 60
#define MIKALADON_AMBIENT_SFX_MAX_DELAY 120

/* mikaladon_update: firefly hover update: circle drift, bob between heights,
 * periodically drop a spawned object, ambient sfx timers. */

void mikaladon_updateWhileFrozen(GameObject* obj, u8* state, GameObject* attacker, int msg, int wpad0, int wpad1, Vec* wpad2,
                                 int wpad3)
{
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_dn_boar1_c_248);
    ((EnemyState*)state)->current = 0;
    ((EnemyState*)state)->flags2E4 |= 0x20;
    ((EnemyState*)state)->flags2E8 |= 0x8;
}

static void mikaladonRearmAmbientSfx(GameObject* obj, EnemyState* state)
{
    state->intervalTimer -= timeDelta;
    if (state->intervalTimer <= gMikaladonZero[0])
    {
        state->intervalTimer =
            (f32)(int)randomGetRange(MIKALADON_AMBIENT_SFX_MIN_DELAY, MIKALADON_AMBIENT_SFX_MAX_DELAY);
        Sfx_PlayFromObject(obj, SFXTRIG_id_31);
    }
}

static void mikaladonDropPayload(GameObject* obj)
{
    MikaladonDropSetup* setup;
    GameObject* spawned;

    setup = (MikaladonDropSetup*)Obj_AllocObjectSetup(sizeof(MikaladonDropSetup), SEQOBJ11E_GCROBOT_DROP_OBJ);
    setup->base.posX = obj->anim.localPosX;
    setup->base.posY = MIKALADON_DROP_HEIGHT_OFFSET + obj->anim.localPosY;
    setup->base.posZ = obj->anim.localPosZ;
    setup->base.color[0] = 1;
    setup->base.color[1] = 1;
    setup->base.color[2] = 0xff;
    setup->base.color[3] = 0xff;
    spawned = loadObjectAtObject(obj, &setup->base);
    if (spawned != NULL)
    {
        spawned->ownerObj = obj;
        Sfx_PlayFromObject(obj, SFXTRIG_id_249);
    }
}

void mikaladon_update(GameObject* obj, EnemyState* state)
{
    f32 y;
    f32 sinOut;
    f32 cosOut;

    state->phaseAngle =
        MIKALADON_ORBIT_ANGLE_SPEED * timeDelta + (f32)(u32)state->phaseAngle;
    angleToVec2Precise(state->phaseAngle, &sinOut, &cosOut);
    sinOut = sinOut * state->aggroRange + state->mikaladon.orbitCenterX;
    cosOut = cosOut * state->aggroRange + state->mikaladon.orbitCenterZ;
    if (state->userData1 == MIKALADON_PHASE_ORBIT)
    {
        f32 dx;
        f32 dz;

        y = obj->anim.localPosY;
        dx = state->mikaladon.orbitCenterX -
             ((GameObject*)state->trackedObj)->anim.localPosX;
        dz = state->mikaladon.orbitCenterZ -
             ((GameObject*)state->trackedObj)->anim.localPosZ;
        if (sqrtf(dx * dx + dz * dz) <= MIKALADON_TRIGGER_RADIUS_SCALE * state->aggroRange)
        {
            state->userData1 = MIKALADON_PHASE_DESCEND;
            state->userData2 = 0;
        }
    }
    else if (state->userData1 == MIKALADON_PHASE_DESCEND)
    {
        y = obj->anim.localPosY - MIKALADON_DESCENT_SPEED * timeDelta;
        if (y <= state->mikaladon.homeY - MIKALADON_DESCENT_DISTANCE)
        {
            state->userData1 = MIKALADON_PHASE_ASCEND;
        }
        else
        {
            state->userData2 =
                (f32)(u32)state->userData2 + timeDelta;
            if (state->userData2 > MIKALADON_DROP_INTERVAL)
            {
                state->userData2 = 0;
                if ((u8)Obj_CanSetupObject() != 0)
                {
                    mikaladonDropPayload(obj);
                }
            }
        }
    }
    else
    {
        y = MIKALADON_ASCENT_SPEED * timeDelta + obj->anim.localPosY;
        if (y >= state->mikaladon.homeY)
        {
            state->userData1 = MIKALADON_PHASE_ORBIT;
        }
    }
    obj->anim.velocityX = oneOverTimeDelta * (sinOut - obj->anim.localPosX);
    obj->anim.velocityY = oneOverTimeDelta * (y - obj->anim.localPosY);
    obj->anim.velocityZ = oneOverTimeDelta * (cosOut - obj->anim.localPosZ);
    baddieTurnTowardLookDir(obj, state, 0xf, 7.5f, 1.0f, 0);
    mikaladonRearmAmbientSfx(obj, state);
    state->mikaladon.loopSfxTimer -= timeDelta;
    if (state->mikaladon.loopSfxTimer <= gMikaladonZero[0])
    {
        state->mikaladon.loopSfxTimer = gMikaladonDefaultPeriod[0];
        Sfx_PlayFromObject(obj, SFXTRIG_id_24a);
    }
}

void mikaladon_init(GameObject* obj, EnemyState* state)
{
    f32 zero;
    f32 lblA;
    f32 a, b;

    zero = gMikaladonDefaultPeriod[0];
    state->sightRange = zero;
    state->flags2E4 = 1;
    state->animPlaySpeed = 0.01f;
    state->gravity = 0.006f;
    lblA = 1.0f;
    state->drag = lblA;
    state->moveId0 = 1;
    state->moveSpeedScale0 = lblA;
    state->moveId1 = 3;
    state->moveSpeedScale1 = lblA;
    state->moveId2 = 1;
    state->moveSpeedScale2 = lblA;
    state->mikaladon.orbitCenterX = obj->anim.localPosX;
    state->mikaladon.homeY = obj->anim.localPosY;
    state->mikaladon.orbitCenterZ = obj->anim.localPosZ;
    state->userData1 = MIKALADON_PHASE_ORBIT;
    state->userData2 = 0;
    state->phaseAngle = 0;
    state->mikaladon.loopSfxTimer = zero;
    state->intervalTimer = zero;
    state->pathStep = 8.0f;

    angleToVec2Precise(state->phaseAngle, &a, &b);
    obj->anim.localPosX =
        a * state->aggroRange + state->mikaladon.orbitCenterX;
    obj->anim.localPosZ =
        b * state->aggroRange + state->mikaladon.orbitCenterZ;
}
