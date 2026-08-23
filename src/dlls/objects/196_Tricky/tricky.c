/*
 * Tricky companion DLL.
 *
 * Blend-channel weight animation (Tricky_updateBlendChannelWeight), the
 * color-variant fade (trickyUpdateColorVariant), impress reaction (trickyImpress), queued-path particle emission
 * (Tricky_emitQueuedPathParticles), baddie target search
 * (trickyFindNearestUsableBaddie) and queued-command target selection
 * (trickySelectQueuedCommandTarget), plus small state accessors.
 */

#include "main/dll/partfx_interface.h"
#include "main/vecmath.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/tricky_state.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "main/model.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_80136a40.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/dll_0019_dll19func0.h"
#include "main/track_dolphin_api.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/rom_curve_def.h"
#include "main/lightmap_api.h"
#include "main/pi_dolphin_api.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/obj_list.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/objHitReact.h"
#include "main/objfx.h"
#include "main/dll/objfsa.h"
#include "main/gamebits.h"
#include "main/dll/skeetla.h"
#include "main/objprint_sound_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/baddie/trickyfollow.h"
#include "main/dll/objfsa_query_api.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_0014_api.h"
#include "main/dll/skeetla_anim_api.h"
#include "main/dll/Hcurves_api.h"
#include "main/dll/baddie/MMP_critterspit.h"
#include "main/dll/mmp_cratercritter.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx.h"
#include "dlls/objects/243_flameblast.h"
#include "dlls/objects/235.h"
#include "dlls/objects/312_GroundAnima.h"
#include "main/dll/tumbleweedbush.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/dll/player_target.h"
#include "game/objects/object_setup.h"
#include "main/trig.h"
#include "main/frustum.h"
#include "dlls/objects/245_SidekickBal.h"
#include "dlls/objects/417_NW_mammoth.h"
#include "dlls/objects/429_SH_thorntai.h"
#include "main/dll/tricky_substates.h"
#include "dlls/objects/209_TumbleWeedB.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/dll/skeetla_route_api.h"
#include "main/dll/tricky_rollroute.h"
#include "main/game_ui_interface.h"
#include "main/sky_interface.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/pad.h"
#include "main/dll/tricky_api.h"
#include "main/objprint_api.h"
#include "main/dll/objfx_api.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/object_render.h"
#include "main/shader_api.h"
#include "main/objanim.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/track_bbox_api.h"
#include "main/obj_path.h"
#include "main/model_light.h"
#include "dolphin/mtx.h"
#include "main/dll/cmenu_item_table.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/dll/baddie_state.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state_api.h"
#include "main/dll/WC/WCbeacon.h"
#include "main/voxmaps.h"
#include "main/dll/DR/dll_026B_drchimmey.h"
#include "dlls/objects/452_DIMIceWall.h"
#include "dlls/objects/448_DIMLogFire.h"
#include "dlls/objects/465_DIMTruthHor.h"
#include "dlls/objects/435_SH_Beacon.h"
#include "dlls/objects/437.h"
#include "main/main_internal.h"
#include "main/dll/baddie_frozen.h"
#include "dlls/objects/316_XYZAnimator.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/pi_dolphin_path_api.h"
#include "main/newshadows_audio_api.h"

typedef struct {
    u16 a;
    u16 b;
} TrickySfxPair;

typedef struct TrickyBaddieTargetPlacement {
    u8 pad0[0x14];
    s32 mapEventId;
    s16 disableGameBit;
    s16 enableGameBit;
} TrickyBaddieTargetPlacement;

STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, mapEventId) == 0x14);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, disableGameBit) == 0x18);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, enableGameBit) == 0x1A);

/* Rena audio enum names for Tricky voice lines. */
#define TRICKY_VOICE_SFX_TIRED                 0x298
#define TRICKY_VOICE_SFX_GROWL                 0x299
#define TRICKY_VOICE_SFX_ROLLING               0x29b
#define TRICKY_VOICE_SFX_FINISH_FLAME          0x29d
#define TRICKY_VOICE_SFX_WAIT_UP_FOX           0x34d
#define TRICKY_VOICE_SFX_WAIT_FOR_ME           0x34e
#define TRICKY_VOICE_SFX_HEY                   0x34f
#define TRICKY_VOICE_SFX_GET_OFF               0x350
#define TRICKY_VOICE_SFX_LOOK_AT_THIS          0x351
#define TRICKY_VOICE_SFX_IM_HUNGRY             0x352
#define TRICKY_VOICE_SFX_YAWN2                 0x353
#define TRICKY_VOICE_SFX_YAWN                  0x354
#define TRICKY_VOICE_SFX_LETS_PLAY             0x355
#define TRICKY_VOICE_SFX_COOL                  0x356
#define TRICKY_VOICE_SFX_SNIFF                 0x357
#define TRICKY_VOICE_SFX_BAD_GUY               0x358
#define TRICKY_VOICE_SFX_FOOD                  0x359
#define TRICKY_VOICE_SFX_THERES_SOMETHING_NEAR 0x35a
#define TRICKY_VOICE_SFX_GET_MFOX              0x35b
#define TRICKY_VOICE_SFX_YEAH                  0x35c
#define TRICKY_VOICE_SFX_IM_NOT_DOING_IT       0x35d
#define TRICKY_VOICE_SFX_HELLO                 0x35e
#define TRICKY_VOICE_SFX_HI_FELLA              0x35f
#define TRICKY_VOICE_SFX_DUM_DE_DUM            0x360
#define TRICKY_VOICE_SFX_LAUGH                 0x361
#define TRICKY_VOICE_SFX_CHEWING               0x362
#define TRICKY_VOICE_SFX_MMMM_TASTY            0x363
#define TRICKY_VOICE_SFX_IM_STUFFED            0x364
#define TRICKY_VOICE_SFX_WHERE_ARE_WE_GOING    0x365
#define TRICKY_VOICE_SFX_SCARED                0x392

const u16 gTrickyInitialPathControlStartId[1] = {0x0A08};
const TrickySfxPair sTrickyImpressSfxPair = {TRICKY_VOICE_SFX_COOL, TRICKY_VOICE_SFX_YEAH};
const u16 gTrickyQuestPromptSfxIds[2] = {TRICKY_VOICE_SFX_THERES_SOMETHING_NEAR, TRICKY_VOICE_SFX_LOOK_AT_THIS};
const u16 gTrickySubstateSfxIdPairA[2] = {TRICKY_VOICE_SFX_YEAH, TRICKY_VOICE_SFX_LAUGH};
const u16 gTrickySubstateSfxIdPairB[2] = {TRICKY_VOICE_SFX_YEAH, TRICKY_VOICE_SFX_LAUGH};
const u16 gSkeetlaFootstepSfxIds01[2] = {TRICKY_VOICE_SFX_LAUGH, TRICKY_VOICE_SFX_WHERE_ARE_WE_GOING};
const u16 gSkeetlaFootstepSfxId2[1] = {TRICKY_VOICE_SFX_LETS_PLAY};

#define gTrickyFloatZero              0.0f
#define sTrickyFloatTen               10.0f
#define sTrickyFloat0_004             0.004f
#define sTrickyFloatOne               1.0f
#define sTrickyFloat0_01              0.01f
#define sTrickyFloat0_7               0.7f
#define sTrickyFloatNeg0_01           -0.01f
#define sTrickyFloatTwo               2.0f
#define TRICKY_FLOAT_TEN              sTrickyFloatTen
#define TRICKY_FLOAT_0_004            sTrickyFloat0_004
#define TRICKY_FLOAT_ONE              sTrickyFloatOne
#define TRICKY_FLOAT_0_01             sTrickyFloat0_01
#define TRICKY_FLOAT_0_7              sTrickyFloat0_7
#define TRICKY_FLOAT_NEG_0_01         sTrickyFloatNeg0_01
#define TRICKY_FLOAT_TWO              sTrickyFloatTwo
#define TRICKY_COLOR_FADE_ALPHA_SCALE (sTrickyColorFadeAlphaScale[0])

extern const char sTrickyShouldNeverStopCirclingError[];

extern char sSidekickCommandDebugTextBlock[];

extern const f32 gTrickyTimer30Frames[1];
extern const f32 gTrickyTimer150Frames[1];
extern const f32 gTrickyVisibilityProbeRadius[1];
extern const f32 gTrickyRemoteRecallDistanceSq[1];
extern const f32 gTrickyRecallCooldownFrames[1];
extern const f32 gTrickyAudioEventMinSpeed[1];
extern const f32 gTrickyAmbientActivityBase[1];
extern const f64 gTrickyAmbientWanderScale[1];
extern const f32 gTrickyChildVoicePeriodFrames[1];

/* Repeated Tricky movement-animation contract values. */
#define TRICKY_TIMER_20_FRAMES           (gTrickyTimer20Frames[0])
#define TRICKY_WATER_COOLDOWN_FRAMES     TRICKY_TIMER_600_FRAMES
#define TRICKY_CHILD_BLINK_PERIOD_FRAMES (gTrickyTimer30Frames[0])
#define TRICKY_CHILD_BLINK_HOLD_FRAMES   TRICKY_TIMER_20_FRAMES
#define TRICKY_CHILD_BLINK_FORCE_FRAMES  (gTrickyTimer150Frames[0])
#define TRICKY_CHILD_VOICE_PERIOD_FRAMES (gTrickyChildVoicePeriodFrames[0])
#define TRICKY_REMOTE_RECALL_DISTANCE_SQ (gTrickyRemoteRecallDistanceSq[0])
#define TRICKY_VISIBILITY_PROBE_RADIUS   (gTrickyVisibilityProbeRadius[0])
#define TRICKY_RECALL_COOLDOWN_FRAMES    (gTrickyRecallCooldownFrames[0])
#define TRICKY_AUDIO_EVENT_MIN_SPEED     (gTrickyAudioEventMinSpeed[0])
#define TRICKY_AMBIENT_ACTIVITY_BASE     (gTrickyAmbientActivityBase[0])
#define TRICKY_AMBIENT_WANDER_SCALE      (gTrickyAmbientWanderScale[0])
#define gTrickyPositionOffsetScale       0.1f
#define TRICKY_POSITION_OFFSET_SCALE     gTrickyPositionOffsetScale
#define TRICKY_PATH_SEARCH_BULK_STEPS    0x1f4
#define TRICKY_IDLE_VOICE_MIN_FRAMES     500
#define TRICKY_IDLE_VOICE_MAX_FRAMES     750
#define TRICKY_VOICE_MOVE_MIN            0x29
#define TRICKY_VOICE_MOVE_END            0x30
#define TRICKY_VOICE_CHANNEL             0x10
#define TRICKY_ANIM_LAND_IDLE            0
#define TRICKY_ANIM_WALK_SLOW            1
#define TRICKY_ANIM_WALK_MEDIUM          2
#define TRICKY_ANIM_WALK_FAST            4
#define TRICKY_ANIM_RUN                  5
#define TRICKY_ANIM_SWIM                 7
#define TRICKY_ANIM_SWIM_TURN            8
#define TRICKY_ANIM_TURN_LEFT_SMALL      9
#define TRICKY_ANIM_TURN_RIGHT_SMALL     10
#define TRICKY_ANIM_TURN_LEFT_MEDIUM     11
#define TRICKY_ANIM_TURN_RIGHT_MEDIUM    12
#define TRICKY_ANIM_IDLE_FOOD_WAIT       0x0d
#define TRICKY_ANIM_FOLLOW_ARC_RETURN    0x0e
#define TRICKY_ANIM_FETCH_THROW_READY    0x10
#define TRICKY_ANIM_FETCH_PICKUP_LAND    0x11
#define TRICKY_ANIM_FETCH_THROW_LAND     0x13
#define TRICKY_ANIM_HUNGRY_IDLE          0x14
#define TRICKY_ANIM_FOLLOW_JUMP_PREP     0x15
#define TRICKY_ANIM_FOLLOW_JUMP          0x16
#define TRICKY_ANIM_FOLLOW_JUMPUP_FAST   0x17
#define TRICKY_ANIM_FOLLOW_JUMPUP_SLOW   0x18
#define TRICKY_ANIM_FOLLOW_JUMPDOWN      0x19
#define TRICKY_ANIM_FLAME_BREATH         0x1a
#define TRICKY_ANIM_WATER_IDLE           0x1b
#define TRICKY_ANIM_FETCH_PICKUP_WATER   0x1c
#define TRICKY_ANIM_FETCH_THROW_WATER    0x1d
#define TRICKY_ANIM_IDLE_FIDGET_B_START  0x21
#define TRICKY_ANIM_IDLE_FIDGET_B_END    0x22
#define TRICKY_ANIM_IDLE_FIDGET_A_START  0x23
#define TRICKY_ANIM_IDLE_FIDGET_A_END    0x24
#define TRICKY_ANIM_IDLE_WANDER          0x25
#define TRICKY_ANIM_IDLE_PICK            0x26
#define TRICKY_ANIM_TURN_LEFT_LARGE      0x27
#define TRICKY_ANIM_TURN_RIGHT_LARGE     0x28
#define TRICKY_ANIM_HOWL_START           0x29
#define TRICKY_ANIM_HOWL_HOLD            0x2a
#define TRICKY_ANIM_HOWL_END             0x2b
#define TRICKY_ANIM_HOWL_IDLE_PICK       0x2c
#define TRICKY_ANIM_DIG_FOOD_START_A     0x2c
#define TRICKY_ANIM_AMBIENT_HOWL         0x2d
#define TRICKY_ANIM_DIG_FOOD_START_B     0x2d
#define TRICKY_ANIM_DIG_FOOD_LOOP        0x2e
#define TRICKY_ANIM_DIG_FOOD_END         0x2f
#define TRICKY_ANIM_LAND_RUN_LOOP        0x30
#define TRICKY_ANIM_IDLE_FOOD_CHEW       0x31
#define TRICKY_ANIM_GUARD_GROWL          0x32
#define TRICKY_ANIM_GROWL_WINDUP         0x33
#define TRICKY_ANIM_DIG                  0x34
#define TRICKY_TURN_LARGE_ANGLE          0x3555
#define TRICKY_TURN_MEDIUM_ANGLE         0x2000
#define TRICKY_COMMAND_TTL_FRAMES        3
#define TRICKY_COMMAND_PHASE_IDLE        -1
#define TRICKY_COMMAND_PHASE_NONE        0
#define TRICKY_COMMAND_PHASE_DIG         1
#define TRICKY_COMMAND_PHASE_GUARD       3
#define TRICKY_COMMAND_PHASE_FLAME       4
#define TRICKY_COMMAND_PHASE_FETCH_BALL  5

#define TRICKY_STATE_FLAG_SIDESTEP                0x20  /* apply sidestepDelta lateral offset */
#define TRICKY_STATE_FLAG_BACKSTEP                0x40  /* apply backstepDelta offset */
#define TRICKY_STATE_FLAG_VERTICAL_MOVE           0x80  /* apply verticalDelta to localPosY */
#define TRICKY_STATE_FLAG_ROTATE                  0x100 /* interpolate rotation toward targetYaw target */
#define TRICKY_STATE_FLAG_SEQUENCE_CALLBACK       0x1u
#define TRICKY_STATE_FLAG_STUCK_VOICE_PENDING     0x2u
#define TRICKY_STATE_FLAG_FOOD_WARNING_PENDING    0x4u
#define TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED 0x8u
#define TRICKY_STATE_FLAG_SEQUENCE_LATCHED        0x200u
#define TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE     0x4000u
#define TRICKY_STATE_FLAG_GROUND_SNAP             0x2000u
#define TRICKY_STATE_FLAG_POSITION_RELOCATED      0x80000u
#define TRICKY_STATE_HEEL_RECALL_REQUEST_FLAGS    0x30002LL
#define TRICKY_STATE_FLAG_TURN_REQUEST            0x100000u
#define TRICKY_STATE_FLAG_TURN_REQUEST_PREV       0x200000u
#define TRICKY_STATE_FLAG_TURN_LEFT               0x400000u
#define TRICKY_STATE_FLAG_TURN_RIGHT              0x800000u
#define TRICKY_STATE_TURN_SELECT_CLEAR_MASK       0xef2fffff
#define TRICKY_STATE_TURN_RIGHT_FLAGS             0x900000LL
#define TRICKY_STATE_TURN_LEFT_FLAGS              0x500000LL
#define TRICKY_STATE_DIG_TUNNEL_FLAGS             0x2010LL
#define TRICKY_STATE_SEQUENCE_DONE_CLEAR_MASK     0x4201
#define TRICKY_STATE_FLAG_TURNING_U32             0x10000000
#define TRICKY_STATE_FLAG_TURNING                 0x10000000LL
#define TRICKY_STATE_FLAG_SUN_VOICE_PLAYED_U32    0x20000000U
#define TRICKY_STATE_FLAG_SUN_VOICE_PLAYED        0x20000000LL
#define TRICKY_STATE_FLAG_FEED_VOICE_PENDING_U32  0x40000000
#define TRICKY_STATE_FLAG_FEED_VOICE_PENDING      0x40000000LL
#define TRICKY_STATE_FLAG_IMPRESS_PENDING_U32     0x80000000U
#define TRICKY_STATE_FLAG_MOVE_ADVANCING_WIDE     0x8000000LL
#define TRICKY_STATE_CHILD_ACTIVITY_FLAGS (TRICKY_STATE_FLAG_CHILDREN_ACTIVE | TRICKY_STATE_FLAG_CHILDREN_CLEANUP)

#define TRICKY_MOVE_FLAG_KEEP_PROGRESS        0x01000000
#define TRICKY_MOVE_FLAG_ROOT_TRANSLATE       0x02000000
#define TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION 0x04000000
#define TRICKY_MOVE_FLAG_WALK_LOOP            (TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_MOVE_FLAG_ROOT_TRANSLATE)
#define TRICKY_MOVE_FLAG_JUMP_ARC                                                                                      \
    (TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION | TRICKY_STATE_FLAG_BACKSTEP | TRICKY_STATE_FLAG_VERTICAL_MOVE)
#define TRICKY_MOVE_ACTIVE_FLAG_MASK 0x060001e0LL

#define TRICKY_CURVE_LINK_IDS_OFFSET                     offsetof(RomCurveDef, linkIds)
#define TRICKY_CURVE_LINK_ID_FROM_NODE_OFFSET(node, off) (*(int*)((node) + (off) + TRICKY_CURVE_LINK_IDS_OFFSET))
#define TRICKY_CURVE_LINK_ID_FROM_NODE_INDEX(node, idx)  (((int*)((char*)(node) + TRICKY_CURVE_LINK_IDS_OFFSET))[idx])
#define TRICKY_PATH_SEARCH_AT_CURSOR(cursor)             (((TrickyState*)(cursor))->pathSearches[0])
#define TRICKY_PATCH_AT_CURSOR(cursor)                   (((TrickyState*)(cursor))->patch[0])
#define TRICKY_PATCH_TARGET_AT_CURSOR(cursor)            (((TrickyState*)(cursor))->patchTargets[0])
#define TRICKY_FLAME_CHILD_AT_CURSOR(cursor)             (((TrickyState*)(cursor))->flameChildren[0])
#define TRICKY_COMMAND_AT_STATE_CURSOR(cursor) ((TrickyCommand*)((u8*)(cursor) + offsetof(TrickyState, commands)))

/* The one partfx effect emitted along Tricky's queued impress path. */
#define TRICKY_PATH_PARTFX 0x533

#define TRICKY_BADDIE_OBJGROUP       3
#define TRICKY_INTERACTABLE_OBJGROUP 49 /* things Tricky can activate; excluded from baddie targeting */
/* creatures excluded from Tricky's baddie targeting (retail OBJECTS.bin names). */
#define TRICKY_SEQID_WHIRLPOOL 2129 /* "Whirlpool" (DLL 0xC9) */
#define TRICKY_SEQID_VAMBAT    1022 /* "Vambat" (DLL 0xC9) */
#define TRICKY_SEQID_WB        1239 /* "WB" (DLL 0xC9) */
#define TRICKY_SEQID_PINPON    593  /* "PinPon" (DLL 0xC9) */

/* Bit setter at bit 6 (0x40) of obj->_b8->_58. */
void trickySetSoundSuppressed(GameObject* obj, int value) {
    ((TrickyState*)obj->extra)->soundSuppressed = value;
}

int trickyTryPlaySound(GameObject* obj, u16 sfxId, int volume) {
    TrickyState* state = obj->extra;
    s16 move;

    if (state->soundSuppressed) {
        return 0;
    }
    move = obj->anim.currentMove;
    switch (move) {
    case 41:
    case 42:
    case 43:
    case 44:
    case 45:
    case 46:
    case 47:
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) != 0) {
        return 0;
    }
    objSoundStartTimed(obj, &state->soundState, sfxId, volume, -1, 0);
    return 1;
}

void objAnimFreeChildren(GameObject* obj, TrickyState* state, GameObject** child) {
    char buf[4];
    void* childA;
    void* childB;
    void* zzzChild;

    if (*child == NULL) {
        return;
    }
    ObjLink_DetachChild(obj, *child);
    Obj_FreeObject(*child);
    *child = NULL;
    buf[0] = -1;
    buf[1] = -1;
    buf[2] = -1;
    childA = state->childA;
    if (childA != NULL) {
        buf[state->packedSlots.promptASlot] = 1;
    }
    childB = state->childB;
    if (childB != NULL) {
        buf[state->packedSlots.promptBSlot] = 1;
    }
    zzzChild = state->child;
    if (zzzChild != NULL) {
        buf[state->packedSlots.zzzSlot] = 1;
    }
    if (buf[0] == -1) {
        if (childA != NULL) {
            ObjLink_DetachChild(obj, childA);
            ObjLink_AttachChild(obj, state->childA, 0);
            state->packedSlots.promptASlot = 0;
        } else if (childB != NULL) {
            ObjLink_DetachChild(obj, childB);
            ObjLink_AttachChild(obj, state->childB, 0);
            state->packedSlots.promptBSlot = 0;
        } else if (zzzChild != NULL) {
            ObjLink_DetachChild(obj, zzzChild);
            ObjLink_AttachChild(obj, state->child, 0);
            state->packedSlots.zzzSlot = 0;
        }
    }
}

/* Weighted blend-channel animator. On blendPending, primes channel 1
 * (weight 0, target weight ratio in blendWeight) and latches blendActive.
 * While blendActive is set, ramps blendWeight toward energy / maxEnergy with
 * acceleration 0.004f and damping 0.7f, clamps to [0, 1.0f], and pushes the
 * result to the model's blend channel 1 as `2.0f * weight - 1.0f`. */
void Tricky_updateBlendChannelWeight(GameObject* obj, TrickyState* state) {
    ObjModel* model;
    f32 target;
    f32 max;
    f32 blendWeight;
    Obj_GetActiveModel(obj);
    if (state->blendPending) {
        model = Obj_GetActiveModel(obj);
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, gTrickyFloatZero, 0x21);
        state->blendWeight = TRICKY_FLOAT_TEN;
        ObjModel_SetBlendChannelWeight(model, 0, gTrickyFloatZero);
        state->blendPending = 0;
        state->blendActive = 1;
    }
    if (state->blendActive) {
        TrickyStats* stats = state->stats;
        target = (f32)(u32)stats->energy / (f32)(u32)stats->maxEnergy;
        if (target > state->blendWeight) {
            state->blendVelocity = TRICKY_FLOAT_0_004 * timeDelta + state->blendVelocity;
            state->blendWeight = state->blendVelocity * timeDelta + state->blendWeight;
            if (state->blendWeight > (max = TRICKY_FLOAT_ONE)) {
                state->blendVelocity = gTrickyFloatZero;
                state->blendWeight = max;
            } else if (state->blendWeight > target) {
                if (state->blendVelocity < TRICKY_FLOAT_0_01) {
                    state->blendVelocity = gTrickyFloatZero;
                    state->blendWeight = target;
                } else {
                    state->blendVelocity *= TRICKY_FLOAT_0_7;
                }
            }
        } else if (target < state->blendWeight) {
            state->blendVelocity = state->blendVelocity - TRICKY_FLOAT_0_004 * timeDelta;
            state->blendWeight = state->blendVelocity * timeDelta + state->blendWeight;
            blendWeight = state->blendWeight;
            if (blendWeight < gTrickyFloatZero) {
                state->blendWeight = state->blendVelocity = gTrickyFloatZero;
            }
            if (state->blendWeight < target) {
                if (state->blendVelocity > TRICKY_FLOAT_NEG_0_01) {
                    state->blendVelocity = gTrickyFloatZero;
                    state->blendWeight = target;
                } else {
                    state->blendVelocity *= TRICKY_FLOAT_0_7;
                }
            }
        }
        ObjModel_SetBlendChannelWeight(Obj_GetActiveModel(obj), 1,
                                       TRICKY_FLOAT_TWO * state->blendWeight - TRICKY_FLOAT_ONE);
    }
}

const f32 gTrickyTimer20Frames[1] = {20.0f};
static const f32 sTrickyColorFadeAlphaScale[1] = {196.0f};
const f32 gTrickyEventTimeSentinel[1] = {-100000.0f};
const f32 gTrickyEventStaleSeconds[1] = {8.0f};
const f32 gTrickyMaxDistance[1] = {340282346638528859811704183484516925440.0f};
const f32 gTrickySpeedDecayStep[1] = {-0.15f};
const f32 gTrickySmallSpeedStep[1] = {0.05f};
static const f32 sTrickyFloat100[1] = {100.0f};
static const f32 sTrickyFloatNeg0_17[1] = {-0.17f};
static const f32 sTrickyFloat40[1] = {40.0f};
static const f32 sTrickyFloat400[1] = {400.0f};
static const f32 sTrickyFloat0_014[1] = {0.014f};
static const f32 sTrickyFloat300[1] = {300.0f};
const f32 gTrickyFastMoveBlendSpeed[1] = {0.02f};
const f32 gTrickyTimer600Frames[1] = {600.0f};
const f32 gTrickyLandMoveBlendSpeed[1] = {0.005f};
const f32 gTrickyRouteReverseStep[1] = {-2.0f};
const f32 gTrickyRouteLookaheadScale[1] = {1.5f};
const f32 gTrickyYawStepRate[1] = {512.0f};
const f32 gTrickyPi[1] = {3.1415927f};
const f32 gTrickyAngleHalfTurnUnits[1] = {32768.0f};

#define gTrickyEventTimeSentinel         (gTrickyEventTimeSentinel[0])
#define gTrickyEventStaleSeconds         (gTrickyEventStaleSeconds[0])
#define gTrickyMaxDistance               (gTrickyMaxDistance[0])
#define gTrickySpeedDecayStep            (gTrickySpeedDecayStep[0])
#define gTrickySmallSpeedStep            (gTrickySmallSpeedStep[0])
#define TRICKY_FLOAT_100                 (sTrickyFloat100[0])
#define TRICKY_FLOAT_NEG_0_17            (sTrickyFloatNeg0_17[0])
#define TRICKY_FLOAT_40                  (sTrickyFloat40[0])
#define TRICKY_FLOAT_400                 (sTrickyFloat400[0])
#define TRICKY_FLOAT_0_014               (sTrickyFloat0_014[0])
#define TRICKY_FLOAT_300                 (sTrickyFloat300[0])
#define TRICKY_FAST_MOVE_BLEND_SPEED     (gTrickyFastMoveBlendSpeed[0])
#define TRICKY_TIMER_600_FRAMES          (gTrickyTimer600Frames[0])
#define TRICKY_LAND_MOVE_BLEND_SPEED     (gTrickyLandMoveBlendSpeed[0])
#define TRICKY_ROUTE_REVERSE_STEP        (gTrickyRouteReverseStep[0])
#define TRICKY_ROUTE_LOOKAHEAD_SCALE     (gTrickyRouteLookaheadScale[0])
#define TRICKY_YAW_STEP_RATE             (gTrickyYawStepRate[0])
#define TRICKY_PI                        (gTrickyPi[0])
#define TRICKY_ANGLE_HALF_TURN_UNITS     (gTrickyAngleHalfTurnUnits[0])
#define TRICKY_BALL_RETURNS_PER_COLOR    10
#define TRICKY_BALL_RETURN_COUNT_MAX     0xef
#define TRICKY_COLOR_CHANGE_SEEN_GAMEBIT 1005
#define TRICKY_COLOR_CHANGE_SEQUENCE_ID  5

void trickyUpdateColorVariant(GameObject* obj, TrickyState* state) {
    u8 colorVariant = state->stats->ballReturnCount / TRICKY_BALL_RETURNS_PER_COLOR;

    if (state->colorVariant != colorVariant) {
        f32 t;
        if (mainGetBit(TRICKY_COLOR_CHANGE_SEEN_GAMEBIT) == 0) {
            mainSetBits(TRICKY_COLOR_CHANGE_SEEN_GAMEBIT, 1);
            (*gObjectTriggerInterface)->runSequence(TRICKY_COLOR_CHANGE_SEQUENCE_ID, obj, -1);
            state->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
            state->colorFadeTimer += TRICKY_TIMER_20_FRAMES;
        }
        state->colorFadeTimer -= timeDelta;
        t = state->colorFadeTimer;
        if (!(t > TRICKY_TIMER_20_FRAMES)) {
            if (t > gTrickyFloatZero) {
                f32 alpha;
                if (t > TRICKY_FLOAT_TEN) {
                    alpha = 1.0f - (t - TRICKY_FLOAT_TEN) / TRICKY_FLOAT_TEN;
                } else {
                    Obj_GetActiveModel(obj)->textureRefs->swapSelector = colorVariant;
                    alpha = state->colorFadeTimer / TRICKY_FLOAT_TEN;
                }
                Obj_SetModelColorOverrideRecursive(obj, 255, 255, 255, TRICKY_COLOR_FADE_ALPHA_SCALE * alpha, 1);
            } else {
                state->colorVariant = colorVariant;
                Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
            }
        }
    }
}

static inline int skeetla_isInWater(TrickyState* state) {
    if (gTrickyFloatZero == state->waterLevel) {
        return 0;
    }
    if (gTrickyEventTimeSentinel == state->eventTime) {
        return 1;
    }
    if (state->currentTime - state->eventTime > gTrickyEventStaleSeconds) {
        return 1;
    }
    return 0;
}

/* Latch the impress move and prime impressTimer. */
void trickyImpress(GameObject* obj) {
    TrickyState* state = obj->extra;
    state->stateFlags |= TRICKY_STATE_FLAG_IMPRESS_PENDING_U32;
    state->impressTimer = TRICKY_TIMER_20_FRAMES;
}

/* GameBit-gated recall request. Returns 1 only when Tricky is already in an active command. */
int Tricky_requestRecallAndCheckBusy(GameObject* obj) {
    TrickyState* state = obj->extra;
    if ((u32)mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0u) {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0u) {
            return 1;
        }
    }
    return 0;
}

PPCWGPipe GXWGFifo : (0xCC008000);

f32 trickyGetAnimSpeed(GameObject* obj) {
    return ((TrickyState*)obj->extra)->speed;
}

GameObject* trickyGetStayPoint(GameObject* obj) {
    return ((TrickyState*)obj->extra)->followObj;
}
int trickyGetAimPitchOffset(GameObject* obj) {
    return ((TrickyState*)obj->extra)->modelAnchorRotY;
}
f32* trickyGetQueuedPathParticlePos(GameObject* obj) {
    return &((TrickyState*)obj->extra)->renderPosX;
}

GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes) {
    GameObject** baddieCursor;
    GameObject** baddieList;
    GameObject* closestBaddie;
    int i;
    f32 bestDistSq;
    int count;

    bestDistSq = maxRadius;
    closestBaddie = 0;
    baddieList = (GameObject**)objGetAllOfType(TRICKY_BADDIE_OBJGROUP, &count);
    bestDistSq = bestDistSq * bestDistSq;
    i = 0;
    baddieCursor = baddieList;

    for (; i < count; baddieCursor++, i++) {
        TrickyBaddieTargetPlacement* placement;
        f32 healthFraction;
        int disabledByBit, enabledByBit;
        s32 disableGameBit, enableGameBit;

        if (dll_19_isBaddieControlObject(*baddieCursor) != 0) {
            healthFraction = (*gBaddieControlInterface)->getHealthFraction(*baddieCursor);
        } else {
            healthFraction = enemy_getHealthFraction(*baddieCursor);
        }

        placement = (TrickyBaddieTargetPlacement*)(*baddieCursor)->anim.placementData;
        disableGameBit = placement->disableGameBit;
        if (disableGameBit == -1) {
            disabledByBit = 0;
        } else {
            disabledByBit = mainGetBit(disableGameBit);
        }
        enableGameBit = placement->enableGameBit;
        if (enableGameBit == -1) {
            enabledByBit = 1;
        } else {
            enabledByBit = mainGetBit(enableGameBit);
        }

        if (objIsObjectType(*baddieCursor, TRICKY_INTERACTABLE_OBJGROUP) == 0 && healthFraction > gTrickyFloatZero &&
            disabledByBit == 0 && enabledByBit != 0) {
            if ((*baddieCursor)->anim.romDefNo != TRICKY_SEQID_WHIRLPOOL) {
                if ((*gMapEventInterface)->shouldNotSaveTime(placement->mapEventId) != 0) {
                    if (allowSpecialTypes == 0) {
                        s16 romDefNo = (*baddieCursor)->anim.romDefNo;
                        if (romDefNo == TRICKY_SEQID_VAMBAT || romDefNo == TRICKY_SEQID_WB ||
                            romDefNo == DLL1B5_SEQUENCE_ID_SC_BABY_LIGHTFOOT || romDefNo == TRICKY_SEQID_PINPON) {
                            continue;
                        }
                    }
                    {
                        f32 dist = vec3f_distanceSquared(&origin->anim.worldPosX, &(*baddieCursor)->anim.worldPosX);
                        if (dist < bestDistSq) {
                            bestDistSq = dist;
                            closestBaddie = *baddieCursor;
                        }
                    }
                }
            }
        }
    }
    return closestBaddie;
}

void Tricky_emitQueuedPathParticles(GameObject* obj, TrickyState* state) {
    struct {
        s16 hx, hy, hz;
        f32 fk;
        f32 dx, dy, dz;
    } stk;
    u8 i = 0x14;
    u32 flags = state->stateFlags;
    if ((flags & TRICKY_STATE_CHILD_ACTIVITY_FLAGS) == 0) {
        return;
    }
    stk.dx = state->renderPosX - obj->anim.worldPosX;
    stk.dy = state->renderPosY - obj->anim.worldPosY;
    stk.dz = state->renderPosZ - obj->anim.worldPosZ;
    stk.fk = 1.0f;
    stk.hx = obj->anim.rotX;
    stk.hy = obj->anim.rotY;
    stk.hz = obj->anim.rotZ;
    if ((flags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
        while (i-- != 0) {
            (*gPartfxInterface)->spawnObject(obj, TRICKY_PATH_PARTFX, &stk, 2, -1, NULL);
        }
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
    }
}

int trickySelectQueuedCommandTarget(TrickyState* state, int commandType) {
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    int commandCursorAddr;
    int commandIndex;
    GameObject* bestPriorityTarget;
    GameObject* bestFallbackTarget;

    bestPriorityDist = gTrickyMaxDistance;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (commandIndex = 0, commandCursorAddr = (int)state; commandIndex < state->commandCount;
         commandCursorAddr += sizeof(TrickyCommand), commandIndex++) {
        if (TRICKY_COMMAND_AT_STATE_CURSOR(commandCursorAddr)->commandType == commandType) {
            f32 dist =
                getXZDistanceSquared(&state->playerObj->anim.worldPosX,
                                     &TRICKY_COMMAND_AT_STATE_CURSOR(commandCursorAddr)->targetObj->anim.worldPosX);

            if (TRICKY_COMMAND_AT_STATE_CURSOR(commandCursorAddr)->commandKind == TRICKY_COMMAND_KIND_PRIORITY) {
                if (dist < bestPriorityDist) {
                    bestPriorityDist = dist;
                    bestPriorityTarget = TRICKY_COMMAND_AT_STATE_CURSOR(commandCursorAddr)->targetObj;
                }
            } else if (dist < bestFallbackDist) {
                bestFallbackDist = dist;
                bestFallbackTarget = TRICKY_COMMAND_AT_STATE_CURSOR(commandCursorAddr)->targetObj;
            }
        }
    }

    if (bestPriorityTarget != NULL) {
        state->followObj = bestPriorityTarget;
    } else {
        if (bestFallbackTarget == NULL) {
            return 0;
        }
        state->followObj = bestFallbackTarget;
    }

    {
        f32* targetPos = &state->followObj->anim.worldPosX;
        if (state->targetPosPtr != targetPos) {
            state->targetPosPtr = targetPos;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
    }

    state->substate = 0;
    return 1;
}

/*
 * Tricky per-frame collision, ground
 * snapping and path-control update.
 *
 * trickyUpdateCollisionAndPathState snaps Tricky to the ground, applies water
 * buoyancy, processes priority hits (lighting fx, hit sparks, out-of-water
 * bark), then drives the path-control interface and copies the resulting
 * yaw/roll back onto the object. trickyAdvanceRouteTargetAhead walks the
 * RomCurve route target forward and trickyTurnTowardYaw eases the object's
 * facing toward a requested yaw.
 */

/* group owned by another DLL, queried here */
#define SIDEREPEL_OBJGROUP      0x40 /* DLL 0xEB siderepel */
#define SKEETLA_TARGET_OBJGROUP 5
/* Per-node fan-out limit: status[]/bestDistances[]/outRoutes[] hold at most
 * this many linked route candidates (status[8] / f32 bestDistances[8]). */
#define TRICKY_ROUTE_CANDIDATE_COUNT   8
#define SKEETLA_LINKED_SOURCE_ID_OBJ_A 0x1ca
#define SKEETLA_LINKED_SOURCE_ID_OBJ_B 0x160
#define SKEETLA_PARTICLE_SPARK_A       0xca
#define SKEETLA_PARTICLE_SPARK_B       0xcb
#define SKEETLA_CONTACT_OBJ_PROJBALL   0x1f /* "projball" (DLL 0xE3) */

/* attacker romDefNo that triggers the staff-impact sfx (retail OBJECTS.bin). */
#define SKEETLA_ATTACKER_SEQID_STAFF 0x69
/* "staff" (DLL 0xE2) */
#define SKEETLA_PARTICLE_SPAWN_FLAGS 0x200001
#define TRICKY_HITMASK_ALL_SOURCES   0x7f
#define TRICKY_HITMASK_NO_LOW_SOURCE 0x7e

enum TrickyDamageType {
    TRICKY_DAMAGE_INSTANT_DEATH = 0x01,
    TRICKY_DAMAGE_DIM2_SNOWBALL = 0x04,
    TRICKY_DAMAGE_BOMB_PLANT_EXPLOSION = 0x05,
    TRICKY_DAMAGE_MMP_CRATERF = 0x09,
    TRICKY_DAMAGE_MMP_BARREL = 0x0a,
    TRICKY_DAMAGE_PROJBALL = 0x0e,
    TRICKY_DAMAGE_FIRE = 0x1f,
};
#define SKEETLA_PARTICLE_RANDOM_RATE 4
void tricky_state06_nop(void);
void trickyFlame();
void trickyGuard();
void tricky_moveToFollowTarget();
void tricky_idleAndEat();
void tricky_fetchBall();
void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state);
void trickyUpdateCircling();
void tricky_trackTumbleweed();

typedef void (*TrickyStateHandler)(void* obj, void* state);
typedef int (*TrickySubstateHandler)(GameObject* obj, TrickyState* state);

typedef struct TrickyPathPointCollisionData {
    f32 point[3];
    TrickyStateHandler stateHandlers[18];
    TrickySubstateHandler substateHandlers[13];
} TrickyPathPointCollisionData;

STATIC_ASSERT(offsetof(TrickyPathPointCollisionData, point) == 0x0);
STATIC_ASSERT(offsetof(TrickyPathPointCollisionData, stateHandlers) == 0xC);
STATIC_ASSERT(offsetof(TrickyPathPointCollisionData, substateHandlers) == 0x54);
STATIC_ASSERT(sizeof(TrickyPathPointCollisionData) == 0x88);

#define TRICKY_HANDLER_TABLE_OFFSET          0x24
#define TRICKY_SUBSTATE_HANDLER_TABLE_OFFSET 0x6c

typedef enum TrickyDebugStringOffset {
    TRICKY_DBG_IN_WATER = 0x184,
    TRICKY_DBG_OUT_OF_WATER = 0x190,
    TRICKY_DBG_MOVE_OUT_OF_WATER = 0x1a0,
    TRICKY_DBG_TURN_IN_WATER = 0x1bc,
    TRICKY_DBG_TURN_OUT_OF_WATER = 0x1d0,
    TRICKY_DBG_WALK_GROUP_STATUS = 0x1e8,
    TRICKY_DBG_ZERO_ACTIVE_WALK_GROUP = 0x214,
    TRICKY_DBG_SPEED_UPDATE = 0x268,
    TRICKY_DBG_TARGET_IN_WALKGROUP_OR_PATCH = 0x284,
    TRICKY_DBG_TARGET_OUTSIDE_WALKGROUP_AND_PATCHES = 0x2b0,
    TRICKY_DBG_TARGET_PATCH_GROUP = 0x2e4,
    TRICKY_DBG_PATCH_LAST_XYZ = 0x308,
    TRICKY_DBG_LAST_PATCH_POINT = 0x328,
    TRICKY_DBG_NOT_IN_WALKGROUP_OR_PATCH = 0x344,
    TRICKY_DBG_PATCH_ROUTE_ERROR = 0x374,
    TRICKY_DBG_PATCH_ROUTE_ERROR_2 = 0x3ec,
    TRICKY_DBG_MOVEMENT_STATE = 0x404,
    TRICKY_DBG_WALK_WAIT = 0x41c,
    TRICKY_DBG_WALK_FREE = 0x428,
    TRICKY_DBG_WALK_START_PATCH = 0x434,
    TRICKY_DBG_WALK_PATCH_EXIT = 0x448,
    TRICKY_DBG_WALK_END_PATCH = 0x45c,
    TRICKY_DBG_WALK_TO_NODE = 0x46c,
    TRICKY_DBG_CURVE_SETUP = 0x480,
    TRICKY_DBG_WALK_NODES = 0x490,
    TRICKY_DBG_JUMP_RUN_UP = 0x49c,
    TRICKY_DBG_JUMP_PREP = 0x4ac,
    TRICKY_DBG_JUMPING = 0x4b8,
    TRICKY_DBG_JUMP_UP_RUN_UP = 0x4c4,
    TRICKY_DBG_JUMP_DOWN_OR_UP = 0x4d4,
    TRICKY_DBG_JUMPDOWN_RUNUP = 0x4e8,
    TRICKY_DBG_INVALID_MOVEMENT_STATE = 0x4f8,
    TRICKY_DBG_GROWLAT_GOTO = 0x558,
    TRICKY_DBG_GROWLAT_GROWLING = 0x568,
    TRICKY_DBG_GROWLAT_GOTOFLAME = 0x57c,
    TRICKY_DBG_GROWLAT_FLAME = 0x590,
    TRICKY_DBG_BADDIEALERT_GOTO = 0x5a0,
    TRICKY_DBG_BADDIEALERT_BARK = 0x5b4,
    TRICKY_DBG_BADDIEALERT_GOTOFLAME = 0x5cc,
    TRICKY_DBG_BADDIEALERT_FLAME = 0x5e4,
    TRICKY_DBG_GUARD_INIT = 0x648,
    TRICKY_DBG_GUARD_FINDING = 0x654,
    TRICKY_DBG_GUARD_TOSPOT = 0x664,
    TRICKY_DBG_GUARD_TOFRONT = 0x674,
    TRICKY_DBG_GUARD_TOBADDIE = 0x684,
    TRICKY_DBG_GUARD_FLAME = 0x694,
    TRICKY_DBG_GUARD_DOWNTOGROWL = 0x6a4,
    TRICKY_DBG_GUARD_GROWL = 0x6b8,
    TRICKY_DBG_GUARD_UPFROMGROWL = 0x6c8,
    TRICKY_DBG_FLAME_NONE = 0x700,
    TRICKY_DBG_FLAME_FINDING_OUT = 0x70c,
    TRICKY_DBG_FLAME_GOINGTOEDGE = 0x720,
    TRICKY_DBG_FLAME_TOSTART = 0x734,
    TRICKY_DBG_FLAME_OUT = 0x744,
    TRICKY_DBG_FLAME_FINDING_IN = 0x750,
    TRICKY_DBG_FLAME_TURNING_IN = 0x764,
    TRICKY_DBG_FLAME_IN = 0x778,
    TRICKY_DBG_FLAME_TOEND = 0x784,
    TRICKY_DBG_DIGTUNNEL_FINDING = 0x7b8,
    TRICKY_DBG_DIGTUNNEL_GOINGTOSTART = 0x7cc,
    TRICKY_DBG_DIGTUNNEL_DIGGING = 0x7e4,
    TRICKY_DBG_DIGTUNNEL_TOEND1 = 0x7f8,
    TRICKY_DBG_DIGTUNNEL_TOEND2 = 0x810,
    TRICKY_DBG_DIGTUNNEL_WAIT = 0x824,
    TRICKY_DBG_SIDECOMMAND_HITS = 0x894,
    TRICKY_DBG_SIDECOMMAND_ENERGY = 0x8b4,
    TRICKY_DBG_COMMAND_WRONG_OBJECT = 0x8c4,
} TrickyDebugStringOffset;

typedef enum TrickyStateId {
    TRICKY_STATE_ATTACH_TO_WALKGROUP = 0,
    TRICKY_STATE_FOLLOW_PLAYER = 1,
    TRICKY_STATE_FIND_SECRET_DIG = 2,
    TRICKY_STATE_DIG_TUNNEL = 3,
    TRICKY_STATE_NOP_4 = 4,
    TRICKY_STATE_BALL_ROLL = 5,
    TRICKY_STATE_NOP_6 = 6,
    TRICKY_STATE_FLAME = 7,
    TRICKY_STATE_GUARD = 8,
    TRICKY_STATE_MOVE_TO_FOLLOW_TARGET = 9,
    TRICKY_STATE_IDLE_AND_EAT = 10,
    TRICKY_STATE_FETCH_BALL = 11,
    TRICKY_STATE_CIRCLING_TARGET_POS = 12,
    TRICKY_STATE_CIRCLING = 13,
    TRICKY_STATE_GROWL = 14,
    TRICKY_STATE_IDLE_WANDER = 15,
    TRICKY_STATE_TRACK_TUMBLEWEED = 16,
    TRICKY_STATE_GO_TO_WARP_POINT = 17,
} TrickyStateId;

char gTrickyDebugStringTable[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x41, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

TrickyPathPointCollisionData gTrickyPathPointCollision = {
    {0.0f, 0.0f, 0.0f},
    {
        (TrickyStateHandler)tricky_attachToWalkGroup,
        (TrickyStateHandler)tricky_stateFollowPlayer,
        (TrickyStateHandler)tricky_stateFindSecretDig,
        (TrickyStateHandler)trickyDigTunnel,
        (TrickyStateHandler)tricky_state04_nop,
        (TrickyStateHandler)tricky_updateBallRoll,
        (TrickyStateHandler)tricky_state06_nop,
        (TrickyStateHandler)trickyFlame,
        (TrickyStateHandler)trickyGuard,
        (TrickyStateHandler)tricky_moveToFollowTarget,
        (TrickyStateHandler)tricky_idleAndEat,
        (TrickyStateHandler)tricky_fetchBall,
        (TrickyStateHandler)trickyUpdateCirclingTargetPosition,
        (TrickyStateHandler)trickyUpdateCircling,
        (TrickyStateHandler)trickyGrowl,
        (TrickyStateHandler)tricky_stateIdleWander,
        (TrickyStateHandler)tricky_trackTumbleweed,
        (TrickyStateHandler)tricky_stateGoToWarpPoint,
    },
    {
        (TrickySubstateHandler)tricky_substateFollowIdle,
        (TrickySubstateHandler)tricky_substateReturnToHeel,
        (TrickySubstateHandler)tricky_substateWaitQueuedMove,
        (TrickySubstateHandler)tricky_substateSleep,
        (TrickySubstateHandler)tricky_substateHowlCall,
        (TrickySubstateHandler)tricky_substateWaitMoveEnd,
        (TrickySubstateHandler)tricky_substateFidgetB,
        (TrickySubstateHandler)tricky_substateFidgetA,
        (TrickySubstateHandler)tricky_substateIdlePick,
        (TrickySubstateHandler)tricky_substateDigForFood,
        (TrickySubstateHandler)tricky_substateBegForFood,
        (TrickySubstateHandler)tricky_substateFlameBreath,
        (TrickySubstateHandler)tricky_substateApproachThorntail,
    },
};

ObjectDescriptor21 gTrickyObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_20_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)Tricky_init,
        (ObjectDescriptorCallback)Tricky_update,
        (ObjectDescriptorCallback)Tricky_hitDetect,
        (ObjectDescriptorCallback)Tricky_render,
        (ObjectDescriptorCallback)Tricky_free,
        0,
        (ObjectDescriptorExtraSizeCallback)Tricky_getExtraSize,
        (ObjectDescriptorCallback)Tricky_getAvailableCommands,
        (ObjectDescriptorCallback)Tricky_updateSideCommandPrompts,
        (ObjectDescriptorCallback)sideCommandEnable,
        (ObjectDescriptorCallback)Tricky_getEnergy,
        (ObjectDescriptorCallback)Tricky_getEnergyMax,
        (ObjectDescriptorCallback)Tricky_commandPlayBall,
        (ObjectDescriptorCallback)Tricky_requestMoveToObject,
        (ObjectDescriptorCallback)Tricky_requestRecall,
        (ObjectDescriptorCallback)Tricky_isPlayingBall,
        (ObjectDescriptorCallback)Tricky_isGuarding,
    },
    (ObjectDescriptorCallback)Tricky_getCurrentCommandType,
};

void trickyUpdateCollisionAndPathState(GameObject* obj) {
    TrickyState* state;
    f32 hitOffsetY;
    GameObject* lastContactObj;
    f32 nearestDistance;
    f32 hitPos[3];
    f32 lightArgs[3];
    f32* hitPosPtr;
    u8 doGroundSnap;
    int doHeightSnap;
    int hitKind;
    f32 contactTimer;

    state = (TrickyState*)obj->extra;
    doGroundSnap = 0;
    nearestDistance = TRICKY_FLOAT_100;

    if ((objPosToMapBlockIdx(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ) == -1) &&
        ((state->stateFlags & TRICKY_STATE_FLAG_POSITION_RELOCATED) == 0)) {
        state->heightUpdateActive = 0;
        obj->anim.localPosX = obj->anim.previousLocalPosX;
        obj->anim.localPosY = obj->anim.previousLocalPosY;
        obj->anim.localPosZ = obj->anim.previousLocalPosZ;
    }

    state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_POSITION_RELOCATED;

    if (state->groundSnapCounter != 0) {
        state->groundSnapCounter -= 1;
        doGroundSnap = 1;
    } else if ((state->stateFlags & TRICKY_STATE_FLAG_GROUND_SNAP) != 0) {
        doGroundSnap = 1;
    }

    if (doGroundSnap != 0) {
        trackGetNearestGroundOffset(obj, obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ, &hitOffsetY, 0);
        obj->anim.localPosY -= hitOffsetY;
        state->heightUpdateActive = 0;
    }

    if (((s8)state->heightUpdateActive != 0) && (state->heightTracking == 0u)) {
        doHeightSnap = skeetla_isInWater(state);

        if (doHeightSnap != 0) {
            obj->anim.velocityY = 0.0f;
            obj->anim.localPosY = state->currentTime - 0.01f;
        } else {
            obj->anim.velocityY += TRICKY_FLOAT_NEG_0_17 * timeDelta;
            obj->anim.localPosY += obj->anim.velocityY * timeDelta;
        }
    } else {
        obj->anim.velocityY = gTrickyFloatZero;
    }

    lastContactObj = (GameObject*)obj->anim.hitReactState->activeHit;
    if (((obj->anim.hitReactState->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) == 0) ||
        (lastContactObj->anim.romDefNo == SKEETLA_CONTACT_OBJ_PROJBALL)) {
        lastContactObj = NULL;
    }

    if ((state->stateFlags & TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED) != 0) {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= TRICKY_FLOAT_40) {
            if (vec3f_distanceSquared(&obj->anim.worldPosX, &Obj_GetPlayerObject()->anim.worldPosX) >
                TRICKY_FLOAT_400) {
                state->contactTimer -= TRICKY_FLOAT_40;
                obj->anim.modelInstance->runtimeSourceHitMask = TRICKY_HITMASK_ALL_SOURCES;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED;
            }
        }
    } else if ((state->lastContactObj != NULL) && (lastContactObj == state->lastContactObj)) {
        state->contactTimer += timeDelta;
        contactTimer = state->contactTimer;
        if (contactTimer >= TRICKY_FLOAT_TEN) {
            state->contactTimer = contactTimer - TRICKY_FLOAT_TEN;
            state->stateFlags |= TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED;
            obj->anim.modelInstance->runtimeSourceHitMask = TRICKY_HITMASK_NO_LOW_SOURCE;
        }
    } else {
        state->contactTimer = gTrickyFloatZero;
    }

    state->lastContactObj = lastContactObj;
    hitKind = ObjHits_PollPriorityHitWithCooldown(obj, &state->hitCooldown, &lastContactObj, (hitPosPtr = hitPos));
    state->light = hitKind;

    switch (state->light) {
    case TRICKY_DAMAGE_INSTANT_DEATH:
    case 2:
    case TRICKY_DAMAGE_DIM2_SNOWBALL:
    case TRICKY_DAMAGE_BOMB_PLANT_EXPLOSION:
    case TRICKY_DAMAGE_PROJBALL:
    case 0xf:
    case 0x11:
    case 0x13:
        objDoHitParticleFx(obj, TRICKY_FLOAT_0_014, lightArgs, 1, 0);
        break;
    case 7:
    case 8:
    case TRICKY_DAMAGE_MMP_CRATERF:
    case TRICKY_DAMAGE_MMP_BARREL:
    case 0xb:
    case 0xc:
        objfx_spawnHitEmitterAtPos(hitPosPtr, 8, 0xff, 0x20, 0x20);
        objDoHitParticleFx(obj, TRICKY_FLOAT_0_014, lightArgs, 4, 0);
        if (lastContactObj->anim.romDefNo == SKEETLA_ATTACKER_SEQID_STAFF) {
            Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
        }
        break;
    case TRICKY_DAMAGE_FIRE:
        state->particleTimer = TRICKY_FLOAT_300;
        break;
    }

    if ((s8)state->heightUpdateActive == 0) {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
    }

    if ((coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ) == 0xe) ||
        (objGetNearestTypeTo(SKEETLA_TARGET_OBJGROUP, obj, &nearestDistance) != NULL)) {
        state->pathControlFlags &= ~4;
    } else {
        state->pathControlFlags |= 4;
    }

    (*gPathControlInterface)->update(obj, &state->pathControlFlags, timeDelta);
    (*gPathControlInterface)->apply(obj, &state->pathControlFlags);
    (*gPathControlInterface)->advance(obj, &state->pathControlFlags, timeDelta);

    obj->anim.rotY = state->pathRotY;
    obj->anim.rotZ = state->pathRotZ;
}

int trickyAdvanceRouteTargetAhead(GameObject* obj, RomCurveWalker* route, f32 speed) {
    f32 limit;
    f32 maxSq, dist, step;
    int iter;
    int result;
    f32 maxDist;

    result = 0;
    maxDist = TRICKY_ROUTE_LOOKAHEAD_SCALE * (speed * timeDelta);
    maxSq = maxDist * maxDist;
    dist = getXZDistanceSquared(&route->posX, &obj->anim.worldPosX);
    if (route->reverse != 0) {
        step = TRICKY_ROUTE_REVERSE_STEP;
    } else {
        step = 2.0f;
    }
    iter = 0;
    limit = TRICKY_FLOAT_100;
    for (; iter < 5; iter++) {
        if (dist > limit && maxSq < dist) {
            return result;
        }
        result = 1;
        RomCurve_stepClamped(route, step);
        dist = getXZDistanceSquared(&route->posX, &obj->anim.worldPosX);
    }
    return 1;
}

int trickyTurnTowardYaw(GameObject* obj, s16 targetYaw) {
    TrickyState* state;
    int currentYaw;
    int wrappedYaw;
    int delta;
    int step;

    state = obj->extra;
    state->targetYaw = targetYaw;

    wrappedYaw = (u16)(s16)targetYaw;
    currentYaw = obj->anim.rotX;
    delta = currentYaw - wrappedYaw;
    if (delta > 0x8000) {
        delta -= 0xffff;
    }
    if (delta < -0x8000) {
        delta += 0xffff;
    }

    if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) != 0) {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_TURN_REQUEST_PREV;
    } else {
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_TURN_REQUEST_PREV;
    }
    state->stateFlags &= TRICKY_STATE_TURN_SELECT_CLEAR_MASK;

    if (delta > 0x10) {
        state->stateFlags |= TRICKY_STATE_TURN_RIGHT_FLAGS;
    } else if (delta < -0x10) {
        state->stateFlags |= TRICKY_STATE_TURN_LEFT_FLAGS;
    } else {
        obj->anim.rotX = targetYaw;
        return 0;
    }

    if (delta > 0x200) {
        step = (s32)(TRICKY_YAW_STEP_RATE * timeDelta);
        obj->anim.rotX = currentYaw - step;
        state->stateFlags |= TRICKY_STATE_FLAG_TURNING;
    } else if (delta < -0x200) {
        step = (s32)(TRICKY_YAW_STEP_RATE * timeDelta);
        obj->anim.rotX = currentYaw + step;
        state->stateFlags |= TRICKY_STATE_FLAG_TURNING;
    } else {
        obj->anim.rotX = targetYaw;
    }

    return delta;
}

/*
 * Tricky steering, animation selection and RomCurve route walking.
 *
 * moveTricky steers toward a target point with object-avoidance
 * (trickyApplyObjectAvoidanceToStep) and picks a walk/run/turn anim plus
 * footstep sfx by speed. The RomCurve helpers (trickySelectRouteEntry and
 * friends) choose and walk the spline route Tricky follows, gated by game
 * bits on each curve. skeetla_spawnLinkedSparks emits the contact-spark
 * particles for the object Tricky is linked to.
 */

f32 gTrickyPathControlSetupParams[2] = {0.05f, 8.5f};
f32 gTrickyPathPointCollisionRadius = 8.0f;
char sSkeetlaVelDebugFmt[] = "Vel %f\n";
/* Unreferenced zero bytes trail the debug format in retail .sdata. */
u8 gap_09_803DBC54_sdata[4] = {0};

static inline f32 skeetla_pathSpeedDelta(GameObject* obj) {
    TrickyState* state = (TrickyState*)obj->extra;
    f32* currentPathPoint;
    f32 dx;
    f32 dz;
    f32 previousSpeed;
    f32 currentSpeed;
    f32 delta;

    currentPathPoint = state->targetPosPtr;
    if (state->targetPosPtr == state->previousPathPoint) {
        dx = state->previousPathX - obj->anim.worldPosX;
        dz = state->previousPathZ - obj->anim.worldPosZ;
        previousSpeed = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));

        dx = currentPathPoint[0] - obj->anim.worldPosX;
        dz = currentPathPoint[2] - obj->anim.worldPosZ;
        currentSpeed = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));
        delta = currentSpeed - previousSpeed;
    } else {
        delta = gTrickyFloatZero;
    }

    return delta;
}

static inline void skeetla_updateFacingFromMoveVector(GameObject* obj, s16* turnDeltaOut) {
    TrickyState* state;
    int yaw;

    state = (TrickyState*)obj->extra;

    if (((state->dirX * state->dirX) + (state->dirZ * state->dirZ)) > 0.01f) {
        yaw = (s16)getAngle(-state->dirX, -state->dirZ);
        *turnDeltaOut = trickyTurnTowardYaw(obj, yaw);
        state->dirX = -mathSinf((TRICKY_PI * (f32)(int)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);
        state->dirZ = -mathCosf((TRICKY_PI * (f32)(int)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);
    }
}

static inline void skeetla_faceMoveVector(GameObject* obj) {
    s16 ignoredTurnDelta;

    skeetla_updateFacingFromMoveVector(obj, &ignoredTurnDelta);
}

const f32 gTrickyAvoidanceRepathEpsilonSq[1] = {0.0001f};
const f32 gTrickyRunMoveThreshold[1] = {2.5f};
const f32 gTrickyFastWalkMoveThreshold[1] = {0.66f};
const f32 gTrickySlowWalkMoveThreshold[1] = {0.33f};
const f32 gTrickyTurnMoveBlendSpeed[1] = {0.04f};
const f32 gTrickyAnimTransitionFrames[1] = {15.0f};

#define TRICKY_AVOIDANCE_REPATH_EPSILON_SQ (gTrickyAvoidanceRepathEpsilonSq[0])
#define TRICKY_TINY_MOVE_BLEND_SPEED       TRICKY_AVOIDANCE_REPATH_EPSILON_SQ
#define TRICKY_RUN_MOVE_THRESHOLD          (gTrickyRunMoveThreshold[0])
#define TRICKY_FAST_WALK_MOVE_THRESHOLD    (gTrickyFastWalkMoveThreshold[0])
#define TRICKY_SLOW_WALK_MOVE_THRESHOLD    (gTrickySlowWalkMoveThreshold[0])
#define TRICKY_TURN_MOVE_BLEND_SPEED       (gTrickyTurnMoveBlendSpeed[0])
#define TRICKY_ANIM_TRANSITION_FRAMES      (gTrickyAnimTransitionFrames[0])

static inline void skeetla_playFootstepSfx(GameObject* obj, u16 sfxId) {
    TrickyState* state = obj->extra;
    if (((TrickyState*)obj->extra)->soundSuppressed == 0u &&
        ((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END) || (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
        (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0)) {
        objSoundStartTimed(obj, &state->soundState, sfxId, 0x500, -1, 0);
    }
}

int moveTricky(GameObject* obj, f32* targetPos) {
    f32 desiredNextPos[3];
    f32 avoidanceNextPos[3];
    u16 sfxIds[3];
    u16 sfxId;
    char* debugText;
    TrickyState* state;
    f32 currentSpeed;
    f32 minMoveSpeed;
    f32 dirLength;
    f32 componentSpeed;
    f32 animPathSpeedDelta;
    int turnDeltaAbs;

    debugText = gTrickyDebugStringTable;
    state = obj->extra;
    currentSpeed = state->speed;
    trickyDebugPrint(sSkeetlaVelDebugFmt, currentSpeed);

    state->dirX = targetPos[0] - obj->anim.worldPosX;
    state->dirZ = targetPos[2] - obj->anim.worldPosZ;
    dirLength = sqrtf((state->dirX * state->dirX) + (state->dirZ * state->dirZ));
    if (gTrickyFloatZero != dirLength) {
        state->dirX /= dirLength;
        state->dirZ /= dirLength;
    }

    minMoveSpeed = gTrickySmallSpeedStep;
    if (currentSpeed < minMoveSpeed) {
        componentSpeed = minMoveSpeed * state->dirX;
        desiredNextPos[0] = timeDelta * componentSpeed + obj->anim.worldPosX;
        desiredNextPos[1] = obj->anim.worldPosY;
        componentSpeed = minMoveSpeed * state->dirZ;
        desiredNextPos[2] = timeDelta * componentSpeed + obj->anim.worldPosZ;
    } else {
        desiredNextPos[0] = timeDelta * (state->dirX * currentSpeed) + obj->anim.worldPosX;
        desiredNextPos[1] = obj->anim.worldPosY;
        desiredNextPos[2] = timeDelta * (state->dirZ * currentSpeed) + obj->anim.worldPosZ;
    }

    avoidanceNextPos[0] = desiredNextPos[0];
    avoidanceNextPos[1] = desiredNextPos[1];
    avoidanceNextPos[2] = desiredNextPos[2];
    trickyApplyObjectAvoidanceToStep(&obj->anim.worldPosX, avoidanceNextPos, targetPos);
    if (vec3f_distanceSquared(desiredNextPos, avoidanceNextPos) > TRICKY_AVOIDANCE_REPATH_EPSILON_SQ) {
        state->dirX = avoidanceNextPos[0] - obj->anim.worldPosX;
        state->dirZ = avoidanceNextPos[2] - obj->anim.worldPosZ;
        dirLength = sqrtf((state->dirX * state->dirX) + (state->dirZ * state->dirZ));
        if (gTrickyFloatZero != dirLength) {
            state->dirX /= dirLength;
            state->dirZ /= dirLength;
        }
    }

    if (currentSpeed >= gTrickySmallSpeedStep) {
        skeetla_faceMoveVector(obj);
        if (skeetla_isInWater(state) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_SWIM, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_ROOT_TRANSLATE);
            state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
            state->particleTimer = gTrickyFloatZero;
            trickyDebugPrint(debugText + TRICKY_DBG_IN_WATER);
        } else {
            if (state->stateIndex == TRICKY_STATE_FOLLOW_PLAYER) {
                if (skeetla_pathSpeedDelta(obj) >= gTrickyFloatZero) {
                    animPathSpeedDelta = skeetla_pathSpeedDelta(obj);
                } else {
                    animPathSpeedDelta = skeetla_pathSpeedDelta(obj);
                    animPathSpeedDelta = -animPathSpeedDelta;
                }

                if (animPathSpeedDelta > gTrickyFloatZero) {
                    state->sfxIntervalTimer -= timeDelta;
                    if (state->sfxIntervalTimer <= gTrickyFloatZero) {
                        state->sfxIntervalTimer = (f32)(int)randomGetRange(600, 1200);
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            if (currentSpeed > 1.0f) {
                                sfxId = randomGetRange(TRICKY_VOICE_SFX_WAIT_UP_FOX, TRICKY_VOICE_SFX_WAIT_FOR_ME);
                                skeetla_playFootstepSfx(obj, sfxId);
                            } else {
                                *(u32*)sfxIds = *(u32*)gSkeetlaFootstepSfxIds01;
                                sfxIds[2] = gSkeetlaFootstepSfxId2[0];
                                if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
                                    randomGetRange(0, 2);
                                } else {
                                    randomGetRange(0, 1);
                                }
                                sfxId = sfxIds[randomGetRange(0, 2)];
                                skeetla_playFootstepSfx(obj, sfxId);
                            }
                        }
                    }
                }
            }

            if (currentSpeed > TRICKY_RUN_MOVE_THRESHOLD) {
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                trickyRequestMove(obj, TRICKY_ANIM_LAND_RUN_LOOP, TRICKY_TINY_MOVE_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (currentSpeed > 1.0f) {
                trickyRequestMove(obj, TRICKY_ANIM_RUN, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (currentSpeed > TRICKY_FAST_WALK_MOVE_THRESHOLD) {
                trickyRequestMove(obj, TRICKY_ANIM_WALK_FAST, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (currentSpeed > TRICKY_SLOW_WALK_MOVE_THRESHOLD) {
                trickyRequestMove(obj, TRICKY_ANIM_WALK_MEDIUM, TRICKY_TINY_MOVE_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_WALK_LOOP);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_WALK_SLOW, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_WALK_LOOP);
            }
            trickyDebugPrint(debugText + TRICKY_DBG_MOVE_OUT_OF_WATER);
        }
    } else {
        s16 previousYaw;
        s16 turnDelta;
        u32 flagsSnapshot;

        previousYaw = obj->anim.rotX;
        turnDelta = 0;
        skeetla_updateFacingFromMoveVector(obj, &turnDelta);
        turnDeltaAbs = turnDelta;

        if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) != 0) {
            if (skeetla_isInWater(state) != 0) {
                trickyDebugPrint(debugText + TRICKY_DBG_TURN_IN_WATER);
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
            } else {
                int animId;
                u32 flags;

                trickyDebugPrint(debugText + TRICKY_DBG_TURN_OUT_OF_WATER);
                flags = state->stateFlags;
                if ((flags & TRICKY_STATE_FLAG_TURN_LEFT) != 0) {
                    if ((turnDeltaAbs >= 0 ? turnDeltaAbs : -turnDeltaAbs) > TRICKY_TURN_LARGE_ANGLE) {
                        animId = TRICKY_ANIM_TURN_LEFT_LARGE;
                    } else {
                        turnDeltaAbs = turnDeltaAbs >= 0 ? turnDelta : -turnDeltaAbs;
                        if (turnDeltaAbs > TRICKY_TURN_MEDIUM_ANGLE) {
                            animId = TRICKY_ANIM_TURN_LEFT_MEDIUM;
                        } else {
                            animId = TRICKY_ANIM_TURN_LEFT_SMALL;
                        }
                    }
                } else if ((flags & TRICKY_STATE_FLAG_TURN_RIGHT) != 0) {
                    if ((turnDeltaAbs >= 0 ? turnDeltaAbs : -turnDeltaAbs) > TRICKY_TURN_LARGE_ANGLE) {
                        animId = TRICKY_ANIM_TURN_RIGHT_LARGE;
                    } else {
                        turnDeltaAbs = turnDeltaAbs >= 0 ? turnDelta : -turnDeltaAbs;
                        if (turnDeltaAbs > TRICKY_TURN_MEDIUM_ANGLE) {
                            animId = TRICKY_ANIM_TURN_RIGHT_MEDIUM;
                        } else {
                            animId = TRICKY_ANIM_TURN_RIGHT_SMALL;
                        }
                    }
                }
                obj->anim.rotX = previousYaw;
                trickyRequestMove(obj, animId, TRICKY_TURN_MOVE_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_STATE_FLAG_ROTATE);
            }
        }

        state->speed = gTrickySmallSpeedStep;
        flagsSnapshot = state->stateFlags;
        if (((flagsSnapshot & TRICKY_STATE_FLAG_TURN_REQUEST) == 0) &&
            ((flagsSnapshot & TRICKY_STATE_FLAG_TURN_REQUEST_PREV) == 0)) {
            return 0;
        }
    }
    return 1;
}

int trickyRequestMove(GameObject* obj, int newState, f32 speed, u32 flags) {
    TrickyState* state = obj->extra;
    f32 fz;
    if (state->moveId == newState) {
        if (obj->anim.currentMove == newState) {
            state->moveProgress = speed;
            state->stateFlags = state->stateFlags | flags;
        }
        return 1;
    }
    if ((flags & TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION) != 0) {
        state->animTransitionTimer = TRICKY_ANIM_TRANSITION_FRAMES;
    }
    state->moveId = newState;
    state->moveProgressTarget = speed;
    state->pendingStateFlags = flags;
    if ((flags & TRICKY_STATE_FLAG_SIDESTEP) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_SIDESTEP;
    }
    if ((flags & TRICKY_STATE_FLAG_BACKSTEP) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_BACKSTEP;
    }
    if ((flags & TRICKY_STATE_FLAG_VERTICAL_MOVE) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_VERTICAL_MOVE;
    }
    if ((flags & TRICKY_STATE_FLAG_ROTATE) == 0) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_ROTATE;
    }
    fz = 1.0f;
    state->sidestepDelta = fz;
    state->backstepDelta = fz;
    state->verticalDelta = fz;
    state->rotStepScale = fz;
    if (state->animTransitionTimer >= TRICKY_ANIM_TRANSITION_FRAMES) {
        return 1;
    }
    return 0;
}

static inline RomCurveDef* skeetla_validateRouteEntry(RomCurveDef* entry) {
    if (entry == NULL) {
        return NULL;
    }
    if (((entry->requiredBit == -1) || (mainGetBit(entry->requiredBit) != 0)) &&
        ((entry->forbiddenBit == -1) || (mainGetBit(entry->forbiddenBit) == 0))) {
        return entry;
    }

    return NULL;
}

RomCurveDef* trickyFindNearestLinkedRouteEntry(TrickyState* context, RomCurveDef* routeDef, int linkSelector,
                                               int routeFlagValue) {
    RomCurveDef* candidates[4];
    RomCurveDef* entry;
    f32 bestDistance;
    f32 distance;
    u16 mask;
    u16 i;
    u16 count;
    u16 bestIndex;
    int curveId;
    s16 requiredBit;
    s16 forbiddenBit;

    i = 0;
    count = 0;
    mask = 1;
    while (i < 4) {
        curveId = routeDef->linkIds[i];
        if ((curveId > -1) && ((((routeDef->blockedLinkMask & mask) ^ routeFlagValue) == 0))) {
            candidates[count] = (*gRomCurveInterface)->getById(curveId);
            if (candidates[count] != NULL) {
                entry = candidates[count];
                if ((linkSelector == 0) || (routeDef->linkWalkGroups[count] == linkSelector)) {
                    requiredBit = entry->requiredBit;
                    if ((requiredBit == -1) || (mainGetBit(requiredBit) != 0)) {
                        forbiddenBit = entry->forbiddenBit;
                        if ((forbiddenBit == -1) || (mainGetBit(forbiddenBit) == 0)) {
                            if ((routeDef->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B) ||
                                (entry->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A)) {
                                count++;
                            }
                        }
                    }
                }
            }
        }
        i++;
        mask <<= 1;
        routeFlagValue <<= 1;
    }

    if (count != 0) {
        bestDistance = getXZDistanceSquared(&context->playerObj->anim.worldPosX, &candidates[0]->x);
        bestIndex = 0;
        for (i = 1; i < count; i++) {
            distance = getXZDistanceSquared(&context->playerObj->anim.worldPosX, &candidates[i]->x);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestIndex = i;
            }
        }

        return candidates[bestIndex];
    }
    return NULL;
}

RomCurveDef* trickyFindPathRouteEntry(TrickyState* state, u32 route, int pathId) {
    if (pathId == 0) {
        return NULL;
    }

    if ((state->cachedPathId == pathId) && (state->cachedRouteId == route)) {
        state->cachedRouteEntry = pathSearchGetNextPoint(&state->pathSearches[8]);
        if (state->cachedRouteEntry == NULL) {
            return NULL;
        }

        state->cachedRouteEntry = skeetla_validateRouteEntry(state->cachedRouteEntry);
        if (state->cachedRouteEntry != NULL) {
            return (state)->cachedRouteEntry;
        }
    }

    pathSearchBegin(&state->pathSearches[8], (RomCurveDef*)route, state->targetPosPtr, pathId, state->route.reverse);
    if (pathSearchStep(&state->pathSearches[8], TRICKY_PATH_SEARCH_BULK_STEPS) != 1) {
        return NULL;
    }

    pathSearchBuildPath(&state->pathSearches[8]);
    state->cachedRouteEntry = pathSearchGetNextPoint(&state->pathSearches[8]);
    state->cachedPathId = pathId;
    return (state)->cachedRouteEntry;
}

int trickyFindReachableRouteIndex(TrickyState* state, RomCurveDef** candidateRoutes, u8* candidateRouteFlags,
                                  int targetWalkGroup) {
    RomCurveDef** beginRouteCursor;
    u8* searchCursor;
    RomCurveDef** routeCursor;
    RomCurveDef** fallbackRouteCursor;
    u8* beginSearchCursor;
    s8* statusCursor;
    s8 searchPass;
    s8 routeStatus[TRICKY_ROUTE_CANDIDATE_COUNT];
    s8 beginIndex;
    s8 fallbackIndex;
    s8 candidateIndex;
    s8 inactiveCandidateCount;

    for (beginIndex = 0, beginRouteCursor = candidateRoutes, beginSearchCursor = (u8*)state;
         beginIndex < TRICKY_ROUTE_CANDIDATE_COUNT; beginIndex++) {
        if (*beginRouteCursor != NULL) {
            pathSearchBegin(&TRICKY_PATH_SEARCH_AT_CURSOR(beginSearchCursor), *beginRouteCursor, state->targetPosPtr,
                            targetWalkGroup, candidateRouteFlags[beginIndex]);
        }
        beginRouteCursor++;
        beginSearchCursor += sizeof(PathSearch);
    }

    for (searchPass = 0; searchPass < 100; searchPass++) {
        inactiveCandidateCount = 0;
        for (candidateIndex = 0, routeCursor = candidateRoutes, searchCursor = (u8*)state, statusCursor = routeStatus;
             candidateIndex < TRICKY_ROUTE_CANDIDATE_COUNT; candidateIndex++) {
            if (*routeCursor != NULL) {
                *statusCursor = pathSearchStep(&TRICKY_PATH_SEARCH_AT_CURSOR(searchCursor), 1);
            } else {
                *statusCursor = -1;
            }

            switch (*statusCursor) {
            case 1:
                return candidateIndex;
            case -1:
                *routeCursor = NULL;
                inactiveCandidateCount++;
                break;
            }
            routeCursor++;
            searchCursor += sizeof(PathSearch);
            statusCursor++;
        }

        switch (inactiveCandidateCount) {
        case 7:
            for (fallbackIndex = 0, fallbackRouteCursor = candidateRoutes; fallbackIndex < TRICKY_ROUTE_CANDIDATE_COUNT;
                 fallbackIndex++) {
                if (*fallbackRouteCursor != NULL) {
                    routeStatus[(int)fallbackIndex] =
                        pathSearchStep(&state->pathSearches[(int)fallbackIndex], TRICKY_PATH_SEARCH_BULK_STEPS);
                    if (routeStatus[(int)fallbackIndex] == 1) {
                        return fallbackIndex;
                    }
                    return -1;
                }
                fallbackRouteCursor++;
            }
        case 8:
            return -1;
        }
    }

    return -1;
}

RomCurveDef* trickySelectRouteEntry(TrickyState* state, RomCurveDef* routeDef, u8 routeFlagValue) {
    RomCurveDef* entry;

    entry = NULL;

    if ((state->cachedRouteDef == routeDef) && (state->cachedWalkGroup == state->walkGroup) &&
        (state->cachedRouteFlags == (routeFlagValue & 0xffu))) {
        entry = skeetla_validateRouteEntry(state->validatedRouteEntry);
    }

    if (entry == NULL) {
        entry = trickyFindNearestLinkedRouteEntry(state, routeDef, state->walkGroup, routeFlagValue & 0xff);
        if (entry == NULL) {
            entry = trickyFindPathRouteEntry(state, (u32)routeDef, state->walkGroup);
        }

        if (entry == NULL) {
            if (state->savedWalkGroup != 0) {
                entry =
                    trickyFindNearestLinkedRouteEntry(state, routeDef, state->savedWalkGroup, routeFlagValue & 0xff);
                if (entry == NULL) {
                    entry = trickyFindPathRouteEntry(state, (u32)routeDef, state->savedWalkGroup);
                }
                if (entry != NULL) {
                    state->walkGroup = state->savedWalkGroup;
                }
            }

            if (entry == NULL) {
                entry = trickyFindNearestLinkedRouteEntry(state, routeDef, 0, routeFlagValue & 0xff);
                state->walkGroup = 0;
            }
        }
    }

    state->cachedRouteDef = routeDef;
    state->validatedRouteEntry = entry;
    state->cachedWalkGroup = state->walkGroup;
    state->cachedRouteFlags = routeFlagValue;
    return entry;
}

void trickyRankLinkedRouteCandidates(GameObject* obj, u8* outRouteFlags, s16 linkSelector, RomCurveDef** outRoutes) {
    f32 bestDistances[TRICKY_ROUTE_CANDIDATE_COUNT];
    int i;
    RomCurveDef** curves;
    int linkCurveId;
    int count;
    RomCurveDef** cp;
    int curveIdx;
    RomCurveDef* linkedCurve;
    f32 curveX;
    f32 targetXDistanceSquared;
    f32 targetZDistanceSquared;
    f32 curveZ;
    f32* p;
    f32 score;
    f32 init;
    RomCurveDef* curve;
    u8 j;
    u8 routeFlags;
    u8 k;
    f32* bd;
    RomCurveDef** rp;
    TrickyState* state;

    state = obj->extra;
    curves = (*gRomCurveInterface)->getCurves(&count);

    init = gTrickyMaxDistance;
    bd = bestDistances;
    rp = outRoutes;
    for (i = 0; i < TRICKY_ROUTE_CANDIDATE_COUNT; i++) {
        *bd++ = init;
        *rp++ = NULL;
    }

    if (linkSelector == 0) {
        return;
    }

    for (curveIdx = 0, cp = curves; curveIdx < count; cp++, curveIdx++) {
        curve = *cp;
        if ((curve->type != 0x24) || (curve->walkGroup != 0)) {
            continue;
        }
        if (((curve->requiredBit != -1) && (mainGetBit(curve->requiredBit) == 0)) ||
            ((curve->forbiddenBit != -1) && (mainGetBit(curve->forbiddenBit) != 0))) {
            continue;
        }

        curveZ = curve->z;
        p = state->targetPosPtr;
        {
            targetZDistanceSquared = (p[2] - curveZ) * (p[2] - curveZ);
            curveX = curve->x;
            targetXDistanceSquared = (p[0] - curveX) * (p[0] - curveX);
            {
                f32 objectXDistanceSquared = (obj->anim.worldPosX - curveX) * (obj->anim.worldPosX - curveX);
                f32 objectZDistanceSquared = (obj->anim.worldPosZ - curveZ) * (obj->anim.worldPosZ - curveZ);
                score = targetZDistanceSquared +
                        (targetXDistanceSquared + (objectXDistanceSquared + objectZDistanceSquared));
            }
        }
        if (score < bestDistances[7]) {
            for (j = 0; j < 4; j++) {
                linkCurveId = curve->linkIds[j];
                if ((linkCurveId > -1) && (curve->linkWalkGroups[j] == linkSelector)) {
                    if (curve->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A) {
                        linkedCurve = (*gRomCurveInterface)->getById(linkCurveId);
                        if ((linkedCurve != NULL) && (linkedCurve->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B)) {
                            continue;
                        }
                    }

                    routeFlags = (u8)(curve->blockedLinkMask >> j);
                    break;
                }
            }

            if (j == 4) {
                continue;
            }

            for (j = 0; j < TRICKY_ROUTE_CANDIDATE_COUNT; j++) {
                if (score < bestDistances[j]) {
                    for (k = 7; k > j; k--) {
                        outRouteFlags[k] = outRouteFlags[k - 1];
                        outRoutes[k] = outRoutes[k - 1];
                        bestDistances[k] = bestDistances[k - 1];
                    }

                    outRouteFlags[j] = (routeFlags & 1) ^ 1;
                    outRoutes[j] = curve;
                    bestDistances[j] = score;
                    break;
                }
            }
        }
    }
}

void skeetla_spawnLinkedSparks(GameObject* obj) {
    TrickyState* state;
    GameObject* linkedObj;
    SkeetlaParticleSpawnArgs args;

    state = obj->extra;
    linkedObj = state->followObj;

    args.x = state->sparkPos0X;
    args.y = state->sparkPos0Y;
    args.z = state->sparkPos0Z;
    args.objectId = obj->anim.rotX;
    if (linkedObj->anim.romDefNo == SKEETLA_LINKED_SOURCE_ID_OBJ_A) {
        args.sourceId = (u8)((u32 (*)(GameObject*))linkedObj->anim.dll[0][10])(linkedObj);
    } else if (linkedObj->anim.romDefNo == SKEETLA_LINKED_SOURCE_ID_OBJ_B) {
        args.sourceId = (u8)((u32 (*)(GameObject*))linkedObj->anim.dll[0][10])(linkedObj);
    } else {
        args.sourceId = 0;
    }

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }

    args.x = state->sparkPos1X;
    args.y = state->sparkPos1Y;
    args.z = state->sparkPos1Z;
    args.objectId = obj->anim.rotX;

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args, SKEETLA_PARTICLE_SPAWN_FLAGS, -1, NULL);
    }
}

const f32 gTrickyAvoidanceBlendStepScale[1] = {0.125f};

#define TRICKY_AVOIDANCE_BLEND_STEP_SCALE (gTrickyAvoidanceBlendStepScale[0])

void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* guardPoint, f32* center, f32 minDistance,
                                 f32 moveDistance) {
    f32 projection[3];
    f32 dx;
    f32 centerToEnd;
    f32 minDistanceSq;
    f32 limitDistanceSq;
    f32 guardDistance;
    f32 startGuardDistance;
    f32 slope[1];
    f32 intercept;
    f32 perpSlope;
    f32 dz;
    f32 centerToStart;
    f32 length;
    int useBlendedDistance;

    useBlendedDistance = 0;
    centerToStart = getXZDistanceSquared(center, start);
    centerToEnd = getXZDistanceSquared(center, end);
    minDistanceSq = minDistance * minDistance;
    limitDistanceSq = moveDistance * moveDistance;

    if (centerToEnd > centerToStart) {
        return;
    }

    guardDistance = getXZDistanceSquared(guardPoint, center);
    if (guardDistance < minDistanceSq) {
        return;
    }

    startGuardDistance = getXZDistanceSquared(start, guardPoint);
    if (getXZDistanceSquared(start, center) > startGuardDistance) {
        return;
    }

    if (centerToStart < limitDistanceSq) {
        limitDistanceSq = centerToStart;
        useBlendedDistance = 1;
    }

    if (!(centerToEnd < limitDistanceSq)) {
        return;
    }

    slope[0] = (end[2] - start[2]) / (end[0] - start[0]);
    intercept = start[2] - (slope[0] * start[0]);
    perpSlope = (start[0] - end[0]) / (end[2] - start[2]);
    projection[0] = ((center[2] - (perpSlope * center[0])) - intercept) / (slope[0] - perpSlope);
    projection[2] = (slope[0] * projection[0]) + intercept;

    if (!(getXZDistanceSquared(center, projection) < minDistanceSq)) {
        return;
    }

    dx = end[0] - center[0];
    dz = end[2] - center[2];
    length = sqrtf((dx * dx) + (dz * dz));
    if (gTrickyFloatZero != length) {
        dx /= length;
        dz /= length;
    }

    if (useBlendedDistance != 0) {
        moveDistance = sqrtf(limitDistanceSq);
        {
            f32 blend = moveDistance - sqrtf(centerToEnd);
            moveDistance = moveDistance - (blend * TRICKY_AVOIDANCE_BLEND_STEP_SCALE);
        }
    }

    end[0] = center[0] + (dx * moveDistance);
    end[2] = center[2] + (dz * moveDistance);
}

/* group owned by another DLL, queried here */

void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* guardPoint) {
    int count;
    int startIndex;
    int objectCount;
    GameObject** objects;
    GameObject* obj;
    SideRepelPlacement* repelPlacement;
    ObjDef* modelDef;
    ObjHitsPriorityState* hitState;
    u16 minRadius;
    GameObject** op;
    f32 scale;
    int i;

    objects = objGetAllOfType(SIDEREPEL_OBJGROUP, &count);
    for (i = 0, op = objects, scale = TRICKY_POSITION_OFFSET_SCALE; i < count; i++) {
        obj = *op;
        repelPlacement = (SideRepelPlacement*)obj->anim.placementData;
        trickyAdjustStepAroundPoint(start, end, guardPoint, &obj->anim.worldPosX,
                                    scale * (f32)(u32)repelPlacement->minDistance,
                                    scale * (f32)(u32)repelPlacement->moveDistance);
        op++;
    }

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    for (i = startIndex, op = objects + i; i < objectCount; i++) {
        obj = *op;
        modelDef = obj->anim.modelInstance;
        minRadius = modelDef->avoidRadiusX;
        if (minRadius != 0) {
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if ((hitState != NULL) && ((hitState->flags & 1) != 0)) {
                trickyAdjustStepAroundPoint(start, end, guardPoint, &obj->anim.worldPosX,
                                            TRICKY_POSITION_OFFSET_SCALE * (f32)(u32)minRadius,
                                            TRICKY_POSITION_OFFSET_SCALE * (f32)(u32)modelDef->avoidRadiusZ);
            }
        }
        op++;
    }
}

/*
 * Tricky sidekick follow/path-walk movement. trickyUpdateMovementState is
 * the per-frame movement step that resolves the target's walk/patch group and
 * drives motion through a substate machine and RomCurveWalker route;
 * trickyUpdateApproachSpeed ramps the follow speed toward a target point. The
 * The named gTricky* scalar constants are this DLL's .sdata2 movement tuning pool.
 */

char sInWaterMessage[] = "in water\n";

char sTrickyDryLandDebugMessage[] = "out of water\n"
                                    "\0\0\0"
                                    "moveTricky: out of water\n"
                                    "\0\0\0"
                                    "Turning in water\n"
                                    "\0\0\0"
                                    "Turning out of water\n"
                                    "\0\0\0"
                                    "tricky wg %d->%d target wg %d, dest wg %d\n"
                                    "\0\0"
                                    "tricky last walk group is zero. Has he been loaded within a walk group? %f %f %f\n"
                                    "\0\0\0"
                                    "velbefore %f, vel now %f\n"
                                    "\0\0\0"
                                    "target is within a walkGroup or its patch\n"
                                    "\0\0"
                                    "target is not within a walkGroup or any patches\n"
                                    "\0\0\0\0"
                                    "target is within patch group %d\n"
                                    "\0\0\0\0"
                                    "Patch %d: Last xyz %f %f %f\n"
                                    "\0\0\0\0"
                                    "Last Patch Point %f %f %f\n"
                                    "\0\0"
                                    "Tricky is neither in a walkgroup or in a patch\n"
                                    "\0"
                                    "tricky error, target patch %d, targetWalkGroup %d, trickyWalkGroup %d, tricky "
                                    "last walkGroup %d, tricky in patch %d\n"
                                    "\0\0\0\0"
                                    "tricky error 2!!!!!\n"
                                    "\0\0\0\0"
                                    "movement state is %d\n"
                                    "\0\0\0"
                                    "walk wait\n"
                                    "\0\0"
                                    "walk free\n"
                                    "\0\0"
                                    "walk start patch\n"
                                    "\0\0\0"
                                    "walk patch exit\n"
                                    "\0\0\0\0"
                                    "walk end patch\n"
                                    "\0"
                                    "walk to node %d %d\n"
                                    "\0"
                                    "curve setup\n"
                                    "\0\0\0\0"
                                    "walk nodes\n"
                                    "\0"
                                    "Jump run up\n"
                                    "\0\0\0\0"
                                    "Jump prep\n"
                                    "\0\0"
                                    "Jumping\n"
                                    "\0\0\0\0"
                                    "Jump up run up\n"
                                    "\0"
                                    "JUMPDOWN or JUMPUP\n"
                                    "\0"
                                    "JUMPDOWN_RUNUP\n"
                                    "\0"
                                    "entered a non valid movementstate\n"
                                    "\0";

#define TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed)                                                    \
    do {                                                                                                               \
        s16 previousYaw;                                                                                               \
        s16 routeYaw;                                                                                                  \
        s16 yawDelta;                                                                                                  \
                                                                                                                       \
        previousYaw =                                                                                                  \
            getAngle((state)->prevLocalPosX - (obj)->anim.localPosX, (state)->prevLocalPosZ - (obj)->anim.localPosZ);  \
        routeYaw =                                                                                                     \
            getAngle((state)->prevLocalPosX - (state)->route.posX, (state)->prevLocalPosZ - (state)->route.posZ);      \
        yawDelta = previousYaw - (u16)routeYaw;                                                                        \
        if (0x8000 < yawDelta) {                                                                                       \
            yawDelta = yawDelta - 0xffff;                                                                              \
        }                                                                                                              \
        if (yawDelta < -0x8000) {                                                                                      \
            yawDelta = yawDelta + 0xffff;                                                                              \
        }                                                                                                              \
        if (yawDelta > 0x4000) {                                                                                       \
            yawDelta -= 0x8000;                                                                                        \
        } else if (yawDelta < -0x4000) {                                                                               \
            yawDelta += 0x8000;                                                                                        \
        }                                                                                                              \
        if (0x1000 < ((yawDelta >= 0) ? yawDelta : -yawDelta)) {                                                       \
            (state)->speed = (previousSpeed);                                                                          \
            trickyUpdateApproachSpeed((obj), TRICKY_RUN_MOVE_THRESHOLD, (state), &(state)->route.posX, 1);             \
        }                                                                                                              \
    } while (0)

#define TRICKY_ADVANCE_ROUTE_TO_END(state)                                                                             \
    do {                                                                                                               \
        if ((state)->route.reverse != 0) {                                                                             \
            while ((state)->route.atSegmentEnd != 0) {                                                                 \
                RomCurve_stepClamped(&(state)->route, TRICKY_ROUTE_REVERSE_STEP);                                      \
            }                                                                                                          \
        } else {                                                                                                       \
            while ((state)->route.atSegmentEnd == 0) {                                                                 \
                RomCurve_stepClamped(&(state)->route, TRICKY_FLOAT_TWO);                                               \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

#define TRICKY_FOLLOW_MAX_SPEED                 (gTrickyFollowMaxSpeed[0])
#define TRICKY_FOLLOW_JUMPUP_FAST_BLEND_SPEED   (gTrickyFollowAnim17Speed[0])
#define TRICKY_FOLLOW_JUMPUP_SLOW_BLEND_SPEED   (gTrickyFollowAnim18Speed[0])
#define TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR   (gTrickyFollowVerticalDeltaDivisorA[0])
#define TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED      (gTrickyFollowJumpdownBlendSpeed[0])
#define TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR (gTrickyFollowVerticalDeltaDivisorB[0])
#define TRICKY_FOLLOW_ARC_SPEED                 (gTrickyFollowArcSpeed[0])
#define TRICKY_FOLLOW_ARC_HALF_PROGRESS         (gTrickyFollowArcHalfProgress[0])
#define TRICKY_FOLLOW_ARC_QUARTER_PROGRESS      (gTrickyFollowArcQuarterProgress[0])
#define TRICKY_FOLLOW_ARC_COEFFICIENT           (gTrickyFollowArcCoefficient[0])
#define TRICKY_FOLLOW_ARC_PROGRESS_WINDOW       (gTrickyFollowArcProgressWindow[0])
#define TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW       (gTrickyFollowArcEndpointWindow[0])
#define TRICKY_FOLLOW_ARC_MIDDLE_WINDOW         (gTrickyFollowArcMiddleWindow[0])
#define TRICKY_FOLLOW_JUMP_LAND_SPEED           (gTrickyFollowJumpLandSpeed[0])

const f32 gTrickyDefaultStoppingRadius[1] = {5.0f};
const f32 gTrickyFollowMaxSpeed[1] = {3.0f};
const f32 gTrickyFollowAnim17Speed[1] = {0.0135f};
const f32 gTrickyFollowAnim18Speed[1] = {0.00975f};
const f32 gTrickyFollowVerticalDeltaDivisorA[1] = {32.865f};
const f32 gTrickyFollowJumpdownBlendSpeed[1] = {0.0125f};
const f32 gTrickyFollowVerticalDeltaDivisorB[1] = {33.114f};
const f32 gTrickyFollowArcSpeed[1] = {2.3f};
const f32 gTrickyFollowArcHalfProgress[1] = {0.5f};
const f32 gTrickyFollowArcQuarterProgress[1] = {0.25f};
const f32 gTrickyFollowArcCoefficient[1] = {-0.017f};
const f32 gTrickyFollowArcProgressWindow[1] = {24.0f};
const f32 gTrickyFollowArcEndpointWindow[1] = {6.0f};
const f32 gTrickyFollowArcMiddleWindow[1] = {12.0f};
const f32 gTrickyFollowJumpLandSpeed[1] = {0.75f};

#define TRICKY_DEFAULT_STOPPING_RADIUS (gTrickyDefaultStoppingRadius[0])

int trickyUpdateMovementState(GameObject* obj, f32 stoppingRadius, TrickyState* state) {
    u8* cachedPatchIdCursor;
    u8* cachedPatchTargetCursor;
    int targetPatchGroup;
    u8* patchInfoGroupCursor;
    u8* cachedPatchIdWriteCursor;
    RomCurveDef* routeNode;
    f32* target;
    char* debugStrings = gTrickyDebugStringTable;
    int objectWalkGroup;
    int targetWalkGroup;
    u8 didMove = 1;
    RomCurveDef* prevNode;
    u32 patchGroupForCheck;
    s16 linkedWalkGroupId;
    u32 prod;
    int routeDirection;
    u8* cachedPatchTargetWriteCursor;
    int i;
    u8 patchSlot;
    f32* patchTarget;
    u16 walkGroupLink;
    u8 patchMaskBit;
    f32 previousSpeed;
    f32 dist;
    f32 len;
    f32 v;
    f32 k;
    f32 sqz;
    f32 sqx;
    u8 walkGroupPair[2];
    u8 routeFlags[8];
    struct {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } rot;
    f32 delta[3];
    ObjfsaWalkGroupPatchInfo patchInfo;
    RomCurveDef* routePtrs[9];

    if ((state->movementState < 5) && (isInWalkGroupOrPatch(&obj->anim.worldPosX) == 0)) {
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
        obj->anim.localPosX = state->homePosX;
        obj->anim.localPosY = state->homePosY;
        obj->anim.localPosZ = state->homePosZ;
        obj->anim.worldPosX = state->homePosX;
        obj->anim.worldPosY = state->homePosY;
        obj->anim.worldPosZ = state->homePosZ;
        ObjHits_SyncObjectPosition(obj);
    }
    target = state->targetPosPtr;
    objectWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0);
    if ((objectWalkGroup != 0) && (state->activeWalkGroup != objectWalkGroup)) {
        state->activeWalkGroup = objectWalkGroup;
        {
            u32 mask;
            u32 f2 = state->stateFlags;
            mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
            state->stateFlags = f2 & mask;
        }
        state->patch[0] = 0;
        state->patch[1] = 0;
        state->patch[2] = 0;
        state->patch[3] = 0;
    }
    targetWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(target, &patchInfo);
    if (((objectWalkGroup != 0) && (targetWalkGroup == 0)) &&
        ((walkGroupLink = getPatchGroup(target, objectWalkGroup)) != 0)) {
        walkPath_writeU16LE(walkGroupLink, walkGroupPair);
        if (walkGroupPair[0] == objectWalkGroup) {
            targetWalkGroup = walkGroupPair[1];
        } else {
            targetWalkGroup = walkGroupPair[0];
        }
    }
    if ((targetWalkGroup != 0) && (targetWalkGroup != state->walkGroup)) {
        state->walkGroup = targetWalkGroup;
    }
    state->savedWalkGroup = state->walkGroup;
    trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_GROUP_STATUS, state->activeWalkGroup, objectWalkGroup,
                     targetWalkGroup, state->walkGroup);
    if (state->activeWalkGroup == 0) {
        trickyReportError(debugStrings + TRICKY_DBG_ZERO_ACTIVE_WALK_GROUP, obj->anim.worldPosX, obj->anim.worldPosY,
                          obj->anim.worldPosZ);
    }
    previousSpeed = state->speed;
    trickyUpdateApproachSpeed(obj, stoppingRadius, state, target, 0);
    trickyDebugPrint(debugStrings + TRICKY_DBG_SPEED_UPDATE, previousSpeed, state->speed);
    if (targetWalkGroup == state->activeWalkGroup) {

        state->stateFlags |= TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
        i = 0;
        patchMaskBit = 1;
        patchInfoGroupCursor = (u8*)&patchInfo;
        cachedPatchIdWriteCursor = (u8*)state;
        cachedPatchTargetWriteCursor = (u8*)state;
        for (; i < 4; patchInfoGroupCursor += sizeof(patchInfo.patchGroupIds[0]),
                      cachedPatchIdWriteCursor += sizeof(state->patch[0]),
                      cachedPatchTargetWriteCursor += sizeof(state->patchTargets[0]), i++, patchMaskBit <<= 1) {
            if (patchInfo.patchMask & patchMaskBit) {
                TRICKY_PATCH_AT_CURSOR(cachedPatchIdWriteCursor) =
                    ((ObjfsaWalkGroupPatchInfo*)patchInfoGroupCursor)->patchGroupIds[0];
                TRICKY_PATCH_TARGET_AT_CURSOR(cachedPatchTargetWriteCursor).x = target[0];
                TRICKY_PATCH_TARGET_AT_CURSOR(cachedPatchTargetWriteCursor).y = target[1];
                TRICKY_PATCH_TARGET_AT_CURSOR(cachedPatchTargetWriteCursor).z = target[2];
            }
        }
    }
    if ((targetWalkGroup != 0) && (targetWalkGroup == state->activeWalkGroup)) {
        state->linkedWalkGroup = 0;
    } else {
        u32 wgProd;

        wgProd = targetWalkGroup * state->activeWalkGroup & 0xffff;
        if (wgProd != 0) {
            u16* ids = patchInfo.patchGroupIds;

            for (i = 0, linkedWalkGroupId = wgProd; i < 4; ids++, i++) {
                if ((wgProd == *ids) && (((1 << i) & patchInfo.patchMask) != 0)) {
                    state->linkedWalkGroup = linkedWalkGroupId;
                    state->linkedPatchPos.x = target[0];
                    state->linkedPatchPos.y = target[1];
                    state->linkedPatchPos.z = target[2];
                }
            }
        }
    }
    if (isInWalkGroupOrPatch(target) != 0) {
        trickyDebugPrint(debugStrings + TRICKY_DBG_TARGET_IN_WALKGROUP_OR_PATCH);
    } else {
        trickyDebugPrint(debugStrings + TRICKY_DBG_TARGET_OUTSIDE_WALKGROUP_AND_PATCHES);
    }
    trickyDebugPrint(debugStrings + TRICKY_DBG_TARGET_PATCH_GROUP, getPatchGroup(target, state->activeWalkGroup));
    if ((state->stateFlags & TRICKY_STATE_FLAG_PATH_PATCHES_VALID) != 0) {
        int slotIdx;

        slotIdx = 0;
        cachedPatchIdCursor = (u8*)state;
        cachedPatchTargetCursor = (u8*)state;
        for (; slotIdx < 4; cachedPatchIdCursor += sizeof(state->patch[0]),
                            cachedPatchTargetCursor += sizeof(state->patchTargets[0]), slotIdx++) {
            if (TRICKY_PATCH_AT_CURSOR(cachedPatchIdCursor) != 0) {
                trickyDebugPrint(debugStrings + TRICKY_DBG_PATCH_LAST_XYZ, slotIdx,
                                 TRICKY_PATCH_TARGET_AT_CURSOR(cachedPatchTargetCursor).x,
                                 TRICKY_PATCH_TARGET_AT_CURSOR(cachedPatchTargetCursor).y,
                                 TRICKY_PATCH_TARGET_AT_CURSOR(cachedPatchTargetCursor).z);
            }
        }
    }
    if (state->linkedWalkGroup != 0) {
        trickyDebugPrint(debugStrings + TRICKY_DBG_LAST_PATCH_POINT, state->linkedPatchPos.x, state->linkedPatchPos.y,
                         state->linkedPatchPos.z);
    }
    {
        int trickyPatch;

        targetPatchGroup = getPatchGroup(target, state->activeWalkGroup) & 0xffff;
        trickyPatch = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup) & 0xffff;
        if ((targetWalkGroup != 0) && (objectWalkGroup == targetWalkGroup)) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
        } else {
            walkGroupLink = Objfsa_GetWalkGroupIndexForMove(&obj->anim.worldPosX, target, state->activeWalkGroup);
            if (walkGroupLink != 0) {
                state->movementState = TRICKY_MOVE_WALK_FREE;
                if (walkGroupLink != state->activeWalkGroup) {
                    state->activeWalkGroup = walkGroupLink;
                    {
                        u32 mask;
                        u32 f2 = state->stateFlags;
                        mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                        state->stateFlags = f2 & mask;
                    }
                    state->patch[0] = 0;
                    state->patch[1] = 0;
                    state->patch[2] = 0;
                    state->patch[3] = 0;
                }
            } else if (state->movementState < 5) {
                int i;

                if ((u32)targetPatchGroup != 0) {
                    if (targetWalkGroup == 0) {
                        if (objectWalkGroup != 0) {
                            for (i = 0, cachedPatchIdCursor = (u8*)state; i < 4;
                                 cachedPatchIdCursor += sizeof(state->patch[0]), i++) {
                                if (TRICKY_PATCH_AT_CURSOR(cachedPatchIdCursor) == targetPatchGroup) {
                                    patchSlot = i;
                                    state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                    break;
                                }
                            }
                            if (i == 4) {
                                if (targetPatchGroup & (state->cachedWalkGroup == 0xff)) {
                                    state->walkGroup = (int)(targetPatchGroup & 0xff00) >> 8;
                                } else {
                                    state->walkGroup = targetPatchGroup & 0xff;
                                }
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            if ((u32)trickyPatch != 0) {
                                for (i = 0, cachedPatchIdCursor = (u8*)state; i < 4;
                                     cachedPatchIdCursor += sizeof(state->patch[0]), i++) {
                                    if (TRICKY_PATCH_AT_CURSOR(cachedPatchIdCursor) == trickyPatch) {
                                        trickyPatch = i & 0xffff;
                                        state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                        break;
                                    }
                                }
                                if (i == 4) {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, trickyPatch);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                trickyReportError(debugStrings + TRICKY_DBG_NOT_IN_WALKGROUP_OR_PATCH);
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    } else {
                        if (objectWalkGroup != 0) {
                            for (i = 0, cachedPatchIdCursor = (u8*)state; i < 4;
                                 cachedPatchIdCursor += sizeof(state->patch[0]), i++) {
                                if (TRICKY_PATCH_AT_CURSOR(cachedPatchIdCursor) == targetPatchGroup) {
                                    patchSlot = i;
                                    state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                    break;
                                }
                            }
                            if (i == 4) {
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            if (objectWalkGroup == 0 &&
                                (u32)(targetPatchGroup =
                                          getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup) & 0xffff) != 0) {
                                if (state->linkedWalkGroup == targetPatchGroup) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, (u16)targetPatchGroup);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                patchGroupForCheck = targetPatchGroup & 0xffff;
                                i = isPointWithinPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup,
                                                            patchGroupForCheck);
                                trickyReportError(debugStrings + TRICKY_DBG_PATCH_ROUTE_ERROR, patchGroupForCheck,
                                                  targetWalkGroup, objectWalkGroup, state->activeWalkGroup, i);
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    }
                } else {
                    if (targetWalkGroup == 0) {
                        if (objectWalkGroup != 0) {
                            u16 pid = Objfsa_GetPatchGroupIdAtPoint(target);
                            if (pid == 0) {
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            } else {
                                state->walkGroup = pid & 0xff;
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            state->movementState = TRICKY_MOVE_WALK_WAIT;
                        }
                    } else {
                        if (objectWalkGroup != 0) {
                            if (isPointWithinPatchGroup(
                                    &obj->anim.worldPosX, state->activeWalkGroup,
                                    (targetWalkGroup = targetWalkGroup * objectWalkGroup & 0xffff)) != 0) {
                                if (state->linkedWalkGroup == targetWalkGroup) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    state->movementState = TRICKY_MOVE_CURVE_SETUP;
                                }
                            } else {
                                for (i = 0, cachedPatchIdCursor = (u8*)state; i < 4;
                                     cachedPatchIdCursor += sizeof(state->patch[0]), i++) {
                                    if (TRICKY_PATCH_AT_CURSOR(cachedPatchIdCursor) == targetWalkGroup) {
                                        patchSlot = i;
                                        state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                        break;
                                    }
                                }
                                if ((i == 4) || (targetWalkGroup != state->linkedWalkGroup)) {
                                    state->movementState = TRICKY_MOVE_CURVE_SETUP;
                                }
                            }
                        } else {
                            u16 p = getPatchGroup(&obj->anim.worldPosX, state->activeWalkGroup);
                            if (p != 0) {
                                if (targetWalkGroup == state->activeWalkGroup) {
                                    for (i = 0, cachedPatchIdCursor = (u8*)state; i < 4;
                                         cachedPatchIdCursor += sizeof(state->patch[0]), i++) {
                                        if (TRICKY_PATCH_AT_CURSOR(cachedPatchIdCursor) == p) {
                                            patchSlot = i;
                                            state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                            break;
                                        }
                                    }
                                    if (i == 4) {
                                        Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, p);
                                        state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                    }
                                } else if (state->linkedWalkGroup == p) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, p);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                trickyReportError(debugStrings + TRICKY_DBG_PATCH_ROUTE_ERROR_2);
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    }
                }
            }
        }
    }
    if (state->movementState < 5) {
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GROUND_SNAP;
    }
    trickyDebugPrint(debugStrings + TRICKY_DBG_MOVEMENT_STATE, state->movementState);
    switch (state->movementState) {
        char routeNodeType;
        RomCurveDef* node;
    case TRICKY_MOVE_WALK_WAIT:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_WAIT);
        v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
        state->speed = (v < gTrickyFloatZero) ? gTrickyFloatZero : v;
        if (gTrickyFloatZero == state->speed) {
            didMove = 0;
        } else {
            didMove = moveTricky(obj, target);
        }
        break;
    case TRICKY_MOVE_WALK_FREE:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_FREE);
        didMove = moveTricky(obj, target);
        break;
    case TRICKY_MOVE_WALK_START_PATCH:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_START_PATCH);
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, gTrickyFloatZero, state, patchTarget = &state->patchTargets[patchSlot].x, 1);
        didMove = moveTricky(obj, patchTarget);
        break;
    case TRICKY_MOVE_WALK_PATCH_EXIT:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_PATCH_EXIT);
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->patchExitPos.x, 1);
        didMove = moveTricky(obj, &state->patchExitPos.x);
        break;
    case TRICKY_MOVE_WALK_END_PATCH:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_END_PATCH);
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->linkedPatchPos.x, 1);
        didMove = moveTricky(obj, &state->linkedPatchPos.x);
        break;
    case TRICKY_MOVE_WALK_TO_NODE:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_TO_NODE, 10,
                         (int)getXZDistanceSquared(&state->routeSeedNode->x, &obj->anim.worldPosX));
        dist = getXZDistanceSquared(&state->routeSeedNode->x, &obj->anim.worldPosX);
        if (TRICKY_FLOAT_TEN > dist) {
            state->route.reverse = state->routeSeedDir;
            prevNode = state->routeSeedNode;
            node = trickySelectRouteEntry(state, prevNode, state->routeSeedDir);
            if (node == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurveDef* nextNode = trickySelectRouteEntry(state, node, state->routeSeedDir);
                if (nextNode == 0) {
                    state->movementState = TRICKY_MOVE_WALK_WAIT;
                } else {
                    RomCurve_setupHermiteSegment(&state->route, (u8*)prevNode, node, nextNode);
                    RomCurve_stepClamped(&state->route, 0.1f);
                    TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
                    trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
                    didMove = moveTricky(obj, &state->route.posX);
                    switch (prevNode->subtype) {
                    case ROMCURVE_TRICKY_SUBTYPE_JUMP:
                        node = state->route.currentNode;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (gTrickyFloatZero != len) {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        state->speed = TRICKY_FOLLOW_MAX_SPEED;
                        trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMP_PREP, TRICKY_TINY_MOVE_BLEND_SPEED,
                                          TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                        state->movementState = TRICKY_MOVE_JUMP_PREP;
                        state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                        break;
                    case ROMCURVE_TRICKY_SUBTYPE_JUMPUP:
                        node = state->route.currentNode;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (gTrickyFloatZero != len) {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        if ((int)randomGetRange(0, 1) != 0) {
                            trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPUP_FAST,
                                              TRICKY_FOLLOW_JUMPUP_FAST_BLEND_SPEED, TRICKY_MOVE_FLAG_JUMP_ARC);
                        } else {
                            trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPUP_SLOW,
                                              TRICKY_FOLLOW_JUMPUP_SLOW_BLEND_SPEED, TRICKY_MOVE_FLAG_JUMP_ARC);
                        }
                        state->verticalDelta = (((RomCurveDef*)state->route.currentNode)->y - obj->anim.worldPosY) /
                                               TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR;
                        state->movementState = TRICKY_MOVE_JUMPUP;
                        TRICKY_ADVANCE_ROUTE_TO_END(state);
                        state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                        break;
                    case ROMCURVE_TRICKY_SUBTYPE_JUMPDOWN:
                        node = state->route.currentNode;
                        state->dirX = node->x - obj->anim.worldPosX;
                        state->dirZ = node->z - obj->anim.worldPosZ;
                        sqx = state->dirX * state->dirX;
                        sqz = state->dirZ * state->dirZ;
                        len = sqrtf(sqx + sqz);
                        if (gTrickyFloatZero != len) {
                            state->dirX = state->dirX / len;
                            state->dirZ = state->dirZ / len;
                        }
                        trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPDOWN, TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED,
                                          TRICKY_MOVE_FLAG_JUMP_ARC);
                        state->verticalDelta = (obj->anim.worldPosY - ((RomCurveDef*)state->route.currentNode)->y) /
                                               TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR;
                        state->movementState = TRICKY_MOVE_JUMPDOWN;
                        TRICKY_ADVANCE_ROUTE_TO_END(state);
                        state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
                        break;
                    case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_A:
                    case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_B:
                        state->stateFlags = state->stateFlags | TRICKY_STATE_FLAG_GROUND_SNAP;
                    default:
                        state->movementState = TRICKY_MOVE_WALK_NODES;
                    }
                }
            }
        } else {
            prevNode = state->routeSeedNode;
            if (prevNode == NULL) {
                node = NULL;
            } else if (((prevNode->requiredBit == -1) || (mainGetBit(prevNode->requiredBit) != 0)) &&
                       ((prevNode->forbiddenBit == -1) || (mainGetBit(prevNode->forbiddenBit) == 0))) {
                node = prevNode;
            } else {
                node = NULL;
            }
            if ((node != 0) || (objectWalkGroup == 0)) {
                state->speed = previousSpeed;
                trickyUpdateApproachSpeed(obj, TRICKY_RUN_MOVE_THRESHOLD, state, &state->routeSeedNode->x, 1);
                didMove = moveTricky(obj, &state->routeSeedNode->x);
            } else {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            }
        }
        break;
    case TRICKY_MOVE_CURVE_SETUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_CURVE_SETUP);
        trickyRankLinkedRouteCandidates(obj, routeFlags, (s16)objectWalkGroup, routePtrs);
        i = trickyFindReachableRouteIndex(state, routePtrs, routeFlags, state->walkGroup);
        if (i == -1) {
            state->speed = previousSpeed;
            return 2;
        }
        state->routeSeedDir = routeFlags[i];
        state->routeSeedNode = routePtrs[i];
        state->speed = previousSpeed;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->routeSeedNode->x, 1);
        didMove = moveTricky(obj, &state->routeSeedNode->x);
        state->movementState = TRICKY_MOVE_WALK_TO_NODE;
        break;
    case TRICKY_MOVE_WALK_NODES:
        trickyDebugPrint(debugStrings + TRICKY_DBG_WALK_NODES);
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < gTrickyFloatZero) ? gTrickyFloatZero : v;
        }
        routeNode = state->route.currentNode;
        if ((((RomCurveDef*)state->route.previousNode)->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B) &&
            (routeNode->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B)) {
            int i;
            u8 step;
            char found;
            f32* tpos = state->targetPosPtr;
            delta[0] = tpos[0] - obj->anim.worldPosX;
            delta[1] = tpos[1] - obj->anim.worldPosY;
            delta[2] = tpos[2] - obj->anim.worldPosZ;
            rot.angle = -obj->anim.rotX;
            rot._pad0 = 0;
            rot._pad1 = 0;
            vecRotateZXY(&rot.angle, delta);
            if ((delta[2] > gTrickyFloatZero) && (gTrickyFloatZero != state->speed)) {
                for (step = 0; step < 4; step++) {
                    u8 grp = routeNode->linkWalkGroups[step];
                    if (grp == state->walkGroup) {
                        break;
                    }
                }
                if (step == 4) {
                    pathSearchBegin(&state->pathSearches[0], (RomCurveDef*)state->route.nextNode, state->targetPosPtr,
                                    state->walkGroup, state->route.reverse);
                    pathSearchBegin(&state->pathSearches[1], (RomCurveDef*)state->route.previousNode,
                                    state->targetPosPtr, state->walkGroup, state->route.reverse ^ 1);
                    found = 0;
                    for (i = 0; (u8)(i = i + 1) < 100 && (found != 1);) {
                        found = pathSearchStep(&state->pathSearches[0], 1);
                        if (found != 1) {
                            found = pathSearchStep(&state->pathSearches[1], 1);
                            switch (found) {
                            case 0:
                                break;
                            case 1:
                                prod = (state->route.reverse ^ 1) & 0xff;
                                if (prod == 0) {
                                    RomCurve_stepClamped(&state->route, TRICKY_FLOAT_TWO);
                                } else {
                                    RomCurve_stepClamped(&state->route, TRICKY_ROUTE_REVERSE_STEP);
                                }
                                state->route.reverse = prod;
                                RomCurve_swapEndpointNodes(&state->route);
                                break;
                            case -1:
                                found = 1;
                                break;
                            }
                        }
                    }
                }
            }
        }
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            node = trickySelectRouteEntry(state, state->route.nextNode, routeDirection & 0xff);
            if (node != 0) {
                RomCurve_advanceToNextSegment(&state->route, node);
                routeNodeType = ((RomCurveDef*)state->route.previousNode)->subtype;
                switch (routeNodeType) {
                case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_A:
                case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_B:
                    prod = state->stateFlags;
                    if ((prod & TRICKY_STATE_FLAG_GROUND_SNAP) != 0) {
                        state->stateFlags = prod & ~(u64)TRICKY_STATE_FLAG_GROUND_SNAP;
                    } else {
                        state->stateFlags = prod | TRICKY_STATE_FLAG_GROUND_SNAP;
                    }
                    break;
                }
            } else {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
                break;
            }
        } else {
            node = trickySelectRouteEntry(state, state->route.currentNode, routeDirection & 0xff);
            if (node == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
                break;
            }
            if (node != state->route.nextNode) {
                RomCurve_setSegmentEndNode(&state->route, node);
            }
        }
        if ((state->savedWalkGroup == 0) || (objectWalkGroup != state->savedWalkGroup)) {
            TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        }
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        didMove = moveTricky(obj, &state->route.posX);
        routeNodeType = ((RomCurveDef*)state->route.currentNode)->subtype;
        switch (routeNodeType) {
        case ROMCURVE_TRICKY_SUBTYPE_JUMP:
            state->movementState = TRICKY_MOVE_JUMP_RUNUP;
            break;
        case ROMCURVE_TRICKY_SUBTYPE_JUMPUP:
            state->movementState = TRICKY_MOVE_JUMPUP_RUNUP;
            break;
        case ROMCURVE_TRICKY_SUBTYPE_JUMPDOWN:
            state->movementState = TRICKY_MOVE_JUMPDOWN_RUNUP;
            break;
        }
        break;
    case TRICKY_MOVE_JUMP_RUNUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_RUN_UP);
        v = gTrickySmallSpeedStep * timeDelta + previousSpeed;
        state->speed = (v > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : v;
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < gTrickyFloatZero) ? gTrickyFloatZero : v;
        }
        TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            RomCurveDef* nextRouteNode = trickySelectRouteEntry(state, state->route.nextNode, routeDirection & 0xff);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                node = state->route.currentNode;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (gTrickyFloatZero != len) {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                state->speed = TRICKY_FOLLOW_MAX_SPEED;
                trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMP_PREP, TRICKY_TINY_MOVE_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                state->movementState = TRICKY_MOVE_JUMP_PREP;
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
            }
        }
        break;
    case TRICKY_MOVE_JUMP_PREP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_PREP);
        if ((u8)(state->stateFlags & TRICKY_STATE_FLAG_TURNING_U32)) {
            v = TRICKY_FLOAT_NEG_0_01 * timeDelta + previousSpeed;
            if (v < gTrickyFloatZero) {
                v = gTrickyFloatZero;
            }
        } else if (previousSpeed > (v = TRICKY_FOLLOW_ARC_SPEED)) {
            k = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            v = (k < v) ? v : k;
        } else {
            k = gTrickySmallSpeedStep * timeDelta + previousSpeed;
            v = (k > v) ? v : k;
        }
        state->speed = v;
        {
            f32 dz;
            f32 dx;
            f32 sqz;
            f32 sqx;

            dx = ((TrickyState*)obj->extra)->dirX;
            sqx = dx;
            sqx = sqx * sqx;
            dz = ((TrickyState*)obj->extra)->dirZ;
            sqz = dz;
            sqz = sqz * sqz;
            if (sqx + sqz > TRICKY_FLOAT_0_01) {
                trickyTurnTowardYaw(obj, (s16)getAngle(-dx, -dz));
            }
        }
        if (obj->anim.currentMoveProgress < TRICKY_FOLLOW_ARC_HALF_PROGRESS) {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed, &state->moveProgress);
            obj->anim.localPosX = timeDelta * (state->dirX * state->speed) + obj->anim.localPosX;
            obj->anim.localPosZ = timeDelta * (state->dirZ * state->speed) + obj->anim.localPosZ;
        } else {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed * TRICKY_FOLLOW_ARC_QUARTER_PROGRESS,
                                         &state->moveProgress);
            obj->anim.localPosX =
                timeDelta * (state->dirX * (state->speed * (k = TRICKY_FOLLOW_ARC_QUARTER_PROGRESS))) +
                obj->anim.localPosX;
            obj->anim.localPosZ = timeDelta * (state->dirZ * (state->speed * k)) + obj->anim.localPosZ;
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            f32 dx;
            TrickyJumpArc* arc = &state->jumpArc;
            RomCurveDef* landNode = state->route.currentNode;
            dx = landNode->x - obj->anim.worldPosX;
            sqx = dx * dx;
            dx = landNode->z - obj->anim.worldPosZ;
            dx = dx * dx;
            len = sqrtf(sqx + dx);
            arc->duration = len / TRICKY_FOLLOW_ARC_SPEED;
            arc->time = (v = gTrickyFloatZero);
            arc->baseX = obj->anim.worldPosX;
            arc->baseY = obj->anim.worldPosY;
            arc->baseZ = obj->anim.worldPosZ;
            arc->landX = landNode->x;
            arc->landZ = landNode->z;
            k = arc->duration;
            arc->riseCoeff = -(TRICKY_FOLLOW_ARC_COEFFICIENT * k * k - (landNode->y - obj->anim.worldPosY)) / k;
            trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMP, v, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->arcMoveProgress = arc->time / arc->duration;
            state->speed = TRICKY_FOLLOW_ARC_SPEED;
            state->movementState = TRICKY_MOVE_JUMPING;
            TRICKY_ADVANCE_ROUTE_TO_END(state);
        }
        break;
    case TRICKY_MOVE_JUMPING: {
        TrickyJumpArc* arc = &state->jumpArc;
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMPING);
        arc->time = arc->time + timeDelta;
        if (arc->time >= arc->duration) {
            obj->anim.localPosY = ((RomCurveDef*)state->route.currentNode)->y;
            state->arcMoveProgress = TRICKY_FLOAT_ONE;
            state->movementState = TRICKY_MOVE_WALK_NODES;
        } else {
            f32 baseX = arc->baseX;
            f32 baseZ;
            obj->anim.localPosX = (arc->landX - baseX) * (arc->time / arc->duration) + baseX;
            k = arc->time;
            obj->anim.localPosY = TRICKY_FOLLOW_ARC_COEFFICIENT * k * k + (arc->riseCoeff * k + arc->baseY);
            baseZ = arc->baseZ;
            obj->anim.localPosZ = (arc->landZ - baseZ) * (arc->time / arc->duration) + baseZ;
            v = arc->duration;
            if (v <= TRICKY_FOLLOW_ARC_PROGRESS_WINDOW) {
                state->arcMoveProgress = arc->time / v;
            } else {
                k = arc->time;
                if (k <= TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    state->arcMoveProgress = k / TRICKY_FOLLOW_ARC_PROGRESS_WINDOW;
                } else if (k >= v - TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    f32 adj;
                    adj = TRICKY_FOLLOW_ARC_PROGRESS_WINDOW - v;
                    state->arcMoveProgress = (adj + k) / TRICKY_FOLLOW_ARC_PROGRESS_WINDOW;
                } else {
                    k = (k - TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) / (v - TRICKY_FOLLOW_ARC_MIDDLE_WINDOW);
                    state->arcMoveProgress = TRICKY_FOLLOW_ARC_QUARTER_PROGRESS + k * TRICKY_FOLLOW_ARC_HALF_PROGRESS;
                }
            }
            Obj_SetParent(obj, NULL, 0);
            state->heightUpdateActive = 0;
        }
        break;
    }
    case TRICKY_MOVE_JUMPUP_RUNUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_UP_RUN_UP);
        v = gTrickySmallSpeedStep * timeDelta + previousSpeed;
        state->speed = (v > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : v;
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < gTrickyFloatZero) ? gTrickyFloatZero : v;
        }
        TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            RomCurveDef* nextRouteNode = trickySelectRouteEntry(state, state->route.nextNode, routeDirection & 0xff);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                node = state->route.currentNode;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (gTrickyFloatZero != len) {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                if ((int)randomGetRange(0, 1) != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPUP_FAST, TRICKY_FOLLOW_JUMPUP_FAST_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_JUMP_ARC);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPUP_SLOW, TRICKY_FOLLOW_JUMPUP_SLOW_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_JUMP_ARC);
                }
                state->verticalDelta = (((RomCurveDef*)state->route.currentNode)->y - obj->anim.worldPosY) /
                                       TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR;
                state->movementState = TRICKY_MOVE_JUMPUP;
                TRICKY_ADVANCE_ROUTE_TO_END(state);
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
            }
        }
        break;
    case TRICKY_MOVE_JUMPUP:
    case TRICKY_MOVE_JUMPDOWN:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMP_DOWN_OR_UP);
        state->heightUpdateActive = 0;
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        {
            f32 dz;
            f32 dx;
            dx = ((TrickyState*)obj->extra)->dirX;
            sqz = dx;
            sqz = sqz * sqz;
            dz = ((TrickyState*)obj->extra)->dirZ;
            sqx = dz;
            sqx = sqx * sqx;
            if (sqz + sqx > TRICKY_FLOAT_0_01) {
                trickyTurnTowardYaw(obj, (s16)getAngle(-dx, -dz));
            }
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            state->speed = TRICKY_FOLLOW_JUMP_LAND_SPEED;
            moveTricky(obj, &state->route.posX);
            state->movementState = TRICKY_MOVE_WALK_NODES;
        }
        break;
    case TRICKY_MOVE_JUMPDOWN_RUNUP:
        trickyDebugPrint(debugStrings + TRICKY_DBG_JUMPDOWN_RUNUP);
        v = gTrickySmallSpeedStep * timeDelta + previousSpeed;
        state->speed = (v > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : v;
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            v = gTrickySpeedDecayStep * timeDelta + previousSpeed;
            state->speed = (v < gTrickyFloatZero) ? gTrickyFloatZero : v;
        }
        TRICKY_SLOW_FOR_SHARP_ROUTE_TURN(obj, state, previousSpeed);
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            RomCurveDef* nextRouteNode = trickySelectRouteEntry(state, state->route.nextNode, routeDirection & 0xff);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                node = state->route.currentNode;
                state->dirX = node->x - obj->anim.worldPosX;
                state->dirZ = node->z - obj->anim.worldPosZ;
                sqx = state->dirX * state->dirX;
                sqz = state->dirZ * state->dirZ;
                len = sqrtf(sqx + sqz);
                if (gTrickyFloatZero != len) {
                    state->dirX = state->dirX / len;
                    state->dirZ = state->dirZ / len;
                }
                trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPDOWN, TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_JUMP_ARC);
                state->verticalDelta = (obj->anim.worldPosY - ((RomCurveDef*)state->route.currentNode)->y) /
                                       TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR;
                state->movementState = TRICKY_MOVE_JUMPDOWN;
                TRICKY_ADVANCE_ROUTE_TO_END(state);
                state->voiceCooldown = TRICKY_TIMER_600_FRAMES;
            }
        }
        break;
    default:
        trickyDebugPrint(debugStrings + TRICKY_DBG_INVALID_MOVEMENT_STATE);
    }
    if (state->movementState < 5) {
        if (isInWalkGroupOrPatch(&obj->anim.worldPosX) != 0) {
            state->homePosX = obj->anim.worldPosX;
            state->homePosY = obj->anim.worldPosY;
            state->homePosZ = obj->anim.worldPosZ;
        } else {
            (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
            obj->anim.localPosX = state->homePosX;
            obj->anim.localPosY = state->homePosY;
            obj->anim.localPosZ = state->homePosZ;
            obj->anim.worldPosX = state->homePosX;
            obj->anim.worldPosY = state->homePosY;
            obj->anim.worldPosZ = state->homePosZ;
            ObjHits_SyncObjectPosition(obj);
        }
    }
    {
        u8 movementState = state->movementState;

        if (((((movementState == TRICKY_MOVE_WALK_WAIT) || (movementState == TRICKY_MOVE_WALK_START_PATCH)) ||
              (movementState == TRICKY_MOVE_WALK_PATCH_EXIT)) ||
             (movementState == TRICKY_MOVE_WALK_END_PATCH)) &&
            (gTrickyFloatZero == state->speed)) {
            return 2;
        }
    }
    if (didMove != 0) {
        return 1;
    }
    return 0;
}

void trickyUpdateApproachSpeed(GameObject* obj, f32 stoppingRadius, TrickyState* state, f32* targetPos,
                               u8 slowWhenFacingAway) {
    struct {
        s16 angle; /* -anim.rotX */
        s16 _pad0;
        s16 _pad1;
    } rotation;
    f32 targetDelta[3];
    f32 deceleration;
    f32 deltaTime;
    f32 projectedSpeed;
    f32 stoppingDistance;
    f32 stoppingRadiusSq;
    f32 totalStoppingRadius;
    f32 targetDistanceSq;
    f32 dx;
    f32 dz;
    f32 previousPathSpeed;
    f32 candidateSpeed;
    f32* currentPathPoint;
    TrickyState* objectState;

    stoppingDistance = gTrickySmallSpeedStep;
    projectedSpeed = state->speed;
    deltaTime = timeDelta;
    deceleration = gTrickySpeedDecayStep * deltaTime;
    while (projectedSpeed > gTrickyFloatZero) {
        stoppingDistance = projectedSpeed * deltaTime + stoppingDistance;
        projectedSpeed = projectedSpeed + deceleration;
    }
    totalStoppingRadius = stoppingRadius + stoppingDistance;
    stoppingRadiusSq = totalStoppingRadius;
    stoppingRadiusSq = stoppingRadiusSq * totalStoppingRadius;
    targetDistanceSq = getXZDistanceSquared(targetPos, &obj->anim.worldPosX);
    if (targetDistanceSq < stoppingRadiusSq) {
        candidateSpeed = state->speed;
        candidateSpeed = candidateSpeed + gTrickySpeedDecayStep * timeDelta;
        state->speed = (candidateSpeed < gTrickyFloatZero) ? gTrickyFloatZero : candidateSpeed;
        return;
    }
    if (slowWhenFacingAway != 0) {
        targetDelta[0] = targetPos[0] - obj->anim.worldPosX;
        targetDelta[1] = targetPos[1] - obj->anim.worldPosY;
        targetDelta[2] = targetPos[2] - obj->anim.worldPosZ;
        rotation.angle = -obj->anim.rotX;
        rotation._pad0 = 0;
        rotation._pad1 = 0;
        vecRotateZXY(&rotation.angle, targetDelta);
        if (targetDelta[2] > gTrickyFloatZero) {
            candidateSpeed = state->speed;
            candidateSpeed = candidateSpeed + gTrickySpeedDecayStep * timeDelta;
            state->speed = (candidateSpeed < gTrickyFloatZero) ? gTrickyFloatZero : candidateSpeed;
            return;
        }
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_TURNING_U32) != 0) {
        state->speed = TRICKY_FLOAT_NEG_0_01 * timeDelta + state->speed;
        if (state->speed < 0.0f) {
            state->speed = 0.0f;
        }
        return;
    }
    {
        f32 deltaSpeed = TRICKY_DEFAULT_STOPPING_RADIUS + totalStoppingRadius;
        f32 deltaSpeedSq = deltaSpeed * deltaSpeed;
        objectState = obj->extra;
        currentPathPoint = objectState->targetPosPtr;
        if (currentPathPoint == objectState->previousPathPoint) {
            dx = objectState->previousPathX - obj->anim.worldPosX;
            dz = objectState->previousPathZ - obj->anim.worldPosZ;
            previousPathSpeed = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
            dx = currentPathPoint[0] - obj->anim.worldPosX;
            dz = currentPathPoint[2] - obj->anim.worldPosZ;
            {
                f32 distOther = sqrtf(dx * dx + dz * dz) * oneOverTimeDelta;
                candidateSpeed = distOther - previousPathSpeed;
            }
        } else {
            candidateSpeed = gTrickyFloatZero;
        }
        if (targetDistanceSq < deltaSpeedSq) {
            if (candidateSpeed > gTrickyFloatZero) {
                f32 curSpeed = state->speed;
                if (candidateSpeed < curSpeed) {
                    f32 step = gTrickySpeedDecayStep * timeDelta + curSpeed;
                    state->speed = (step < candidateSpeed) ? candidateSpeed : step;
                    return;
                } else {
                    f32 step;
                    if (candidateSpeed > TRICKY_FOLLOW_MAX_SPEED) {
                        step = gTrickySmallSpeedStep * timeDelta + curSpeed;
                        state->speed = (step > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : step;
                        return;
                    }
                    step = gTrickySmallSpeedStep * timeDelta + curSpeed;
                    state->speed = (step > candidateSpeed) ? candidateSpeed : step;
                    return;
                }
            }
        }
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) != 0) {
        state->speed = TRICKY_FAST_MOVE_BLEND_SPEED * timeDelta + state->speed;
        if (state->speed > TRICKY_FOLLOW_MAX_SPEED) {
            state->speed = TRICKY_FOLLOW_MAX_SPEED;
        }
        return;
    }
    {
        f32 step = state->speed;
        step = step + gTrickySmallSpeedStep * timeDelta;
        state->speed = (step > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : step;
    }
}

const f32 gTrickyCloseDistanceSq[1] = {2500.0f};
const f32 gTrickyTimer30Frames[1] = {30.0f};
const f32 gTrickyGrowlDigStartRadius[1] = {25.0f};
const f32 gTrickyFlameDoneProgress[1] = {0.95f};
const f32 gTrickyCirclingApproachRadius[1] = {50.0f};
const f32 gTrickyTimer150Frames[1] = {150.0f};
const f32 gTrickyCirclingCloseDistanceSq[1] = {3600.0f};
const f32 gTrickyCirclingFarDistanceSq[1] = {5625.0f};
const f32 gTrickyCirclingChargeRadius[1] = {55.0f};
const f32 gTrickyCirclingSpawnProgress[1] = {0.3f};
const f32 gTrickyFetchCarryDelayFrames[1] = {180.0f};
const f32 gTrickyFetchBallReachRadius[1] = {13.0f};
const f32 gTrickyFetchPickupBlendSpeed[1] = {0.03f};
const f32 gTrickyFetchThrowDelayFrames[1] = {60.0f};
const f32 gTrickyFetchLaunchProgress[1] = {0.65f};
const f32 gTrickyVisibilityProbeRadius[1] = {19.0f};
const f32 gTrickyFlameHelperReleaseProgress[1] = {0.8f};
const f32 gCannonballRollSpeedLimit[1] = {1.2f};
const f32 gCannonballRouteBackstep[1] = {-10.0f};
const f32 gTrickyDigTunnelBlendSpeed[1] = {0.033f};
const f32 gTrickySecretDigScanDistanceSq[1] = {10000.0f};
const f32 gTrickyIdleWanderBlendSpeed[1] = {0.0025f};
const f32 gTrickyIdlePickBlendSpeed[1] = {0.0075f};
const f32 gTrickyHowlCallBlendSpeed[1] = {0.003f};
const f32 gTrickyAmbientActivityBase[1] = {200.0f};
const f64 gTrickyAmbientWanderScale[1] = {0.1};
const f32 gTrickyAmbientHowlBlendSpeed[1] = {0.015f};
const f32 gTrickyContactFlameThreshold[1] = {3000.0f};
const f32 gTrickyRemoteRecallDistanceSq[1] = {360000.0f};
const f32 gTrickyPathParticleScale[1] = {0.4f};
const f32 gTrickyFirepipeHeightDistSq[1] = {841.0f};
const f32 gTrickyLostEventTime[1] = {-10000.0f};
const f32 gTrickyRecallCooldownFrames[1] = {1200.0f};
const f32 gTrickyAudioEventMinSpeed[1] = {0.2f};
const f32 gTrickyChildVoicePeriodFrames[1] = {2400.0f};

#define TRICKY_CLOSE_DISTANCE_SQ             (gTrickyCloseDistanceSq[0])
#define TRICKY_TIMER_30_FRAMES               (gTrickyTimer30Frames[0])
#define TRICKY_GROWL_DIG_START_RADIUS        (gTrickyGrowlDigStartRadius[0])
#define TRICKY_FLAME_DONE_PROGRESS           (gTrickyFlameDoneProgress[0])
#define TRICKY_CIRCLING_APPROACH_RADIUS      (gTrickyCirclingApproachRadius[0])
#define TRICKY_TIMER_150_FRAMES              (gTrickyTimer150Frames[0])
#define TRICKY_CIRCLING_CLOSE_DISTANCE_SQ    (gTrickyCirclingCloseDistanceSq[0])
#define TRICKY_CIRCLING_FAR_DISTANCE_SQ      (gTrickyCirclingFarDistanceSq[0])
#define TRICKY_CIRCLING_CHARGE_RADIUS        (gTrickyCirclingChargeRadius[0])
#define TRICKY_CIRCLING_SPAWN_PROGRESS       (gTrickyCirclingSpawnProgress[0])
#define TRICKY_FETCH_CARRY_DELAY_FRAMES      (gTrickyFetchCarryDelayFrames[0])
#define TRICKY_FETCH_BALL_REACH_RADIUS       (gTrickyFetchBallReachRadius[0])
#define TRICKY_FETCH_PICKUP_BLEND_SPEED      (gTrickyFetchPickupBlendSpeed[0])
#define TRICKY_FETCH_THROW_DELAY_FRAMES      (gTrickyFetchThrowDelayFrames[0])
#define TRICKY_FETCH_LAUNCH_PROGRESS         (gTrickyFetchLaunchProgress[0])
#define TRICKY_FLAME_HELPER_RELEASE_PROGRESS (gTrickyFlameHelperReleaseProgress[0])
#define TRICKY_DIG_TUNNEL_BLEND_SPEED        (gTrickyDigTunnelBlendSpeed[0])
#define TRICKY_SECRET_DIG_SCAN_DISTANCE_SQ   (gTrickySecretDigScanDistanceSq[0])
#define TRICKY_IDLE_WANDER_BLEND_SPEED       (gTrickyIdleWanderBlendSpeed[0])
#define TRICKY_IDLE_PICK_BLEND_SPEED         (gTrickyIdlePickBlendSpeed[0])
#define TRICKY_HOWL_CALL_BLEND_SPEED         (gTrickyHowlCallBlendSpeed[0])
#define TRICKY_AMBIENT_HOWL_BLEND_SPEED      (gTrickyAmbientHowlBlendSpeed[0])
#define TRICKY_CONTACT_FLAME_THRESHOLD       (gTrickyContactFlameThreshold[0])
#define TRICKY_PATH_PARTICLE_SCALE           (gTrickyPathParticleScale[0])
#define TRICKY_FIREPIPE_HEIGHT_DIST_SQ       (gTrickyFirepipeHeightDistSq[0])
#define TRICKY_LOST_EVENT_TIME               (gTrickyLostEventTime[0])

#define TRICKYWARP_OBJ_GROUP 0x4b /* DLL 0x100 trickywarp */

void tricky_stateGoToWarpPoint(GameObject* self, TrickyState* state) {
    GameObject* nearest;
    f32 rejectDist;
    f32 minDist;
    f32 dist;
    f32 z;
    GameObject** objs;
    GameObject** objsList;
    int count;
    int i;
    int inWater;
    GameObject* best;

    nearest = NULL;
    best = NULL;
    minDist = gTrickyMaxDistance;

    if (trickyShouldGoToWarpPoint(self, state) == 0) {
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        z = gTrickyFloatZero;
        state->cooldownA = z;
        state->cooldownB.f = z;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
        state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
        return;
    }

    objsList = (GameObject**)objGetAllOfType(TRICKYWARP_OBJ_GROUP, &count);
    i = 0;
    objs = objsList;
    rejectDist = TRICKY_CLOSE_DISTANCE_SQ;
    for (; i < count; i++) {
        dist = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &(*objs)->anim.worldPosX);
        if (dist > rejectDist) {
            dist = getXZDistanceSquared(&self->anim.worldPosX, &(*objs)->anim.worldPosX);
            if (dist < minDist) {
                best = *objs;
                minDist = dist;
            }
        }
        objs++;
    }

    nearest = best;
    if (nearest != NULL) {
        state->followObj = nearest;
        if (state->targetPosPtr != &nearest->anim.worldPosX) {
            state->targetPosPtr = &nearest->anim.worldPosX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        if (trickyUpdateMovementState(self, TRICKY_ANIM_TRANSITION_FRAMES, state) == 1) {
            return;
        }
    }

    inWater = skeetla_isInWater(state);

    if (inWater != 0) {
        trickyRequestMove(self, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
        state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
        state->particleTimer = gTrickyFloatZero;
        trickyDebugPrint(sInWaterMessage);
    } else {
        trickyRequestMove(self, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        trickyDebugPrint(sTrickyDryLandDebugMessage);
    }
}

/*
 * Should Tricky head for a trickywarp point?
 *
 * Queried with Tricky (arg1) and his own TrickyState extra block (arg2). It returns:
 *   0 - no,
 *   1 - yes,
 *   2 - yes, and the player is still right next to him (the enter condition).
 *
 * The answer is no outright while another object of group 0x53 is nearby.
 * Otherwise, while no guard command is mid-dispatch and the
 * owning player carries the parent-slack flag, map cell 0x38 gates the answer
 * behind the TrickyFood game bits and any other cell arms the cooldown packed
 * into statusFlags and answers yes. The final range test promotes a "1" to a
 * "2" when the player sits within 2500.0f squared units of Tricky.
 */

#define MMPCRITTERSPIT_OBJFLAG_PARENT_SLACK 0x1000
#define PRESSURESWITCHFB_REMOVE_GROUP_ID    0x53 /* DLL 0xFB pressureswitchfb (self-registers) */

int trickyShouldGoToWarpPoint(GameObject* tricky, TrickyState* state) {
    int result = 0;
    f32 dist = TRICKY_FLOAT_40;
    TrickyState* st = state;

    if (st->warpCooldown != 0) {
        st->warpCooldown--;
        result = 1;
    }

    if (objGetNearestTypeTo(PRESSURESWITCHFB_REMOVE_GROUP_ID, tricky, &dist) != NULL) {
        return 0;
    }

    if (st->commandPhase != TRICKY_COMMAND_PHASE_GUARD) {
        GameObject* playerObj = st->playerObj;

        if ((playerObj->objectFlags & MMPCRITTERSPIT_OBJFLAG_PARENT_SLACK) != 0) {
            if (coordsToMapCell(tricky->anim.localPosX, tricky->anim.localPosZ) == 0x38) {
                if ((mainGetBit(0x385) == 0) && (mainGetBit(0x384) != 0)) {
                    if ((mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) ||
                        (mainGetBit(GAMEBIT_ITEM_TrickyFood_GrabInProgress) != 0)) {
                        result = 1;
                    }
                }
            } else {
                st->warpCooldown = 0x1F;
                result = 1;
            }
        }
    }

    if (result == 1) {
        GameObject* playerObj = state->playerObj;

        if (vec3f_distanceSquared(&playerObj->anim.worldPosX, &tricky->anim.worldPosX) < TRICKY_CLOSE_DISTANCE_SQ) {
            return 2;
        }
    }
    return result;
}

/*
 * Tricky "growl/dig" action handler.
 *
 * trickyGrowl drives a four-step substate machine for the Tricky sidekick:
 *   0  growl windup  - barks (TRICKY_VOICE_SFX_GROWL), kicks off TRICKY_ANIM_GROWL_WINDUP
 *   1  face target   - turns toward the followed object (extra+0x28), with a
 *                      random chance to bark again, until anim flag + timer hit
 *   2  dig start     - if loading isn't locked, spawns seven child objects
 *                      (Obj_AllocObjectSetup/objSetupObject into scratch700..),
 *                      plays/loops the dig sfx (0x3db/0x3dc) and runs TRICKY_ANIM_DIG
 *   3  dig end       - on move progress >= threshold, resets child anim speed,
 *                      stops the dig loop, barks (TRICKY_VOICE_SFX_FINISH_FLAME) and clears the
 *                      action's state flags, returning to substate 0
 *
 * Barks are gated on bit 6 of TrickyState.statusFlags, the current anim move
 * being outside [0x29,0x30), and no sfx already playing on channel 0x10.
 */

#define CHILD_OBJECT_COUNT          7
#define TRICKY_CHILD_OBJ_FLAMEBLAST 0x4f0 /* "flameblast" (DLL 0xF3) */

enum {
    TRICKYGROWL_WINDUP = 0,
    TRICKYGROWL_FACE_TARGET = 1,
    TRICKYGROWL_DIG_START = 2,
    TRICKYGROWL_DIG_END = 3
};

char sTrickyGrowlAtDebugTextBlock[] = "GROWLAT_GOTO\n"
                                      "\0\0\0"
                                      "GROWLAT_GROWLING\n"
                                      "\0\0\0"
                                      "GROWLAT_GOTOFLAME\n"
                                      "\0\0"
                                      "GROWLAT_FLAME\n"
                                      "\0\0"
                                      "BADDIEALERT_GOTO\n"
                                      "\0\0\0"
                                      "BADDIEALERT_BARK %d %d\n"
                                      "\0"
                                      "BADDIEALLERT_GOTOFLAME\n"
                                      "\0"
                                      "BADDIEALLERT_FLAME\n";

void trickyGrowl(GameObject* obj, TrickyState* trickyState) {
    TrickyState* barkState;
    int i;
    int j;
    TrickyState* finishSoundState;
    void** slot;
    FlameblastPlacement* setup;
    void** slot2;
    char* strBase = gTrickyDebugStringTable;

    switch (trickyState->substate) {
    case TRICKYGROWL_WINDUP:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_GOTO);
        if (trickyUpdateMovementState(obj, TRICKY_TIMER_30_FRAMES, trickyState) == 0) {
            barkState = obj->extra;
            if (barkState->soundSuppressed == 0u) {
                s16 move = obj->anim.currentMove;
                if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &barkState->soundState, TRICKY_VOICE_SFX_GROWL, 0x100, -1, 0);
                    }
                }
            }
            trickyState->substate = TRICKYGROWL_FACE_TARGET;
            trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_LAND_MOVE_BLEND_SPEED,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->flameCommandPending = 0;
        }
        break;
    case TRICKYGROWL_FACE_TARGET:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_GROWLING);
        if (trickyState->stats->energy != 0 && trickyState->flameCommandPending != 0) {
            trickyState->substate = TRICKYGROWL_DIG_START;
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;
            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
            if (randomGetRange(0, 10) == 0) {
                barkState = obj->extra;
                if (barkState->soundSuppressed == 0u) {
                    s16 move = obj->anim.currentMove;
                    if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &barkState->soundState, TRICKY_VOICE_SFX_GROWL, 0x100, -1, 0);
                        }
                    }
                }
            }
        }
        break;
    case TRICKYGROWL_DIG_START:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_GOTOFLAME);
        if (trickyUpdateMovementState(obj, TRICKY_GROWL_DIG_START_RADIUS, trickyState) == 0) {
            if ((u8)Obj_CanSetupObject() != 0) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (i = 0, slot = (void**)trickyState; i < CHILD_OBJECT_COUNT; slot++, i++) {
                    setup = (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_CHILD_OBJ_FLAMEBLAST);
                    setup->base.color[0] = 2;
                    setup->base.color[1] = 1;
                    setup->streamIndex = i;
                    TRICKY_FLAME_CHILD_AT_CURSOR(slot) =
                        objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            }
            trickyState->stats->energy--;
            trickyRequestMove(obj, TRICKY_ANIM_DIG, TRICKY_LAND_MOVE_BLEND_SPEED,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKYGROWL_DIG_END;
            trickyState->flameCommandPending = 0;
        }
        break;
    case TRICKYGROWL_DIG_END:
        trickyDebugPrint(strBase + TRICKY_DBG_GROWLAT_FLAME);
        if (obj->anim.currentMoveProgress >= TRICKY_FLAME_DONE_PROGRESS) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (j = 0, slot2 = (void**)trickyState; j < CHILD_OBJECT_COUNT; slot2++, j++) {
                objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(slot2));
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            finishSoundState = obj->extra;
            if (finishSoundState->soundSuppressed == 0u) {
                s16 move = obj->anim.currentMove;
                if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &finishSoundState->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                    }
                }
            }
            trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            trickyState->substate = TRICKYGROWL_WINDUP;
            {
                f32 resetValue = gTrickyFloatZero;
                trickyState->cooldownA = resetValue;
                trickyState->cooldownB.f = resetValue;
            }
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 mm = -1;
                trickyState->commandPhase = mm;
            }
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;
            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    }
}

/*
 * Tricky companion "circle the enemy" combat behaviour (part of the
 * tricky AI module; operates on TrickyState, the per-object scratch at
 * GameObject.extra).
 *
 * trickyFindCirclingTarget       - picks the object Tricky should circle:
 *                                   the current follow target if it is the
 *                                   special romDefNo 0x6a3 actor, else the
 *                                   player's lock-on target, validated
 *                                   against ObjGroup 3 by a triangle-
 *                                   inequality distance test.
 * trickyUpdateCirclingTargetPosition
 *                                - orbits Tricky around followObj: picks a
 *                                   random spin direction once, advances the
 *                                   orbit angle while it stays near the seed
 *                                   heading, and writes the desired
 *                                   x/y/z onto the state; trickyUpdateMovementState
 *                                   then steers toward it.
 * trickyUpdateCircling                    - the circling state machine, dispatched on
 *                                   substate t->substate (0 acquire, 1 approach,
 *                                   2/3/4 the special charge/spawn/finish
 *                                   path, 5 orbit-and-pick-best). It spawns
 *                                   helper objects (ids 0x17b, 0x4f0),
 *                                   plays/loops bark and effect sounds, and
 *                                   drives the shared TRICKY_* state macros.
 */

/* group owned by another DLL, queried here */
#define ANIMOBJD2_OBJFLAG_FREED 0x40
/* Objects spawned by the trickyUpdateCircling state machine (retail OBJECTS.bin names
   "TrickyFood" and "flameblast"). */
#define ANIMOBJD2_TRICKY_FOOD_OBJ_ID 0x17b
#define ANIMOBJD2_FLAMEBLAST_OBJ_ID  0x4f0
/* romDefNo of the special actor Tricky circles when it is the current follow target (docblock: "the special romDefNo 0x6a3 actor") */
#define ANIMOBJD2_CIRCLE_TARGET_SEQID 0x6a3

/* trickyUpdateCircling circling substate machine (TrickyState.substate; this object's
 * own values, not a globally shared TrickyState enum). */
enum AnimObjD2Substate {
    ANIMOBJD2_SUBSTATE_ACQUIRE = 0,  /* find/lock onto a target        */
    ANIMOBJD2_SUBSTATE_APPROACH = 1, /* close on the seed heading      */
    ANIMOBJD2_SUBSTATE_CHARGE = 2,   /* retarget + start charge anim   */
    ANIMOBJD2_SUBSTATE_SPAWN = 3,    /* spawn the 7 drip helper objects*/
    ANIMOBJD2_SUBSTATE_FINISH = 4,   /* speed up helpers, bark, reset  */
    ANIMOBJD2_SUBSTATE_ORBIT = 5     /* orbit and pick the best target */
};

/* Spawn-setup buffer seeded in the substate-3 drip burst (defNo 0x4f0).
 * Reuses ObjPlacement's color head and adds a signed stream index at 0x1a. */
typedef struct AnimObjD2DripSetup {
    ObjPlacement head; /* 0x00: color[0..1] written */
    u8 pad18[0x1a - 0x18];
    s16 index; /* 0x1a */
} AnimObjD2DripSetup;

GameObject* trickyFindCirclingTarget(GameObject* obj, TrickyState* state);

#define TRICKY_RETARGET(st, X)                                                                                         \
    {                                                                                                                  \
        f32* px = &((GameObject*)(X))->anim.worldPosX;                                                                 \
        if (((TrickyState*)(st))->targetPosPtr != px) {                                                                \
            ((TrickyState*)(st))->targetPosPtr = px;                                                                   \
            {                                                                                                          \
                u32 m;                                                                                                 \
                u32 flags = ((TrickyState*)(st))->stateFlags;                                                          \
                m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;                                                             \
                ((TrickyState*)(st))->stateFlags = flags & m;                                                          \
            }                                                                                                          \
            ((TrickyState*)(st))->linkedWalkGroup = 0;                                                                 \
        }                                                                                                              \
    }

#define TRICKY_RESET_TAIL(st)                                                                                          \
    {                                                                                                                  \
        f32 z = gTrickyFloatZero;                                                                                      \
        ((TrickyState*)(st))->cooldownA = z;                                                                           \
        ((TrickyState*)(st))->cooldownB.f = z;                                                                         \
        ((TrickyState*)(st))->stateFlags &= (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;                                    \
        ((TrickyState*)(st))->stateFlags &= (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;                                    \
        ((TrickyState*)(st))->stateFlags &= (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;                                      \
        ((TrickyState*)(st))->stateFlags &= (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;                                     \
        ((TrickyState*)(st))->commandPhase = TRICKY_COMMAND_PHASE_IDLE;                                                \
    }
#define TRICKY_RESET(st)                                                                                               \
    ((TrickyState*)(st))->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;                                                     \
    ((TrickyState*)(st))->substate = 0;                                                                                \
    TRICKY_RESET_TAIL(st)

static inline int trickyAcquireCirclingTarget(TrickyState* state) {
    int hasTarget;

    if ((state->followObj = trickyFindNearestUsableBaddie(state->playerObj, TRICKY_TIMER_150_FRAMES, 0)) != NULL) {
        f32* targetPos = &state->followObj->anim.worldPosX;

        if (state->targetPosPtr != targetPos) {
            state->targetPosPtr = targetPos;
            {
                u32 flags;
                u32 mask;

                flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        hasTarget = 1;
    } else {
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        hasTarget = 0;
        state->substate = hasTarget;
        TRICKY_RESET_TAIL((u8*)state)
    }

    return hasTarget;
}

#define TRICKY_BARK(obj, snd, p4, cfg)                                                                                 \
    {                                                                                                                  \
        cfg = (u8*)((GameObject*)(obj))->extra;                                                                        \
        if (!((TrickyState*)cfg)->soundSuppressed) {                                                                   \
            s16 a0 = ((GameObject*)(obj))->anim.currentMove;                                                           \
            if (a0 >= TRICKY_VOICE_MOVE_END || a0 < TRICKY_VOICE_MOVE_MIN) {                                           \
                if (Sfx_IsPlayingFromObjectChannel((GameObject*)(obj), TRICKY_VOICE_CHANNEL) == 0) {                   \
                    objSoundStartTimed((GameObject*)(obj), &((TrickyState*)cfg)->soundState, snd, p4, -1, 0);          \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    }

void trickyUpdateCircling(GameObject* obj, TrickyState* state) {
    char* str = gTrickyDebugStringTable;
    u8 ok;
    int hasTarget;
    GameObject* bestWarp = NULL;
    f32 bestDetourSavings = gTrickyFloatZero;
    int warpCount;
    u8* approachCfg;
    u8* orbitCfg;
    u8* finishCfg;

    switch (state->substate) {
    case ANIMOBJD2_SUBSTATE_ACQUIRE: {
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_GOTO);
        ok = trickyUpdateMovementState(obj, TRICKY_CIRCLING_APPROACH_RADIUS, state);
        hasTarget = trickyAcquireCirclingTarget(state);
        if (hasTarget != 0) {
            if (state->flameCommandPending == 0) {
                {
                    GameObject* ct = trickyFindCirclingTarget(obj, state);
                    state->cooldownB.ptr = ct;
                    if (ct != NULL) {
                        state->followObj = state->cooldownB.obj;
                        state->circlingWarpDetour = NULL;
                        state->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                        break;
                    }
                }
            }
            if (ok == 2) {
                TRICKY_RESET((u8*)state);
                break;
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) <
                TRICKY_CIRCLING_CLOSE_DISTANCE_SQ) {
                int b;
                f32 z;
                state->substate = ANIMOBJD2_SUBSTATE_APPROACH;
                z = gTrickyFloatZero;
                state->cooldownA = z;
                b = skeetla_isInWater(state);
                if (b != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(str + TRICKY_DBG_IN_WATER);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(str + TRICKY_DBG_OUT_OF_WATER);
                }
            }
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_APPROACH: {
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_BARK, state->stats->energy, state->flameCommandPending);
        ok = trickyUpdateMovementState(obj, TRICKY_CIRCLING_APPROACH_RADIUS, state);
        hasTarget = trickyAcquireCirclingTarget(state);
        if (hasTarget != 0) {
            if (state->flameCommandPending == 0) {
                {
                    GameObject* ct = trickyFindCirclingTarget(obj, state);
                    state->cooldownB.ptr = ct;
                    if (ct != NULL) {
                        state->followObj = state->cooldownB.obj;
                        state->circlingWarpDetour = NULL;
                        state->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                        break;
                    }
                }
            }
            if (ok == 2) {
                TRICKY_RESET((u8*)state);
                break;
            }
            if (ok == 0) {
                trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
            }
            if (state->flameCommandPending != 0) {
                if (state->stats->energy < 2) {
                    state->flameCommandPending = 0;
                    if ((u8)Obj_CanSetupObject() != 0) {
                        state->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                        TRICKY_RESET((u8*)state);
                        if (state->child == NULL) {
                            AnimObjD2DripSetup* setup =
                                (AnimObjD2DripSetup*)Obj_AllocObjectSetup(0x20, ANIMOBJD2_TRICKY_FOOD_OBJ_ID);
                            s8 slots[4];
                            int free_;
                            slots[0] = -1;
                            slots[1] = -1;
                            slots[2] = -1;
                            if (state->childA != NULL) {
                                slots[state->packedSlots.promptASlot] = 1;
                            }
                            if (state->childB != NULL) {
                                slots[state->packedSlots.promptBSlot] = 1;
                            }
                            if (state->child != NULL) {
                                slots[state->packedSlots.zzzSlot] = 1;
                            }
                            if (slots[0] == -1) {
                                free_ = 0;
                            } else if (slots[1] == -1) {
                                free_ = 1;
                            } else if (slots[2] == -1) {
                                free_ = 2;
                            } else if (slots[3] == -1) {
                                free_ = 3;
                            } else {
                                free_ = -1;
                            }
                            state->packedSlots.zzzSlot = free_;
                            state->child = (void*)objSetupObject((ObjPlacement*)setup, 4, -1, -1, obj->anim.parent);
                            ObjLink_AttachChild(obj, state->child, state->packedSlots.zzzSlot);
                            {
                                f32 z3 = gTrickyFloatZero;
                                state->childPhaseTimer0 = z3;
                                state->childPhaseTimer1 = z3;
                                state->childPhaseTimer2 = z3;
                            }
                        }
                    }
                } else {
                    state->substate = ANIMOBJD2_SUBSTATE_CHARGE;
                    break;
                }
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) >
                TRICKY_CIRCLING_FAR_DISTANCE_SQ) {
                state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
                break;
            }
            state->cooldownA -= timeDelta;
            if (state->cooldownA < gTrickyFloatZero) {
                f32 rv;
                rv = (s32)randomGetRange(0xc8, 0x258);
                state->cooldownA = rv * TRICKY_FOLLOW_ARC_HALF_PROGRESS;
                TRICKY_BARK((int*)obj, TRICKY_VOICE_SFX_ROLLING, 0x1000, approachCfg);
            }
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_CHARGE: {
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_GOTOFLAME);
        ok = trickyUpdateMovementState(obj, TRICKY_CIRCLING_CHARGE_RADIUS, state);
        hasTarget = trickyAcquireCirclingTarget(state);
        if (hasTarget != 0 && ok != 1) {
            trickyRequestMove(obj, TRICKY_ANIM_DIG, TRICKY_LAND_MOVE_BLEND_SPEED,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = ANIMOBJD2_SUBSTATE_SPAWN;
            state->flameCommandPending = 0;
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_SPAWN:
        if (obj->anim.currentMove != 0x34) {
            break;
        }
        if (obj->anim.currentMoveProgress > TRICKY_CIRCLING_SPAWN_PROGRESS) {
            if ((u8)Obj_CanSetupObject() != 0) {
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                {
                    int i = 0;
                    u8* p = (u8*)state;
                    for (; i < 7; i++) {
                        AnimObjD2DripSetup* setup =
                            (AnimObjD2DripSetup*)Obj_AllocObjectSetup(0x24, ANIMOBJD2_FLAMEBLAST_OBJ_ID);
                        setup->head.color[0] = 2;
                        setup->head.color[1] = 1;
                        setup->index = i;
                        TRICKY_FLAME_CHILD_AT_CURSOR(p) =
                            objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        p += 4;
                    }
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            }
            state->stats->energy -= 2;
            state->substate = ANIMOBJD2_SUBSTATE_FINISH;
        }
        break;
    case ANIMOBJD2_SUBSTATE_FINISH: {
        u32 fl;
        trickyDebugPrint(str + TRICKY_DBG_BADDIEALERT_FLAME);
        fl = state->stateFlags;
        if (fl & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
            state->stateFlags = fl & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            {
                u8* p;
                int i = 0;
                p = (u8*)state;
                for (; i < 7; i++) {
                    objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(p));
                    p += 4;
                }
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            TRICKY_BARK((int*)obj, TRICKY_VOICE_SFX_FINISH_FLAME, 0, finishCfg);
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags = flags & mask;
            }
            state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_ORBIT: {
        void** warpCursor;
        GameObject* target;
        GameObject* nearestBaddie = trickyFindNearestUsableBaddie(state->playerObj, TRICKY_TIMER_150_FRAMES, 0);
        if (nearestBaddie != NULL && nearestBaddie->anim.romDefNo == ANIMOBJD2_CIRCLE_TARGET_SEQID) {
            target = nearestBaddie;
        } else {
            target = (GameObject*)Player_GetTargetObject((int)state->playerObj);
        }
        if (target != state->cooldownB.obj || state->flameCommandPending != 0) {
            TRICKY_RETARGET((u8*)state, state->followObj);
            state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
        } else {
            void** warpList = (void**)objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
            int i = 0;
            warpCursor = warpList;
            for (; i < warpCount; i++) {
                f32 warpToTarget =
                    Vec_xzDistance(&((GameObject*)warpCursor[0])->anim.worldPosX, &target->anim.worldPosX);
                f32 warpToPlayer =
                    Vec_xzDistance(&((GameObject*)warpCursor[0])->anim.worldPosX, &state->playerObj->anim.worldPosX);
                f32 targetToPlayer = Vec_xzDistance(&target->anim.worldPosX, &state->playerObj->anim.worldPosX);
                if (warpToTarget + warpToPlayer > 2.0f * targetToPlayer) {
                    f32 warpToTricky =
                        Vec_xzDistance(&((GameObject*)warpCursor[0])->anim.worldPosX, &obj->anim.worldPosX);
                    if (warpToPlayer - warpToTricky > bestDetourSavings) {
                        bestDetourSavings = warpToPlayer - warpToTricky;
                        bestWarp = warpCursor[0];
                    }
                }
                warpCursor++;
            }
            {
                GameObject* circlingWarpDetour = state->circlingWarpDetour;
                if (circlingWarpDetour != NULL && (circlingWarpDetour->objectFlags & ANIMOBJD2_OBJFLAG_FREED)) {
                    state->circlingWarpDetour = NULL;
                    TRICKY_RETARGET((u8*)state, state->playerObj);
                }
            }
            if (bestWarp != NULL) {
                if (state->circlingWarpDetour == NULL) {
                    TRICKY_BARK((int*)obj, TRICKY_VOICE_SFX_GET_MFOX, 0x500, orbitCfg);
                }
                if (state->circlingWarpDetour == NULL || state->circlingWarpDetour != bestWarp) {
                    state->circlingWarpDetour = bestWarp;
                    TRICKY_RETARGET((u8*)state, state->circlingWarpDetour);
                }
            }
        }
        {
            u8 orbitMovementStatus;
            if (state->circlingWarpDetour != NULL) {
                orbitMovementStatus = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
            } else {
                orbitMovementStatus = trickyUpdateMovementState(obj, gTrickyMaxDistance, state);
            }
            if (orbitMovementStatus != 1) {
                int useSwimMove;
                useSwimMove = skeetla_isInWater(state);
                if (useSwimMove != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(str + TRICKY_DBG_IN_WATER);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(str + TRICKY_DBG_OUT_OF_WATER);
                }
            }
        }
        break;
    }
    }
}

GameObject* trickyFindCirclingTarget(GameObject* obj, TrickyState* state) {
    GameObject* target;
    GameObject** list;
    int count;
    int i;
    f32 d1, d2, d3;

    target = state->followObj;
    if (target->anim.romDefNo == ANIMOBJD2_CIRCLE_TARGET_SEQID) {
        return target;
    }

    target = (GameObject*)playerGetTargetObject(state->playerObj);
    if (target != NULL) {
        list = objGetAllOfType(TRICKY_BADDIE_OBJGROUP, &count);
        for (i = 0; i < count; i++) {
            if (*list == target) {
                d1 = Vec_xzDistance(&obj->anim.worldPosX, &target->anim.worldPosX);
                d2 = Vec_xzDistance(&obj->anim.worldPosX, &state->playerObj->anim.worldPosX);
                d3 = Vec_xzDistance(&target->anim.worldPosX, &state->playerObj->anim.worldPosX);
                if ((d1 + d2) < 2.0f * d3) {
                    return target;
                }
                break;
            }
            list++;
        }
    }
    return NULL;
}

void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state) {
    GameObject* target = state->followObj;
    f32 dx = target->anim.worldPosX - obj->anim.worldPosX;
    f32 dz = target->anim.worldPosZ - obj->anim.worldPosZ;
    int angle = atan2Angle16(dx, dz);
    s32 delta;
    s32 absDelta;

    if (state->substate == ANIMOBJD2_SUBSTATE_ACQUIRE) {
        state->circlingDirection.i = randomGetRange(0, 1);
        if (state->circlingDirection.i == 0) {
            state->circlingDirection.i = -1;
        }
        state->circlingAngle.i = angle;
        state->substate = ANIMOBJD2_SUBSTATE_APPROACH;
    }

    delta = angle - (s32)(u16)state->circlingAngle.u;
    if (delta > 0x8000) {
        delta -= 0xFFFF;
    }
    if (delta < -0x8000) {
        delta += 0xFFFF;
    }

    if (delta >= 0) {
        absDelta = delta;
    } else {
        absDelta = -delta;
    }
    if (absDelta < 0x2000) {
        state->circlingAngle.i = state->circlingAngle.i + (state->circlingDirection.i << 11);
    }

    state->circlingTargetX.f =
        state->followObj->anim.worldPosX - TRICKY_CIRCLING_APPROACH_RADIUS * fsin16Precise((u16)state->circlingAngle.i);
    state->circlingTargetY.f = state->followObj->anim.worldPosY;
    state->circlingTargetZ.f =
        state->followObj->anim.worldPosZ - TRICKY_CIRCLING_APPROACH_RADIUS * fcos16Precise((u16)state->circlingAngle.i);

    if (trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) == 0) {
        trickyReportError(sTrickyShouldNeverStopCirclingError);
    }
}

const char sTrickyShouldNeverStopCirclingError[] = "error tricky should never stop when circling\n";

/*
 * Tricky companion-AI substate handlers (TrickyState::substate machines).
 *
 * Each entry point is one behavior tick dispatched off TrickyState->substate:
 *   tricky_fetchBall - fetch/carry-ball behavior (grab a thrown ball via
 *                      sidekickBall_* entry points, swim or walk to it, return it).
 *   tricky_idleAndEat - idle/eat ambient state (random bark cues, eating anim).
 *   tricky_trackTumbleweed - track a TumbleweedBush target and steer Tricky toward it,
 *                 gated by game bit 0x48b.
 *   tricky_moveToFollowTarget - simple swim-or-walk move toward the follow target.
 *
 * Common to all: water is detected by comparing waterLevel / eventTime /
 * currentTime to pick a swim anim vs a ground anim. tricky_fetchBall and tricky_idleAndEat play a
 * localized bark sfx unless one is already on object channel 16. Debug strings
 * are emitted via
 * trickyDebugPrint. tricky_state.h owns the TrickyState layout; the gTricky*
 * floats are pooled .sdata2 tuning constants shared throughout this DLL.
 *
 * tricky_fetchBall's case numbering/fallthrough (0 into 1, 4 into 5 via the label
 * inside the if) is ground truth from the retail jump table at 0x8031D910 --
 * do not renumber or "un-nest" case 5.
 */

#define TRICKY_CLEAR_RESET_FLAGS(st)                                                                                   \
    {                                                                                                                  \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;                                    \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;                                    \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;                                      \
        ((TrickyState*)(st))->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;                                     \
        {                                                                                                              \
            s8 mm;                                                                                                     \
            mm = -1;                                                                                                   \
            ((TrickyState*)(st))->commandPhase = mm;                                                                   \
        }                                                                                                              \
    }

void tricky_fetchBall(GameObject* obj, TrickyState* state) {
    int status;
    TrickyState* extra;
    int useSwimAnim;
    s16 move;
    f32 bob;
    f32 resetTimer;
    f32* targetPos;

    switch (state->substate) {
    case 0:
        state->fetchBallObj = state->followObj;
        state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
        state->substate = 1;
        state->sfxIntervalTimer = (f32)(s32)randomGetRange(150, 300);
        /* fall through */
    case 1:
        if (sidekickBall_isHeldOrMoving(state->fetchBallObj) != 0) {
            status = trickyUpdateMovementState(obj, TRICKY_FETCH_BALL_REACH_RADIUS, state);
            if (status == 0) {
                useSwimAnim = skeetla_isInWater(state);
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_PICKUP_WATER, TRICKY_FETCH_PICKUP_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_PICKUP_LAND, TRICKY_FETCH_PICKUP_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                }
                state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->substate = 3;
                sidekickBall_setIdle(state->fetchBallObj, obj);
            } else if (status == 2) {
                extra = obj->extra;
                if (extra->soundSuppressed == 0) {
                    move = (obj)->anim.currentMove;
                    if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &extra->soundState, 861, 1280, -1, 0);
                        }
                    }
                }
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = 0;
                resetTimer = gTrickyFloatZero;
                state->cooldownA = resetTimer;
                state->cooldownB.f = resetTimer;
                TRICKY_CLEAR_RESET_FLAGS(state);
            }
        } else {
            status = trickyUpdateMovementState(obj, TRICKY_TIMER_20_FRAMES, state);
            if (status == 0) {
                if (state->fetchCarryDelayTimer > gTrickyFloatZero) {
                    useSwimAnim = skeetla_isInWater(state);
                    if (useSwimAnim != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        state->particleTimer = gTrickyFloatZero;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        trickyDebugPrint(sTrickyDryLandDebugMessage);
                    }
                    state->fetchCarryDelayTimer -= timeDelta;
                    if (state->fetchCarryDelayTimer <= gTrickyFloatZero) {
                        useSwimAnim = skeetla_isInWater(state);
                        if (useSwimAnim != 0) {
                            state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
                        } else {
                            state->fetchThrowRetryTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
                        }
                    }
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_THROW_READY, TRICKY_FAST_MOVE_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                    state->fetchThrowRetryTimer -= timeDelta;
                    if (state->fetchThrowRetryTimer <= gTrickyFloatZero) {
                        state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
                    }
                }
            } else if (status == 1) {
                state->sfxIntervalTimer -= timeDelta;
                if (state->sfxIntervalTimer <= gTrickyFloatZero) {
                    state->sfxIntervalTimer = (f32)(s32)randomGetRange(150, 300);
                    extra = obj->extra;
                    if (extra->soundSuppressed != 0) {
                        break;
                    }
                    move = (obj)->anim.currentMove;
                    if (move < 48) {
                        if (move >= 41) {
                            break;
                        }
                    }
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &extra->soundState, 865, 1280, -1, 0);
                    }
                }
            } else {
                useSwimAnim = skeetla_isInWater(state);
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(sTrickyDryLandDebugMessage);
                }
            }
        }
        break;
    case 6:
        if ((obj)->anim.currentMoveProgress >= TRICKY_FETCH_LAUNCH_PROGRESS) {
            status = (int)state->fetchBallObj;
            ((GameObject*)status)->anim.localPosY += TRICKY_DEFAULT_STOPPING_RADIUS;
            bob = -mathCosf(TRICKY_PI * (f32)(s32) * (short*)obj / TRICKY_ANGLE_HALF_TURN_UNITS);
            sidekickBall_launch(state->fetchBallObj, obj,
                                -mathSinf(TRICKY_PI * (f32)(s32) * (short*)obj / TRICKY_ANGLE_HALF_TURN_UNITS), 1.0f,
                                bob);
            state->substate = 2;
        }
        break;
    case 2:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            state->colorFadeTimer = TRICKY_TIMER_20_FRAMES;
            if (state->stats->ballReturnCount >= TRICKY_BALL_RETURN_COUNT_MAX) {
                state->stats->ballReturnCount = 0;
            } else {
                state->stats->ballReturnCount++;
            }
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags = flags & mask;
            }
            state->substate = 7;
            targetPos = &state->followObj->anim.worldPosX;
            if (state->targetPosPtr != targetPos) {
                state->targetPosPtr = targetPos;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
        }
        break;
    case 7:
        status = trickyUpdateMovementState(obj, TRICKY_TIMER_20_FRAMES, state);
        if (status != 1) {
            useSwimAnim = skeetla_isInWater(state);
            if (useSwimAnim != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(sInWaterMessage);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
            return;
        }
        if (sidekickBall_isIdle(state->followObj) != 0) {
            state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
            state->substate = 1;
        }
        break;
    case 3:
        if ((obj)->anim.currentMoveProgress >= TRICKY_FOLLOW_ARC_HALF_PROGRESS) {
            state->substate = 4;
        }
        break;
    case 4:
        if ((obj)->anim.currentMoveProgress >= TRICKY_FLAME_DONE_PROGRESS) {
            targetPos = &state->playerObj->anim.worldPosX;
            if (state->targetPosPtr != targetPos) {
                state->targetPosPtr = targetPos;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
            state->substate = 5;
        case 5:
            if (trickyUpdateMovementState(obj, TRICKY_TIMER_30_FRAMES, state) == 0) {
                useSwimAnim = skeetla_isInWater(state);
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_THROW_WATER, TRICKY_FETCH_PICKUP_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_THROW_LAND, TRICKY_FETCH_PICKUP_BLEND_SPEED,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                }
                state->substate = 6;
            }
        }
        break;
    }
    if (((state->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) &&
        ViewFrustum_IsSphereVisible(&(obj)->anim.localPosX, TRICKY_VISIBILITY_PROBE_RADIUS) == 0) {
        Obj_FreeObject(state->followObj);
    } else {
        sidekickBall_keepAlive(state->fetchBallObj);
    }
}

void tricky_idleAndEat(GameObject* obj, TrickyState* state) {
    TrickyState* extra;
    int inWater;
    s16 move;

    if (tricky_handleFeedOrTalk(obj, state) == 0) {
        if (trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) == 0) {
            state->idleSfxTimer -= timeDelta;
            if (state->idleSfxTimer <= gTrickyFloatZero) {
                state->idleSfxTimer =
                    (f32)(s32)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
                extra = obj->extra;
                if (extra->soundSuppressed == 0) {
                    move = obj->anim.currentMove;
                    if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &extra->soundState, 864, 1280, -1, 0);
                        }
                    }
                }
            }
            inWater = skeetla_isInWater(state);
            if (inWater != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch (obj->anim.currentMove) {
                case TRICKY_ANIM_IDLE_FOOD_WAIT:
                    if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_CHEW, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    }
                    break;
                case TRICKY_ANIM_IDLE_FOOD_CHEW:
                    break;
                default:
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_WAIT, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    break;
                }
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
        }
    }
}

void tricky_trackTumbleweed(GameObject* obj, TrickyState* state) {
    int inWater;
    float dx;
    float dz;
    float distance;
    f32 resetTimer;
    float* targetPos;
    GameObject* trackedObj;
    u32 currentBit;
    u8 bitIndex;
    u8 newBit;

    switch (state->substate) {
    case 0:
        newBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        state->tumbleweedCountLatch.nib.hi = newBit;
        state->tumbleweedTargetObj = NULL;
        state->substate = 1;
    case 1:
        currentBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        bitIndex = state->tumbleweedCountLatch.nib.hi;
        if (bitIndex != currentBit) {
            state->tumbleweedCountLatch.nib.hi++;
            state->stats->energy -= 2;
        }
        targetPos = NW_mammoth_getSpawnPosition(state->followObj);
        trackedObj = tumbleweedbush_findNearestActive(targetPos);
        if (trackedObj != 0 && state->stats->energy != 0) {
            if (trackedObj != state->tumbleweedTargetObj &&
                (u8*)state->targetPosPtr != (u8*)&state->tumbleweedTargetX) {
                state->targetPosPtr = &state->tumbleweedTargetX;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
            dx = *targetPos - obj->anim.worldPosX;
            dz = targetPos[2] - obj->anim.worldPosZ;
            distance = sqrtf(dx * dx + dz * dz);
            if (gTrickyFloatZero != distance) {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = TRICKY_CIRCLING_APPROACH_RADIUS;
            state->tumbleweedTargetX = -(distance * dx - trackedObj->anim.worldPosX);
            state->tumbleweedTargetY = trackedObj->anim.worldPosY;
            state->tumbleweedTargetZ = -(distance * dz - trackedObj->anim.worldPosZ);
            if (trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) == 0) {
                inWater = skeetla_isInWater(state);
                if (inWater != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(sTrickyDryLandDebugMessage);
                }
            }
        } else {
            state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            state->substate = 0;
            resetTimer = gTrickyFloatZero;
            state->cooldownA = resetTimer;
            state->cooldownB.f = resetTimer;
            TRICKY_CLEAR_RESET_FLAGS(state);
        }
        break;
    }
}

void tricky_moveToFollowTarget(GameObject* obj, TrickyState* state) {
    int inWater;
    int result;

    result = trickyUpdateMovementState(obj, TRICKY_ANIM_TRANSITION_FRAMES, state);
    if (result == 0) {
        inWater = skeetla_isInWater(state);
        if (inWater != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
            state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
            state->particleTimer = gTrickyFloatZero;
            trickyDebugPrint(sInWaterMessage);
        } else {
            trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
            trickyDebugPrint(sTrickyDryLandDebugMessage);
        }
    }
}

/* Tricky flame/guard AI. Spawns Tricky's flameblast (def 0x4F0) for the
 * fire-breath/guard behaviour. */

#define TRICKY_GUARD_HELPER_COUNT      7
#define TRICKY_GUARD_APPROACH_GROUP    3
#define TRICKY_GUARD_HELPER_SETUP_SIZE 0x24
#define TRICKY_GUARD_HELPER_DEF_ID     0x04F0

#define TRICKY_STATE(st) ((TrickyState*)(st))

#define TRICKY_CLEAR_FLAG(st, flag)                                                                                    \
    {                                                                                                                  \
        u32 m;                                                                                                         \
        u32 f2 = TRICKY_STATE(st)->stateFlags;                                                                         \
        m = ~(flag);                                                                                                   \
        TRICKY_STATE(st)->stateFlags = f2 & m;                                                                         \
    }

#define TRICKY_INVALIDATE_PATH_PATCHES(st) TRICKY_CLEAR_FLAG(st, TRICKY_STATE_FLAG_PATH_PATCHES_VALID)

#define TRICKY_MARK_HELPERS_FINISHED(st)                                                                               \
    {                                                                                                                  \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_FLAG_CHILDREN_ACTIVE);                                                      \
        TRICKY_STATE(st)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;                                            \
    }

#define TRICKY_STATE_CLEAR_RESET_FLAGS(st)                                                                             \
    {                                                                                                                  \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_FLAG_COMMAND_ACTIVE);                                                       \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_FLAG_RECALL_REQUEST);                                                       \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_FLAG_HEEL_REQUEST);                                                         \
        TRICKY_CLEAR_FLAG(st, TRICKY_STATE_FLAG_GUARD_REQUEST);                                                        \
        TRICKY_STATE(st)->commandPhase = TRICKY_COMMAND_PHASE_IDLE;                                                    \
    }

int trickyGuardFindBaddieTarget(TrickyState* state);

static inline int trickyGuardIsBaddieTargetValid(TrickyState* state) {
    GameObject* target = state->guardTarget;
    int count;
    GameObject** objects;
    s16 i;

    objects = (GameObject**)objGetAllOfType(TRICKY_GUARD_APPROACH_GROUP, &count);
    for (i = 0; i < count; i++) {
        if (*objects == target) {
            return 1;
        }
        objects++;
    }
    return 0;
}

static inline void trickyPlayVoice(GameObject* obj, TrickyState* state, u16 sfxId, int volume) {
    s16 move;

    if (state->soundSuppressed) {
        return;
    }
    move = obj->anim.currentMove;
    if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
            objSoundStartTimed(obj, &state->soundState, sfxId, volume, -1, 0);
        }
    }
}

static inline void trickyStopFlameChildren(GameObject* obj, TrickyState* state) {
    state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
    {
        int childIndex = 0;
        u8* childState = (u8*)state;

        for (; childIndex < CHILD_OBJECT_COUNT; childState += sizeof(GameObject*), childIndex++) {
            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(childState));
        }
    }
    Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
    trickyPlayVoice(obj, obj->extra, TRICKY_VOICE_SFX_FINISH_FLAME, 0);
}

static inline void trickySpawnFlameChildren(GameObject* obj, TrickyState* state) {
    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    {
        int childIndex = 0;
        u8* childState = (u8*)state;

        for (; childIndex < CHILD_OBJECT_COUNT; childState += sizeof(GameObject*), childIndex++) {
            FlameblastPlacement* setup =
                (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_CHILD_OBJ_FLAMEBLAST);

            setup->base.color[0] = 2;
            setup->base.color[1] = 1;
            setup->streamIndex = childIndex;
            TRICKY_FLAME_CHILD_AT_CURSOR(childState) =
                objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
        }
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
    Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
}

typedef enum TrickyGuardState {
    TRICKY_GUARD_INIT = 0,
    TRICKY_GUARD_FINDING = 1,
    TRICKY_GUARD_TO_SPOT = 2,
    TRICKY_GUARD_TO_FRONT = 3,
    TRICKY_GUARD_TO_BADDIE = 4,
    TRICKY_GUARD_FLAME = 5,
    TRICKY_GUARD_DOWN_TO_GROWL = 6,
    TRICKY_GUARD_GROWL = 7,
    TRICKY_GUARD_UP_FROM_GROWL = 8,
} TrickyGuardState;

#define TRICKY_GUARD_POST_DISTANCE       TRICKY_ANIM_TRANSITION_FRAMES
#define TRICKY_GUARD_APPROACH_RADIUS     TRICKY_DEFAULT_STOPPING_RADIUS
#define TRICKY_GUARD_BADDIE_RADIUS       TRICKY_ANIM_TRANSITION_FRAMES
#define TRICKY_GUARD_FLAME_DONE_PROGRESS TRICKY_FLAME_DONE_PROGRESS
#define TRICKY_GUARD_GROWL_RANDOM_RATE   10
#define TRICKY_GUARD_GROWL_MAX_SECONDS   TRICKY_TIMER_150_FRAMES
#define TRICKY_GUARD_GROWL_LEASH_DIST_SQ TRICKY_CLOSE_DISTANCE_SQ
#define TRICKY_GUARD_GROWL_DOWN_BLEND    0.01f
#define TRICKY_GUARD_GROWL_UP_BLEND      -0.01f
#define TRICKY_GUARD_FLAME_SFX_ID        TRICKY_VOICE_SFX_FINISH_FLAME
#define TRICKY_GUARD_GROWL_SFX_ID        TRICKY_VOICE_SFX_GROWL
#define TRICKY_GUARD_GROWL_SFX_PARAM     0x100

char sTrickyGuardDebugTextBlock[] = "GUARD_INIT\n"
                                    "\0"
                                    "GUARD_FINDING\n"
                                    "\0\0"
                                    "GUARD_TOSPOT\n"
                                    "\0\0\0"
                                    "GUARD_TOFRONT\n"
                                    "\0\0"
                                    "GUARD_TOBADDIE\n"
                                    "\0"
                                    "GUARD_FLAME\n"
                                    "\0\0\0\0"
                                    "GUARD_DOWNTOGROWL\n"
                                    "\0\0"
                                    "GUARD_GROWL\n"
                                    "\0\0\0\0"
                                    "GUARD_UPFROMGROWL\n"
                                    "\0";

void trickyGuard(GameObject* obj, TrickyState* trickyState) {
    char* debugText = gTrickyDebugStringTable;
    int helperIndex;
    TrickyState* flameSoundState;
    TrickyState* growlSoundState;
    TrickyState* randomSoundState;
    void** helperSlot;
    void** finishSlot;
    int finishIndex;
    FlameblastPlacement* helperSetup;
    f32* guardTargetPos;

    switch (trickyState->substate) {
    case TRICKY_GUARD_INIT:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_INIT);
        trickyState->guardWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(trickyState->targetPosPtr, 0x0);
        trickyState->guardPoint[0] =
            (f32)(trickyState->followObj->anim.worldPosX -
                  TRICKY_GUARD_POST_DISTANCE *
                      mathSinf((TRICKY_PI * trickyState->followObj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS));
        trickyState->guardPoint[1] = trickyState->followObj->anim.worldPosY;
        trickyState->guardPoint[2] =
            (f32)(trickyState->followObj->anim.worldPosZ -
                  TRICKY_GUARD_POST_DISTANCE *
                      mathCosf((TRICKY_PI * trickyState->followObj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS));
        trickyState->guardCanSpawnHelpers = 0;
        trickyState->substate = TRICKY_GUARD_FINDING;
        break;
    case TRICKY_GUARD_FINDING:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_FINDING);
        trickyUpdateMovementState(obj, TRICKY_GUARD_APPROACH_RADIUS, trickyState);
        if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0x0)) {
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
        }
        break;
    case TRICKY_GUARD_TO_SPOT:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_TOSPOT);
        if (trickyUpdateMovementState(obj, TRICKY_GUARD_APPROACH_RADIUS, trickyState) == 0) {
            if (trickyState->targetPosPtr != trickyState->guardPoint) {
                trickyState->targetPosPtr = trickyState->guardPoint;
                TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
                trickyState->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_GUARD_TO_FRONT;
        } else {
            trickyGuardFindBaddieTarget(trickyState);
            break;
        }
    case TRICKY_GUARD_TO_FRONT:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_TOFRONT);
        if (trickyUpdateMovementState(obj, TRICKY_GUARD_APPROACH_RADIUS, trickyState) == 0) {
            if (skeetla_isInWater(trickyState) != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                (trickyState)->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                (trickyState)->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(debugText + TRICKY_DBG_IN_WATER);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(debugText + TRICKY_DBG_OUT_OF_WATER);
            }
        }
        trickyGuardFindBaddieTarget(trickyState);
        break;
    case TRICKY_GUARD_TO_BADDIE:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_TOBADDIE);
        if (trickyUpdateMovementState(obj, TRICKY_GUARD_BADDIE_RADIUS, trickyState) == 0) {
            trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (trickyState->stats->energy != 0 && trickyState->guardCanSpawnHelpers != 0) {
                if ((u8)Obj_CanSetupObject() != 0) {
                    trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                    for (helperIndex = 0, helperSlot = (void**)trickyState; helperIndex < TRICKY_GUARD_HELPER_COUNT;
                         helperIndex++) {
                        helperSetup = (FlameblastPlacement*)Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE,
                                                                                 TRICKY_GUARD_HELPER_DEF_ID);
                        helperSetup->base.color[0] = 2;
                        helperSetup->base.color[1] = 1;
                        helperSetup->streamIndex = helperIndex;
                        TRICKY_FLAME_CHILD_AT_CURSOR(helperSlot) =
                            (void*)objSetupObject(&helperSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        helperSlot++;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                    Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                }
                trickyState->stats->energy--;
                trickyRequestMove(obj, TRICKY_ANIM_DIG, TRICKY_LAND_MOVE_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                trickyState->substate = TRICKY_GUARD_FLAME;
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_GUARD_GROWL, TRICKY_GUARD_GROWL_DOWN_BLEND,
                                  TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                trickyState->substate = TRICKY_GUARD_DOWN_TO_GROWL;
            }
        } else {
            if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(trickyState->targetPosPtr, 0x0)) {
                break;
            }
            guardTargetPos = &trickyState->followObj->anim.worldPosX;
            if (trickyState->targetPosPtr != guardTargetPos) {
                trickyState->targetPosPtr = guardTargetPos;
                TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
                trickyState->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
            break;
        }
    case TRICKY_GUARD_FLAME:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_FLAME);
        if (obj->anim.currentMoveProgress >= TRICKY_GUARD_FLAME_DONE_PROGRESS) {
            TRICKY_MARK_HELPERS_FINISHED(trickyState);
            for (finishIndex = 0, finishSlot = (void**)trickyState; finishIndex < TRICKY_GUARD_HELPER_COUNT;
                 finishIndex++) {
                objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(finishSlot));
                finishSlot++;
            }
            Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            flameSoundState = obj->extra;
            if (!flameSoundState->soundSuppressed) {
                s16 move = obj->anim.currentMove;

                if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &flameSoundState->soundState, TRICKY_GUARD_FLAME_SFX_ID, 0, -1, 0);
                    }
                }
            }
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (trickyGuardFindBaddieTarget(trickyState) == 0) {
                guardTargetPos = &trickyState->followObj->anim.worldPosX;
                if (trickyState->targetPosPtr != guardTargetPos) {
                    trickyState->targetPosPtr = guardTargetPos;
                    TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
                    trickyState->linkedWalkGroup = 0;
                }
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        } else if (trickyGuardIsBaddieTargetValid(trickyState) != 0) {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_DOWN_TO_GROWL:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_DOWNTOGROWL);
        if (obj->anim.currentMoveProgress >= TRICKY_GUARD_FLAME_DONE_PROGRESS) {
            trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_LAND_MOVE_BLEND_SPEED,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->guardTimer = gTrickyFloatZero;
            growlSoundState = obj->extra;
            if (!growlSoundState->soundSuppressed) {
                s16 move = obj->anim.currentMove;

                if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &growlSoundState->soundState, TRICKY_GUARD_GROWL_SFX_ID,
                                           TRICKY_GUARD_GROWL_SFX_PARAM, -1, 0);
                    }
                }
            }
            trickyState->substate = TRICKY_GUARD_GROWL;
        } else if (trickyGuardIsBaddieTargetValid(trickyState) != 0) {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_GROWL:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_GROWL);
        if (randomGetRange(0, TRICKY_GUARD_GROWL_RANDOM_RATE) == 0) {
            randomSoundState = obj->extra;
            if (!randomSoundState->soundSuppressed) {
                s16 move = obj->anim.currentMove;

                if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &randomSoundState->soundState, TRICKY_GUARD_GROWL_SFX_ID,
                                           TRICKY_GUARD_GROWL_SFX_PARAM, -1, 0);
                    }
                }
            }
        }
        trickyState->guardTimer = trickyState->guardTimer + timeDelta;
        if ((trickyState->guardTimer >= TRICKY_GUARD_GROWL_MAX_SECONDS &&
             getXZDistanceSquared(trickyState->targetPosPtr, &obj->anim.worldPosX) >=
                 TRICKY_GUARD_GROWL_LEASH_DIST_SQ) ||
            trickyGuardIsBaddieTargetValid(trickyState) == 0) {
            trickyRequestMove(obj, TRICKY_ANIM_GUARD_GROWL, TRICKY_GUARD_GROWL_UP_BLEND,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->substate = TRICKY_GUARD_UP_FROM_GROWL;
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_UP_FROM_GROWL:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_UPFROMGROWL);
        if (obj->anim.currentMoveProgress <= gTrickySmallSpeedStep) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (trickyGuardFindBaddieTarget(trickyState) == 0) {
                guardTargetPos = &trickyState->followObj->anim.worldPosX;
                if (trickyState->targetPosPtr != guardTargetPos) {
                    trickyState->targetPosPtr = guardTargetPos;
                    TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
                    trickyState->linkedWalkGroup = 0;
                }
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        }
        break;
    }
}

int trickyGuardFindBaddieTarget(TrickyState* trickyState) {
    int baddieCount;
    f32 distanceSq;
    f32 bestDistanceSq;
    GameObject** baddieCursor;
    s16 baddieIndex;
    GameObject** baddieObjects;
    GameObject* bestTarget = NULL;

    baddieObjects = (GameObject**)objGetAllOfType(TRICKY_GUARD_APPROACH_GROUP, &baddieCount);
    baddieIndex = 0;
    baddieCursor = baddieObjects;
    for (; baddieIndex < baddieCount; baddieIndex++) {
        distanceSq = getXZDistanceSquared(&(*baddieCursor)->anim.worldPosX, trickyState->guardPoint);
        if (bestTarget == NULL) {
            if (trickyState->guardWalkGroup ==
                Objfsa_GetWalkGroupIndexAtPoint(&(*baddieCursor)->anim.worldPosX, NULL)) {
                bestDistanceSq = distanceSq;
                bestTarget = *baddieCursor;
            }
        } else if (distanceSq < bestDistanceSq) {
            if (trickyState->guardWalkGroup ==
                Objfsa_GetWalkGroupIndexAtPoint(&(*baddieCursor)->anim.worldPosX, NULL)) {
                bestDistanceSq = distanceSq;
                bestTarget = *baddieCursor;
            }
        }
        baddieCursor++;
    }
    if (bestTarget != NULL) {
        trickyState->guardTarget = bestTarget;
        if (trickyState->targetPosPtr != &bestTarget->anim.worldPosX) {
            trickyState->targetPosPtr = &bestTarget->anim.worldPosX;
            TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
            trickyState->linkedWalkGroup = 0;
        }
        trickyState->substate = TRICKY_GUARD_TO_BADDIE;
        return 1;
    }
    return 0;
}

typedef enum TrickyFlameState {
    TRICKY_FLAME_NONE = 0,
    TRICKY_FLAME_FINDING_IN = 1,
    TRICKY_FLAME_TURNING_IN = 2,
    TRICKY_FLAME_FINDING_OUT = 3,
    TRICKY_FLAME_GOING_TO_EDGE = 4,
    TRICKY_FLAME_TO_START = 5,
    TRICKY_FLAME_IN = 6,
    TRICKY_FLAME_OUT = 7,
    TRICKY_FLAME_TO_END = 8,
} TrickyFlameState;

char sTrickyFlameDebugTextBlock[] = "FLAME_NONE\n"
                                    "\0"
                                    "FLAME_FINDING_OUT\n"
                                    "\0\0"
                                    "FLAME_GOINGTOEDGE\n"
                                    "\0\0"
                                    "FLAME_TOSTART\n"
                                    "\0\0"
                                    "FLAME_OUT\n"
                                    "\0\0"
                                    "FLAME_FINDING_IN\n"
                                    "\0\0\0"
                                    "FLAME_TURNING_IN\n"
                                    "\0\0\0"
                                    "FLAME_IN\n"
                                    "\0\0\0"
                                    "FLAME_TOEND\n"
                                    "\0\0\0";

void trickyFlame(GameObject* obj, TrickyState* trickyState) {
    char* debugTextBase = gTrickyDebugStringTable;
    void** flameChildCursor;
    int flameScratch;
    void** releaseChildCursor;
    int releaseChildIndex;
    FlameblastPlacement* flameSetup;
    int flameActive;
    f32* target;
    f32 zero;

    switch (trickyState->substate) {
    case TRICKY_FLAME_NONE:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_NONE);
        trickyState->flameEdgeNode = Objfsa_FindNearestCurveType24(&trickyState->followObj->anim.worldPosX, -1, 4);
        if (trickyState->flameEdgeNode->walkGroup != 0) {
            target = &trickyState->flameEdgeNode->x;
            if (trickyState->targetPosPtr != target) {
                trickyState->targetPosPtr = target;
                TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
                (trickyState)->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_FLAME_FINDING_IN;
        } else {
            trickyState->flameReturnNode = (*gRomCurveInterface)->getById(trickyState->flameEdgeNode->linkIds[0]);
            target = &trickyState->flameReturnNode->x;
            if (trickyState->targetPosPtr != target) {
                trickyState->targetPosPtr = target;
                TRICKY_INVALIDATE_PATH_PATCHES(trickyState);
                (trickyState)->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_FLAME_FINDING_OUT;
        }
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
        break;
    case TRICKY_FLAME_FINDING_OUT:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_FINDING_OUT);
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
        if ((u8)trickyState->flameReturnNode->walkGroup ==
            Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL)) {
            trickyState->movementState = TRICKY_MOVE_WALK_FREE;
            trickyState->substate = TRICKY_FLAME_GOING_TO_EDGE;
        }
        break;
    case TRICKY_FLAME_GOING_TO_EDGE:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_GOINGTOEDGE);
        target = &trickyState->flameEdgeNode->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, target, 1);
        moveTricky(obj, target);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKY_FLAME_TO_START;
        }
        break;
    case TRICKY_FLAME_TO_START:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_TOSTART);
        target = &trickyState->flameEdgeNode->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, target, 1);
        if (moveTricky(obj, target) != 0) {
            break;
        }
        trickyRequestMove(obj, TRICKY_ANIM_FLAME_BREATH, TRICKY_FLOAT_0_004, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        trickyState->substate = TRICKY_FLAME_OUT;
        trickyState->stats->energy -= 4;
        /* fall through */
    case TRICKY_FLAME_OUT:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_OUT);
        {
            s16 flameYaw = (s16)(trickyState->flameEdgeNode->yaw << 8);
            s16 turnDelta = (s16)(flameYaw - (u16)obj->anim.rotX);
            int turnDeltaAbs;
            if (turnDelta > 0x8000) {
                turnDelta = (s16)(turnDelta - 0xFFFF);
            }
            if (turnDelta < -0x8000) {
                turnDelta = (s16)(turnDelta + 0xFFFF);
            }
            turnDeltaAbs = turnDelta;
            turnDeltaAbs = (turnDeltaAbs >= 0) ? turnDeltaAbs : -turnDeltaAbs;
            if (turnDeltaAbs >= 0x4000) {
                flameYaw = (s16)(flameYaw + 0x8000);
            }
            trickyTurnTowardYaw(obj, flameYaw);
        }
        do {
            if (obj->anim.currentMoveProgress > TRICKY_FOLLOW_ARC_QUARTER_PROGRESS) {
                if ((trickyState->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
                    if ((u8)Obj_CanSetupObject() != 0) {
                        trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                        for (flameScratch = 0, flameChildCursor = (void**)trickyState;
                             flameScratch < TRICKY_GUARD_HELPER_COUNT; flameScratch++) {
                            flameSetup = (FlameblastPlacement*)Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE,
                                                                                    TRICKY_GUARD_HELPER_DEF_ID);
                            flameSetup->base.color[0] = 2;
                            flameSetup->base.color[1] = 1;
                            flameSetup->streamIndex = flameScratch;
                            TRICKY_FLAME_CHILD_AT_CURSOR(flameChildCursor) = (void*)objSetupObject(
                                &flameSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                            flameChildCursor++;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                        Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                    }
                } else {
                    TrickyActionCallback callback = trickyState->actionCallback;
                    if (callback != NULL && callback(trickyState->followObj, 1) == 0) {
                    } else if (obj->anim.currentMoveProgress > TRICKY_FLAME_HELPER_RELEASE_PROGRESS) {
                        TRICKY_MARK_HELPERS_FINISHED(trickyState);
                        for (flameScratch = 0, flameChildCursor = (void**)trickyState;
                             flameScratch < TRICKY_GUARD_HELPER_COUNT; flameScratch++) {
                            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(flameChildCursor));
                            flameChildCursor++;
                        }
                        Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                        flameScratch = (int)obj->extra;
                        if (((TrickyState*)flameScratch)->soundSuppressed == 0) {
                            s16 a0 = obj->anim.currentMove;
                            if (a0 >= TRICKY_VOICE_MOVE_END || a0 < TRICKY_VOICE_MOVE_MIN) {
                                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                                    objSoundStartTimed(obj, &((TrickyState*)flameScratch)->soundState,
                                                       TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                                }
                            }
                        }
                        flameActive = 0;
                        break;
                    }
                }
            }
            flameActive = 1;
        } while (0);
        if (flameActive == 0) {
            trickyState->substate = TRICKY_FLAME_TO_END;
            (trickyState)->guardTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
        }
        break;
    case TRICKY_FLAME_FINDING_IN:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_FINDING_IN);
        {
            int r = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
            if (r == 0) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                trickyState->substate = TRICKY_FLAME_TURNING_IN;
            } else if (r == 2) {
                trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                trickyState->substate = TRICKY_FLAME_NONE;
                zero = gTrickyFloatZero;
                trickyState->guardPoint[0] = zero;
                trickyState->guardPoint[1] = zero;
                TRICKY_STATE_CLEAR_RESET_FLAGS(trickyState);
            }
        }
        break;
    case TRICKY_FLAME_TURNING_IN:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_TURNING_IN);
        target = &trickyState->followObj->anim.worldPosX;
        trickyUpdateApproachSpeed(obj, gTrickyMaxDistance, trickyState, target, 1);
        if (moveTricky(obj, target) == 0) {
            trickyRequestMove(obj, TRICKY_ANIM_FLAME_BREATH, TRICKY_FLOAT_0_004, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->substate = TRICKY_FLAME_IN;
            trickyState->stats->energy -= 4;
        }
        break;
    case TRICKY_FLAME_IN:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_IN);
        do {
            if (obj->anim.currentMoveProgress > TRICKY_FOLLOW_ARC_QUARTER_PROGRESS) {
                if ((trickyState->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
                    if ((u8)Obj_CanSetupObject() != 0) {
                        trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                        for (flameScratch = 0, flameChildCursor = (void**)trickyState;
                             flameScratch < TRICKY_GUARD_HELPER_COUNT; flameScratch++) {
                            flameSetup = (FlameblastPlacement*)Obj_AllocObjectSetup(TRICKY_GUARD_HELPER_SETUP_SIZE,
                                                                                    TRICKY_GUARD_HELPER_DEF_ID);
                            flameSetup->base.color[0] = 2;
                            flameSetup->base.color[1] = 1;
                            flameSetup->streamIndex = flameScratch;
                            TRICKY_FLAME_CHILD_AT_CURSOR(flameChildCursor) = (void*)objSetupObject(
                                &flameSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                            flameChildCursor++;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                        Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                    }
                } else {
                    TrickyActionCallback callback = trickyState->actionCallback;
                    if (callback != NULL && callback(trickyState->followObj, 1) == 0) {
                    } else if (obj->anim.currentMoveProgress > TRICKY_FLAME_HELPER_RELEASE_PROGRESS) {
                        TRICKY_MARK_HELPERS_FINISHED(trickyState);
                        for (releaseChildIndex = 0, releaseChildCursor = (void**)trickyState;
                             releaseChildIndex < TRICKY_GUARD_HELPER_COUNT; releaseChildIndex++) {
                            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(releaseChildCursor));
                            releaseChildCursor++;
                        }
                        Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                        flameChildCursor = (void**)obj->extra;
                        if (((TrickyState*)flameChildCursor)->soundSuppressed == 0) {
                            s16 a0 = obj->anim.currentMove;
                            if (a0 >= TRICKY_VOICE_MOVE_END || a0 < TRICKY_VOICE_MOVE_MIN) {
                                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                                    objSoundStartTimed(obj, &((TrickyState*)flameChildCursor)->soundState,
                                                       TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                                }
                            }
                        }
                        flameActive = 0;
                        break;
                    }
                }
            }
            flameActive = 1;
        } while (0);
        if (flameActive == 0) {
            trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            trickyState->substate = TRICKY_FLAME_NONE;
            zero = gTrickyFloatZero;
            trickyState->guardPoint[0] = zero;
            trickyState->guardPoint[1] = zero;
            TRICKY_STATE_CLEAR_RESET_FLAGS(trickyState);
        }
        break;
    case TRICKY_FLAME_TO_END:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_TOEND);
        trickyState->guardTimer -= timeDelta;
        if (trickyState->guardTimer <= gTrickyFloatZero) {
            target = &trickyState->flameReturnNode->x;
            trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, target, 1);
            moveTricky(obj, target);
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
                trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                trickyState->substate = TRICKY_FLAME_NONE;
                zero = gTrickyFloatZero;
                trickyState->guardPoint[0] = zero;
                trickyState->guardPoint[1] = zero;
                TRICKY_STATE_CLEAR_RESET_FLAGS(trickyState);
            }
        }
        break;
    }
}
void tricky_state06_nop(void) {
}

/*
 * Tricky rom-curve route walker. tricky_updateBallRoll is the per-frame
 * update that rolls the object along its rom-curve route.
 *
 * Before init (init-done byte 0x0a == 0): the ball homes onto its curve
 * (CANNONBALL_CURVE). Once the owner and the ball share a walk group it
 * picks the route direction by comparing owner-to-endpoint distances,
 * binds the route walker to the chosen segment, steps it, seeds the sfx
 * timer and marks init done.
 *
 * After init: at each segment end it gathers the valid branch nodes
 * (gated by the node-set's per-branch mask byte), picks the nearest to
 * the current owner, retargets the walker, then accelerates/decays the
 * roll speed toward CANNONBALL_ROLL_SPEED_LIMIT, advances and moves the
 * ball. Off the walk grid it sets CANNONBALL_HIDE_FLAG. The sfx timer
 * periodically plays the rolling sound (TRICKY_VOICE_SFX_ROLLING) on object channel 0x10
 * when the current move is outside the 0x29..0x2f window.
 */

/* The "ball" is the Tricky cannonball's TrickyState extra block: substate is
 * the init-done byte, speed the roll speed, stateFlags the flag word, route the
 * embedded RomCurveWalker, followObj/playerObj the owner links,
 * cannonballStartCurve the curve link, and cannonballRollSfxTimer the rolling
 * SFX countdown. */
#define CANNONBALL_HIDE_FLAG        0x10
#define CANNONBALL_SPEED_DECAY_FLAG 0x10000000
#define CANNONBALL_BRANCH_COUNT     4
#define CANNONBALL_ROLL_DECAY_STEP  TRICKY_FLOAT_NEG_0_01
#define CANNONBALL_INIT_WALK_RADIUS TRICKY_DEFAULT_STOPPING_RADIUS
#define CANNONBALL_ROUTE_FORESTEP   TRICKY_FLOAT_TEN
#define CANNONBALL_SFX_TIMER_MIN    200
#define CANNONBALL_SFX_TIMER_MAX    600
#define CANNONBALL_ROLL_SFX_ID      TRICKY_VOICE_SFX_ROLLING
#define CANNONBALL_ROLL_SFX_PARAM   0x1000

#define CANNONBALL_ROLL_SPEED_LIMIT (gCannonballRollSpeedLimit[0])
#define CANNONBALL_ROUTE_BACKSTEP   (gCannonballRouteBackstep[0])

void tricky_updateBallRoll(GameObject* obj, TrickyState* ball) {
    RomCurveDef* toNode;
    u8 nodeCount = 0;
    int branchCurveId;
    RomCurveDef* branchNode;
    s32* branchLinkId;
    u32 branchMask;
    int branchIndex;
    int i;
    RomCurveDef* curve;
    RomCurveDef* fromNode;
    s32 nodeIds[4];
    RomCurveDef* curveArg;
    RomCurveDef* candidateNode;
    RomCurveDef* targetNode;
    f32 speed;
    f64 distance;
    f64 bestDistance;

    if (ball->substate != 0) {
        if (ball->route.reverse == 0) {
            if (ball->route.atSegmentEnd != 0) {
                branchNode = (RomCurveDef*)ball->route.nextNode;
                branchMask = 1;
                branchLinkId = branchNode->linkIds;
                for (branchIndex = 0; branchIndex < CANNONBALL_BRANCH_COUNT; branchIndex++) {
                    branchCurveId = *branchLinkId++;
                    if (branchCurveId > -1 && ((branchNode->blockedLinkMask & branchMask) == 0)) {
                        nodeIds[nodeCount++] = branchCurveId;
                    }
                    branchMask <<= 1;
                }
            }
        } else if (ball->route.atSegmentEnd == 0) {
            int reverseBranchCurveId;
            RomCurveDef* reverseBranchNode;
            s32* reverseBranchLinkId;
            u32 reverseBranchMask;
            reverseBranchNode = (RomCurveDef*)ball->route.nextNode;
            reverseBranchMask = 1;
            reverseBranchLinkId = reverseBranchNode->linkIds;
            for (branchIndex = 0; branchIndex < CANNONBALL_BRANCH_COUNT; branchIndex++) {
                reverseBranchCurveId = *reverseBranchLinkId++;
                if (reverseBranchCurveId > -1 && ((reverseBranchNode->blockedLinkMask & reverseBranchMask) != 0)) {
                    nodeIds[nodeCount++] = reverseBranchCurveId;
                }
                reverseBranchMask <<= 1;
            }
        }

        if (nodeCount != 0) {
            targetNode = (*gRomCurveInterface)->getById(nodeIds[0]);
            bestDistance = getXZDistanceSquared(&ball->followObj->anim.worldPosX, &targetNode->x);

            for (i = 1, branchLinkId = &nodeIds[1]; i < nodeCount; i++) {
                candidateNode = (*gRomCurveInterface)->getById(*branchLinkId);
                distance = getXZDistanceSquared(&ball->followObj->anim.worldPosX, &candidateNode->x);
                if (distance < bestDistance) {
                    targetNode = candidateNode;
                    bestDistance = distance;
                }
                branchLinkId++;
            }

            RomCurve_advanceToNextSegment(&ball->route, targetNode);
        }

        speed = ball->speed;
        if ((u8)(ball->stateFlags & CANNONBALL_SPEED_DECAY_FLAG) != 0) {
            speed += CANNONBALL_ROLL_DECAY_STEP * timeDelta;
            if (speed < gTrickyFloatZero) {
                speed = gTrickyFloatZero;
            }
        } else if (speed > CANNONBALL_ROLL_SPEED_LIMIT) {
            speed += gTrickySpeedDecayStep * timeDelta;
            if (speed < CANNONBALL_ROLL_SPEED_LIMIT) {
                speed = CANNONBALL_ROLL_SPEED_LIMIT;
            }
        } else {
            speed += gTrickySmallSpeedStep * timeDelta;
            if (speed > CANNONBALL_ROLL_SPEED_LIMIT) {
                speed = CANNONBALL_ROLL_SPEED_LIMIT;
            }
        }

        ball->speed = speed;
        trickyAdvanceRouteTargetAhead(obj, &ball->route, ball->speed);
        moveTricky(obj, &ball->route.posX);

        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
            ball->stateFlags &= ~(u64)CANNONBALL_HIDE_FLAG;
        } else {
            ball->stateFlags |= CANNONBALL_HIDE_FLAG;
        }

        ball->cannonballRollSfxTimer -= timeDelta;
        if (ball->cannonballRollSfxTimer < gTrickyFloatZero) {
            ball->cannonballRollSfxTimer = (f32)(int)randomGetRange(CANNONBALL_SFX_TIMER_MIN, CANNONBALL_SFX_TIMER_MAX);
            trickyPlayVoice(obj, obj->extra, CANNONBALL_ROLL_SFX_ID, CANNONBALL_ROLL_SFX_PARAM);
        }
    } else {
        trickyUpdateMovementState(obj, CANNONBALL_INIT_WALK_RADIUS, ball);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) ==
            Objfsa_GetWalkGroupIndexAtPoint(&ball->cannonballStartCurve->x, NULL)) {
            curve = ball->cannonballStartCurve;

            fromNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomUnblockedLink(curve, 0));
            toNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBlockedLink(curve, 0));

            bestDistance = getXZDistanceSquared(&ball->playerObj->anim.worldPosX, &fromNode->x);
            distance = getXZDistanceSquared(&ball->playerObj->anim.worldPosX, &toNode->x);

            curveArg = curve;
            if (bestDistance > distance) {
                targetNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomUnblockedLink(fromNode, 0));
                ball->route.reverse = 0;
            } else {
                fromNode = toNode;
                targetNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBlockedLink(toNode, 0));
                ball->route.reverse = 1;
            }

            RomCurve_setupHermiteSegment(&ball->route, curveArg, fromNode, targetNode);
            if (ball->route.reverse != 0) {
                RomCurve_stepClamped(&ball->route, CANNONBALL_ROUTE_BACKSTEP);
            } else {
                RomCurve_stepClamped(&ball->route, CANNONBALL_ROUTE_FORESTEP);
            }

            ball->cannonballRollSfxTimer = gTrickyFloatZero;
            ball->substate = 1;
        }
    }
}

void tricky_state04_nop(void) {
}

/*
 * Tricky companion behaviour states (part of the tricky DLL, 0x00C4).
 *
 * Each function here is one entry of Tricky's per-frame substate machine,
 * dispatched off TrickyState::substate either directly or through the
 * function-pointer table walked in tricky_stateFollowPlayer. They drive Tricky along ROM
 * curve paths (rom_curve_interface), follow/feed the player, run the dig
 * and flame-breath sequences, pick random idle moves and emit the matching
 * object sounds (audio/sfx). tricky_handleFeedOrTalk handles the shared
 * feeding/Y-button-item interaction and is called as a guard at the top of
 * most states. Water-vs-land animation selection (the repeated
 * waterLevel/eventTime/currentTime ladder) chooses swim vs walk anims throughout.
 */

/* GameCube controller button mask */
#define PAD_BUTTON_A 0x100

/* child objects spawned by this TU (retail OBJECTS.bin names) */
#define TRICKY_CHILD_OBJ_FOOD 0x17b /* "TrickyFood" */

/*
 * A ROM/FSA walk-curve node as Tricky's tunnel/follow states see it (via the
 * rom_curve_interface getById() / Objfsa_*Curve* lookups). Byte-compatible with
 * the shared RomCurveDef, but with the walk-group id at +3 that those states
 * key off (which RomCurveDef leaves in its pad).
 */
void tricky_handlePlayerContact(GameObject* obj, TrickyState* state);
const TrickyItemIdList gTrickyCmdQueryInit = {{TRICKY_COMMAND_TYPE_CALL, TRICKY_COMMAND_TYPE_FIND_SECRET,
                                               TRICKY_COMMAND_TYPE_STAY, TRICKY_COMMAND_TYPE_FLAME,
                                               TRICKY_COMMAND_TYPE_THROW_BALL}};
const TrickyItemIdList gTrickyFoodItemIds = {{TRICKY_COMMAND_TYPE_CALL, TRICKY_COMMAND_TYPE_FIND_SECRET,
                                              TRICKY_COMMAND_TYPE_STAY, TRICKY_COMMAND_TYPE_FLAME,
                                              TRICKY_COMMAND_TYPE_THROW_BALL}};

static inline void trickyPlayWhineSfx(u32 id, GameObject* obj) {
    TrickyState* sfxState = obj->extra;
    if (sfxState->soundSuppressed == 0 &&
        (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
        Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
        objSoundStartTimed(obj, &sfxState->soundState, id, 0x500, -1, 0);
    }
}

static inline void trickyAdvanceNode(TrickyState* state) {
    int idx;
    u8* linkNode;
    int linkId;
    int off;
    int k;
    idx = 0;
    off = 0;
    for (k = 4; k != 0; k--) {
        linkNode = state->digTunnelExitNode.ptr;
        linkId = TRICKY_CURVE_LINK_ID_FROM_NODE_OFFSET(linkNode, off);
        if (linkId > -1 && linkId != ((RomCurveDef*)state->digTunnelStartNode.ptr)->id) {
            state->digTunnelStartNode.ptr = linkNode;
            state->digTunnelExitNode.ptr =
                (u8*)(*gRomCurveInterface)
                    ->getById(TRICKY_CURVE_LINK_ID_FROM_NODE_INDEX(state->digTunnelExitNode.ptr, idx));
            break;
        }
        off += 4;
        idx++;
    }
}

char sTrickyDigTunnelDebugTextBlock[] = "DIGTUNNEL_FINDING\n"
                                        "\0\0"
                                        "DIGTUNNEL_GOINGTOSTART\n"
                                        "\0"
                                        "DIGTUNNEL_DIGGING\n"
                                        "\0\0"
                                        "DIGTUNNEL_TOEND1 %f\n"
                                        "\0\0\0\0"
                                        "DIGTUNNEL_TOEND2\n"
                                        "\0\0\0"
                                        "DIGTUNNEL_WAIT\n";

void trickyDigTunnel(GameObject* obj, TrickyState* state) {
    u32 sfxTable;
    u8* base;
    RomCurveDef* pc;
    u8* pos;
    u8* ptr;
    int gidx;
    int inWater;
    u16 id;
    f32 vz, vx, spd, z, vxx;

    base = (u8*)gTrickyDebugStringTable;
    sfxTable = *(u32*)gTrickySubstateSfxIdPairB;
    switch (state->substate) {
    case 0:
        pc = Objfsa_FindNearestCurveType24(state->targetPosPtr, -1, 2);
        state->digTunnelEntryNode.ptr = (u8*)(*gRomCurveInterface)->getById(pc->linkIds[0]);
        state->digTunnelStartNode.ptr = pc;
        state->digTunnelExitNode.ptr = (u8*)(*gRomCurveInterface)->getById(pc->linkIds[1]);
        if (((RomCurveDef*)state->digTunnelExitNode.ptr)->walkGroup != 0) {
            state->digTunnelExitNode.u = state->digTunnelExitNode.u ^ state->digTunnelEntryNode.u;
            state->digTunnelEntryNode.u = state->digTunnelEntryNode.u ^ state->digTunnelExitNode.u;
            state->digTunnelExitNode.u = state->digTunnelExitNode.u ^ state->digTunnelEntryNode.u;
        }
        ptr = (u8*)&((RomCurveDef*)state->digTunnelEntryNode.ptr)->x;
        if (state->targetPosPtr != (f32*)ptr) {
            state->targetPosPtr = (f32*)ptr;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->substate = 1;
    case 1:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_FINDING));
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        gidx = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
        if (((RomCurveDef*)state->digTunnelEntryNode.ptr)->walkGroup == gidx) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
            state->substate = 2;
        }
        break;
    case 2:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_GOINGTOSTART));
        pos = (u8*)&((RomCurveDef*)state->digTunnelStartNode.ptr)->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, (f32*)pos, 1);
        if (moveTricky(obj, (f32*)pos) == 0) {
            state->stateFlags |= TRICKY_STATE_DIG_TUNNEL_FLAGS;
            state->substate = 3;
        } else {
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
                state->stateFlags |= TRICKY_STATE_DIG_TUNNEL_FLAGS;
            }
        }
        break;
    case 3:
        trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_ARC_RETURN, TRICKY_DIG_TUNNEL_BLEND_SPEED,
                          TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        state->dirX =
            ((RomCurveDef*)state->digTunnelExitNode.ptr)->x - ((RomCurveDef*)state->digTunnelStartNode.ptr)->x;
        state->dirZ =
            ((RomCurveDef*)state->digTunnelExitNode.ptr)->z - ((RomCurveDef*)state->digTunnelStartNode.ptr)->z;
        Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
        state->digTunnelWhineTimer.f = (f32)(int)randomGetRange(0x14, 0xb4);
        state->substate = 4;
    case 4:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_DIGGING));
        state->digTunnelWhineTimer.f -= timeDelta;
        if (state->digTunnelWhineTimer.f <= gTrickyFloatZero) {
            state->digTunnelWhineTimer.f = (f32)(int)randomGetRange(0x14, 0xb4);
            state->digTunnelWhineTimer.f *= TRICKY_FLOAT_100;
            ptr = obj->extra;
            if (((TrickyState*)ptr)->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &((TrickyState*)ptr)->soundState, TRICKY_VOICE_SFX_DUM_DE_DUM, 0x500, -1, 0);
            }
        }
        spd = GROUND_ANIMATOR_INTERFACE(state->followObj)->applyPress(state->followObj, obj);
        obj->anim.localPosX = state->dirX * spd + ((RomCurveDef*)state->digTunnelStartNode.ptr)->x;
        obj->anim.localPosZ = state->dirZ * spd + ((RomCurveDef*)state->digTunnelStartNode.ptr)->z;
        vx = ((TrickyState*)obj->extra)->dirX;
        vxx = vx * vx;
        vz = ((TrickyState*)obj->extra)->dirZ;
        spd = vz * vz;
        if (vxx + spd > 0.01f) {
            trickyTurnTowardYaw(obj, getAngle(-vx, -vz));
        }
        if (GROUND_ANIMATOR_INTERFACE(state->followObj)->isFullySunk(state->followObj) != 0) {
            {
                int off;
                int linkId;
                u8* linkNode;
                int idx;
                int k;

                idx = 0;
                off = 0;
                for (k = 4; k != 0; k--) {
                    linkNode = state->digTunnelExitNode.ptr;
                    linkId = TRICKY_CURVE_LINK_ID_FROM_NODE_OFFSET(linkNode, off);
                    if (linkId > -1 && linkId != ((RomCurveDef*)state->digTunnelStartNode.ptr)->id) {
                        state->digTunnelStartNode.ptr = linkNode;
                        state->digTunnelExitNode.ptr =
                            (u8*)(*gRomCurveInterface)
                                ->getById(TRICKY_CURVE_LINK_ID_FROM_NODE_INDEX(state->digTunnelExitNode.ptr, idx));
                        break;
                    }
                    off += 4;
                    idx++;
                }
            }
            state->stats->energy -= 4;
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            state->substate = 5;
            id = *(u16*)((char*)&sfxTable + randomGetRange(0, 1) * 2);
            ptr = obj->extra;
            if (((TrickyState*)ptr)->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &((TrickyState*)ptr)->soundState, id, 0x500, -1, 0);
            }
        }
        break;
    case 5:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_TOEND1),
                         Vec_xzDistance(&obj->anim.worldPosX, &((RomCurveDef*)state->digTunnelExitNode.ptr)->x));
        pos = (u8*)&((RomCurveDef*)state->digTunnelExitNode.ptr)->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, (f32*)pos, 1);
        if (moveTricky(obj, (f32*)pos) == 0) {
            trickyAdvanceNode(state);
            state->substate = 6;
        }
        break;
    case 6:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_TOEND2));
        pos = (u8*)&((RomCurveDef*)state->digTunnelExitNode.ptr)->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, (f32*)pos, 1);
        if (moveTricky(obj, (f32*)pos) == 0) {
            inWater = skeetla_isInWater(state);
            if (inWater != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
                trickyDebugPrint((char*)(base + TRICKY_DBG_IN_WATER));
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint((char*)(base + TRICKY_DBG_OUT_OF_WATER));
            }
            state->stateFlags &= ~TRICKY_STATE_DIG_TUNNEL_FLAGS;
            state->substate = 7;
        }
        break;
    case 7:
        trickyDebugPrint((char*)(base + TRICKY_DBG_DIGTUNNEL_WAIT));
        gidx = Objfsa_GetWalkGroupIndexAtPoint(&state->playerObj->anim.worldPosX, NULL);
        {
            int currentGroup;

            currentGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
            if (currentGroup == gidx) {
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = 0;
                z = gTrickyFloatZero;
                state->cooldownA = z;
                state->cooldownB.f = z;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
                {
                    s8 mm;
                    mm = -1;
                    state->commandPhase = mm;
                }
            }
        }
        break;
    }
}

void tricky_stateFindSecretDig(GameObject* obj, TrickyState* state) {
    u32 sfxTable;
    u8* ptr;
    GameObject* pc;
    int ret;
    f32 spd;
    f32 dist;
    f32 z;

    sfxTable = *(u32*)gTrickySubstateSfxIdPairA;
    pc = state->followObj;
    switch (state->substate) {
    case 0:
        state->secretDigCurve = Objfsa_FindNearestEnabledCurveType24(&state->followObj->anim.worldPosX, -1, 2);
        if (state->secretDigCurve != NULL &&
            getXZDistanceSquared(&state->followObj->anim.worldPosX, &state->secretDigCurve->x) >
                TRICKY_SECRET_DIG_SCAN_DISTANCE_SQ) {
            state->secretDigCurve = NULL;
        }
        state->substate = 1;
    case 1:
        ret = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        if (ret == 0) {
            if (state->secretDigCurve != NULL) {
                state->substate = 2;
                ptr = (u8*)&state->secretDigCurve->x;
                if (state->targetPosPtr != (f32*)ptr) {
                    state->targetPosPtr = (f32*)ptr;
                    {
                        u32 mask;
                        u32 flags = state->stateFlags;
                        mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                        state->stateFlags = flags & mask;
                    }
                    state->linkedWalkGroup = 0;
                }
            } else {
                state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->substate = 3;
                state->secretDigPressTimer = gTrickyFloatZero;
                state->secretDigWhineTimer = (f32)(int)randomGetRange(0x28, 0x50);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
                trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_ARC_RETURN, TRICKY_DIG_TUNNEL_BLEND_SPEED,
                                  TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            }
        } else if (ret == 2) {
            state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            state->substate = 0;
            z = gTrickyFloatZero;
            state->cooldownA = z;
            state->cooldownB.f = z;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 mm;
                mm = -1;
                state->commandPhase = mm;
            }
        }
        break;
    case 2:
        if (trickyUpdateMovementState(obj, gTrickyMaxDistance, state) == 0) {
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = 3;
            state->secretDigPressTimer = gTrickyFloatZero;
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
            trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_ARC_RETURN, TRICKY_DIG_TUNNEL_BLEND_SPEED,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        }
        break;
    case 3:
        state->secretDigPressTimer += timeDelta;
        state->secretDigWhineTimer -= timeDelta;
        if (state->secretDigPressTimer >= TRICKY_FETCH_THROW_DELAY_FRAMES) {
            state->substate = 4;
            state->secretDigOriginX = obj->anim.worldPosX;
            state->secretDigOriginZ = obj->anim.worldPosZ;
            ptr = (u8*)state->secretDigCurve;
            if (ptr != NULL) {
                pc = state->followObj;
                state->dirX = ((RomCurveDef*)ptr)->x - pc->anim.worldPosX;
                state->dirZ = ((RomCurveDef*)ptr)->z - pc->anim.worldPosZ;
                dist = sqrtf(state->dirX * state->dirX + state->dirZ * state->dirZ);
                if (gTrickyFloatZero != dist) {
                    state->dirX = state->dirX / dist;
                    state->dirZ = state->dirZ / dist;
                }
            }
        }
        break;
    case 4:
        state->secretDigWhineTimer -= timeDelta;
        if (state->secretDigWhineTimer <= gTrickyFloatZero) {
            state->secretDigWhineTimer = (f32)(int)randomGetRange(0x28, 0x50);
            state->secretDigWhineTimer *= TRICKY_FLOAT_100;
            trickyPlayWhineSfx(TRICKY_VOICE_SFX_DUM_DE_DUM, obj);
        }
        spd = GROUND_ANIMATOR_INTERFACE(pc)->applyPress((GameObject*)pc, obj);
        obj->anim.localPosX = state->secretDigOriginX - state->dirX * spd;
        obj->anim.localPosZ = state->secretDigOriginZ - state->dirZ * spd;
        if (GROUND_ANIMATOR_INTERFACE(pc)->isFullySunk((GameObject*)pc) != 0) {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            state->stats->energy -= 4;
            state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            state->substate = 0;
            z = gTrickyFloatZero;
            state->cooldownA = z;
            state->cooldownB.f = z;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 mm;
                mm = -1;
                state->commandPhase = mm;
            }
            trickyPlayWhineSfx(*(u16*)((char*)&sfxTable + randomGetRange(0, 1) * 2), obj);
        }
        break;
    }
}

typedef struct TrickyFnRow {
    u8 pad[0x6c];
    int (*fn)(u8*, u8*);
} TrickyFnRow;

void tricky_stateFollowPlayer(GameObject* obj, TrickyState* state) {
    u8* base;
    GameObject* found;
    TrickyState* other;
    GameObject* target;
    TrickyState* sfxState;
    int inWater;
    f32 z;

    base = (u8*)gTrickyDebugStringTable;
    found = NULL;
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if (state->pendingFollowRequest != 0) {
            switch ((int)state->pendingFollowRequest) {
            case 1: {
                target = state->pendingFollowObj;
                other = obj->extra;
                if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    if ((other->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                        other->followObj = target;
                        if (other->targetPosPtr != &target->anim.worldPosX) {
                            other->targetPosPtr = &target->anim.worldPosX;
                            {
                                u32 mask;
                                u32 flags = other->stateFlags;
                                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                                other->stateFlags = flags & mask;
                            }
                            other->linkedWalkGroup = 0;
                        }
                        other->substate = 0;
                        other->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                    } else {
                        other->pendingFollowRequest = 1;
                        other->pendingFollowObj = target;
                        other->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
                    }
                }
                if (tricky_handleFeedOrTalk(obj, state) == 0 &&
                    trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) == 0) {
                    state->idleSfxTimer -= timeDelta;
                    if (state->idleSfxTimer <= gTrickyFloatZero) {
                        state->idleSfxTimer =
                            (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
                        sfxState = obj->extra;
                        if (sfxState->soundSuppressed == 0 &&
                            (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                             obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                            Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_DUM_DE_DUM, 0x500, -1, 0);
                        }
                    }
                    inWater = skeetla_isInWater(state);
                    if (inWater != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        state->particleTimer = gTrickyFloatZero;
                        trickyDebugPrint((char*)(base + TRICKY_DBG_IN_WATER));
                    } else {
                        switch (obj->anim.currentMove) {
                        case TRICKY_ANIM_IDLE_FOOD_WAIT:
                            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
                                trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_CHEW, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                            }
                            break;
                        default:
                            trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_WAIT, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        case TRICKY_ANIM_IDLE_FOOD_CHEW:
                            break;
                        }
                        trickyDebugPrint((char*)(base + TRICKY_DBG_OUT_OF_WATER));
                    }
                }
            } break;
            default:
                break;
            }
            state->pendingFollowRequest = 0;
            return;
        }
        found = Tricky_findNearestGroup4BObject(obj, state);
    }
    if (found != NULL) {
        state->groundSnapCounter = 2;
        (*gPathControlInterface)->attachObject(obj, &state->pathControlFlags);
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        z = gTrickyFloatZero;
        state->cooldownA = z;
        state->cooldownB.f = z;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
        {
            s8 mm;
            mm = -1;
            state->commandPhase = mm;
        }
        obj->anim.localPosX = found->anim.localPosX;
        obj->anim.localPosY = found->anim.localPosY;
        obj->anim.localPosZ = found->anim.localPosZ;
        obj->anim.worldPosX = found->anim.worldPosX;
        obj->anim.worldPosY = found->anim.worldPosY;
        obj->anim.worldPosZ = found->anim.worldPosZ;
        ObjHits_SyncObjectPosition(obj);
        obj->anim.rotX = found->anim.rotX;
        state->movementState = TRICKY_MOVE_WALK_WAIT;
        z = gTrickyFloatZero;
        state->prevSpeed = z;
        state->speed = z;
        state->homePosX = found->anim.worldPosX;
        state->homePosY = found->anim.worldPosY;
        state->homePosZ = found->anim.worldPosZ;
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_POSITION_RELOCATED;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GROUND_SNAP;
    } else {
        state->cooldownA -= timeDelta;
        if (state->cooldownA < 0.0f) {
            state->cooldownA = 0.0f;
        }
        tricky_handlePlayerContact(obj, state);
        {
            if (((TrickySubstateHandler*)(base + TRICKY_SUBSTATE_HANDLER_TABLE_OFFSET))[state->substate](obj, state) ==
                0) {
                inWater = skeetla_isInWater(state);
                if (inWater != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_WANDER, TRICKY_IDLE_WANDER_BLEND_SPEED, 0);
                }
            }
        }
    }
}

int tricky_substateApproachThorntail(GameObject* obj, TrickyState* state) {
    TrickyState* tex;
    short move;
    u16 sfxId;
    float pos[3];

    objGetJointWorldPosition(state->followObj, 0, pos);
    if (getXZDistanceSquared(pos, &state->wanderTargetX) > TRICKY_FLOAT_100) {
        state->wanderTargetX = pos[0];
        state->wanderTargetY = pos[1];
        state->wanderTargetZ = pos[2];
    }
    if (state->thorntailIdleMovePending != 0) {
        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) != 0) {
            return 0;
        }
        tricky_startRandomIdleMove((GameObject*)(obj), state);
    } else if ((u8)trickyUpdateMovementState(obj, TRICKY_TIMER_30_FRAMES, state) != 1) {
        state->thorntailIdleMovePending = 1;
        sfxId = randomGetRange(862, 863);
        tex = obj->extra;
        if (tex->soundSuppressed == 0) {
            move = obj->anim.currentMove;
            if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &tex->soundState, sfxId, 1280, -1, 0);
                }
            }
        }
        return 0;
    }
    return 1;
}

int tricky_substateFlameBreath(GameObject* obj, TrickyState* state) {
    int spawnIndex;
    int cleanupIndex;
    TrickyState* sfxState;
    u8* spawnChildCursor;
    u8* cleanupChildCursor;
    FlameblastPlacement* setup;

    switch (obj->anim.currentMove) {
    case TRICKY_ANIM_FLAME_BREATH:
        if (obj->anim.currentMoveProgress > TRICKY_FOLLOW_ARC_QUARTER_PROGRESS &&
            (state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
            if ((u8)Obj_CanSetupObject() != 0) {
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (spawnIndex = 0, spawnChildCursor = (u8*)state; spawnIndex < 7;
                     spawnChildCursor += 4, spawnIndex++) {
                    setup = (FlameblastPlacement*)Obj_AllocObjectSetup(0x24, TRICKY_CHILD_OBJ_FLAMEBLAST);
                    setup->base.color[0] = 2;
                    setup->base.color[1] = 1;
                    setup->streamIndex = spawnIndex;
                    TRICKY_FLAME_CHILD_AT_CURSOR(spawnChildCursor) =
                        objSetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
            }
        } else {
            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                for (cleanupIndex = 0, cleanupChildCursor = (u8*)state; cleanupIndex < 7;
                     cleanupChildCursor += 4, cleanupIndex++) {
                    objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(cleanupChildCursor));
                }
                Sfx_RemoveLoopedObjectSound((GameObject*)obj, SFXTRIG_trpopn_c);
                sfxState = obj->extra;
                if (sfxState->soundSuppressed == 0 &&
                    (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                    Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                }
                state->substate = 10;
            }
        }
        break;
    default:
        trickyRequestMove(obj, TRICKY_ANIM_FLAME_BREATH, TRICKY_FLOAT_0_004, 0);
    }
    return 1;
}

int tricky_substateBegForFood(GameObject* obj, TrickyState* state) {
    TrickyState* tex;
    int result;
    short move;
    TrickyItemIdList buf;

    buf = gTrickyFoodItemIds;
    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        state->cooldownB.f = gTrickyFloatZero;
        {
            u32 mask;
            u32 flags = state->stateFlags;
            mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags = flags & mask;
        }
        state->substate = 0;
        return 1;
    }
    result = (*gGameUIInterface)->isOneOfItemsBeingUsed(buf.ids, TRICKY_ITEM_ID_COUNT);
    switch (result) {
    case 0:
    case 1:
    case 3:
    case 4:
    case 5:
        tex = obj->extra;
        if (tex->soundSuppressed == 0u) {
            move = (obj)->anim.currentMove;
            if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &tex->soundState, 861, 1280, -1, 0);
                }
            }
        }
        break;
    }
    if (gTrickyFloatZero == state->cooldownB.f) {
        {
            u32 mask;
            u32 flags = state->stateFlags;
            mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags = flags & mask;
        }
        state->substate = 0;
    }
    if ((u8)trickyUpdateMovementState(obj, TRICKY_TIMER_20_FRAMES, state) == 1) {
        return 1;
    }
    return 0;
}

int tricky_substateDigForFood(GameObject* obj, TrickyState* state) {
    short move;
    int b;
    PartFxSpawnParams spawnBuf;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        return 1;
    }
    (obj)->anim.resetHitboxFlags = (obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = (obj)->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_DIG_FOOD_START_A:
    case TRICKY_ANIM_DIG_FOOD_START_B:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_DIG_FOOD_LOOP, TRICKY_FOLLOW_JUMPDOWN_BLEND_SPEED, 0);
        }
        break;
    case TRICKY_ANIM_DIG_FOOD_LOOP: {
        if (((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) &&
            (((state->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0 || randomGetRange(0, 2) == 0) ||
             state->cooldownB.f > gTrickyFloatZero)) {
            trickyRequestMove(obj, TRICKY_ANIM_DIG_FOOD_END, 0.01f, 0);
        }
        spawnBuf.posX = (obj)->anim.worldPosX;
        spawnBuf.posY = (obj)->anim.worldPosY;
        spawnBuf.posZ = (obj)->anim.worldPosZ;
        spawnBuf.scale = 0.7f;
        (*gPartfxInterface)->spawnObject((void*)obj, 2022, &spawnBuf, 0x200001, -1, NULL);
        break;
    }
    case TRICKY_ANIM_DIG_FOOD_END:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            b = skeetla_isInWater(state);
            if (b != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(sInWaterMessage);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags = flags & mask;
            }
            state->substate = 0;
        }
        break;
    }
    return 1;
}

int tricky_substateIdlePick(GameObject* obj, TrickyState* state) {
    TrickyState* sfxState;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        return 1;
    }
    if ((u8)trickyUpdateMovementState(obj, gTrickyMaxDistance, state) != 1) {
        if (state->childB != NULL) {
            sfxState = obj->extra;
            if (sfxState->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_SNIFF, 0, -1, 0);
            }
            trickyRequestMove(obj, TRICKY_ANIM_IDLE_PICK, TRICKY_IDLE_PICK_BLEND_SPEED, 0);
            state->substate = 5;
        } else {
            switch (randomGetRange(0, 6)) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
                tricky_startRandomIdleMove(obj, state);
                break;
            default:
                tricky_pickAmbientActivity(obj, state);
                break;
            }
        }
    }
    return 1;
}

u32 tricky_substateFidgetA(GameObject* obj, TrickyState* trickyState) {
    short move;
    int foodResult;

    foodResult = tricky_handleFeedOrTalk(obj, trickyState);
    if (foodResult != 0) {
        return 1;
    }
    move = (obj)->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_IDLE_FIDGET_A_START:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_A_END, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        }
        break;
    case TRICKY_ANIM_IDLE_FIDGET_A_END:
        if (((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) && ((int)randomGetRange(0, 3) == 0)) {
            trickyState->substate = 0;
        }
        break;
    }
    return 1;
}

u32 tricky_substateFidgetB(GameObject* obj, TrickyState* trickyState) {
    short move;
    int foodResult;

    foodResult = tricky_handleFeedOrTalk(obj, trickyState);
    if (foodResult != 0) {
        return 1;
    }
    move = (obj)->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_IDLE_FIDGET_B_START:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_B_END, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        }
        break;
    case TRICKY_ANIM_IDLE_FIDGET_B_END:
        if (((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) && ((int)randomGetRange(0, 3) == 0)) {
            trickyState->substate = 0;
        }
        break;
    }
    return 1;
}

u32 tricky_substateWaitMoveEnd(GameObject* obj, TrickyState* trickyState) {
    TrickyState* ref;
    int val;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    for (val = 0; val < trickyState->animEvents.triggerCount; val++) {
        if (trickyState->animEvents.triggeredIds[val] != 0) {
            continue;
        }
        ref = obj->extra;
        if (ref->soundSuppressed != 0U) {
            continue;
        }
        if ((int)(obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
            (int)(obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN) {
            if (((int (*)(GameObject*, int))Sfx_IsPlayingFromObjectChannel)(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &ref->soundState, TRICKY_VOICE_SFX_SNIFF, 0, 0xffffffff, 0);
            }
        }
    }
    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
        if (trickyState->moveId == (int)(obj)->anim.currentMove) {
            trickyState->substate = 0;
        }
    }
    return 1;
}

int tricky_substateHowlCall(GameObject* obj, TrickyState* trickyState) {
    char bval;
    short move;
    float fval;
    int b[1];
    int val;
    PartFxSpawnParams fxBuf;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    (obj)->anim.resetHitboxFlags = (obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = (obj)->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_HOWL_START:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_HOWL_HOLD, TRICKY_HOWL_CALL_BLEND_SPEED, 0);
        }
        break;
    case TRICKY_ANIM_HOWL_HOLD:
        trickyState->moveHoldTimer = trickyState->moveHoldTimer - timeDelta;
        if (trickyState->moveHoldTimer <= gTrickyFloatZero) {
            if (((trickyState->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) ||
                (trickyState->cooldownB.f > gTrickyFloatZero)) {
                trickyRequestMove(obj, TRICKY_ANIM_HOWL_END, 0.01f, 0);
            } else {
                val = (*gSkyInterface)->getSunPosition(0);
                if (val == 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_HOWL_IDLE_PICK, TRICKY_IDLE_PICK_BLEND_SPEED, 0);
                    trickyState->substate = 9;
                }
            }
        }
        for (val = 0; val < trickyState->animEvents.triggerCount; val++) {
            bval = trickyState->animEvents.triggeredIds[val];
            if (bval == '\0') {
                objSoundStartTimed(obj, &trickyState->soundState, 0x390, 0x500, -1, 0);
            } else if (bval == '\a') {
                objSoundStartTimed(obj, &trickyState->soundState, 0x391, 0x100, -1, 0);
            }
        }
        fval = trickyState->sparkleFxTimer - timeDelta;
        trickyState->sparkleFxTimer = fval;
        if (fval <= gTrickyFloatZero) {
            if (((obj)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                fxBuf.posX = trickyState->renderPosX;
                fxBuf.posY = 2.0f + trickyState->renderPosY;
                fxBuf.posZ = trickyState->renderPosZ;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7f0, &fxBuf, 0x200001, -1, NULL);
            }
            trickyState->sparkleFxTimer = TRICKY_TIMER_30_FRAMES;
        }
        break;
    case TRICKY_ANIM_HOWL_END:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            b[0] = skeetla_isInWater(trickyState);
            if (b[0] != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                trickyState->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                trickyState->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(sInWaterMessage);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                trickyState->stateFlags = flags & mask;
            }
            trickyState->substate = 0;
        }
        break;
    }
    return 1;
}

int tricky_substateSleep(GameObject* obj, TrickyState* state) {
    s8 slots[4];
    TrickyState* sfxState;
    u8* e;
    int idx;
    f32 z;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        state->substate = 0;
        return 1;
    }
    if (cMenuGetSelectedItem() == GAMEBIT_ITEM_TrickyFood_Count) {
        state->substate = 0;
        return 1;
    }
    state->sfxRepeatTimer -= timeDelta;
    if (state->sfxRepeatTimer < gTrickyFloatZero) {
        sfxState = (obj)->extra;
        if (sfxState->soundSuppressed == 0 &&
            ((obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END || (obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
            Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
            objSoundStartTimed(obj, &sfxState->soundState, 0x29a, 0x100, -1, 0);
        }
        state->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
    }
    if (state->child == NULL && (u8)Obj_CanSetupObject() != 0) {
        e = (u8*)Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_FOOD);
        slots[0] = -1;
        slots[1] = -1;
        slots[2] = -1;
        if (state->childA != NULL) {
            slots[state->packedSlots.promptASlot] = 1;
        }
        if (state->childB != NULL) {
            slots[state->packedSlots.promptBSlot] = 1;
        }
        if (state->child != NULL) {
            slots[state->packedSlots.zzzSlot] = 1;
        }
        if (slots[0] == -1) {
            idx = 0;
        } else if (slots[1] == -1) {
            idx = 1;
        } else if (slots[2] == -1) {
            idx = 2;
        } else if (slots[3] == -1) {
            idx = 3;
        } else {
            idx = -1;
        }
        state->packedSlots.zzzSlot = idx;
        state->child = objSetupObject((ObjPlacement*)e, 4, -1, -1, (obj)->anim.parent);
        ObjLink_AttachChild(obj, state->child, state->packedSlots.zzzSlot);
        z = gTrickyFloatZero;
        state->childPhaseTimer0 = z;
        state->childPhaseTimer1 = z;
        state->childPhaseTimer2 = z;
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0 && state->cooldownA <= gTrickyFloatZero &&
        mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0) {
        trickyRequestMove(obj, TRICKY_ANIM_HOWL_START, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        sfxState = (obj)->extra;
        if (sfxState->soundSuppressed == 0 &&
            ((obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END || (obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
            Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
            objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_YAWN, 0x1000, -1, 0);
        }
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = 4;
        state->moveHoldTimer = (f32)(int)randomGetRange(0x78, 0xf0);
    }
    return 1;
}

u32 tricky_substateWaitQueuedMove(GameObject* obj, TrickyState* trickyState) {
    int val;

    val = tricky_handleFeedOrTalk(obj, trickyState);
    if (val != 0) {
        return 1;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
        if (trickyState->moveId == (int)(obj)->anim.currentMove) {
            trickyState->substate = 0;
        }
    }
    return 1;
}

u32 tricky_substateReturnToHeel(GameObject* obj, TrickyState* trickyState) {
    int val;

    val = tricky_handleFeedOrTalk(obj, trickyState);
    if (val != 0) {
        return 1;
    }
    val = trickyUpdateMovementState(obj, TRICKY_TIMER_20_FRAMES, (TrickyState*)trickyState);
    if (val == 1) {
        if (gTrickyFloatZero == trickyState->cooldownA) {
            trickyState->substate = 0;
        }
        return 1;
    }
    trickyState->substate = 0;
    return 0;
}

int tricky_substateFollowIdle(GameObject* obj, TrickyState* state) {
    TrickyState* voiceState;
    short currentMove;
    u8 movementResult;
    f32* followBase;
    int inWater;
    float stoppingRadius;

    state->followObj = state->playerObj;
    followBase = &state->followObj->anim.worldPosX;
    if (state->targetPosPtr != followBase) {
        state->targetPosPtr = followBase;
        {
            u32 mask;
            u32 flags = state->stateFlags;
            mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
            state->stateFlags = flags & mask;
        }
        state->linkedWalkGroup = 0;
    }
    if (gTrickyFloatZero == state->cooldownA) {
        {
            s8 mm;
            mm = -1;
            state->commandPhase = mm;
        }
        stoppingRadius = TRICKY_TIMER_30_FRAMES;
    } else {
        if ((state->stateFlags & TRICKY_STATE_FLAG_HEEL_REQUEST) != 0) {
            state->commandPhase = TRICKY_COMMAND_PHASE_NONE;
            state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
        }
        stoppingRadius = TRICKY_TIMER_20_FRAMES;
    }
    movementResult = trickyUpdateMovementState(obj, stoppingRadius, state);
    if (movementResult != 1) {
        if (movementResult == 2) {
            if ((state->stateFlags & TRICKY_STATE_FLAG_STUCK_VOICE_PENDING) != 0) {
                voiceState = obj->extra;
                if (voiceState->soundSuppressed == 0u) {
                    currentMove = (obj)->anim.currentMove;
                    if (currentMove >= TRICKY_VOICE_MOVE_END || currentMove < TRICKY_VOICE_MOVE_MIN) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &voiceState->soundState, 861, 1280, -1, 0);
                        }
                    }
                }
            }
        }
        inWater = skeetla_isInWater(state);
        if (inWater != 0) {
            return 0;
        }
        return tricky_updateIdleBehavior(obj, state);
    }
    state->idleActivityPending = 1;
    return 1;
}

u32 tricky_updateIdleBehavior(GameObject* obj, TrickyState* trickyState) {
    int handled;
    TrickyState* voiceState;
    u32 randomDelay;

    handled = tricky_handleFeedOrTalk((GameObject*)(obj), trickyState);
    if (handled != 0) {
        return 1;
    }
    if (trickyState->cooldownC > gTrickyFloatZero) {
        trickyRequestMove(obj, TRICKY_ANIM_WATER_IDLE, 0.01f, 0);
        trickyState->substate = 2;
        trickyState->cooldownC = gTrickyFloatZero;
        return 1;
    }
    if (trickyState->idleActivityPending != 0U) {
        trickyState->idleTimer = TRICKY_AMBIENT_ACTIVITY_BASE;
        trickyState->idleActivityPending = 0;
        trickyState->idleActivityDelayActive = 1;
    }
    if (trickyState->idleActivityDelayActive != 0U) {
        trickyState->idleTimer -= timeDelta;
        if (trickyState->idleTimer <= gTrickyFloatZero) {
            trickyState->cooldownA = TRICKY_FLOAT_300;
            randomDelay = randomGetRange(200, 500);
            trickyState->idleTimer = (f32)(s32)randomDelay;
            trickyState->idleActivityDelayActive = 0;
            trickyState->substate = 1;
        }
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)) {
        return 1;
    }
    handled = (*gSkyInterface)->getSunPosition(0);
    if (handled == 0) {
        trickyState->stateFlags = trickyState->stateFlags & ~TRICKY_STATE_FLAG_SUN_VOICE_PLAYED;
    }
    handled = (*gSkyInterface)->getSunPosition(0);
    if ((handled != 0) && ((trickyState->stateFlags & TRICKY_STATE_FLAG_SUN_VOICE_PLAYED_U32) == 0)) {
        trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_SUN_VOICE_PLAYED;
        handled = (int)obj->extra;
        if ((((TrickyState*)handled)->soundSuppressed == 0U) &&
            ((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
             !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL))) {
            objSoundStartTimed(obj, &((TrickyState*)handled)->soundState, TRICKY_VOICE_SFX_YAWN2, 0x500, 0xffffffff, 0);
        }
        return 0;
    }
    if (trickyState->stats->energy <= 3) {
        trickyRequestMove(obj, TRICKY_ANIM_HUNGRY_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 3;
        trickyState->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
        return 1;
    }
    trickyState->idleTimer -= timeDelta;
    if (trickyState->idleTimer <= gTrickyFloatZero) {
        randomDelay = randomGetRange(200, 500);
        trickyState->idleTimer = (f32)(s32)randomDelay;
        if (trickyState->stats->energy <= 7) {
            trickyRequestMove(obj, TRICKY_ANIM_HUNGRY_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
            trickyState->substate = 3;
            trickyState->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
            return 1;
        }
        if (trickyState->cooldownA > gTrickyFloatZero) {
            tricky_startRandomIdleMove((GameObject*)(obj), trickyState);
        } else {
            if (trickyState->childB != NULL) {
                voiceState = obj->extra;
                if (((voiceState->soundSuppressed == 0U) &&
                     (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                      (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
                     !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL))) {
                    objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_SNIFF, 0, 0xffffffff, 0);
                }
                trickyRequestMove(obj, TRICKY_ANIM_IDLE_PICK, TRICKY_IDLE_PICK_BLEND_SPEED, 0);
                trickyState->substate = 5;
            } else {
                randomDelay = randomGetRange(0, 6);
                switch ((int)randomDelay) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 4:
                    tricky_startRandomIdleMove(obj, trickyState);
                    break;
                default:
                    tricky_pickAmbientActivity(obj, (TrickyState*)trickyState);
                    break;
                }
            }
        }
        return 1;
    }
    return 0;
}

void tricky_pickAmbientActivity(GameObject* obj, TrickyState* state) {
    f32 searchRadius[2];
    TrickyState* sfxState;
    u8 minActivity;
    u8 maxActivity;
    GameObject* found;
    int wanderYaw;
    f32 wanderAngle;

    minActivity = 1;
    maxActivity = 3;
    searchRadius[0] = TRICKY_AMBIENT_ACTIVITY_BASE;
    found = objGetNearestTypeTo(SHTHORNTAIL_OBJECT_GROUP, obj, searchRadius);
    if (found != NULL && ((found)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        minActivity = 0;
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0 || mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0) {
        maxActivity = 2;
    }
    switch (randomGetRange(minActivity, maxActivity)) {
    case 0:
        state->followObj = found;
        objGetJointWorldPosition(found, 0, &state->wanderTargetX);
        if ((u8*)state->targetPosPtr != (u8*)&state->wanderTargetX) {
            state->targetPosPtr = &state->wanderTargetX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->thorntailIdleMovePending = 0;
        state->substate = 0xc;
        break;
    case 1:
        wanderYaw = randomGetRange(0x20, 0xff);
        wanderYaw = (s16)((obj->anim.rotX + wanderYaw) * 0x100);
        wanderAngle = TRICKY_PI * (f32)wanderYaw / TRICKY_ANGLE_HALF_TURN_UNITS;
        state->wanderTargetX = (f32)(TRICKY_AMBIENT_WANDER_SCALE * -mathSinf(wanderAngle) + obj->anim.localPosX);
        state->wanderTargetY = obj->anim.localPosY;
        state->wanderTargetZ = (f32)(TRICKY_POSITION_OFFSET_SCALE * -mathCosf(wanderAngle) + obj->anim.localPosZ);
        if ((u8*)state->targetPosPtr != (u8*)&state->wanderTargetX) {
            state->targetPosPtr = &state->wanderTargetX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->substate = 8;
        break;
    case 2:
        trickyRequestMove(obj, TRICKY_ANIM_AMBIENT_HOWL, TRICKY_AMBIENT_HOWL_BLEND_SPEED, 0);
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = 9;
        break;
    case 3:
        trickyRequestMove(obj, TRICKY_ANIM_HOWL_START, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        sfxState = obj->extra;
        if (sfxState->soundSuppressed == 0 &&
            (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
            Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
            objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_YAWN, 0x1000, -1, 0);
        }
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = 4;
        state->moveHoldTimer = (f32)(int)randomGetRange(0x78, 0xf0);
        break;
    }
}

void tricky_startRandomIdleMove(GameObject* obj, TrickyState* trickyState) {
    int idleChoice;
    TrickyState* voiceState;

    idleChoice = randomGetRange(0, 4);
    switch (idleChoice) {
    case 0:
        trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 2;
        break;
    case 1:
        voiceState = obj->extra;
        if (voiceState->soundSuppressed == 0U) {
            if ((obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END || (obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN) {
                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_SNIFF, 0, 0xffffffff, 0);
                }
            }
        }
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_PICK, TRICKY_IDLE_PICK_BLEND_SPEED, 0);
        trickyState->substate = 5;
        break;
    case 2:
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_B_START, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 6;
        break;
    case 3:
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_A_START, TRICKY_TURN_MOVE_BLEND_SPEED, 0);
        trickyState->substate = 7;
        break;
    case 4:
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_WANDER, TRICKY_IDLE_WANDER_BLEND_SPEED, 0);
        trickyState->substate = 2;
        break;
    }
}

int tricky_handleFeedOrTalk(GameObject* obj, TrickyState* state) {
    TrickyState* interactionState;
    u8 talkSequenceId;
    int sequenceId;
    u8 canFeed;
    u8 currentFoodProgress;
    u8 targetFoodProgress;
    u8 progressDelta;
    u8 foodCount;
    u8 foodNeeded;
    int inWater;
    s16 yButtonItem[4];

    canFeed = 0;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    foodCount = mainGetBit(GAMEBIT_ITEM_TrickyFood_Count);
    if (foodCount != 0) {
        getYButtonItem(yButtonItem);
        if (yButtonItem[0] == GAMEBIT_ITEM_TrickyFood_Count) {
            canFeed = 1;
        }
        if (cMenuGetSelectedItem() == GAMEBIT_ITEM_TrickyFood_Count) {
            canFeed = 1;
        }
    }
    if (canFeed != 0) {
        if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
            if ((*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
                currentFoodProgress = state->stats->energy;
                targetFoodProgress = state->stats->maxEnergy;
                if (currentFoodProgress == targetFoodProgress) {
                    interactionState = obj->extra;
                    interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
                    interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_CALLBACK;
                    inWater = skeetla_isInWater(interactionState);
                    if (inWater != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        interactionState->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        interactionState->particleTimer = gTrickyFloatZero;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        trickyDebugPrint(sTrickyDryLandDebugMessage);
                    }
                    (*gObjectTriggerInterface)->runSequence(3, (void*)obj, -1);
                    interactionState->sequencePreserveBlend = 1;
                } else {
                    progressDelta = targetFoodProgress - currentFoodProgress;
                    foodNeeded = (u32)progressDelta >> 2;
                    if (progressDelta % 4) {
                        foodNeeded += 1;
                    }
                    if (foodNeeded > foodCount) {
                        state->pendingEnergy = currentFoodProgress + (foodCount << 2);
                        mainSetBits(GAMEBIT_ITEM_TrickyFood_Count, 0);
                    } else {
                        state->pendingEnergy = currentFoodProgress + (foodNeeded << 2);
                        mainSetBits(GAMEBIT_ITEM_TrickyFood_Count, foodCount - foodNeeded);
                    }
                    if (state->pendingEnergy > state->stats->maxEnergy) {
                        state->pendingEnergy = state->stats->maxEnergy;
                    }
                    interactionState = obj->extra;
                    interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
                    inWater = skeetla_isInWater(interactionState);
                    if (inWater != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        interactionState->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                        interactionState->particleTimer = gTrickyFloatZero;
                        trickyDebugPrint(sInWaterMessage);
                    } else {
                        trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                        trickyDebugPrint(sTrickyDryLandDebugMessage);
                    }
                    (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                    interactionState->sequencePreserveBlend = 1;
                    state->stateFlags |= TRICKY_STATE_FLAG_FEED_VOICE_PENDING;
                }
                buttonDisable(0, PAD_BUTTON_A);
                return 1;
            }
        } else {
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        }
    } else {
        talkSequenceId = mainGetBit(GAMEBIT_TrickyTalk);
        if (talkSequenceId != 0xff && cMenuGetSelectedItem() == -1) {
            if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                mainSetBits(GAMEBIT_TrickyTalk, 0xff);
                interactionState = obj->extra;
                sequenceId = talkSequenceId;
                interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
                if (sequenceId != 2) {
                    interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_CALLBACK;
                }
                inWater = skeetla_isInWater(interactionState);
                if (inWater != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    interactionState->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                    interactionState->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(sInWaterMessage);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(sTrickyDryLandDebugMessage);
                }
                (*gObjectTriggerInterface)->runSequence(sequenceId, (void*)obj, -1);
                interactionState->sequencePreserveBlend = 1;
                buttonDisable(0, PAD_BUTTON_A);
                return 1;
            }
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        }
    }
    return 0;
}

void tricky_handlePlayerContact(GameObject* obj, TrickyState* state) {
    GameObject* hit[1];
    TrickyState* sfxState;
    f32 fv;
    int inWater;

    state->cooldownB.f -= timeDelta;
    if (state->cooldownB.f < 0.0f) {
        state->cooldownB.f = 0.0f;
    }
    if (ObjHits_GetPriorityHit(obj, hit, 0, 0) != 0 && hit[0]->ownerObj != NULL &&
        ((GameObject*)hit[0]->ownerObj)->anim.classId == 1) {
        fv = state->cooldownB.f;
        if (fv <= gTrickyFloatZero) {
            state->cooldownB.f += TRICKY_FETCH_CARRY_DELAY_FRAMES;
            sfxState = obj->extra;
            if (sfxState->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_HEY, 0x500, -1, 0);
            }
        } else {
            state->cooldownB.f += TRICKY_TIMER_600_FRAMES;
            if (state->substate != 0xb) {
                if (state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) {
                    if (state->cooldownB.f > TRICKY_CONTACT_FLAME_THRESHOLD) {
                        state->cooldownB.f *= TRICKY_FOLLOW_ARC_HALF_PROGRESS;
                        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0) {
                            inWater = skeetla_isInWater(state);
                            if (inWater == 0) {
                                state->substate = 0xb;
                                return;
                            }
                        }
                        sfxState = obj->extra;
                        if (sfxState->soundSuppressed == 0 &&
                            (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                             obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                            Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_GET_OFF, 0x500, -1, 0);
                        }
                    } else {
                        sfxState = obj->extra;
                        if (sfxState->soundSuppressed == 0 &&
                            (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                             obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                            Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_GET_OFF, 0x500, -1, 0);
                        }
                    }
                } else {
                    sfxState = obj->extra;
                    if (sfxState->soundSuppressed == 0 &&
                        (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                         obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                        Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_GET_OFF, 0x500, -1, 0);
                    }
                    state->substate = 10;
                    state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                }
            }
        }
    }
}

/* group owned by another DLL, queried here */

/* child/reward objects spawned by this DLL (retail OBJECTS.bin names) */
#define TRICKY_CHILD_OBJ_BADGE_A       0x244 /* "TrickyBadge" */
#define TRICKY_CHILD_OBJ_BADGE_B       0x254 /* "TrickyBadge" */
#define TRICKY_CHILD_OBJ_QUEST         0x17c /* "TrickyQuest..." */
#define TRICKY_CHILD_OBJ_EXCLAMATION   0x175 /* "TrickyExcla..." */
#define TRICKY_CHILD_OBJ_SIDEKICK_BALL 0x112 /* "SidekickBal..." (DLL 0xF5 sidekickball) */
#define TRICKY_OBJ_BLUE_MUSHROOM       0x6a  /* "BlueMushroo..." (DLL 0x1A7) */

/* Command-target romDefNo values from the Rena object definition enum. */
#define TRICKY_TARGET_OBJ_WCTEMPLE_PRESSURE  0x36
#define TRICKY_TARGET_OBJ_SH_BEACON          0x3c
#define TRICKY_TARGET_OBJ_CCEYE_VINES        0x102
#define TRICKY_TARGET_OBJ_STAY_POINT         0x104
#define TRICKY_TARGET_OBJ_CF_DOOR_LIGHT      0x131
#define TRICKY_TARGET_OBJ_DIM_LOG_FIRE       0x191
#define TRICKY_TARGET_OBJ_LINK_BLUE_MUSHROOM 0x193
#define TRICKY_TARGET_OBJ_BURNABLE_VINE      0x194
#define TRICKY_TARGET_OBJ_NW_MAMMOTH         0x195
#define TRICKY_TARGET_OBJ_LINK_SNOW_PRESSURE 0x19f
#define TRICKY_TARGET_OBJ_DIM_ICE_WALL       0x1c9
#define TRICKY_TARGET_OBJ_SH_PRESSURE        0x26c
#define TRICKY_TARGET_OBJ_DFP_TRANSLA        0x352
#define TRICKY_TARGET_OBJ_DR_CHIMMEY         0x470
#define TRICKY_TARGET_OBJ_DR_COLLAPSE        0x475
#define TRICKY_TARGET_OBJ_VFP_PUZZLE_POINT   0x546
#define TRICKY_TARGET_OBJ_VFP_FLAMEPOINT     0x551
#define TRICKY_TARGET_OBJ_MS_PLANTING_SEED   0x54c
#define TRICKY_TARGET_OBJ_SH_WHITEMUSHROOM   0x658
#define TRICKY_TARGET_OBJ_ICE_HOLE           0x6f9
#define TRICKY_TARGET_OBJ_TRICKY_GUARD       0x6f0
#define TRICKY_TARGET_OBJ_DIM_TRUTH_HORN     0x718
#define TRICKY_TARGET_OBJ_SC_PRESSURE        0x7c3
#define TRICKY_TARGET_OBJ_TUMBLEWEED2        0x3fb
#define TRICKY_TARGET_OBJ_WC_BEACON          0x50f
#define TRICKY_TARGET_OBJ_ARW_TIMED_MIN      0x542

/* GameObject.objectFlags bit (distinct field from stateFlags above). */
#define TRICKY_OBJFLAG_PARENT_SLACK            0x1000
#define TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID 0x46406
#define TRICKY_OBJGROUP                        1
#define TRICKY_BBOX_HIT_SCRATCH_SIZE           84
#define TRICKY_HELPER_WARP_OBJECT_ID           0x25 /* "warp" transporter / WarpPoint */

typedef enum TrickySequenceEvent {
    TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN = 1,
    TRICKY_SEQUENCE_EVENT_SPAWN_BADGE = 2,
    TRICKY_SEQUENCE_EVENT_STORE_ENERGY = 3,
    TRICKY_SEQUENCE_EVENT_HIDE_SHADOW = 0x2B,
    TRICKY_SEQUENCE_EVENT_SHOW_SHADOW = 0x2C,
} TrickySequenceEvent;

int gTrickyUnusedSbss;
u32 gTrickyWarpHelperObject;

GameObject* Tricky_findNearestGroup4BObject(GameObject* obj, TrickyState* state) {
    GameObject** objs;
    int count[1];
    GameObject* result;
    f32 d;
    f32 bestD;
    int i;

    result = 0;
    objs = objGetAllOfType(TRICKYWARP_OBJ_GROUP, count);
    d = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &obj->anim.worldPosX);
    if ((d >= TRICKY_REMOTE_RECALL_DISTANCE_SQ) || (state->cooldownA > gTrickyFloatZero)) {
        if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX, TRICKY_VISIBILITY_PROBE_RADIUS) == 0) {
            bestD = gTrickyMaxDistance;
            for (i = 0; i < count[0]; i++) {
                f32 cd = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &(*objs)->anim.worldPosX);
                if (cd < d && cd < bestD) {
                    bestD = cd;
                    result = *objs;
                }
                objs++;
            }
        }
    }
    return result;
}

void tricky_stateIdleWander(GameObject* obj, TrickyState* state) {
    TrickyState* sfxState;
    int isInWater;
    u32 sfxDisabled;
    u32 transitionFlag;

    if (tricky_handleFeedOrTalk(obj, state) == 0) {
        state->wanderTargetX =
            obj->anim.worldPosX - mathSinf((TRICKY_PI * (f32)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);
        state->wanderTargetY = (obj)->anim.worldPosY;
        state->wanderTargetZ =
            obj->anim.worldPosZ - mathCosf((TRICKY_PI * (f32)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);

        if (trickyUpdateMovementState(obj, TRICKY_ANIM_TRANSITION_FRAMES, state) != 1) {
            state->idleSfxTimer -= timeDelta;
            if (state->idleSfxTimer <= gTrickyFloatZero) {
                state->idleSfxTimer =
                    (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
                sfxState = obj->extra;
                sfxDisabled = sfxState->soundSuppressed;
                if ((sfxDisabled == 0) &&
                    (((obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END) ||
                     ((obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
                    (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0)) {
                    objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_DUM_DE_DUM, 0x500, -1, 0);
                }
            }

            isInWater = skeetla_isInWater(state);

            if (isInWater) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->cooldownC = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(sInWaterMessage);
            } else {
                switch ((obj)->anim.currentMove) {
                case TRICKY_ANIM_IDLE_FOOD_CHEW:
                    break;
                case TRICKY_ANIM_IDLE_FOOD_WAIT:
                    transitionFlag = state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING;
                    if (transitionFlag != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_CHEW, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    }
                    break;
                default:
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_WAIT, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    break;
                }
                trickyDebugPrint(sTrickyDryLandDebugMessage);
            }
        }
    }
}

void tricky_attachToWalkGroup(GameObject* obj, TrickyState* state) {
    u8 pathBytes[16];
    u32 pathByte = (u8)Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);

    pathBytes[0] = pathByte;
    if (pathByte == 0) {
        int pathId = Objfsa_GetPatchGroupIdAtPoint(&obj->anim.worldPosX);
        if (pathId != 0) {
            walkPath_writeU16LE(pathId & 0xffff, pathBytes);
        }
    }
    if (pathBytes[0] != 0) {
        f32 resetTimer;

        state->walkGroup = pathBytes[0];
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        resetTimer = gTrickyFloatZero;
        state->cooldownA = resetTimer;
        state->cooldownB.f = resetTimer;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
        state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
    }
    if (gTrickyWarpHelperObject == 0) {
        int setup = (int)Obj_AllocObjectSetup(0x18, TRICKY_HELPER_WARP_OBJECT_ID);
        gTrickyWarpHelperObject = (int)objSetupObject((ObjPlacement*)setup, 4, -1, -1, obj->anim.parent);
    }
    state->ownsWarpHelperObject = 1;
}

static inline int trickyGetState(GameObject* obj) {
    return (int)obj->extra;
}

int tricky_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    int state;
    int i;
    ObjSeqState* sequence = animUpdate;
    u8* childSlot;
    int secondChildIndex;
    int childIndex;
    u8* spawnSlot;
    ObjPlacement* setup;
    u8 blockFlags[120];

    state = trickyGetState(obj);
    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0) {
        ObjHits_DisableObject(obj);
        Sfx_StopObjectChannel(obj, 0x7f);
        if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
            ((TrickyState*)state)->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (childIndex = 0, childSlot = (u8*)state; childIndex < CHILD_OBJECT_COUNT;
                 childSlot += sizeof(GameObject*), childIndex++) {
                objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(childSlot));
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            childSlot = obj->extra;
            if (((TrickyState*)childSlot)->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &((TrickyState*)childSlot)->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1,
                                   0);
            }
        }
        Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_LATCHED;
        if ((sequence->flags & 3) == 0) {
            ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
        }
        if (((TrickyState*)state)->sequencePreserveBlend == 0) {
            ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
            ((TrickyState*)state)->blendActive = 0;
        }
    }

    for (i = 0; i < sequence->eventCount; i++) {
        switch (sequence->eventIds[i]) {
        case TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN:
            if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                ((TrickyState*)state)->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                for (secondChildIndex = 0, childSlot = (u8*)state; secondChildIndex < CHILD_OBJECT_COUNT;
                     childSlot += sizeof(GameObject*), secondChildIndex++) {
                    objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(childSlot));
                }
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                childSlot = obj->extra;
                if (((TrickyState*)childSlot)->soundSuppressed == 0 &&
                    (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                    Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &((TrickyState*)childSlot)->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0,
                                       -1, 0);
                }
            } else if ((u8)Obj_CanSetupObject()) {
                ((TrickyState*)state)->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (childIndex = 0, spawnSlot = (u8*)state; childIndex < CHILD_OBJECT_COUNT;
                     spawnSlot += sizeof(GameObject*), childIndex++) {
                    setup = Obj_AllocObjectSetup(sizeof(FlameblastPlacement), TRICKY_CHILD_OBJ_FLAMEBLAST);
                    ((FlameblastPlacement*)setup)->base.color[0] = 2;
                    ((FlameblastPlacement*)setup)->base.color[1] = 1;
                    ((FlameblastPlacement*)setup)->streamIndex = childIndex;
                    TRICKY_FLAME_CHILD_AT_CURSOR(spawnSlot) =
                        objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_SPAWN_BADGE:
            mainSetBits(GAMEBIT_Tricky_LoadBadge, 1);
            if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && ((TrickyState*)state)->spawnedChild == NULL &&
                (u8)Obj_CanSetupObject()) {
                mapGetLoadedMapFlags(blockFlags);
                if (blockFlags[0xd] != 0) {
                    setup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_A);
                } else {
                    setup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_B);
                }
                ((TrickyState*)state)->spawnedChild = objSetupObject(setup, 4, -1, -1, obj->anim.parent);
                ObjLink_AttachChild(obj, ((TrickyState*)state)->spawnedChild, 3);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_STORE_ENERGY:
            ((TrickyState*)state)->stats->energy = ((TrickyState*)state)->pendingEnergy;
            break;
        case TRICKY_SEQUENCE_EVENT_HIDE_SHADOW:
            obj->anim.modelState->flags &= ~(u64)OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        case TRICKY_SEQUENCE_EVENT_SHOW_SHADOW:
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        }
    }

    objAnimFreeChildren(obj, (TrickyState*)state, &((TrickyState*)state)->childA);
    objAnimFreeChildren(obj, (TrickyState*)state, &((TrickyState*)state)->childB);
    objAnimFreeChildren(obj, (TrickyState*)state, &((TrickyState*)state)->child);
    trickyUpdateColorVariant(obj, (TrickyState*)state);
    Tricky_updateBlendChannelWeight(obj, (TrickyState*)state);
    objAudioDispatchAnimEvents(obj, &sequence->animEvents, 1, ((TrickyState*)state)->footPoints,
                               &((TrickyState*)state)->pathControlFlags, 1.0f, 1.0f);
    if ((((TrickyState*)state)->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_CALLBACK) != 0) {
        sequence->flags &= ~0x40;
        characterDoEyeAnims(obj, &((TrickyState*)state)->eyeAnimState);
        return (*gObjectTriggerInterface)->func20(obj, sequence, 1, 0xf, 0x1e, 0, 0);
    }
    return 0;
}

void Tricky_requestRecall(GameObject* obj) {
    TrickyState* state = obj->extra;
    if (mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands)) {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
}

int Tricky_isGuarding(GameObject* obj) {
    u8 mode = ((TrickyState*)obj->extra)->stateIndex;
    if (mode == 8 || mode == 0xe) {
        return 1;
    }
    return 0;
}

int Tricky_isPlayingBall(GameObject* obj) {
    u8 mode;
    int result;
    mode = ((TrickyState*)obj->extra)->stateIndex;
    switch (mode) {
    case 5:
        result = 1;
        break;
    default:
        result = 0;
        break;
    }
    return result;
}

int Tricky_requestMoveToObject(GameObject* obj, GameObject* targetObj) {
    TrickyState* state = obj->extra;
    s32 objBlocked = obj->objectFlags & TRICKY_OBJFLAG_PARENT_SLACK;

    if (objBlocked != 0) {
        return 0;
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        state->followObj = targetObj;
        if (state->targetPosPtr != &targetObj->anim.worldPosX) {
            state->targetPosPtr = &targetObj->anim.worldPosX;
            {
                u32 mask;
                u32 flags = state->stateFlags;

                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        state->substate = 0;
        state->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
    } else {
        state->pendingFollowRequest = 1;
        state->pendingFollowObj = targetObj;
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
    return 1;
}

void Tricky_commandPlayBall(GameObject* obj, int commandEnabled, GameObject* targetObj) {
    TrickyState* state = obj->extra;

    if (commandEnabled != 0) {
        if (state->stateIndex == TRICKY_STATE_BALL_ROLL) {
            if (state->substate != 0) {
                state->followObj = targetObj;
            }
        } else {
            u32 busy = state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            void* nextTarget;
            if (busy != 0) {
                return;
            }
            state->cannonballStartCurve = Objfsa_FindNearestEnabledCurveType24(&targetObj->anim.worldPosX, -1, 3);
            state->cannonballScratch710.f = (f32)(int)randomGetRange(0x168, 0x28);
            state->stateIndex = TRICKY_STATE_BALL_ROLL;
            state->followObj = targetObj;
            nextTarget = &state->cannonballStartCurve->x;
            if ((void*)state->targetPosPtr != nextTarget) {
                state->targetPosPtr = (f32*)nextTarget;
                {
                    u32 mask;
                    u32 flags = state->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    state->stateFlags = flags & mask;
                }
                state->linkedWalkGroup = 0;
            }
            state->substate = 0;
        }
    } else {
        state->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
}

u8 Tricky_getEnergyMax(GameObject* obj) {
    return ((TrickyState*)obj->extra)->stats->maxEnergy;
}
u8 Tricky_getEnergy(GameObject* obj) {
    return ((TrickyState*)obj->extra)->stats->energy;
}

void sideCommandEnable(GameObject* obj, GameObject* targetObj, int commandKind, int commandType) {
    int remaining;
    u8* commandCursor;
    u32 count;
    int commandIndex;
    TrickyState* state;

    state = obj->extra;
    if (state->commandCount == ARRAY_COUNT(state->commands)) {
        trickyReportError(sSidekickCommandDebugTextBlock);
        return;
    }
    state->commandRequestBits = (u8)(state->commandRequestBits | TRICKY_COMMAND_TYPE_TO_ABILITY(commandType));
    commandIndex = 0;
    commandCursor = (u8*)state;
    count = state->commandCount;
    for (remaining = count; remaining > 0; remaining--) {
        if (TRICKY_COMMAND_AT_STATE_CURSOR(commandCursor)->targetObj == targetObj) {
            state->commands[commandIndex].ttlFrames = TRICKY_COMMAND_TTL_FRAMES;
            return;
        }
        commandCursor += sizeof(TrickyCommand);
        commandIndex++;
    }
    state->commands[count].targetObj = targetObj;
    state->commands[state->commandCount].commandKind = commandKind;
    state->commands[state->commandCount].commandType = commandType;
    state->commands[state->commandCount].ttlFrames = TRICKY_COMMAND_TTL_FRAMES;
    state->commandCount++;
}

int Tricky_getCurrentCommandType(GameObject* obj, int* out) {
    *out = ((TrickyState*)obj->extra)->commandPhase;
    return 1;
}

int Tricky_updateSideCommandPrompts(GameObject* obj) {
    TrickyState* state;
    u32 commandMask;
    char cmdByte;
    u16 promptId;
    u8 cond;
    u8 promptA;
    u8 promptB;
    u8 promptC;
    u32 bitVal;
    int ref;
    TrickyState* refB;
    TrickyState* refC;
    u16* setup;
    u32 spawnedObj;
    u8 i;
    char questPromptOccupiedSlots[4];
    char exclamationPromptOccupiedSlots[4];
    u32 promptTable[4];

    state = obj->extra;
    cond = false;
    promptA = false;
    promptB = false;
    promptC = false;
    promptTable[0] = *(u32*)gTrickyQuestPromptSfxIds;
    bitVal = mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands);
    if (bitVal != 0) {
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            state->commandRequestBits = 0;
        }
        commandMask = state->commandRequestBits | (TRICKY_ABILITY_CALL | TRICKY_ABILITY_STAY);
        if (((state->stateIndex == TRICKY_STATE_GUARD) || (state->stateIndex == TRICKY_STATE_CIRCLING)) ||
            ((state->stateIndex == TRICKY_STATE_GROWL && (state->substate == 1)))) {
            commandMask |= TRICKY_ABILITY_FLAME;
            promptA = true;
        } else {
            if (trickyFindNearestUsableBaddie(state->playerObj, TRICKY_AMBIENT_ACTIVITY_BASE, 1) != NULL) {
                promptA = true;
                promptC = true;
            }
        }
        if (state->commandRequestBits != 0) {
            for (i = 0; i < state->commandCount; i++) {
                ref = (int)state + i * sizeof(TrickyCommand);
                cmdByte = TRICKY_COMMAND_AT_STATE_CURSOR(ref)->commandKind;
                if (cmdByte == '\0') {
                    if (TRICKY_COMMAND_AT_STATE_CURSOR(ref)->targetObj->anim.romDefNo == TRICKY_OBJ_BLUE_MUSHROOM) {
                        promptB = true;
                    }
                    promptA = true;
                } else if (cmdByte == '\x01') {
                    cond = true;
                }
            }
        }
        if (((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) &&
            (bitVal = mainGetBit(GAMEBIT_ITEM_TrickyBall_Usable), bitVal != 0)) {
            ref = (int)Obj_GetPlayerObject();
            ref = playerIsInNormalControlUndisguisedOnLand((GameObject*)(ref));
            if ((ref != 0) && (bitVal = mainGetBit(GAMEBIT_NoBallsAllowed), bitVal == 0)) {
                if (playerGetFlags3F0Bit5(state->playerObj) == 0) {
                    commandMask |= TRICKY_ABILITY_THROW_BALL;
                }
            }
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0) {
            commandMask &= ~TRICKY_ABILITY_CALL;
        }
        if (mainGetBit(GAMEBIT_Tricky_Learned_Distract) == 0) {
            commandMask &= ~TRICKY_ABILITY_DISTRACT;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) == 0) {
            commandMask &= ~TRICKY_ABILITY_FLAME;
        }
        state->commandRequestBits = 0;
        if ((cond) && ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0)) {
            state->promptBDespawnTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
            if ((state->childB == NULL) && ((u8)Obj_CanSetupObject() != 0)) {
                bitVal = randomGetRange(0, 1);
                promptId = *(u16*)((int)promptTable + bitVal * 2);
                ref = (int)obj->extra;
                if ((((TrickyState*)ref)->soundSuppressed == 0) &&
                    (((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                       (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
                      !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)))) {
                    objSoundStartTimed(obj, &((TrickyState*)ref)->soundState, promptId, 0x500, 0xffffffff, 0);
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_QUEST);
                questPromptOccupiedSlots[0] = -1;
                questPromptOccupiedSlots[1] = -1;
                questPromptOccupiedSlots[2] = -1;
                if (state->childA != NULL) {
                    questPromptOccupiedSlots[state->packedSlots.promptASlot] = '\x01';
                }
                if (state->childB != NULL) {
                    questPromptOccupiedSlots[state->packedSlots.promptBSlot] = '\x01';
                }
                if (state->child != NULL) {
                    questPromptOccupiedSlots[state->packedSlots.zzzSlot] = '\x01';
                }
                if (questPromptOccupiedSlots[0] == -1) {
                    bitVal = 0;
                } else if (questPromptOccupiedSlots[1] == -1) {
                    bitVal = 1;
                } else if (questPromptOccupiedSlots[2] == -1) {
                    bitVal = 2;
                } else if (questPromptOccupiedSlots[3] == -1) {
                    bitVal = 3;
                } else {
                    bitVal = 0xffffffff;
                }
                state->packedSlots.promptBSlot = bitVal;
                spawnedObj = (int)objSetupObject((ObjPlacement*)setup, 4, -1, 0xffffffff, obj->anim.parent);
                state->childB = (GameObject*)spawnedObj;
                ObjLink_AttachChild(obj, state->childB, state->packedSlots.promptBSlot);
            }
        } else if (state->childB != NULL) {
            state->promptBDespawnTimer = state->promptBDespawnTimer - timeDelta;
            if (state->promptBDespawnTimer <= gTrickyFloatZero) {
                objAnimFreeChildren(obj, state, &state->childB);
            }
        }
        if ((promptA) && ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0)) {
            state->promptADespawnTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
            if ((state->childA == NULL) && ((u8)Obj_CanSetupObject() != 0)) {
                if (randomGetRange(0, 3) == 0) {
                    if (promptB) {
                        refB = obj->extra;
                        if ((refB->soundSuppressed == 0) &&
                            (((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                               (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
                              !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)))) {
                            objSoundStartTimed(obj, &refB->soundState, TRICKY_VOICE_SFX_FOOD, 0x500, 0xffffffff, 0);
                        }
                    } else if ((((promptC) && (refC = obj->extra, refC->soundSuppressed == 0)) &&
                                ((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                                  (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)))) &&
                               !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)) {
                        objSoundStartTimed(obj, &refC->soundState, TRICKY_VOICE_SFX_BAD_GUY, 0x500, 0xffffffff, 0);
                    }
                }
                setup = (u16*)Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_EXCLAMATION);
                exclamationPromptOccupiedSlots[0] = -1;
                exclamationPromptOccupiedSlots[1] = -1;
                exclamationPromptOccupiedSlots[2] = -1;
                if (state->childA != NULL) {
                    exclamationPromptOccupiedSlots[state->packedSlots.promptASlot] = '\x01';
                }
                if (state->childB != NULL) {
                    exclamationPromptOccupiedSlots[state->packedSlots.promptBSlot] = '\x01';
                }
                if (state->child != NULL) {
                    exclamationPromptOccupiedSlots[state->packedSlots.zzzSlot] = '\x01';
                }
                if (exclamationPromptOccupiedSlots[0] == -1) {
                    bitVal = 0;
                } else if (exclamationPromptOccupiedSlots[1] == -1) {
                    bitVal = 1;
                } else if (exclamationPromptOccupiedSlots[2] == -1) {
                    bitVal = 2;
                } else if (exclamationPromptOccupiedSlots[3] == -1) {
                    bitVal = 3;
                } else {
                    bitVal = 0xffffffff;
                }
                state->packedSlots.promptASlot = bitVal;
                spawnedObj = (int)objSetupObject((ObjPlacement*)setup, 4, -1, 0xffffffff, obj->anim.parent);
                state->childA = (GameObject*)spawnedObj;
                ObjLink_AttachChild(obj, state->childA, state->packedSlots.promptASlot);
            }
        } else if (state->childA != NULL) {
            state->promptADespawnTimer = state->promptADespawnTimer - timeDelta;
            if (state->promptADespawnTimer <= gTrickyFloatZero) {
                objAnimFreeChildren(obj, state, &state->childA);
            }
        }
        return commandMask;
    }
    return -1;
}

int Tricky_getAvailableCommands(GameObject* obj) {
    int r = 0;
    if (mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0) {
        r = TRICKY_ABILITY_FIND_SECRET | TRICKY_ABILITY_STAY;
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0) {
            r |= TRICKY_ABILITY_CALL;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
            r |= TRICKY_ABILITY_THROW_BALL;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0) {
            r |= TRICKY_ABILITY_FLAME;
        }
    }
    return r;
}

int Tricky_getExtraSize(void) {
    return 0x83c;
}

void Tricky_free(GameObject* obj, int shouldKeepFlameChildren) {
    int i;
    int childSlot;
    TrickyState* state;
    u32 objId = (u32)obj;

    state = obj->extra;
    freeAndNull((void**)&state->pathSearches[0].nodes);
    freeAndNull((void**)&state->pathSearches[1].nodes);
    freeAndNull((void**)&state->pathSearches[2].nodes);
    freeAndNull((void**)&state->pathSearches[3].nodes);
    freeAndNull((void**)&state->pathSearches[4].nodes);
    freeAndNull((void**)&state->pathSearches[5].nodes);
    freeAndNull((void**)&state->pathSearches[6].nodes);
    freeAndNull((void**)&state->pathSearches[7].nodes);
    freeAndNull((void**)&state->pathSearches[8].nodes);
    objFreeObjectType(obj, TRICKY_OBJGROUP);
    (*gExpgfxInterface)->freeSource(objId);
    if ((shouldKeepFlameChildren == 0) && ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0)) {
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
        state->stateFlags = state->stateFlags | TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
        i = 0;
        childSlot = (int)state;
        do {
            objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(childSlot));
            childSlot = childSlot + 4;
            i = i + 1;
        } while (i < 7);
        Sfx_RemoveLoopedObjectSound((GameObject*)objId, SFXTRIG_trpopn_c);
        childSlot = (int)obj->extra;
        if ((((TrickyState*)childSlot)->soundSuppressed == 0) &&
            (((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
              (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0)))) {
            objSoundStartTimed(obj, &((TrickyState*)childSlot)->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0,
                               0xffffffff, 0);
        }
    }
    doNothing_onTrickyFree();
    objAnimFreeChildren(obj, state, &state->childA);
    objAnimFreeChildren(obj, state, &state->childB);
    objAnimFreeChildren(obj, state, &state->child);
    if (state->spawnedChild != NULL) {
        ObjLink_DetachChild(obj, state->spawnedChild);
        Obj_FreeObject(state->spawnedChild);
    }
    if ((state->ownsWarpHelperObject != 0u) && (gTrickyWarpHelperObject != 0)) {
        Obj_FreeObject((GameObject*)gTrickyWarpHelperObject);
        gTrickyWarpHelperObject = 0;
    }
    return;
}

void Tricky_render(GameObject* obj, int p2, int p3, int p4, int p5, char doRender) {
    int i;
    TrickyState* renderState;
    int pathPointCursor;
    s16* modelAnchorPose;
    TrickyState* state;

    if (doRender != '\0') {
        state = obj->extra;
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        renderState = obj->extra;
        i = 0;
        pathPointCursor = (int)renderState;
        do {
            ObjPath_GetPointWorldPosition(obj, i + 4, &((TrickyState*)pathPointCursor)->pathPointPositions[0].x,
                                          &((TrickyState*)pathPointCursor)->pathPointPositions[0].y,
                                          &((TrickyState*)pathPointCursor)->pathPointPositions[0].z, 0);
            pathPointCursor = pathPointCursor + 0xc;
            i = i + 1;
        } while (i < 4);
        ObjPath_GetPointWorldPosition(obj, 8, &renderState->renderPosX, &renderState->renderPosY,
                                      &renderState->renderPosZ, 0);
        modelAnchorPose = objFindJointPoseVector(obj, 0);
        renderState->modelAnchorRotY = modelAnchorPose[1];
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            switch (state->stateIndex) {
            case 2:
                skeetla_spawnLinkedSparks(obj);
                break;
            case 3:
                if (state->substate == 4) {
                    skeetla_spawnLinkedSparks(obj);
                }
                break;
            }
            if ((((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0) &&
                 (state->stateIndex == TRICKY_STATE_FETCH_BALL)) &&
                (state->substate >= 3)) {
                if (state->substate != 3) {
                    state->fetchBallObj->anim.localPosX = state->renderPosX;
                    state->fetchBallObj->anim.localPosY = state->renderPosY;
                    state->fetchBallObj->anim.localPosZ = state->renderPosZ;
                }
                objRenderModelAndHitVolumes(state->fetchBallObj, p2, p3, p4, p5, 1.0f);
            }
        }
        Tricky_emitQueuedPathParticles(obj, state);
        ObjPath_GetPointWorldPositionArray(obj, 4, 4, (float*)state->footPoints);
        state->particleTimer = state->particleTimer - timeDelta;
        if (state->particleTimer > gTrickyFloatZero) {
            objDoParticleFx(obj, TRICKY_PATH_PARTICLE_SCALE, 6, 1.0f, 0);
        }
    }
    return;
}

void Tricky_hitDetect(GameObject* obj) {
    f32 dy;
    f32 y;
    GameObject** objects;
    int i;
    GameObject* firepipeObj;
    TrickyState* state;
    f32 height;
    f32 z;
    f32 th;
    int count[2];

    state = obj->extra;
    y = obj->anim.localPosY;
    dy = (y - obj->anim.previousLocalPosY >= gTrickyFloatZero) ? y - obj->anim.previousLocalPosY
                                                               : -(y - obj->anim.previousLocalPosY);
    if (1.0f == dy) {
        if (y == obj->anim.worldPosY) {
            state->heightTracking = 1;
            state->heightTrackObjId = -1;
            state->trackedHeight = gTrickyFloatZero;
        }
    } else {
        firepipeObj = ObjList_FindObjectById(TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID);
        if ((firepipeObj != 0) && (getXZDistanceSquared(&obj->anim.worldPosX, &firepipeObj->anim.worldPosX) <
                                   TRICKY_FIREPIPE_HEIGHT_DIST_SQ)) {
            state->heightTracking = 1;
            state->heightTrackObjId = TRICKY_HEIGHT_TRACK_FIREPIPE_OBJECT_ID;
            state->trackedHeight = gTrickyFloatZero;
        }
    }
    if (state->heightTracking != 0u) {
        {
            GameObject** t = (GameObject**)objGetAllOfType(XYZ_ANIMATOR_OBJECT_GROUP, count);
            i = 0;
            objects = t;
        }
        for (; i < count[0]; i++) {
            height = XyzAnimator_getCoordinate(*objects, XYZ_ANIMATOR_COORD_WORLD_Y);
            if (state->heightTrackObjId == -1) {
                dy = (height - obj->anim.localPosY >= gTrickyFloatZero) ? height - obj->anim.localPosY
                                                                        : -(height - obj->anim.localPosY);
                if (dy < TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    state->heightTrackObjId = (*objects)->anim.placement->ident;
                }
            }
            if ((u32)state->heightTrackObjId == (u32)(*objects)->anim.placement->ident) {
                th = state->trackedHeight;
                z = gTrickyFloatZero;
                if ((th != z) && (th == height)) {
                    state->heightTracking = 0;
                } else {
                    obj->anim.localPosY = height;
                    state->trackedHeight = height;
                }
                break;
            }
            objects = objects + 1;
        }
        if (i == count[0]) {
            state->heightTracking = 0;
        }
    }
    return;
}

/* Tricky sidekick command state machine and per-frame update. */
#define TRICKY_RESET_COMMAND(statePtr)                                                                                 \
    ((TrickyState*)(statePtr))->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;                                               \
    ((TrickyState*)(statePtr))->substate = 0;                                                                          \
    zero = gTrickyFloatZero;                                                                                           \
    ((TrickyState*)(statePtr))->cooldownA = zero;                                                                      \
    ((TrickyState*)(statePtr))->cooldownB.f = zero;                                                                    \
    ((TrickyState*)(statePtr))->stateFlags =                                                                           \
        ((TrickyState*)(statePtr))->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;                               \
    ((TrickyState*)(statePtr))->stateFlags =                                                                           \
        ((TrickyState*)(statePtr))->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;                               \
    ((TrickyState*)(statePtr))->stateFlags =                                                                           \
        ((TrickyState*)(statePtr))->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;                                 \
    ((TrickyState*)(statePtr))->stateFlags =                                                                           \
        ((TrickyState*)(statePtr))->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;                                \
    ((TrickyState*)(statePtr))->commandPhase = TRICKY_COMMAND_PHASE_IDLE

#define TRICKY_VOICE(obj, sfx, vol)                                                                                    \
    {                                                                                                                  \
        voiceState = ((GameObject*)obj)->extra;                                                                        \
        if (voiceState->soundSuppressed == 0) {                                                                        \
            if (((GameObject*)obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END ||                                       \
                ((GameObject*)obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN) {                                        \
                if (Sfx_IsPlayingFromObjectChannel((GameObject*)(obj), TRICKY_VOICE_CHANNEL) == 0) {                   \
                    objSoundStartTimed((GameObject*)(obj), &voiceState->soundState, (sfx), (vol), 0xffffffff, 0);      \
                }                                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
    }

#define TRICKY_SPAWN_FOOD_BUBBLE(obj, statePtr)                                                                        \
    if (((TrickyState*)(statePtr))->child == NULL) {                                                                   \
        ObjPlacement* setup_;                                                                                          \
        s8 occupiedSlots_[4];                                                                                          \
        int freeSlot_;                                                                                                 \
        setup_ = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_FOOD);                                                    \
        occupiedSlots_[0] = -1;                                                                                        \
        occupiedSlots_[1] = -1;                                                                                        \
        occupiedSlots_[2] = -1;                                                                                        \
        if (((TrickyState*)(statePtr))->childA != NULL) {                                                              \
            occupiedSlots_[((TrickyState*)(statePtr))->packedSlots.promptASlot] = 1;                                   \
        }                                                                                                              \
        if (((TrickyState*)(statePtr))->childB != NULL) {                                                              \
            occupiedSlots_[((TrickyState*)(statePtr))->packedSlots.promptBSlot] = 1;                                   \
        }                                                                                                              \
        if (((TrickyState*)(statePtr))->child != NULL) {                                                               \
            occupiedSlots_[((TrickyState*)(statePtr))->packedSlots.zzzSlot] = 1;                                       \
        }                                                                                                              \
        if (occupiedSlots_[0] == -1) {                                                                                 \
            freeSlot_ = 0;                                                                                             \
        } else if (occupiedSlots_[1] == -1) {                                                                          \
            freeSlot_ = 1;                                                                                             \
        } else if (occupiedSlots_[2] == -1) {                                                                          \
            freeSlot_ = 2;                                                                                             \
        } else if (occupiedSlots_[3] == -1) {                                                                          \
            freeSlot_ = 3;                                                                                             \
        } else {                                                                                                       \
            freeSlot_ = -1;                                                                                            \
        }                                                                                                              \
        ((TrickyState*)(statePtr))->packedSlots.zzzSlot = freeSlot_;                                                   \
        ((TrickyState*)(statePtr))->child = objSetupObject(setup_, 4, -1, -1, ((GameObject*)(obj))->anim.parent);      \
        ObjLink_AttachChild((GameObject*)(obj), ((TrickyState*)(statePtr))->child,                                     \
                            ((TrickyState*)(statePtr))->packedSlots.zzzSlot);                                          \
        zero = gTrickyFloatZero;                                                                                       \
        ((TrickyState*)(statePtr))->childPhaseTimer0 = zero;                                                           \
        ((TrickyState*)(statePtr))->childPhaseTimer1 = zero;                                                           \
        ((TrickyState*)(statePtr))->childPhaseTimer2 = zero;                                                           \
    }

void Tricky_update(GameObject* obj) {
    char* debugTextBase;
    int state;
    TrickyState* trickyState;
    int commandAlreadyQueued;
    int impressSfxId;
    TrickyState* voiceState;
    struct {
        int index;
    } childLoop;
    int i;
    int commandCursorAddr;
    ObjPlacement* placementSetup;
    int count;
    u32 flags;
    GameObject* nearestBaddie;
    int accepted;
    int waterFootstepActive;
    f32* targetPos;
    f32 zero;
    f32 moveProgress;
    u8 loadedMapFlags[120];
    TrickyItemIdList commandItemQuery;
    TrickySfxPair impressSfxPair;

    debugTextBase = gTrickyDebugStringTable;
    state = (int)obj->extra;
    trickyState = (TrickyState*)state;
    commandAlreadyQueued = 0;
    commandItemQuery = gTrickyCmdQueryInit;
    impressSfxPair = sTrickyImpressSfxPair;
    Objfsa_UpdateWalkGroupPatches();
    if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && (void*)trickyState->spawnedChild == NULL &&
        (u8)Obj_CanSetupObject()) {
        mapGetLoadedMapFlags(loadedMapFlags);
        if (loadedMapFlags[0xd] != 0) {
            placementSetup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_A);
        } else {
            placementSetup = Obj_AllocObjectSetup(0x20, TRICKY_CHILD_OBJ_BADGE_B);
        }
        trickyState->spawnedChild = (void*)objSetupObject((ObjPlacement*)placementSetup, 4, -1, -1, obj->anim.parent);
        ObjLink_AttachChild(obj, trickyState->spawnedChild, 3);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FEED_VOICE_PENDING_U32) != 0) {
        TrickyStats* stats = trickyState->stats;

        if (stats->energy == stats->maxEnergy) {
            TRICKY_VOICE(obj, TRICKY_VOICE_SFX_IM_STUFFED, 0x500);
        } else {
            TRICKY_VOICE(obj, TRICKY_VOICE_SFX_MMMM_TASTY, 0x500);
        }
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_FEED_VOICE_PENDING;
    }
    {
        int flagsByte = trickyState->sideCommandHitFlags;
        trickyDebugPrint(debugTextBase + TRICKY_DBG_SIDECOMMAND_HITS, flagsByte & 1, flagsByte & 2, flagsByte & 4,
                         flagsByte & 8, flagsByte & 0x10, flagsByte & 0x20, flagsByte & 0x40, flagsByte & 0x80);
    }
    {
        TrickyStats* stats = trickyState->stats;

        trickyDebugPrint(debugTextBase + TRICKY_DBG_SIDECOMMAND_ENERGY, stats->energy, stats->maxEnergy);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) != 0) {
        ObjHits_EnableObject(obj);
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE) == 0) {
            TRICKY_RESET_COMMAND(state);
            trickyState->movementState = TRICKY_MOVE_WALK_WAIT;
            trickyState->prevSpeed = zero;
            trickyState->speed = zero;
            trickyState->homePosX = obj->anim.worldPosX;
            trickyState->homePosY = obj->anim.worldPosY;
            trickyState->homePosZ = obj->anim.worldPosZ;
            (*gPathControlInterface)->attachObject((void*)obj, &trickyState->pathControlFlags);
            if (obj->anim.currentMove == 8 || obj->anim.currentMove == 7) {
                trickyState->waterLevel = gTrickyEventStaleSeconds;
                trickyState->eventTime = TRICKY_LOST_EVENT_TIME;
            } else {
                trickyState->waterLevel = gTrickyFloatZero;
            }
        }
        trickyState->stateFlags &= ~TRICKY_STATE_SEQUENCE_DONE_CLEAR_MASK;
        if (trickyState->sequencePreserveBlend != 0) {
            trickyState->sequencePreserveBlend = 0;
        } else {
            trickyState->blendPending = 1;
        }
    }
    if (trickyState->followObj != NULL && (trickyState->followObj->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->groundSnapCounter = 2;
            (*gPathControlInterface)->attachObject((void*)obj, &trickyState->pathControlFlags);
            obj->anim.localPosX = trickyState->homePosX;
            obj->anim.localPosY = trickyState->homePosY;
            obj->anim.localPosZ = trickyState->homePosZ;
            obj->anim.worldPosX = trickyState->homePosX;
            obj->anim.worldPosY = trickyState->homePosY;
            obj->anim.worldPosZ = trickyState->homePosZ;
            ObjHits_SyncObjectPosition(obj);
            childLoop.index = 0;
            trickyState->movementState = childLoop.index;
            zero = gTrickyFloatZero;
            trickyState->prevSpeed = zero;
            trickyState->speed = zero;
            trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_POSITION_RELOCATED;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GROUND_SNAP;
            if ((trickyState->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                u8* childCursor;

                trickyState->stateFlags = trickyState->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                childCursor = (u8*)state;
                for (; childLoop.index < 7; childCursor += 4, childLoop.index++) {
                    objSetAnimSpeedTo1(TRICKY_FLAME_CHILD_AT_CURSOR(childCursor));
                }
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                TRICKY_VOICE(obj, TRICKY_VOICE_SFX_FINISH_FLAME, 0);
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        }
        TRICKY_RESET_COMMAND(state);
        trickyState->followObj = NULL;
    }
    {
        int requestedCommand;

        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0 &&
            (*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
            requestedCommand = 0;
        } else {
            requestedCommand = (*gGameUIInterface)->isOneOfItemsBeingUsed(commandItemQuery.ids, TRICKY_ITEM_ID_COUNT);
        }
        commandCursorAddr = state;
        count = trickyState->commandCount;
        for (i = 0; i < count; i++, commandCursorAddr += sizeof(TrickyCommand)) {
            if (((TrickyState*)commandCursorAddr)->commands[0].commandType == requestedCommand) {
                commandAlreadyQueued = 1;
                break;
            }
        }
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0 &&
            trickyShouldGoToWarpPoint(obj, (TrickyState*)state) == 2) {
            trickyState->stateIndex = TRICKY_STATE_GO_TO_WARP_POINT;
        } else if (trickyState->stateIndex == TRICKY_STATE_GUARD && requestedCommand == TRICKY_COMMAND_TYPE_FLAME) {
            trickyState->guardCanSpawnHelpers = trickyState->guardCanSpawnHelpers ^ 1;
        } else if (trickyState->stateIndex == TRICKY_STATE_CIRCLING && requestedCommand == TRICKY_COMMAND_TYPE_FLAME &&
                   commandAlreadyQueued == 0) {
            trickyState->flameCommandPending = 1;
        } else if (trickyState->stateIndex == TRICKY_STATE_GROWL && requestedCommand == TRICKY_COMMAND_TYPE_FLAME) {
            trickyState->flameCommandPending = 1;
        } else if (requestedCommand == TRICKY_COMMAND_TYPE_CALL) {
            trickyState->stateFlags |= TRICKY_STATE_HEEL_RECALL_REQUEST_FLAGS;
        } else {
            flags = trickyState->stateFlags;
            if ((flags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                switch (requestedCommand) {
                case TRICKY_COMMAND_TYPE_FIND_SECRET:
                    trickyState->commandPhase = TRICKY_COMMAND_PHASE_DIG;
                    trickySelectQueuedCommandTarget(trickyState, TRICKY_COMMAND_TYPE_FIND_SECRET);
                    TRICKY_VOICE(obj, 0x13c, 0);
                    switch (trickyState->followObj->anim.romDefNo) {
                    case SKEETLA_LINKED_SOURCE_ID_OBJ_A:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case SKEETLA_LINKED_SOURCE_ID_OBJ_B:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_DIG_TUNNEL;
                        }
                        break;
                    case TRICKY_OBJ_BLUE_MUSHROOM:
                    case TRICKY_TARGET_OBJ_LINK_BLUE_MUSHROOM:
                    case TRICKY_TARGET_OBJ_TUMBLEWEED2:
                    case TRICKY_TARGET_OBJ_SH_WHITEMUSHROOM:
                        trickyState->stateIndex = TRICKY_STATE_MOVE_TO_FOLLOW_TARGET;
                        break;
                    case TRICKY_TARGET_OBJ_NW_MAMMOTH:
                        if (trickyState->stats->energy < 2) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_TRACK_TUMBLEWEED;
                        }
                        break;
                    case TRICKY_TARGET_OBJ_DFP_TRANSLA:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                TRICKY_RESET_COMMAND(state);
                                TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case 0x358:
                        trickyState->stateIndex = TRICKY_STATE_GROWL;
                        break;
                    default:
                        TRICKY_RESET_COMMAND(state);
                        trickyReportError(debugTextBase + TRICKY_DBG_COMMAND_WRONG_OBJECT);
                        break;
                    }
                    break;
                case TRICKY_COMMAND_TYPE_STAY:
                    accepted = 0;
                    if (trickyState->commandPhase == TRICKY_COMMAND_PHASE_GUARD) {
                        commandCursorAddr = state;
                        count = trickyState->commandCount;
                        for (i = 0; i < count; i++, commandCursorAddr += sizeof(TrickyCommand)) {
                            if (((TrickyState*)commandCursorAddr)->commands[0].commandType ==
                                TRICKY_COMMAND_TYPE_STAY) {
                                accepted = 1;
                            }
                        }
                    } else {
                        accepted = 1;
                    }
                    if (accepted != 0) {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_GUARD;
                        if (trickySelectQueuedCommandTarget(trickyState, TRICKY_COMMAND_TYPE_STAY) != 0) {
                            switch (trickyState->followObj->anim.romDefNo) {
                            case TRICKY_TARGET_OBJ_WCTEMPLE_PRESSURE:
                            case TRICKY_TARGET_OBJ_STAY_POINT:
                            case TRICKY_TARGET_OBJ_CF_DOOR_LIGHT:
                            case TRICKY_TARGET_OBJ_LINK_SNOW_PRESSURE:
                            case TRICKY_TARGET_OBJ_SH_PRESSURE:
                            case TRICKY_TARGET_OBJ_DR_COLLAPSE:
                            case TRICKY_TARGET_OBJ_VFP_PUZZLE_POINT:
                            case TRICKY_TARGET_OBJ_SC_PRESSURE:
                                trickyState->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                                trickyState->idleSfxTimer = (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES,
                                                                                     TRICKY_IDLE_VOICE_MAX_FRAMES);
                                break;
                            case TRICKY_TARGET_OBJ_TRICKY_GUARD:
                                trickyState->stateIndex = TRICKY_STATE_GROWL;
                                break;
                            default:
                                trickyState->stateIndex = TRICKY_STATE_GUARD;
                                break;
                            }
                        } else {
                            trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
                        }
                    }
                    break;
                case TRICKY_COMMAND_TYPE_FLAME:
                    if (trickyState->stats->energy < 4) {
                        if ((u8)Obj_CanSetupObject()) {
                            trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                            TRICKY_RESET_COMMAND(state);
                            TRICKY_SPAWN_FOOD_BUBBLE(obj, state);
                        }
                    } else {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_FLAME;
                        trickySelectQueuedCommandTarget(trickyState, TRICKY_COMMAND_TYPE_FLAME);
                        trickyState->stateIndex = TRICKY_STATE_FLAME;
                        switch (trickyState->followObj->anim.romDefNo) {
                        case TRICKY_TARGET_OBJ_DIM_ICE_WALL:
                            trickyState->actionCallback = dimicewall_countdownCallback;
                            break;
                        case TRICKY_TARGET_OBJ_DIM_TRUTH_HORN:
                            trickyState->actionCallback = dimtruthhornice_countdownCallback;
                            break;
                        case TRICKY_TARGET_OBJ_VFP_FLAMEPOINT:
                            trickyState->actionCallback = vfpflamepoint_countdownCallback;
                            break;
                        case TRICKY_TARGET_OBJ_DIM_LOG_FIRE:
                            trickyState->actionCallback = dimlogfire_countdownCallback;
                            break;
                        case TRICKY_TARGET_OBJ_DR_CHIMMEY:
                            trickyState->actionCallback = drchimmey_countdownCallback;
                            break;
                        case TRICKY_TARGET_OBJ_CCEYE_VINES:
                        case TRICKY_TARGET_OBJ_BURNABLE_VINE:
                        case TRICKY_TARGET_OBJ_ARW_TIMED_MIN:
                        case TRICKY_TARGET_OBJ_MS_PLANTING_SEED:
                        case TRICKY_TARGET_OBJ_ICE_HOLE:
                            trickyState->actionCallback = NULL;
                            break;
                        case TRICKY_TARGET_OBJ_SH_BEACON:
                            trickyState->actionCallback = (TrickyActionCallback)sh_beacon_resetFadeTimerCallback;
                            break;
                        case TRICKY_TARGET_OBJ_WC_BEACON:
                            trickyState->actionCallback = (TrickyActionCallback)wcbeacon_aButtonCallback;
                            break;
                        default:
                            TRICKY_RESET_COMMAND(state);
                            trickyReportError(debugTextBase + TRICKY_DBG_COMMAND_WRONG_OBJECT);
                            break;
                        }
                    }
                    break;
                case TRICKY_COMMAND_TYPE_THROW_BALL:
                    if ((u8)Obj_CanSetupObject()) {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_FETCH_BALL;
                        placementSetup = Obj_AllocObjectSetup(0x18, TRICKY_CHILD_OBJ_SIDEKICK_BALL);
                        placementSetup->color[3] = 0xff;
                        placementSetup->color[0] = 2;
                        placementSetup->posX = obj->anim.worldPosX;
                        placementSetup->posY = obj->anim.worldPosY;
                        placementSetup->posZ = obj->anim.worldPosZ;
                        trickyState->followObj =
                            objSetupObject((ObjPlacement*)placementSetup, 5, -1, -1, obj->anim.parent);
                        targetPos = &trickyState->followObj->anim.worldPosX;
                        if (trickyState->targetPosPtr != targetPos) {
                            trickyState->targetPosPtr = targetPos;
                            {
                                u32 mask;
                                u32 flags = trickyState->stateFlags;
                                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                                trickyState->stateFlags = flags & mask;
                            }
                            trickyState->linkedWalkGroup = 0;
                        }
                        trickyState->substate = 0;
                        trickyState->stateIndex = TRICKY_STATE_FETCH_BALL;
                    }
                    break;
                default:
                    if (trickyState->stateIndex == TRICKY_STATE_FOLLOW_PLAYER &&
                        trickyState->commandPhase != TRICKY_COMMAND_PHASE_NONE &&
                        (flags & TRICKY_STATE_FLAG_HEEL_REQUEST) == 0) {
                        nearestBaddie =
                            trickyFindNearestUsableBaddie(trickyState->playerObj, TRICKY_TIMER_150_FRAMES, 0);
                        if (nearestBaddie != NULL) {
                            trickyState->followObj = nearestBaddie;
                            if (trickyState->targetPosPtr != &nearestBaddie->anim.worldPosX) {
                                trickyState->targetPosPtr = &nearestBaddie->anim.worldPosX;
                                {
                                    u32 mask;
                                    u32 flags = trickyState->stateFlags;
                                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                                    trickyState->stateFlags = flags & mask;
                                }
                                trickyState->linkedWalkGroup = 0;
                            }
                            trickyState->stateIndex = TRICKY_STATE_CIRCLING;
                            trickyState->substate = 0;
                            trickyState->flameCommandPending = 0;
                        }
                    }
                    break;
                }
            } else if (requestedCommand == TRICKY_COMMAND_TYPE_STAY) {
                trickyState->stateFlags = flags | (u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            }
        }
    }
    flags = trickyState->stateFlags;
    if ((flags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if ((flags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) {
            if ((flags & TRICKY_STATE_FLAG_HEEL_REQUEST) != 0) {
                TRICKY_RESET_COMMAND(state);
                trickyState->commandPhase = TRICKY_COMMAND_PHASE_NONE;
            } else {
                TRICKY_RESET_COMMAND(state);
            }
            trickyState->cooldownA = TRICKY_RECALL_COOLDOWN_FRAMES;
        } else if ((flags & TRICKY_STATE_FLAG_GUARD_REQUEST) != 0) {
            trickyState->followObj = obj;
            trickyState->stateIndex = TRICKY_STATE_IDLE_WANDER;
            trickyState->idleSfxTimer =
                (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_FLAG_GUARD_REQUEST;
                trickyState->stateFlags = flags & mask;
            }
            trickyState->commandPhase = TRICKY_COMMAND_PHASE_GUARD;
            if (trickyState->targetPosPtr != &trickyState->wanderTargetX) {
                trickyState->targetPosPtr = &trickyState->wanderTargetX;
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    trickyState->stateFlags = flags & mask;
                }
                trickyState->linkedWalkGroup = 0;
            }
        }
    }
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    trickyState->heightUpdateActive = 1;
    ((TrickyStateHandler*)(debugTextBase + TRICKY_HANDLER_TABLE_OFFSET))[trickyState->stateIndex](obj, (void*)state);
    trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_STUCK_VOICE_PENDING;
    trickyState->animTransitionTimer += timeDelta;
    if (trickyState->animTransitionTimer > TRICKY_ANIM_TRANSITION_FRAMES) {
        if (obj->anim.currentMove != trickyState->moveId) {
            if ((trickyState->pendingStateFlags & TRICKY_MOVE_FLAG_KEEP_PROGRESS) != 0 &&
                (trickyState->stateFlags & TRICKY_MOVE_FLAG_KEEP_PROGRESS) != 0) {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, obj->anim.currentMoveProgress, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, gTrickyFloatZero, 0);
            }
            trickyState->stateFlags &= ~TRICKY_MOVE_ACTIVE_FLAG_MASK;
            trickyState->stateFlags |= trickyState->pendingStateFlags;
            trickyState->animTransitionTimer = gTrickyFloatZero;
            trickyState->moveProgress = trickyState->moveProgressTarget;
        }
    }
    if ((trickyState->stateFlags & TRICKY_MOVE_FLAG_ROOT_TRANSLATE) != 0) {
        obj->anim.localPosX += timeDelta * (trickyState->dirX * trickyState->speed);
        obj->anim.localPosZ += timeDelta * (trickyState->dirZ * trickyState->speed);
        ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, trickyState->speed, &trickyState->moveProgress);
    }
    moveProgress = trickyState->moveProgress;
    zero = gTrickyFloatZero;
    if (moveProgress == zero) {
        ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, trickyState->arcMoveProgress);
    }
    if (ObjAnim_AdvanceCurrentMove(obj, trickyState->moveProgress, timeDelta, (void*)&trickyState->animEvents) != 0) {
        trickyState->stateFlags |= TRICKY_STATE_FLAG_MOVE_ADVANCING_WIDE;
    } else {
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_MOVE_ADVANCING_WIDE;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_ROTATE) != 0) {
        int rotationDiff;
        int rotationStep;

        rotationDiff = trickyState->targetYaw - (u16)obj->anim.rotX;
        if (rotationDiff > 0x8000) {
            rotationDiff -= 0xffff;
        }
        if (rotationDiff < -0x8000) {
            rotationDiff += 0xffff;
        }
        rotationStep = (int)((f32)trickyState->animEvents.rootPitch * trickyState->rotStepScale);
        if ((rotationDiff >= 0 ? rotationDiff : -rotationDiff) >= 4) {
            if ((rotationStep > 0 && rotationDiff > 0) || (rotationStep < 0 && rotationDiff < 0)) {
                if ((rotationStep >= 0 ? rotationStep : -rotationStep) >
                    (rotationDiff >= 0 ? rotationDiff : -rotationDiff)) {
                    obj->anim.rotX += rotationDiff;
                } else {
                    obj->anim.rotX += rotationStep;
                }
            } else {
                obj->anim.rotX += rotationStep;
            }
        } else {
            obj->anim.rotX += rotationDiff;
        }
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_BACKSTEP) != 0) {
        obj->anim.localPosX += trickyState->backstepDelta * (trickyState->dirX * -trickyState->animEvents.rootDeltaZ);
        obj->anim.localPosZ += trickyState->backstepDelta * (trickyState->dirZ * -trickyState->animEvents.rootDeltaZ);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_VERTICAL_MOVE) != 0) {
        obj->anim.localPosY += trickyState->animEvents.rootDeltaY * trickyState->verticalDelta;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SIDESTEP) != 0) {
        obj->anim.localPosX += trickyState->sidestepDelta * (trickyState->dirZ * trickyState->animEvents.rootDeltaX);
        obj->anim.localPosZ += trickyState->sidestepDelta * (trickyState->dirX * -trickyState->animEvents.rootDeltaX);
    }
    if (trickyState->followObj != NULL) {
        trickyState->eyeAnimState.lookAtActive = 1;
        trickyState->eyeAnimState.lookAtPosX = trickyState->followObj->anim.worldPosX;
        trickyState->eyeAnimState.lookAtPosY = trickyState->followObj->anim.worldPosY;
        trickyState->eyeAnimState.lookAtPosZ = trickyState->followObj->anim.worldPosZ;
    } else {
        trickyState->eyeAnimState.lookAtActive = 0;
    }
    if (obj->anim.currentMove == 0x2a) {
        characterHeadLookRelax(obj, &trickyState->eyeAnimState);
        characterCloseEyes(obj, &trickyState->eyeAnimState);
    } else {
        characterUpdateHeadLook(obj, &trickyState->eyeAnimState, gTrickyFloatZero);
        characterDoEyeAnims(obj, &trickyState->eyeAnimState);
    }
    objSoundUpdateMouth(obj, &trickyState->soundState);
    {
        f32* pathCursor;
        TrickyState* pathState;

        pathState = obj->extra;
        pathCursor = pathState->targetPosPtr;
        pathState->previousPathPoint = pathCursor;
        if (pathState->previousPathPoint != NULL) {
            pathState->previousPathX = pathCursor[0];
            pathState->previousPathY = pathCursor[1];
            pathState->previousPathZ = pathCursor[2];
        }
    }
    trickyState->prevSpeed = trickyState->speed;
    i = trickyState->commandCount - 1;
    {
        u8* expiringCommandCursor = (u8*)state + i * sizeof(TrickyCommand);

        for (; i >= 0; expiringCommandCursor -= sizeof(TrickyCommand), i--) {
            s8* ttlFrames = (s8*)&((TrickyState*)expiringCommandCursor)->commands[0].ttlFrames;

            *ttlFrames -= 1;
            if (*ttlFrames == 0) {
                memmove(&((TrickyState*)expiringCommandCursor)->commands[0],
                        &((TrickyState*)(state + (i + 1) * sizeof(TrickyCommand)))->commands[0],
                        (trickyState->commandCount - i - 1) * sizeof(TrickyCommand));
                trickyState->commandCount -= 1;
            }
        }
    }
    if (getXZDistanceSquared(&obj->anim.worldPosX, &trickyState->playerObj->anim.worldPosX) >=
            TRICKY_REMOTE_RECALL_DISTANCE_SQ &&
        mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0) {
        trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
    trickyState->cooldownC -= timeDelta;
    if (trickyState->cooldownC < gTrickyFloatZero) {
        trickyState->cooldownC = gTrickyFloatZero;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FOOD_WARNING_PENDING) != 0) {
        voiceState = obj->extra;
        if (voiceState->soundSuppressed != 0) {
            accepted = 0;
        } else {
            switch (obj->anim.currentMove) {
            case 0x29:
            case 0x2a:
            case 0x2b:
            case 0x2c:
            case 0x2d:
            case 0x2e:
            case 0x2f:
                accepted = 0;
                break;
            default:
                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) != 0) {
                    accepted = 0;
                } else {
                    objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_TIRED, 0x500, 0xffffffff, 0);
                    accepted = 1;
                }
                break;
            }
        }
        if (accepted != 0) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
        }
    }
    trickyState->voiceCooldown -= timeDelta;
    if (trickyState->voiceCooldown < gTrickyFloatZero) {
        trickyState->voiceCooldown = gTrickyFloatZero;
    }
    if (trickyState->voiceCooldown > gTrickyFloatZero) {
        TRICKY_VOICE(obj, 0x29c, 0x100);
    }
    trickyUpdateCollisionAndPathState(obj);
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_IMPRESS_PENDING_U32) != 0) {
        trickyState->impressTimer -= timeDelta;
        if (trickyState->impressTimer <= gTrickyFloatZero) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_IMPRESS_PENDING_U32;
            impressSfxId = ((u16*)&impressSfxPair)[randomGetRange(0, 1)];
            TRICKY_VOICE(obj, impressSfxId, 0x500);
        }
    }
    trickyUpdateColorVariant(obj, (TrickyState*)state);
    Tricky_updateBlendChannelWeight(obj, (TrickyState*)state);
    if (trickyState->speed > TRICKY_AUDIO_EVENT_MIN_SPEED) {
        objAudioDispatchAnimEvents(obj, &trickyState->animEvents, 1, trickyState->footPoints,
                                   &trickyState->pathControlFlags, trickyState->speed, TRICKY_FLOAT_ONE);
    }
    if (gTrickyFloatZero == trickyState->waterLevel) {
        waterFootstepActive = 0;
    } else if (gTrickyEventTimeSentinel == trickyState->eventTime) {
        waterFootstepActive = 1;
    } else if (trickyState->currentTime - trickyState->eventTime > gTrickyEventStaleSeconds) {
        waterFootstepActive = 1;
    } else {
        waterFootstepActive = 0;
    }
    if (waterFootstepActive != 0) {
        ObjAnimEventList* events;
        int waterFootstepSfxId;

        events = &trickyState->animEvents;
        waterFootstepSfxId = 0;
        for (i = 0, count = events->triggerCount; i < count; i++) {
            switch (events->triggeredIds[i]) {
            case 0:
            case 1:
            case 2:
                waterFootstepSfxId = 0x433;
                break;
            }
        }
        if (waterFootstepSfxId != 0) {
            Sfx_PlayFromObject(obj, (u16)waterFootstepSfxId);
        }
    }
    trickyState->prevLocalPosX = obj->anim.previousLocalPosX;
    trickyState->prevLocalPosY = obj->anim.previousLocalPosY;
    trickyState->prevLocalPosZ = obj->anim.previousLocalPosZ;
    if (trickyState->child != NULL) {
        trickyState->childPhaseTimer0 += timeDelta;
        trickyState->childPhaseTimer1 += timeDelta;
        trickyState->childPhaseTimer2 += timeDelta;
        if (trickyState->childPhaseTimer2 > TRICKY_CHILD_BLINK_PERIOD_FRAMES) {
            trickyState->childPhaseTimer2 -= TRICKY_CHILD_BLINK_PERIOD_FRAMES;
        }
        if (trickyState->childPhaseTimer2 >= TRICKY_CHILD_BLINK_HOLD_FRAMES) {
            trickyState->child->anim.flags = trickyState->child->anim.flags | 0x4000;
        } else {
            trickyState->child->anim.flags = trickyState->child->anim.flags & ~0x4000;
        }
        if (trickyState->childPhaseTimer1 > TRICKY_CHILD_BLINK_FORCE_FRAMES) {
            if (trickyState->childPhaseTimer1 > TRICKY_TIMER_600_FRAMES) {
                trickyState->childPhaseTimer1 -= TRICKY_TIMER_600_FRAMES;
            }
            trickyState->child->anim.flags = trickyState->child->anim.flags | 0x4000;
        }
        if (trickyState->childPhaseTimer0 > TRICKY_CHILD_VOICE_PERIOD_FRAMES) {
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
                TRICKY_VOICE(obj, TRICKY_VOICE_SFX_SCARED, 0x500);
            } else {
                TRICKY_VOICE(obj, TRICKY_VOICE_SFX_TIRED, 0x500);
            }
            trickyState->childPhaseTimer0 -= TRICKY_CHILD_VOICE_PERIOD_FRAMES;
        }
        ObjAnim_AdvanceCurrentMove(trickyState->child, TRICKY_FLOAT_0_01, timeDelta, 0);
    }
    if (trickyState->childB != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->childB, TRICKY_FLOAT_0_01, timeDelta, 0);
    }
    if (trickyState->childA != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->childA, TRICKY_FLOAT_0_01, timeDelta, 0);
    }
}

void Tricky_init(GameObject* obj) {
    TrickyState* state;
    ObjModel* model;
    int pathState;
    u32 colorVariant;
    u16 startPath[4];

    state = obj->extra;
    startPath[0] = gTrickyInitialPathControlStartId[0];
    mainSetBits(GAMEBIT_TrickyTalk, 0xff);
    if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
        mainSetBits(GAMEBIT_ITEM_TrickyBall_Usable, 1);
    }
    (obj)->animEventCallback = tricky_SeqFn;
    objAddObjectType(obj, TRICKY_OBJGROUP);
    pathSearchInit(&state->pathSearches[0]);
    pathSearchInit(&state->pathSearches[1]);
    pathSearchInit(&state->pathSearches[2]);
    pathSearchInit(&state->pathSearches[3]);
    pathSearchInit(&state->pathSearches[4]);
    pathSearchInit(&state->pathSearches[5]);
    pathSearchInit(&state->pathSearches[6]);
    pathSearchInit(&state->pathSearches[7]);
    pathSearchInit(&state->pathSearches[8]);
    state->stats = (*gMapEventInterface)->getTrickyStats();
    state->playerObj = Obj_GetPlayerObject();
    state->stateIndex = TRICKY_STATE_ATTACH_TO_WALKGROUP;
    state->commandRequestBits = 0;
    state->previousPathPoint = NULL;
    state->activeWalkGroup = 0;
    state->homePosX = (obj)->anim.worldPosX;
    state->homePosY = (obj)->anim.worldPosY;
    state->homePosZ = (obj)->anim.worldPosZ;
    colorVariant = state->stats->ballReturnCount / TRICKY_BALL_RETURNS_PER_COLOR;
    state->colorVariant = colorVariant;
    model = Obj_GetActiveModel(obj);
    model->textureRefs->swapSelector = state->colorVariant;
    pathState = (int)&state->pathControlFlags;
    (*gPathControlInterface)->init((void*)pathState, 1, 0xa7, 1);
    (*gPathControlInterface)
        ->setLocalPointCollision((void*)pathState, 1, gTrickyPathPointCollision.point, &gTrickyPathPointCollisionRadius,
                                 2);
    (*gPathControlInterface)
        ->setup((void*)pathState, 2, gTrickyDebugStringTable, gTrickyPathControlSetupParams, startPath);
    (*gPathControlInterface)->attachObject((void*)obj, (void*)pathState);
    doNothing_onTrickyInit();
    Objfsa_UpdateWalkGroupPatches();
    state->groundSnapCounter = 2;
    state->blendPending = 1;
    state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
}

void trickyReportError(const char* fmt, ...) {
}

void trickyDebugPrint(const char* fmt, ...) {
}

/* pooled sidekick-command debug format strings with embedded NUL padding. */
char sSidekickCommandDebugTextBlock[] = "sideCommandEnable warning: need to increase MAX_COMM_PRESENT\n"
                                        "\0\0\0"
                                        "hits: %d %d %d %d %d %d %d %d"
                                        "\0\0\0"
                                        "\nEnergy: %d/%d\n"
                                        "\0"
                                        "find command used on the wrong object\n"
                                        "\0\0\0\0\0";

const u32 gTrickyLiteralPoolPadding = 0;
