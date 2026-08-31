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
#include "dolphin/pad.h"
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

typedef union {
    u32 raw;
    u16 ids[2];
} TrickyPackedSfxPair;

typedef struct TrickyBaddieTargetPlacement {
    u8 pad0[0x14];
    s32 mapEventId;
    s16 disableGameBit;
    s16 enableGameBit;
} TrickyBaddieTargetPlacement;

STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, mapEventId) == 0x14);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, disableGameBit) == 0x18);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, enableGameBit) == 0x1A);

/* Tricky voice trigger ids, with unnamed ids decoded against retail audio/data/Sfx.bin. */
#define TRICKY_VOICE_SFX_FIND_SECRET_SNIFF     0x13c /* SFXnewtricky_01j, distinct trigger params */
#define TRICKY_VOICE_SFX_TIRED                 0x298
#define TRICKY_VOICE_SFX_GROWL                 0x299
#define TRICKY_VOICE_SFX_SLEEP_BREATH          0x29a /* SFXsk_trbrth2/3, SFXsk_trgrwl1/2 */
#define TRICKY_VOICE_SFX_ROLLING               0x29b
#define TRICKY_VOICE_SFX_TOY_BARK              0x29c /* SFXsk_toysq2_c, SFXsk_trbark1/2 */
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
#define TRICKY_VOICE_SFX_SNORE_IN              0x390
#define TRICKY_VOICE_SFX_SNORE_OUT             0x391
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
#define TRICKY_PARTFX_HOWL_SPARKLE       0x7f0
#define TRICKY_TURN_LARGE_ANGLE          0x3555
#define TRICKY_TURN_MEDIUM_ANGLE         0x2000
#define TRICKY_WATER_FOOTSTEP_SFX_ID     0x433
#define TRICKY_COMMAND_TTL_FRAMES        3

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
#define TRICKY_STATE_CHILD_ACTIVITY_FLAGS         (TRICKY_STATE_FLAG_CHILDREN_ACTIVE | TRICKY_STATE_FLAG_CHILDREN_CLEANUP)

#define TRICKY_MOVE_FLAG_KEEP_PROGRESS        0x01000000
#define TRICKY_MOVE_FLAG_ROOT_TRANSLATE       0x02000000
#define TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION 0x04000000
#define TRICKY_MOVE_FLAG_WALK_LOOP            (TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_MOVE_FLAG_ROOT_TRANSLATE)
#define TRICKY_MOVE_FLAG_JUMP_ARC                                                                                      \
    (TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION | TRICKY_STATE_FLAG_BACKSTEP | TRICKY_STATE_FLAG_VERTICAL_MOVE)
#define TRICKY_MOVE_ACTIVE_FLAG_MASK 0x060001e0LL

static inline GameObject** trickyFlameChildSlotFromStateCursor(void* cursor) {
    return &((TrickyState*)cursor)->flameChildren[0];
}

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

void objAnimFreeChildren(GameObject* obj, TrickyState* state, GameObject** childRef) {
    char buf[4];
    void* exclamationPromptChild;
    void* questPromptChild;
    void* foodChild;

    if (*childRef == NULL) {
        return;
    }
    ObjLink_DetachChild(obj, *childRef);
    Obj_FreeObject(*childRef);
    *childRef = NULL;
    buf[0] = -1;
    buf[1] = -1;
    buf[2] = -1;
    exclamationPromptChild = state->exclamationPromptChild;
    if (exclamationPromptChild != NULL) {
        buf[state->packedSlots.exclamationPromptSlot] = 1;
    }
    questPromptChild = state->questPromptChild;
    if (questPromptChild != NULL) {
        buf[state->packedSlots.questPromptSlot] = 1;
    }
    foodChild = state->foodChild;
    if (foodChild != NULL) {
        buf[state->packedSlots.foodChildSlot] = 1;
    }
    if (buf[0] == -1) {
        if (exclamationPromptChild != NULL) {
            ObjLink_DetachChild(obj, exclamationPromptChild);
            ObjLink_AttachChild(obj, state->exclamationPromptChild, 0);
            state->packedSlots.exclamationPromptSlot = 0;
        } else if (questPromptChild != NULL) {
            ObjLink_DetachChild(obj, questPromptChild);
            ObjLink_AttachChild(obj, state->questPromptChild, 0);
            state->packedSlots.questPromptSlot = 0;
        } else if (foodChild != NULL) {
            ObjLink_DetachChild(obj, foodChild);
            ObjLink_AttachChild(obj, state->foodChild, 0);
            state->packedSlots.foodChildSlot = 0;
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

const f32 gTrickyTimer20Frames[] = {20.0f};
static const f32 sTrickyColorFadeAlphaScale[] = {196.0f};
const f32 gTrickyEventTimeSentinel[] = {-100000.0f};
const f32 gTrickyEventStaleSeconds[] = {8.0f};
const f32 gTrickyMaxDistance[] = {340282346638528859811704183484516925440.0f};
const f32 gTrickySpeedDecayStep[] = {-0.15f};
const f32 gTrickySmallSpeedStep[] = {0.05f};
static const f32 sTrickyFloat100[] = {100.0f};
static const f32 sTrickyFloatNeg0_17[] = {-0.17f};
static const f32 sTrickyFloat40[] = {40.0f};
static const f32 sTrickyFloat400[] = {400.0f};
static const f32 sTrickyFloat0_014[] = {0.014f};
static const f32 sTrickyFloat300[] = {300.0f};
const f32 gTrickyFastMoveBlendSpeed[] = {0.02f};
const f32 gTrickyTimer600Frames[] = {600.0f};
const f32 gTrickyLandMoveBlendSpeed[] = {0.005f};
const f32 gTrickyRouteReverseStep[] = {-2.0f};
const f32 gTrickyRouteLookaheadScale[] = {1.5f};
const f32 gTrickyYawStepRate[] = {512.0f};
const f32 gTrickyPi[] = {3.1415927f};
const f32 gTrickyAngleHalfTurnUnits[] = {32768.0f};

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
        f32 fadeTimer;
        if (mainGetBit(TRICKY_COLOR_CHANGE_SEEN_GAMEBIT) == 0) {
            mainSetBits(TRICKY_COLOR_CHANGE_SEEN_GAMEBIT, 1);
            (*gObjectTriggerInterface)->runSequence(TRICKY_COLOR_CHANGE_SEQUENCE_ID, obj, -1);
            state->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
            state->colorFadeTimer += TRICKY_TIMER_20_FRAMES;
        }
        state->colorFadeTimer -= timeDelta;
        fadeTimer = state->colorFadeTimer;
        if (!(fadeTimer > TRICKY_TIMER_20_FRAMES)) {
            if (fadeTimer > gTrickyFloatZero) {
                f32 alpha;
                if (fadeTimer > TRICKY_FLOAT_TEN) {
                    alpha = 1.0f - (fadeTimer - TRICKY_FLOAT_TEN) / TRICKY_FLOAT_TEN;
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
    TrickyState* state = obj->extra;
    return state->speed;
}

GameObject* trickyGetStayPoint(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->followObj;
}
int trickyGetAimPitchOffset(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->modelAnchorRotY;
}
f32* trickyGetQueuedPathParticlePos(GameObject* obj) {
    TrickyState* state = obj->extra;
    return &state->renderPosX;
}

GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes) {
    GameObject** baddieCursor;
    GameObject** baddieList;
    GameObject* closestBaddie;
    int baddieIndex;
    f32 bestDistSq;
    int baddieCount;

    bestDistSq = maxRadius;
    closestBaddie = 0;
    baddieList = (GameObject**)objGetAllOfType(TRICKY_BADDIE_OBJGROUP, &baddieCount);
    bestDistSq = bestDistSq * bestDistSq;
    baddieIndex = 0;
    baddieCursor = baddieList;

    for (; baddieIndex < baddieCount; baddieCursor++, baddieIndex++) {
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
    PartFxSpawnParams particleParams;
    u8 spawnCount = 0x14;
    u32 flags = state->stateFlags;
    if ((flags & TRICKY_STATE_CHILD_ACTIVITY_FLAGS) == 0) {
        return;
    }
    particleParams.posX = state->renderPosX - obj->anim.worldPosX;
    particleParams.posY = state->renderPosY - obj->anim.worldPosY;
    particleParams.posZ = state->renderPosZ - obj->anim.worldPosZ;
    particleParams.scale = 1.0f;
    particleParams.rotX = obj->anim.rotX;
    particleParams.rotY = obj->anim.rotY;
    particleParams.rotZ = obj->anim.rotZ;
    if ((flags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
        while (spawnCount-- != 0) {
            (*gPartfxInterface)->spawnObject(obj, TRICKY_PATH_PARTFX, &particleParams, 2, -1, NULL);
        }
        state->stateFlags = state->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
    }
}

int trickySelectQueuedCommandTarget(TrickyState* state, enum TrickyCommandType commandType) {
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    TrickyState* commandCursor;
    int commandIndex;
    GameObject* bestPriorityTarget;
    GameObject* bestFallbackTarget;

    bestPriorityDist = gTrickyMaxDistance;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (commandIndex = 0, commandCursor = state; commandIndex < state->commandCount;
         commandCursor = (TrickyState*)((u8*)commandCursor + sizeof(TrickyCommand)), commandIndex++) {
        if (commandCursor->commands[0].commandType == commandType) {
            f32 dist = getXZDistanceSquared(&state->playerObj->anim.worldPosX,
                                            &commandCursor->commands[0].targetObj->anim.worldPosX);

            if (commandCursor->commands[0].commandKind == TRICKY_COMMAND_KIND_PRIORITY) {
                if (dist < bestPriorityDist) {
                    bestPriorityDist = dist;
                    bestPriorityTarget = commandCursor->commands[0].targetObj;
                }
            } else if (dist < bestFallbackDist) {
                bestFallbackDist = dist;
                bestFallbackTarget = commandCursor->commands[0].targetObj;
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
#define TRICKY_ROUTE_CANDIDATE_COUNT              8
#define SKEETLA_LINKED_SOURCE_ROMDEF_GROUND_ANIMA 0x1ca
#define SKEETLA_LINKED_SOURCE_ROMDEF_WALL_ANIMATO 0x160
#define SKEETLA_PARTICLE_SPARK_A                  0xca
#define SKEETLA_PARTICLE_SPARK_B                  0xcb
#define SKEETLA_CONTACT_OBJ_PROJBALL              0x1f /* "projball" (DLL 0xE3) */

/* attacker romDefNo that triggers the staff-impact sfx (retail OBJECTS.bin). */
#define SKEETLA_ATTACKER_SEQID_STAFF 0x69
/* "staff" (DLL 0xE2) */
#define TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS 0x200001
#define TRICKY_HITMASK_ALL_SOURCES         0x7f
#define TRICKY_HITMASK_NO_LOW_SOURCE       0x7e

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
void trickyFlame(GameObject* obj, TrickyState* trickyState);
void trickyGuard(GameObject* obj, TrickyState* trickyState);
void tricky_moveToFollowTarget(GameObject* obj, TrickyState* state);
void tricky_idleAndEat(GameObject* obj, TrickyState* state);
void tricky_fetchBall(GameObject* obj, TrickyState* state);
void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state);
void trickyUpdateCircling(GameObject* obj, TrickyState* state);
void tricky_trackTumbleweed(GameObject* obj, TrickyState* state);

typedef void (*TrickyStateHandler)(GameObject* obj, TrickyState* state);
typedef int (*TrickySubstateHandler)(GameObject* obj, TrickyState* state);

typedef struct TrickyPathPointCollisionData {
    f32 point[3];
    TrickyStateHandler stateHandlers[18];
    TrickySubstateHandler substateHandlers[13];
} TrickyPathPointCollisionData;

typedef struct TrickyDebugCollisionData {
    char debugStrings[0x18];
    TrickyPathPointCollisionData pathPointCollision;
} TrickyDebugCollisionData;

STATIC_ASSERT(offsetof(TrickyPathPointCollisionData, point) == 0x0);
STATIC_ASSERT(offsetof(TrickyPathPointCollisionData, stateHandlers) == 0xC);
STATIC_ASSERT(offsetof(TrickyPathPointCollisionData, substateHandlers) == 0x54);
STATIC_ASSERT(sizeof(TrickyPathPointCollisionData) == 0x88);
STATIC_ASSERT(offsetof(TrickyDebugCollisionData, debugStrings) == 0x0);
STATIC_ASSERT(offsetof(TrickyDebugCollisionData, pathPointCollision) == 0x18);
STATIC_ASSERT(offsetof(TrickyDebugCollisionData, pathPointCollision.stateHandlers) == 0x24);
STATIC_ASSERT(offsetof(TrickyDebugCollisionData, pathPointCollision.substateHandlers) == 0x6c);

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
        tricky_attachToWalkGroup,
        tricky_stateFollowPlayer,
        tricky_stateFindSecretDig,
        trickyDigTunnel,
        (TrickyStateHandler)tricky_state04_nop,
        tricky_updateBallRoll,
        (TrickyStateHandler)tricky_state06_nop,
        trickyFlame,
        trickyGuard,
        tricky_moveToFollowTarget,
        tricky_idleAndEat,
        tricky_fetchBall,
        trickyUpdateCirclingTargetPosition,
        trickyUpdateCircling,
        trickyGrowl,
        tricky_stateIdleWander,
        tricky_trackTumbleweed,
        tricky_stateGoToWarpPoint,
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
    (ObjectDescriptorCallback)Tricky_getCurrentCommandPhase,
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

static void skeetla_faceMoveVector(GameObject* obj) {
    s16 ignoredTurnDelta;

    skeetla_updateFacingFromMoveVector(obj, &ignoredTurnDelta);
}

const f32 gTrickyAvoidanceRepathEpsilonSq[] = {0.0001f};
const f32 gTrickyRunMoveThreshold[] = {2.5f};
const f32 gTrickyFastWalkMoveThreshold[] = {0.66f};
const f32 gTrickySlowWalkMoveThreshold[] = {0.33f};
const f32 gTrickyTurnMoveBlendSpeed[] = {0.04f};
const f32 gTrickyAnimTransitionFrames[] = {15.0f};

#define TRICKY_AVOIDANCE_REPATH_EPSILON_SQ (gTrickyAvoidanceRepathEpsilonSq[0])
#define TRICKY_TINY_MOVE_BLEND_SPEED       (gTrickyAvoidanceRepathEpsilonSq[0])
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
    s16 turnDeltaScratch;
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
        skeetla_updateFacingFromMoveVector(obj, &turnDeltaScratch);
        if (skeetla_isInWater(state) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_SWIM, TRICKY_TINY_MOVE_BLEND_SPEED, TRICKY_MOVE_FLAG_ROOT_TRANSLATE);
            state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
    u16 linkSlot;
    u16 candidateCount;
    u16 bestIndex;
    int curveId;
    s16 requiredBit;
    s16 forbiddenBit;

    linkSlot = 0;
    candidateCount = 0;
    mask = 1;
    while (linkSlot < 4) {
        curveId = routeDef->linkIds[linkSlot];
        if ((curveId > -1) && ((((routeDef->blockedLinkMask & mask) ^ routeFlagValue) == 0))) {
            candidates[candidateCount] = (*gRomCurveInterface)->getById(curveId);
            if (candidates[candidateCount] != NULL) {
                entry = candidates[candidateCount];
                if ((linkSelector == 0) || (routeDef->linkWalkGroups[candidateCount] == linkSelector)) {
                    requiredBit = entry->requiredBit;
                    if ((requiredBit == -1) || (mainGetBit(requiredBit) != 0)) {
                        forbiddenBit = entry->forbiddenBit;
                        if ((forbiddenBit == -1) || (mainGetBit(forbiddenBit) == 0)) {
                            if ((routeDef->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B) ||
                                (entry->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A)) {
                                candidateCount++;
                            }
                        }
                    }
                }
            }
        }
        linkSlot++;
        mask <<= 1;
        routeFlagValue <<= 1;
    }

    if (candidateCount != 0) {
        bestDistance = getXZDistanceSquared(&context->playerObj->anim.worldPosX, &candidates[0]->x);
        bestIndex = 0;
        for (linkSlot = 1; linkSlot < candidateCount; linkSlot++) {
            distance = getXZDistanceSquared(&context->playerObj->anim.worldPosX, &candidates[linkSlot]->x);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestIndex = linkSlot;
            }
        }

        return candidates[bestIndex];
    }
    return NULL;
}

RomCurveDef* trickyFindPathRouteEntry(TrickyState* state, RomCurveDef* route, int pathId) {
    if (pathId == 0) {
        return NULL;
    }

    if ((state->cachedPathId == pathId) && (state->cachedRouteEntry == route)) {
        state->cachedRouteEntry = pathSearchGetNextPoint(&state->pathSearches[8]);
        if (state->cachedRouteEntry == NULL) {
            return NULL;
        }

        state->cachedRouteEntry = skeetla_validateRouteEntry(state->cachedRouteEntry);
        if (state->cachedRouteEntry != NULL) {
            return (state)->cachedRouteEntry;
        }
    }

    pathSearchBegin(&state->pathSearches[8], route, state->targetPosPtr, pathId, state->route.reverse);
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
            pathSearchBegin(&((TrickyState*)beginSearchCursor)->pathSearches[0], *beginRouteCursor, state->targetPosPtr,
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
                *statusCursor = pathSearchStep(&((TrickyState*)searchCursor)->pathSearches[0], 1);
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
            entry = trickyFindPathRouteEntry(state, routeDef, state->walkGroup);
        }

        if (entry == NULL) {
            if (state->savedWalkGroup != 0) {
                entry =
                    trickyFindNearestLinkedRouteEntry(state, routeDef, state->savedWalkGroup, routeFlagValue & 0xff);
                if (entry == NULL) {
                    entry = trickyFindPathRouteEntry(state, routeDef, state->savedWalkGroup);
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
    int candidateSlot;
    RomCurveDef** allCurves;
    int linkCurveId;
    int curveCount;
    RomCurveDef** curveCursor;
    int curveIdx;
    RomCurveDef* linkedCurve;
    f32 curveX;
    f32 targetXDistanceSquared;
    f32 targetZDistanceSquared;
    f32 curveZ;
    f32* targetPos;
    f32 score;
    f32 initialBestDistance;
    RomCurveDef* curve;
    u8 routeSlot;
    u8 routeFlags;
    u8 shiftSlot;
    f32* bestDistanceCursor;
    RomCurveDef** bestRouteCursor;
    TrickyState* state;

    state = obj->extra;
    allCurves = (*gRomCurveInterface)->getCurves(&curveCount);

    initialBestDistance = gTrickyMaxDistance;
    bestDistanceCursor = bestDistances;
    bestRouteCursor = outRoutes;
    for (candidateSlot = 0; candidateSlot < TRICKY_ROUTE_CANDIDATE_COUNT; candidateSlot++) {
        *bestDistanceCursor++ = initialBestDistance;
        *bestRouteCursor++ = NULL;
    }

    if (linkSelector == 0) {
        return;
    }

    for (curveIdx = 0, curveCursor = allCurves; curveIdx < curveCount; curveCursor++, curveIdx++) {
        curve = *curveCursor;
        if ((curve->type != 0x24) || (curve->walkGroup != 0)) {
            continue;
        }
        if (((curve->requiredBit != -1) && (mainGetBit(curve->requiredBit) == 0)) ||
            ((curve->forbiddenBit != -1) && (mainGetBit(curve->forbiddenBit) != 0))) {
            continue;
        }

        curveZ = curve->z;
        targetPos = state->targetPosPtr;
        {
            targetZDistanceSquared = (targetPos[2] - curveZ) * (targetPos[2] - curveZ);
            curveX = curve->x;
            targetXDistanceSquared = (targetPos[0] - curveX) * (targetPos[0] - curveX);
            {
                f32 objectXDistanceSquared = (obj->anim.worldPosX - curveX) * (obj->anim.worldPosX - curveX);
                f32 objectZDistanceSquared = (obj->anim.worldPosZ - curveZ) * (obj->anim.worldPosZ - curveZ);
                score = targetZDistanceSquared +
                        (targetXDistanceSquared + (objectXDistanceSquared + objectZDistanceSquared));
            }
        }
        if (score < bestDistances[7]) {
            for (routeSlot = 0; routeSlot < 4; routeSlot++) {
                linkCurveId = curve->linkIds[routeSlot];
                if ((linkCurveId > -1) && (curve->linkWalkGroups[routeSlot] == linkSelector)) {
                    if (curve->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A) {
                        linkedCurve = (*gRomCurveInterface)->getById(linkCurveId);
                        if ((linkedCurve != NULL) && (linkedCurve->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B)) {
                            continue;
                        }
                    }

                    routeFlags = (u8)(curve->blockedLinkMask >> routeSlot);
                    break;
                }
            }

            if (routeSlot == 4) {
                continue;
            }

            for (routeSlot = 0; routeSlot < TRICKY_ROUTE_CANDIDATE_COUNT; routeSlot++) {
                if (score < bestDistances[routeSlot]) {
                    for (shiftSlot = 7; shiftSlot > routeSlot; shiftSlot--) {
                        outRouteFlags[shiftSlot] = outRouteFlags[shiftSlot - 1];
                        outRoutes[shiftSlot] = outRoutes[shiftSlot - 1];
                        bestDistances[shiftSlot] = bestDistances[shiftSlot - 1];
                    }

                    outRouteFlags[routeSlot] = (routeFlags & 1) ^ 1;
                    outRoutes[routeSlot] = curve;
                    bestDistances[routeSlot] = score;
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
    if (linkedObj->anim.romDefNo == SKEETLA_LINKED_SOURCE_ROMDEF_GROUND_ANIMA) {
        args.sourceId = (u8)((u32(*)(GameObject*))linkedObj->anim.dll[0][10])(linkedObj);
    } else if (linkedObj->anim.romDefNo == SKEETLA_LINKED_SOURCE_ROMDEF_WALL_ANIMATO) {
        args.sourceId = (u8)((u32(*)(GameObject*))linkedObj->anim.dll[0][10])(linkedObj);
    } else {
        args.sourceId = 0;
    }

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)
            ->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)
            ->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }

    args.x = state->sparkPos1X;
    args.y = state->sparkPos1Y;
    args.z = state->sparkPos1Z;
    args.objectId = obj->anim.rotX;

    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)
            ->spawnObject(obj, SKEETLA_PARTICLE_SPARK_A, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, SKEETLA_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)
            ->spawnObject(obj, SKEETLA_PARTICLE_SPARK_B, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }
}

const f32 gTrickyAvoidanceBlendStepScale[] = {0.125f};

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

const f32 gTrickyDefaultStoppingRadius[] = {5.0f};
const f32 gTrickyFollowMaxSpeed[] = {3.0f};
const f32 gTrickyFollowAnim17Speed[] = {0.0135f};
const f32 gTrickyFollowAnim18Speed[] = {0.00975f};
const f32 gTrickyFollowVerticalDeltaDivisorA[] = {32.865f};
const f32 gTrickyFollowJumpdownBlendSpeed[] = {0.0125f};
const f32 gTrickyFollowVerticalDeltaDivisorB[] = {33.114f};
const f32 gTrickyFollowArcSpeed[] = {2.3f};
const f32 gTrickyFollowArcHalfProgress[] = {0.5f};
const f32 gTrickyFollowArcQuarterProgress[] = {0.25f};
const f32 gTrickyFollowArcCoefficient[] = {-0.017f};
const f32 gTrickyFollowArcProgressWindow[] = {24.0f};
const f32 gTrickyFollowArcEndpointWindow[] = {6.0f};
const f32 gTrickyFollowArcMiddleWindow[] = {12.0f};
const f32 gTrickyFollowJumpLandSpeed[] = {0.75f};

#define TRICKY_DEFAULT_STOPPING_RADIUS (gTrickyDefaultStoppingRadius[0])

int trickyUpdateMovementState(GameObject* obj, f32 stoppingRadius, TrickyState* state) {
    TrickyState* cachedPatchIdCursor;
    TrickyState* cachedPatchTargetCursor;
    int targetPatchGroup;
    u8* patchInfoGroupCursor;
    TrickyState* cachedPatchIdWriteCursor;
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
    TrickyState* cachedPatchTargetWriteCursor;
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
        cachedPatchIdWriteCursor = state;
        cachedPatchTargetWriteCursor = state;
        for (; i < 4;
             patchInfoGroupCursor += sizeof(patchInfo.patchGroupIds[0]),
             cachedPatchIdWriteCursor = (TrickyState*)((u8*)cachedPatchIdWriteCursor + sizeof(state->patch[0])),
             cachedPatchTargetWriteCursor =
                 (TrickyState*)((u8*)cachedPatchTargetWriteCursor + sizeof(state->patchTargets[0])),
             i++, patchMaskBit <<= 1) {
            if (patchInfo.patchMask & patchMaskBit) {
                cachedPatchIdWriteCursor->patch[0] =
                    ((ObjfsaWalkGroupPatchInfo*)patchInfoGroupCursor)->patchGroupIds[0];
                cachedPatchTargetWriteCursor->patchTargets[0].x = target[0];
                cachedPatchTargetWriteCursor->patchTargets[0].y = target[1];
                cachedPatchTargetWriteCursor->patchTargets[0].z = target[2];
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
        cachedPatchIdCursor = state;
        cachedPatchTargetCursor = state;
        for (; slotIdx < 4;
             cachedPatchIdCursor = (TrickyState*)((u8*)cachedPatchIdCursor + sizeof(state->patch[0])),
             cachedPatchTargetCursor = (TrickyState*)((u8*)cachedPatchTargetCursor + sizeof(state->patchTargets[0])),
             slotIdx++) {
            if (cachedPatchIdCursor->patch[0] != 0) {
                trickyDebugPrint(debugStrings + TRICKY_DBG_PATCH_LAST_XYZ, slotIdx,
                                 cachedPatchTargetCursor->patchTargets[0].x, cachedPatchTargetCursor->patchTargets[0].y,
                                 cachedPatchTargetCursor->patchTargets[0].z);
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
                            for (i = 0, cachedPatchIdCursor = state; i < 4;
                                 cachedPatchIdCursor =
                                     (TrickyState*)((u8*)cachedPatchIdCursor + sizeof(state->patch[0])),
                                i++) {
                                if (cachedPatchIdCursor->patch[0] == targetPatchGroup) {
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
                                for (i = 0, cachedPatchIdCursor = state; i < 4;
                                     cachedPatchIdCursor =
                                         (TrickyState*)((u8*)cachedPatchIdCursor + sizeof(state->patch[0])),
                                    i++) {
                                    if (cachedPatchIdCursor->patch[0] == trickyPatch) {
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
                            for (i = 0, cachedPatchIdCursor = state; i < 4;
                                 cachedPatchIdCursor =
                                     (TrickyState*)((u8*)cachedPatchIdCursor + sizeof(state->patch[0])),
                                i++) {
                                if (cachedPatchIdCursor->patch[0] == targetPatchGroup) {
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
                                for (i = 0, cachedPatchIdCursor = state; i < 4;
                                     cachedPatchIdCursor =
                                         (TrickyState*)((u8*)cachedPatchIdCursor + sizeof(state->patch[0])),
                                    i++) {
                                    if (cachedPatchIdCursor->patch[0] == targetWalkGroup) {
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
                                    for (i = 0, cachedPatchIdCursor = state; i < 4;
                                         cachedPatchIdCursor =
                                             (TrickyState*)((u8*)cachedPatchIdCursor + sizeof(state->patch[0])),
                                        i++) {
                                        if (cachedPatchIdCursor->patch[0] == p) {
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
                    RomCurve_setupHermiteSegment(&state->route, prevNode, node, nextNode);
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
        f32 speed = TRICKY_FAST_MOVE_BLEND_SPEED * timeDelta + state->speed;
        state->speed = speed;
        speed = state->speed;
        if (speed > TRICKY_FOLLOW_MAX_SPEED) {
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

const f32 gTrickyCloseDistanceSq[] = {2500.0f};
const f32 gTrickyTimer30Frames[] = {30.0f};
const f32 gTrickyGrowlDigStartRadius[] = {25.0f};
const f32 gTrickyFlameDoneProgress[] = {0.95f};
const f32 gTrickyCirclingApproachRadius[] = {50.0f};
const f32 gTrickyTimer150Frames[] = {150.0f};
const f32 gTrickyCirclingCloseDistanceSq[] = {3600.0f};
const f32 gTrickyCirclingFarDistanceSq[] = {5625.0f};
const f32 gTrickyCirclingChargeRadius[] = {55.0f};
const f32 gTrickyCirclingSpawnProgress[] = {0.3f};
const f32 gTrickyFetchCarryDelayFrames[] = {180.0f};
const f32 gTrickyFetchBallReachRadius[] = {13.0f};
const f32 gTrickyFetchPickupBlendSpeed[] = {0.03f};
const f32 gTrickyFetchThrowDelayFrames[] = {60.0f};
const f32 gTrickyFetchLaunchProgress[] = {0.65f};
const f32 gTrickyVisibilityProbeRadius[] = {19.0f};
const f32 gTrickyFlameHelperReleaseProgress[] = {0.8f};
const f32 gCannonballRollSpeedLimit[] = {1.2f};
const f32 gCannonballRouteBackstep[] = {-10.0f};
const f32 gTrickyDigTunnelBlendSpeed[] = {0.033f};
const f32 gTrickySecretDigScanDistanceSq[] = {10000.0f};
const f32 gTrickyIdleWanderBlendSpeed[] = {0.0025f};
const f32 gTrickyIdlePickBlendSpeed[] = {0.0075f};
const f32 gTrickyHowlCallBlendSpeed[] = {0.003f};
const f32 gTrickyAmbientActivityBase[] = {200.0f};
const f64 gTrickyAmbientWanderScale[] = {0.1};
const f32 gTrickyAmbientHowlBlendSpeed[] = {0.015f};
const f32 gTrickyContactFlameThreshold[] = {3000.0f};
const f32 gTrickyRemoteRecallDistanceSq[] = {360000.0f};
const f32 gTrickyPathParticleScale[] = {0.4f};
const f32 gTrickyFirepipeHeightDistSq[] = {841.0f};
const f32 gTrickyLostEventTime[] = {-10000.0f};
const f32 gTrickyRecallCooldownFrames[] = {1200.0f};
const f32 gTrickyAudioEventMinSpeed[] = {0.2f};
const f32 gTrickyChildVoicePeriodFrames[] = {2400.0f};

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

void tricky_stateGoToWarpPoint(GameObject* obj, TrickyState* state) {
    GameObject* selectedWarp;
    f32 playerRejectDistSq;
    f32 bestTrickyDistSq;
    f32 distSq;
    f32 resetValue;
    GameObject** warpCursor;
    GameObject** warpList;
    int warpCount;
    int warpIndex;
    int inWater;
    GameObject* bestWarp;

    selectedWarp = NULL;
    bestWarp = NULL;
    bestTrickyDistSq = gTrickyMaxDistance;

    if (trickyShouldGoToWarpPoint(obj, state) == 0) {
        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
        state->substate = 0;
        resetValue = gTrickyFloatZero;
        state->cooldownA = resetValue;
        state->cooldownB.f = resetValue;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
        state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
        return;
    }

    warpList = (GameObject**)objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
    warpIndex = 0;
    warpCursor = warpList;
    playerRejectDistSq = TRICKY_CLOSE_DISTANCE_SQ;
    for (; warpIndex < warpCount; warpIndex++) {
        distSq = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &(*warpCursor)->anim.worldPosX);
        if (distSq > playerRejectDistSq) {
            distSq = getXZDistanceSquared(&obj->anim.worldPosX, &(*warpCursor)->anim.worldPosX);
            if (distSq < bestTrickyDistSq) {
                bestWarp = *warpCursor;
                bestTrickyDistSq = distSq;
            }
        }
        warpCursor++;
    }

    selectedWarp = bestWarp;
    if (selectedWarp != NULL) {
        state->followObj = selectedWarp;
        if (state->targetPosPtr != &selectedWarp->anim.worldPosX) {
            state->targetPosPtr = &selectedWarp->anim.worldPosX;
            {
                u32 mask;
                u32 flags = state->stateFlags;
                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                state->stateFlags = flags & mask;
            }
            state->linkedWalkGroup = 0;
        }
        if (trickyUpdateMovementState(obj, TRICKY_ANIM_TRANSITION_FRAMES, state) == 1) {
            return;
        }
    }

    inWater = skeetla_isInWater(state);

    if (inWater != 0) {
        trickyRequestMove(obj, 8, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
        state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
        state->particleTimer = gTrickyFloatZero;
        trickyDebugPrint(sInWaterMessage);
    } else {
        trickyRequestMove(obj, 0, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
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

#define PRESSURESWITCHFB_REMOVE_GROUP_ID 0x53 /* DLL 0xFB pressureswitchfb (self-registers) */

int trickyShouldGoToWarpPoint(GameObject* tricky, TrickyState* state) {
    int result = 0;
    f32 pressureSwitchRadius = TRICKY_FLOAT_40;
    TrickyState* warpState = state;

    if (warpState->warpCooldown != 0) {
        warpState->warpCooldown--;
        result = 1;
    }

    if (objGetNearestTypeTo(PRESSURESWITCHFB_REMOVE_GROUP_ID, tricky, &pressureSwitchRadius) != NULL) {
        return 0;
    }

    if (warpState->commandPhase != TRICKY_COMMAND_PHASE_GUARD) {
        GameObject* playerObj = warpState->playerObj;

        if ((playerObj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0) {
            if (coordsToMapCell(tricky->anim.localPosX, tricky->anim.localPosZ) == 0x38) {
                if ((mainGetBit(0x385) == 0) && (mainGetBit(0x384) != 0)) {
                    if ((mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) ||
                        (mainGetBit(GAMEBIT_ITEM_TrickyFood_GrabInProgress) != 0)) {
                        result = 1;
                    }
                }
            } else {
                warpState->warpCooldown = 0x1F;
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

#define TRICKY_FLAME_CHILD_COUNT       7
#define TRICKY_SPAWN_ROMDEF_FLAMEBLAST 0x4f0 /* flameblast remap-source romDefNo (DLL 0xF3) */

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
    int spawnIndex;
    int releaseIndex;
    TrickyState* finishSoundState;
    void** spawnSlot;
    FlameblastPlacement* setup;
    void** releaseSlot;
    char* debugTextBase = gTrickyDebugStringTable;

    switch (trickyState->substate) {
    case TRICKYGROWL_WINDUP:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_GROWLAT_GOTO);
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
        trickyDebugPrint(debugTextBase + TRICKY_DBG_GROWLAT_GROWLING);
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
        trickyDebugPrint(debugTextBase + TRICKY_DBG_GROWLAT_GOTOFLAME);
        if (trickyUpdateMovementState(obj, TRICKY_GROWL_DIG_START_RADIUS, trickyState) == 0) {
            if ((u8)Obj_CanSetupObject() != 0) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (spawnIndex = 0, spawnSlot = (void**)trickyState; spawnIndex < TRICKY_FLAME_CHILD_COUNT;
                     spawnSlot++, spawnIndex++) {
                    setup = (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);
                    setup->base.color[0] = 2;
                    setup->base.color[1] = 1;
                    setup->streamIndex = spawnIndex;
                    *trickyFlameChildSlotFromStateCursor(spawnSlot) =
                        objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
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
        trickyDebugPrint(debugTextBase + TRICKY_DBG_GROWLAT_FLAME);
        if (obj->anim.currentMoveProgress >= TRICKY_FLAME_DONE_PROGRESS) {
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (releaseIndex = 0, releaseSlot = (void**)trickyState; releaseIndex < TRICKY_FLAME_CHILD_COUNT;
                 releaseSlot++, releaseIndex++) {
                objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(releaseSlot));
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
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
                s8 idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
                trickyState->commandPhase = idleCommandPhase;
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

/* Head-only prompt child setup used for TrickyFood, quest, exclamation, and badge bubbles. */
typedef struct TrickyPromptChildSetup {
    ObjPlacement base; /* 0x00 */
    u8 pad18[0x20 - 0x18];
} TrickyPromptChildSetup;

STATIC_ASSERT(sizeof(TrickyPromptChildSetup) == 0x20);

/* Spawn-setup buffer seeded in the substate-3 drip burst (defNo 0x4f0).
 * Reuses ObjPlacement's color head and adds a signed stream index at 0x1a. */
typedef struct AnimObjD2DripSetup {
    ObjPlacement head; /* 0x00: color[0..1] written */
    u8 pad18[0x1a - 0x18];
    s16 index; /* 0x1a */
    u8 pad1C[0x24 - 0x1C];
} AnimObjD2DripSetup;

STATIC_ASSERT(sizeof(AnimObjD2DripSetup) == 0x24);

GameObject* trickyFindCirclingTarget(GameObject* obj, TrickyState* state);

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
        {
            f32 z = gTrickyFloatZero;
            state->cooldownA = z;
            state->cooldownB.f = z;
            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
            state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
        }
    }

    return hasTarget;
}

void trickyUpdateCircling(GameObject* obj, TrickyState* state) {
    char* debugTextBase = gTrickyDebugStringTable;
    u8 movementStatus;
    int targetAcquired;
    GameObject* bestDetourWarp = NULL;
    f32 bestDetourSavings = gTrickyFloatZero;
    int warpCount;
    TrickyState* approachVoiceState;
    TrickyState* orbitVoiceState;
    TrickyState* finishVoiceState;

    switch (state->substate) {
    case ANIMOBJD2_SUBSTATE_ACQUIRE: {
        trickyDebugPrint(debugTextBase + TRICKY_DBG_BADDIEALERT_GOTO);
        movementStatus = trickyUpdateMovementState(obj, TRICKY_CIRCLING_APPROACH_RADIUS, state);
        targetAcquired = trickyAcquireCirclingTarget(state);
        if (targetAcquired != 0) {
            if (state->flameCommandPending == 0) {
                {
                    GameObject* circlingTarget = trickyFindCirclingTarget(obj, state);
                    state->cooldownB.ptr = circlingTarget;
                    if (circlingTarget != NULL) {
                        state->followObj = state->cooldownB.obj;
                        state->circlingWarpDetour = NULL;
                        state->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                        break;
                    }
                }
            }
            if (movementStatus == 2) {
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
                {
                    f32 resetValue = gTrickyFloatZero;
                    state->cooldownA = resetValue;
                    state->cooldownB.f = resetValue;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
                    state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
                }
                break;
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) <
                TRICKY_CIRCLING_CLOSE_DISTANCE_SQ) {
                int inWater;
                f32 resetValue;
                state->substate = ANIMOBJD2_SUBSTATE_APPROACH;
                resetValue = gTrickyFloatZero;
                state->cooldownA = resetValue;
                inWater = skeetla_isInWater(state);
                if (inWater != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(debugTextBase + TRICKY_DBG_IN_WATER);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(debugTextBase + TRICKY_DBG_OUT_OF_WATER);
                }
            }
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_APPROACH: {
        trickyDebugPrint(debugTextBase + TRICKY_DBG_BADDIEALERT_BARK, state->stats->energy, state->flameCommandPending);
        movementStatus = trickyUpdateMovementState(obj, TRICKY_CIRCLING_APPROACH_RADIUS, state);
        targetAcquired = trickyAcquireCirclingTarget(state);
        if (targetAcquired != 0) {
            if (state->flameCommandPending == 0) {
                {
                    GameObject* circlingTarget = trickyFindCirclingTarget(obj, state);
                    state->cooldownB.ptr = circlingTarget;
                    if (circlingTarget != NULL) {
                        state->followObj = state->cooldownB.obj;
                        state->circlingWarpDetour = NULL;
                        state->substate = ANIMOBJD2_SUBSTATE_ORBIT;
                        break;
                    }
                }
            }
            if (movementStatus == 2) {
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
                {
                    f32 resetValue = gTrickyFloatZero;
                    state->cooldownA = resetValue;
                    state->cooldownB.f = resetValue;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
                    state->stateFlags &= (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
                    state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
                }
                break;
            }
            if (movementStatus == 0) {
                trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
            }
            if (state->flameCommandPending != 0) {
                if (state->stats->energy < 2) {
                    state->flameCommandPending = 0;
                    if ((u8)Obj_CanSetupObject() != 0) {
                        state->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                        state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                        state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
                        {
                            f32 resetValue = gTrickyFloatZero;
                            state->cooldownA = resetValue;
                            state->cooldownB.f = resetValue;
                            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
                            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
                            state->stateFlags &= (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
                            state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
                        }
                        if (state->foodChild == NULL) {
                            TrickyPromptChildSetup* promptSetup = (TrickyPromptChildSetup*)Obj_AllocObjectSetup(
                                sizeof(*promptSetup), ANIMOBJD2_TRICKY_FOOD_OBJ_ID);
                            s8 occupiedPromptSlots[4];
                            int freePromptSlot;
                            occupiedPromptSlots[0] = -1;
                            occupiedPromptSlots[1] = -1;
                            occupiedPromptSlots[2] = -1;
                            if (state->exclamationPromptChild != NULL) {
                                occupiedPromptSlots[state->packedSlots.exclamationPromptSlot] = 1;
                            }
                            if (state->questPromptChild != NULL) {
                                occupiedPromptSlots[state->packedSlots.questPromptSlot] = 1;
                            }
                            if (state->foodChild != NULL) {
                                occupiedPromptSlots[state->packedSlots.foodChildSlot] = 1;
                            }
                            if (occupiedPromptSlots[0] == -1) {
                                freePromptSlot = 0;
                            } else if (occupiedPromptSlots[1] == -1) {
                                freePromptSlot = 1;
                            } else if (occupiedPromptSlots[2] == -1) {
                                freePromptSlot = 2;
                            } else if (occupiedPromptSlots[3] == -1) {
                                freePromptSlot = 3;
                            } else {
                                freePromptSlot = -1;
                            }
                            state->packedSlots.foodChildSlot = freePromptSlot;
                            state->foodChild = objSetupObject(&promptSetup->base, 4, -1, -1, obj->anim.parent);
                            ObjLink_AttachChild(obj, state->foodChild, state->packedSlots.foodChildSlot);
                            {
                                f32 resetValue = gTrickyFloatZero;
                                state->foodVoiceTimer = resetValue;
                                state->foodForceBlinkTimer = resetValue;
                                state->foodBlinkTimer = resetValue;
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
                approachVoiceState = obj->extra;
                if (!approachVoiceState->soundSuppressed) {
                    s16 currentMove = obj->anim.currentMove;
                    if (currentMove >= TRICKY_VOICE_MOVE_END || currentMove < TRICKY_VOICE_MOVE_MIN) {
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            objSoundStartTimed(obj, &approachVoiceState->soundState, TRICKY_VOICE_SFX_ROLLING, 0x1000,
                                               -1, 0);
                        }
                    }
                }
            }
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_CHARGE: {
        trickyDebugPrint(debugTextBase + TRICKY_DBG_BADDIEALERT_GOTOFLAME);
        movementStatus = trickyUpdateMovementState(obj, TRICKY_CIRCLING_CHARGE_RADIUS, state);
        targetAcquired = trickyAcquireCirclingTarget(state);
        if (targetAcquired != 0 && movementStatus != 1) {
            trickyRequestMove(obj, TRICKY_ANIM_DIG, TRICKY_LAND_MOVE_BLEND_SPEED,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = ANIMOBJD2_SUBSTATE_SPAWN;
            state->flameCommandPending = 0;
        }
        break;
    }
    case ANIMOBJD2_SUBSTATE_SPAWN:
        if (obj->anim.currentMove != TRICKY_ANIM_DIG) {
            break;
        }
        if (obj->anim.currentMoveProgress > TRICKY_CIRCLING_SPAWN_PROGRESS) {
            if ((u8)Obj_CanSetupObject() != 0) {
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                {
                    int childIndex = 0;
                    u8* childSlotCursor = (u8*)state;
                    for (; childIndex < TRICKY_FLAME_CHILD_COUNT; childIndex++) {
                        AnimObjD2DripSetup* dripSetup =
                            (AnimObjD2DripSetup*)Obj_AllocObjectSetup(sizeof(*dripSetup), ANIMOBJD2_FLAMEBLAST_OBJ_ID);
                        dripSetup->head.color[0] = 2;
                        dripSetup->head.color[1] = 1;
                        dripSetup->index = childIndex;
                        *trickyFlameChildSlotFromStateCursor(childSlotCursor) =
                            objSetupObject(&dripSetup->head, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        childSlotCursor += sizeof(GameObject*);
                    }
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            }
            state->stats->energy -= 2;
            state->substate = ANIMOBJD2_SUBSTATE_FINISH;
        }
        break;
    case ANIMOBJD2_SUBSTATE_FINISH: {
        u32 flags;
        trickyDebugPrint(debugTextBase + TRICKY_DBG_BADDIEALERT_FLAME);
        flags = state->stateFlags;
        if (flags & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
            state->stateFlags = flags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            {
                u8* childSlotCursor;
                int childIndex = 0;
                childSlotCursor = (u8*)state;
                for (; childIndex < TRICKY_FLAME_CHILD_COUNT; childIndex++) {
                    objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(childSlotCursor));
                    childSlotCursor += sizeof(GameObject*);
                }
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            finishVoiceState = obj->extra;
            if (!finishVoiceState->soundSuppressed) {
                s16 currentMove = obj->anim.currentMove;
                if (currentMove >= TRICKY_VOICE_MOVE_END || currentMove < TRICKY_VOICE_MOVE_MIN) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                        objSoundStartTimed(obj, &finishVoiceState->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                    }
                }
            }
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
            {
                f32* px = &state->followObj->anim.worldPosX;
                if (state->targetPosPtr != px) {
                    state->targetPosPtr = px;
                    {
                        u32 m;
                        u32 flags = state->stateFlags;
                        m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                        state->stateFlags = flags & m;
                    }
                    state->linkedWalkGroup = 0;
                }
            }
            state->substate = ANIMOBJD2_SUBSTATE_ACQUIRE;
        } else {
            void** warpList = (void**)objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
            int warpIndex = 0;
            warpCursor = warpList;
            for (; warpIndex < warpCount; warpIndex++) {
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
                        bestDetourWarp = warpCursor[0];
                    }
                }
                warpCursor++;
            }
            {
                GameObject* circlingWarpDetour = state->circlingWarpDetour;
                if (circlingWarpDetour != NULL && (circlingWarpDetour->objectFlags & OBJECT_OBJFLAG_FREED)) {
                    state->circlingWarpDetour = NULL;
                    {
                        f32* px = &state->playerObj->anim.worldPosX;
                        if (state->targetPosPtr != px) {
                            state->targetPosPtr = px;
                            {
                                u32 m;
                                u32 flags = state->stateFlags;
                                m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                                state->stateFlags = flags & m;
                            }
                            state->linkedWalkGroup = 0;
                        }
                    }
                }
            }
            if (bestDetourWarp != NULL) {
                if (state->circlingWarpDetour == NULL) {
                    orbitVoiceState = obj->extra;
                    if (!orbitVoiceState->soundSuppressed) {
                        s16 currentMove = obj->anim.currentMove;
                        if (currentMove >= TRICKY_VOICE_MOVE_END || currentMove < TRICKY_VOICE_MOVE_MIN) {
                            if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                                objSoundStartTimed(obj, &orbitVoiceState->soundState, TRICKY_VOICE_SFX_GET_MFOX, 0x500,
                                                   -1, 0);
                            }
                        }
                    }
                }
                if (state->circlingWarpDetour == NULL || state->circlingWarpDetour != bestDetourWarp) {
                    state->circlingWarpDetour = bestDetourWarp;
                    {
                        f32* warpTargetPos = &state->circlingWarpDetour->anim.worldPosX;
                        if (state->targetPosPtr != warpTargetPos) {
                            state->targetPosPtr = warpTargetPos;
                            {
                                u32 m;
                                u32 flags = state->stateFlags;
                                m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                                state->stateFlags = flags & m;
                            }
                            state->linkedWalkGroup = 0;
                        }
                    }
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
                    state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                    trickyDebugPrint(debugTextBase + TRICKY_DBG_IN_WATER);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                    trickyDebugPrint(debugTextBase + TRICKY_DBG_OUT_OF_WATER);
                }
            }
        }
        break;
    }
    }
}

GameObject* trickyFindCirclingTarget(GameObject* obj, TrickyState* state) {
    GameObject* target;
    GameObject** baddieList;
    int baddieCount;
    int baddieIndex;
    f32 trickyToTarget;
    f32 trickyToPlayer;
    f32 targetToPlayer;

    target = state->followObj;
    if (target->anim.romDefNo == ANIMOBJD2_CIRCLE_TARGET_SEQID) {
        return target;
    }

    target = (GameObject*)playerGetTargetObject(state->playerObj);
    if (target != NULL) {
        baddieList = objGetAllOfType(TRICKY_BADDIE_OBJGROUP, &baddieCount);
        for (baddieIndex = 0; baddieIndex < baddieCount; baddieIndex++) {
            if (*baddieList == target) {
                trickyToTarget = Vec_xzDistance(&obj->anim.worldPosX, &target->anim.worldPosX);
                trickyToPlayer = Vec_xzDistance(&obj->anim.worldPosX, &state->playerObj->anim.worldPosX);
                targetToPlayer = Vec_xzDistance(&target->anim.worldPosX, &state->playerObj->anim.worldPosX);
                if ((trickyToTarget + trickyToPlayer) < 2.0f * targetToPlayer) {
                    return target;
                }
                break;
            }
            baddieList++;
        }
    }
    return NULL;
}

void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state) {
    GameObject* target = state->followObj;
    f32 dx = target->anim.worldPosX - obj->anim.worldPosX;
    f32 dz = target->anim.worldPosZ - obj->anim.worldPosZ;
    int targetAngle = atan2Angle16(dx, dz);
    s32 angleDelta;
    s32 absAngleDelta;

    if (state->substate == ANIMOBJD2_SUBSTATE_ACQUIRE) {
        state->circlingDirection.i = randomGetRange(0, 1);
        if (state->circlingDirection.i == 0) {
            state->circlingDirection.i = -1;
        }
        state->circlingAngle.i = targetAngle;
        state->substate = ANIMOBJD2_SUBSTATE_APPROACH;
    }

    angleDelta = targetAngle - (s32)(u16)state->circlingAngle.u;
    if (angleDelta > 0x8000) {
        angleDelta -= 0xFFFF;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xFFFF;
    }

    if (angleDelta >= 0) {
        absAngleDelta = angleDelta;
    } else {
        absAngleDelta = -angleDelta;
    }
    if (absAngleDelta < 0x2000) {
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
                            objSoundStartTimed(obj, &extra->soundState, TRICKY_VOICE_SFX_IM_NOT_DOING_IT, 1280, -1, 0);
                        }
                    }
                }
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = 0;
                resetTimer = gTrickyFloatZero;
                state->cooldownA = resetTimer;
                state->cooldownB.f = resetTimer;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
                {
                    s8 idleCommandPhase;
                    idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
                    state->commandPhase = idleCommandPhase;
                }
            }
        } else {
            status = trickyUpdateMovementState(obj, TRICKY_TIMER_20_FRAMES, state);
            if (status == 0) {
                if (state->fetchCarryDelayTimer > gTrickyFloatZero) {
                    useSwimAnim = skeetla_isInWater(state);
                    if (useSwimAnim != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                        state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                        objSoundStartTimed(obj, &extra->soundState, TRICKY_VOICE_SFX_LAUGH, 1280, -1, 0);
                    }
                }
            } else {
                useSwimAnim = skeetla_isInWater(state);
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                            objSoundStartTimed(obj, &extra->soundState, TRICKY_VOICE_SFX_DUM_DE_DUM, 1280, -1, 0);
                        }
                    }
                }
            }
            inWater = skeetla_isInWater(state);
            if (inWater != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                    state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
            {
                s8 idleCommandPhase;
                idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
                state->commandPhase = idleCommandPhase;
            }
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
            state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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

#define TRICKY_GUARD_APPROACH_GROUP 3

int trickyGuardFindBaddieTarget(TrickyState* state);

static inline int trickyGuardIsBaddieTargetValid(GameObject* target) {
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
        GameObject** childSlot = state->flameChildren;

        for (; childIndex < TRICKY_FLAME_CHILD_COUNT; childSlot++, childIndex++) {
            objSetAnimSpeedTo1(*childSlot);
        }
    }
    Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
    trickyPlayVoice(obj, obj->extra, TRICKY_VOICE_SFX_FINISH_FLAME, 0);
}

static inline void trickySpawnFlameChildren(GameObject* obj, TrickyState* state) {
    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    {
        int childIndex = 0;
        GameObject** childSlot = state->flameChildren;

        for (; childIndex < TRICKY_FLAME_CHILD_COUNT; childSlot++, childIndex++) {
            FlameblastPlacement* setup =
                (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);

            setup->base.color[0] = 2;
            setup->base.color[1] = 1;
            setup->streamIndex = childIndex;
            *childSlot = objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
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
                {
                    u32 m;
                    u32 f2 = trickyState->stateFlags;
                    m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    trickyState->stateFlags = f2 & m;
                }
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
                (trickyState)->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                    for (helperIndex = 0, helperSlot = (void**)trickyState; helperIndex < TRICKY_FLAME_CHILD_COUNT;
                         helperIndex++) {
                        helperSetup = (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*helperSetup),
                                                                                 TRICKY_SPAWN_ROMDEF_FLAMEBLAST);
                        helperSetup->base.color[0] = 2;
                        helperSetup->base.color[1] = 1;
                        helperSetup->streamIndex = helperIndex;
                        *trickyFlameChildSlotFromStateCursor(helperSlot) =
                            objSetupObject(&helperSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                        helperSlot++;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                    Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
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
                {
                    u32 m;
                    u32 f2 = trickyState->stateFlags;
                    m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    trickyState->stateFlags = f2 & m;
                }
                trickyState->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
            break;
        }
    case TRICKY_GUARD_FLAME:
        trickyDebugPrint(debugText + TRICKY_DBG_GUARD_FLAME);
        if (obj->anim.currentMoveProgress >= TRICKY_GUARD_FLAME_DONE_PROGRESS) {
            {
                u32 m;
                u32 f2 = trickyState->stateFlags;
                m = ~TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                trickyState->stateFlags = f2 & m;
            }
            trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (finishIndex = 0, finishSlot = (void**)trickyState; finishIndex < TRICKY_FLAME_CHILD_COUNT;
                 finishIndex++) {
                objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(finishSlot));
                finishSlot++;
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
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
                    {
                        u32 m;
                        u32 f2 = trickyState->stateFlags;
                        m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                        trickyState->stateFlags = f2 & m;
                    }
                    trickyState->linkedWalkGroup = 0;
                }
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        } else if (trickyGuardIsBaddieTargetValid(trickyState->guardTarget) != 0) {
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
        } else if (trickyGuardIsBaddieTargetValid(trickyState->guardTarget) != 0) {
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
            trickyGuardIsBaddieTargetValid(trickyState->guardTarget) == 0) {
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
                    {
                        u32 m;
                        u32 f2 = trickyState->stateFlags;
                        m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                        trickyState->stateFlags = f2 & m;
                    }
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
            {
                u32 m;
                u32 f2 = trickyState->stateFlags;
                m = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                trickyState->stateFlags = f2 & m;
            }
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
    FlameblastPlacement* flameblastSetup;
    int flameBreathActive;
    f32* targetPos;
    f32 resetValue;

    switch (trickyState->substate) {
    case TRICKY_FLAME_NONE:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_NONE);
        trickyState->flameEdgeNode = Objfsa_FindNearestCurveType24(&trickyState->followObj->anim.worldPosX, -1, 4);
        if (trickyState->flameEdgeNode->walkGroup != 0) {
            targetPos = &trickyState->flameEdgeNode->x;
            if (trickyState->targetPosPtr != targetPos) {
                trickyState->targetPosPtr = targetPos;
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    trickyState->stateFlags = flags & mask;
                }
                (trickyState)->linkedWalkGroup = 0;
            }
            trickyState->substate = TRICKY_FLAME_FINDING_IN;
        } else {
            trickyState->flameReturnNode = (*gRomCurveInterface)->getById(trickyState->flameEdgeNode->linkIds[0]);
            targetPos = &trickyState->flameReturnNode->x;
            if (trickyState->targetPosPtr != targetPos) {
                trickyState->targetPosPtr = targetPos;
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                    trickyState->stateFlags = flags & mask;
                }
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
        targetPos = &trickyState->flameEdgeNode->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, targetPos, 1);
        moveTricky(obj, targetPos);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKY_FLAME_TO_START;
        }
        break;
    case TRICKY_FLAME_TO_START:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_TOSTART);
        targetPos = &trickyState->flameEdgeNode->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, targetPos, 1);
        if (moveTricky(obj, targetPos) != 0) {
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
                             flameScratch < TRICKY_FLAME_CHILD_COUNT; flameScratch++) {
                            flameblastSetup = (FlameblastPlacement*)Obj_AllocObjectSetup(
                                sizeof(*flameblastSetup), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);
                            flameblastSetup->base.color[0] = 2;
                            flameblastSetup->base.color[1] = 1;
                            flameblastSetup->streamIndex = flameScratch;
                            *trickyFlameChildSlotFromStateCursor(flameChildCursor) =
                                objSetupObject(&flameblastSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                            flameChildCursor++;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                        Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                    }
                } else {
                    TrickyActionCallback callback = trickyState->actionCallback;
                    if (callback != NULL && callback(trickyState->followObj, 1) == 0) {
                    } else if (obj->anim.currentMoveProgress > TRICKY_FLAME_HELPER_RELEASE_PROGRESS) {
                        {
                            u32 mask;
                            u32 flags = trickyState->stateFlags;
                            mask = ~TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                            trickyState->stateFlags = flags & mask;
                        }
                        trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                        for (flameScratch = 0, flameChildCursor = (void**)trickyState;
                             flameScratch < TRICKY_FLAME_CHILD_COUNT; flameScratch++) {
                            objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(flameChildCursor));
                            flameChildCursor++;
                        }
                        Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                        flameScratch = (int)obj->extra;
                        if (((TrickyState*)flameScratch)->soundSuppressed == 0) {
                            s16 currentMove = obj->anim.currentMove;
                            if (currentMove >= TRICKY_VOICE_MOVE_END || currentMove < TRICKY_VOICE_MOVE_MIN) {
                                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                                    objSoundStartTimed(obj, &((TrickyState*)flameScratch)->soundState,
                                                       TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                                }
                            }
                        }
                        flameBreathActive = 0;
                        break;
                    }
                }
            }
            flameBreathActive = 1;
        } while (0);
        if (flameBreathActive == 0) {
            trickyState->substate = TRICKY_FLAME_TO_END;
            (trickyState)->guardTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
        }
        break;
    case TRICKY_FLAME_FINDING_IN:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_FINDING_IN);
        {
            int movementResult = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
            if (movementResult == 0) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                trickyState->substate = TRICKY_FLAME_TURNING_IN;
            } else if (movementResult == 2) {
                trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                trickyState->substate = TRICKY_FLAME_NONE;
                resetValue = gTrickyFloatZero;
                trickyState->guardPoint[0] = resetValue;
                trickyState->guardPoint[1] = resetValue;
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                    trickyState->stateFlags = flags & mask;
                }
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_RECALL_REQUEST;
                    trickyState->stateFlags = flags & mask;
                }
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_HEEL_REQUEST;
                    trickyState->stateFlags = flags & mask;
                }
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_GUARD_REQUEST;
                    trickyState->stateFlags = flags & mask;
                }
                trickyState->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
            }
        }
        break;
    case TRICKY_FLAME_TURNING_IN:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_TURNING_IN);
        targetPos = &trickyState->followObj->anim.worldPosX;
        trickyUpdateApproachSpeed(obj, gTrickyMaxDistance, trickyState, targetPos, 1);
        if (moveTricky(obj, targetPos) == 0) {
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
                             flameScratch < TRICKY_FLAME_CHILD_COUNT; flameScratch++) {
                            flameblastSetup = (FlameblastPlacement*)Obj_AllocObjectSetup(
                                sizeof(*flameblastSetup), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);
                            flameblastSetup->base.color[0] = 2;
                            flameblastSetup->base.color[1] = 1;
                            flameblastSetup->streamIndex = flameScratch;
                            *trickyFlameChildSlotFromStateCursor(flameChildCursor) =
                                objSetupObject(&flameblastSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                            flameChildCursor++;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                        Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                    }
                } else {
                    TrickyActionCallback callback = trickyState->actionCallback;
                    if (callback != NULL && callback(trickyState->followObj, 1) == 0) {
                    } else if (obj->anim.currentMoveProgress > TRICKY_FLAME_HELPER_RELEASE_PROGRESS) {
                        {
                            u32 mask;
                            u32 flags = trickyState->stateFlags;
                            mask = ~TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                            trickyState->stateFlags = flags & mask;
                        }
                        trickyState->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                        for (releaseChildIndex = 0, releaseChildCursor = (void**)trickyState;
                             releaseChildIndex < TRICKY_FLAME_CHILD_COUNT; releaseChildIndex++) {
                            objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(releaseChildCursor));
                            releaseChildCursor++;
                        }
                        Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                        flameChildCursor = (void**)obj->extra;
                        if (((TrickyState*)flameChildCursor)->soundSuppressed == 0) {
                            s16 currentMove = obj->anim.currentMove;
                            if (currentMove >= TRICKY_VOICE_MOVE_END || currentMove < TRICKY_VOICE_MOVE_MIN) {
                                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                                    objSoundStartTimed(obj, &((TrickyState*)flameChildCursor)->soundState,
                                                       TRICKY_VOICE_SFX_FINISH_FLAME, 0, -1, 0);
                                }
                            }
                        }
                        flameBreathActive = 0;
                        break;
                    }
                }
            }
            flameBreathActive = 1;
        } while (0);
        if (flameBreathActive == 0) {
            trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
            trickyState->substate = TRICKY_FLAME_NONE;
            resetValue = gTrickyFloatZero;
            trickyState->guardPoint[0] = resetValue;
            trickyState->guardPoint[1] = resetValue;
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                trickyState->stateFlags = flags & mask;
            }
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_FLAG_RECALL_REQUEST;
                trickyState->stateFlags = flags & mask;
            }
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_FLAG_HEEL_REQUEST;
                trickyState->stateFlags = flags & mask;
            }
            {
                u32 mask;
                u32 flags = trickyState->stateFlags;
                mask = ~TRICKY_STATE_FLAG_GUARD_REQUEST;
                trickyState->stateFlags = flags & mask;
            }
            trickyState->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
        }
        break;
    case TRICKY_FLAME_TO_END:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_FLAME_TOEND);
        trickyState->guardTimer -= timeDelta;
        if (trickyState->guardTimer <= gTrickyFloatZero) {
            targetPos = &trickyState->flameReturnNode->x;
            trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, targetPos, 1);
            moveTricky(obj, targetPos);
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
                trickyState->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                trickyState->substate = TRICKY_FLAME_NONE;
                resetValue = gTrickyFloatZero;
                trickyState->guardPoint[0] = resetValue;
                trickyState->guardPoint[1] = resetValue;
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                    trickyState->stateFlags = flags & mask;
                }
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_RECALL_REQUEST;
                    trickyState->stateFlags = flags & mask;
                }
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_HEEL_REQUEST;
                    trickyState->stateFlags = flags & mask;
                }
                {
                    u32 mask;
                    u32 flags = trickyState->stateFlags;
                    mask = ~TRICKY_STATE_FLAG_GUARD_REQUEST;
                    trickyState->stateFlags = flags & mask;
                }
                trickyState->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
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
    RomCurveDef* blockedNode;
    u8 nodeCount = 0;
    int branchCurveId;
    RomCurveDef* branchNode;
    s32* branchLinkId;
    u32 branchMask;
    int branchIndex;
    int i;
    RomCurveDef* segmentStartCurve;
    RomCurveDef* startCurve;
    RomCurveDef* unblockedNode;
    s32 nodeIds[4];
    RomCurveDef* branchCandidateNode;
    RomCurveDef* nextSegmentNode;
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
            nextSegmentNode = (*gRomCurveInterface)->getById(nodeIds[0]);
            bestDistance = getXZDistanceSquared(&ball->followObj->anim.worldPosX, &nextSegmentNode->x);

            for (i = 1, branchLinkId = &nodeIds[1]; i < nodeCount; i++) {
                branchCandidateNode = (*gRomCurveInterface)->getById(*branchLinkId);
                distance = getXZDistanceSquared(&ball->followObj->anim.worldPosX, &branchCandidateNode->x);
                if (distance < bestDistance) {
                    nextSegmentNode = branchCandidateNode;
                    bestDistance = distance;
                }
                branchLinkId++;
            }

            RomCurve_advanceToNextSegment(&ball->route, nextSegmentNode);
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
            startCurve = ball->cannonballStartCurve;

            unblockedNode =
                (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomUnblockedLink(startCurve, 0));
            blockedNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBlockedLink(startCurve, 0));

            bestDistance = getXZDistanceSquared(&ball->playerObj->anim.worldPosX, &unblockedNode->x);
            distance = getXZDistanceSquared(&ball->playerObj->anim.worldPosX, &blockedNode->x);

            segmentStartCurve = startCurve;
            if (bestDistance > distance) {
                nextSegmentNode =
                    (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomUnblockedLink(unblockedNode, 0));
                ball->route.reverse = 0;
            } else {
                unblockedNode = blockedNode;
                nextSegmentNode =
                    (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBlockedLink(blockedNode, 0));
                ball->route.reverse = 1;
            }

            RomCurve_setupHermiteSegment(&ball->route, segmentStartCurve, unblockedNode, nextSegmentNode);
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

/* child objects spawned by this TU (retail OBJECTS.bin remap-source names) */
#define TRICKY_SPAWN_ROMDEF_FOOD 0x17b /* TrickyFood */

/*
 * A ROM/FSA walk-curve node as Tricky's tunnel/follow states see it (via the
 * rom_curve_interface getById() / Objfsa_*Curve* lookups). Byte-compatible with
 * the shared RomCurveDef, but with the walk-group id at +3 that those states
 * key off (which RomCurveDef leaves in its pad).
 */
void tricky_handlePlayerContact(GameObject* obj, TrickyState* state);
const TrickyCommandTypeList gTrickyCommandQueryInit = {{TRICKY_COMMAND_TYPE_CALL, TRICKY_COMMAND_TYPE_FIND_SECRET,
                                                        TRICKY_COMMAND_TYPE_STAY, TRICKY_COMMAND_TYPE_FLAME,
                                                        TRICKY_COMMAND_TYPE_PLAY_BALL}};
const TrickyCommandTypeList gTrickyFoodCommandQuery = {{TRICKY_COMMAND_TYPE_CALL, TRICKY_COMMAND_TYPE_FIND_SECRET,
                                                        TRICKY_COMMAND_TYPE_STAY, TRICKY_COMMAND_TYPE_FLAME,
                                                        TRICKY_COMMAND_TYPE_PLAY_BALL}};

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
    RomCurveDef* linkNode;
    int linkId;
    int off;
    int k;
    idx = 0;
    off = 0;
    for (k = 4; k != 0; k--) {
        linkNode = state->digTunnelExitNode.curve;
        linkId = *(int*)((u8*)linkNode + off + offsetof(RomCurveDef, linkIds));
        if (linkId > -1 && linkId != state->digTunnelStartNode.curve->id) {
            state->digTunnelStartNode.curve = linkNode;
            state->digTunnelExitNode.curve =
                (*gRomCurveInterface)
                    ->getById(((int*)((char*)state->digTunnelExitNode.curve + offsetof(RomCurveDef, linkIds)))[idx]);
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
    TrickyPackedSfxPair sfxTable;
    char* debugTextBase;
    RomCurveDef* tunnelNode;
    f32* targetPos;
    f32* entryPos;
    TrickyState* voiceState;
    int walkGroup;
    int inWater;
    u16 sfxId;
    f32 dirZ;
    f32 dirX;
    f32 pressDistance;
    f32 resetValue;
    f32 dirXSq;

    debugTextBase = gTrickyDebugStringTable;
    sfxTable.raw = *(u32*)gTrickySubstateSfxIdPairB;
    switch (state->substate) {
    case 0:
        tunnelNode = Objfsa_FindNearestCurveType24(state->targetPosPtr, -1, 2);
        state->digTunnelEntryNode.curve = (*gRomCurveInterface)->getById(tunnelNode->linkIds[0]);
        state->digTunnelStartNode.curve = tunnelNode;
        state->digTunnelExitNode.curve = (*gRomCurveInterface)->getById(tunnelNode->linkIds[1]);
        if (state->digTunnelExitNode.curve->walkGroup != 0) {
            state->digTunnelExitNode.u = state->digTunnelExitNode.u ^ state->digTunnelEntryNode.u;
            state->digTunnelEntryNode.u = state->digTunnelEntryNode.u ^ state->digTunnelExitNode.u;
            state->digTunnelExitNode.u = state->digTunnelExitNode.u ^ state->digTunnelEntryNode.u;
        }
        entryPos = &state->digTunnelEntryNode.curve->x;
        if (state->targetPosPtr != entryPos) {
            state->targetPosPtr = entryPos;
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
        trickyDebugPrint(debugTextBase + TRICKY_DBG_DIGTUNNEL_FINDING);
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        walkGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
        if (state->digTunnelEntryNode.curve->walkGroup == walkGroup) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
            state->substate = 2;
        }
        break;
    case 2:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_DIGTUNNEL_GOINGTOSTART);
        targetPos = &state->digTunnelStartNode.curve->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, targetPos, 1);
        if (moveTricky(obj, targetPos) == 0) {
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
        state->dirX = state->digTunnelExitNode.curve->x - state->digTunnelStartNode.curve->x;
        state->dirZ = state->digTunnelExitNode.curve->z - state->digTunnelStartNode.curve->z;
        Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
        state->digTunnelWhineTimer.f = (f32)(int)randomGetRange(0x14, 0xb4);
        state->substate = 4;
    case 4:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_DIGTUNNEL_DIGGING);
        state->digTunnelWhineTimer.f -= timeDelta;
        if (state->digTunnelWhineTimer.f <= gTrickyFloatZero) {
            state->digTunnelWhineTimer.f = (f32)(int)randomGetRange(0x14, 0xb4);
            state->digTunnelWhineTimer.f *= TRICKY_FLOAT_100;
            voiceState = obj->extra;
            if (voiceState->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_DUM_DE_DUM, 0x500, -1, 0);
            }
        }
        pressDistance = GROUND_ANIMATOR_INTERFACE(state->followObj)->applyPress(state->followObj, obj);
        obj->anim.localPosX = state->dirX * pressDistance + state->digTunnelStartNode.curve->x;
        obj->anim.localPosZ = state->dirZ * pressDistance + state->digTunnelStartNode.curve->z;
        dirX = ((TrickyState*)obj->extra)->dirX;
        dirXSq = dirX * dirX;
        dirZ = ((TrickyState*)obj->extra)->dirZ;
        pressDistance = dirZ * dirZ;
        if (dirXSq + pressDistance > 0.01f) {
            trickyTurnTowardYaw(obj, getAngle(-dirX, -dirZ));
        }
        if (GROUND_ANIMATOR_INTERFACE(state->followObj)->isFullySunk(state->followObj) != 0) {
            {
                int linkOffset;
                int linkId;
                RomCurveDef* exitNode;
                int linkIndex;
                int remainingLinks;

                linkIndex = 0;
                linkOffset = 0;
                for (remainingLinks = 4; remainingLinks != 0; remainingLinks--) {
                    exitNode = state->digTunnelExitNode.curve;
                    linkId = *(int*)((u8*)exitNode + linkOffset + offsetof(RomCurveDef, linkIds));
                    if (linkId > -1 && linkId != state->digTunnelStartNode.curve->id) {
                        state->digTunnelStartNode.curve = exitNode;
                        state->digTunnelExitNode.curve =
                            (*gRomCurveInterface)
                                ->getById(((int*)((char*)state->digTunnelExitNode.curve +
                                                  offsetof(RomCurveDef, linkIds)))[linkIndex]);
                        break;
                    }
                    linkOffset += 4;
                    linkIndex++;
                }
            }
            state->stats->energy -= 4;
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            state->substate = 5;
            sfxId = sfxTable.ids[randomGetRange(0, 1)];
            voiceState = obj->extra;
            if (voiceState->soundSuppressed == 0 &&
                (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) &&
                Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &voiceState->soundState, sfxId, 0x500, -1, 0);
            }
        }
        break;
    case 5:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_DIGTUNNEL_TOEND1,
                         Vec_xzDistance(&obj->anim.worldPosX, &state->digTunnelExitNode.curve->x));
        targetPos = &state->digTunnelExitNode.curve->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, targetPos, 1);
        if (moveTricky(obj, targetPos) == 0) {
            trickyAdvanceNode(state);
            state->substate = 6;
        }
        break;
    case 6:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_DIGTUNNEL_TOEND2);
        targetPos = &state->digTunnelExitNode.curve->x;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, targetPos, 1);
        if (moveTricky(obj, targetPos) == 0) {
            inWater = skeetla_isInWater(state);
            if (inWater != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = gTrickyFloatZero;
                trickyDebugPrint(debugTextBase + TRICKY_DBG_IN_WATER);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_BLEND_SPEED, 0);
                trickyDebugPrint(debugTextBase + TRICKY_DBG_OUT_OF_WATER);
            }
            state->stateFlags &= ~TRICKY_STATE_DIG_TUNNEL_FLAGS;
            state->substate = 7;
        }
        break;
    case 7:
        trickyDebugPrint(debugTextBase + TRICKY_DBG_DIGTUNNEL_WAIT);
        walkGroup = Objfsa_GetWalkGroupIndexAtPoint(&state->playerObj->anim.worldPosX, NULL);
        {
            int currentGroup;

            currentGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
            if (currentGroup == walkGroup) {
                state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
                state->substate = 0;
                resetValue = gTrickyFloatZero;
                state->cooldownA = resetValue;
                state->cooldownB.f = resetValue;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
                {
                    s8 idleCommandPhase;
                    idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
                    state->commandPhase = idleCommandPhase;
                }
            }
        }
        break;
    }
}

void tricky_stateFindSecretDig(GameObject* obj, TrickyState* state) {
    TrickyPackedSfxPair sfxTable;
    RomCurveDef* curve;
    f32* curvePos;
    GameObject* followObj;
    int movementResult;
    f32 pressDistance;
    f32 dirLength;
    f32 z;

    sfxTable.raw = *(u32*)gTrickySubstateSfxIdPairA;
    followObj = state->followObj;
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
        movementResult = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        if (movementResult == 0) {
            if (state->secretDigCurve != NULL) {
                state->substate = 2;
                curvePos = &state->secretDigCurve->x;
                if (state->targetPosPtr != curvePos) {
                    state->targetPosPtr = curvePos;
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
        } else if (movementResult == 2) {
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
                s8 idleCommandPhase;
                idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
                state->commandPhase = idleCommandPhase;
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
            curve = state->secretDigCurve;
            if (curve != NULL) {
                followObj = state->followObj;
                state->dirX = curve->x - followObj->anim.worldPosX;
                state->dirZ = curve->z - followObj->anim.worldPosZ;
                dirLength = sqrtf(state->dirX * state->dirX + state->dirZ * state->dirZ);
                if (gTrickyFloatZero != dirLength) {
                    state->dirX = state->dirX / dirLength;
                    state->dirZ = state->dirZ / dirLength;
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
        pressDistance = GROUND_ANIMATOR_INTERFACE(followObj)->applyPress(followObj, obj);
        obj->anim.localPosX = state->secretDigOriginX - state->dirX * pressDistance;
        obj->anim.localPosZ = state->secretDigOriginZ - state->dirZ * pressDistance;
        if (GROUND_ANIMATOR_INTERFACE(followObj)->isFullySunk(followObj) != 0) {
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
                s8 idleCommandPhase;
                idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
                state->commandPhase = idleCommandPhase;
            }
            trickyPlayWhineSfx(sfxTable.ids[randomGetRange(0, 1)], obj);
        }
        break;
    }
}

void tricky_stateFollowPlayer(GameObject* obj, TrickyState* state) {
    char* debugTextBase;
    TrickyDebugCollisionData* debugData;
    GameObject* found;
    TrickyState* followState;
    GameObject* target;
    TrickyState* sfxState;
    int inWater;
    f32 resetValue;

    debugTextBase = gTrickyDebugStringTable;
    debugData = (TrickyDebugCollisionData*)debugTextBase;
    found = NULL;
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if (state->pendingFollowRequest != 0) {
            switch ((int)state->pendingFollowRequest) {
            case 1: {
                target = state->pendingFollowObj;
                followState = obj->extra;
                if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    if ((followState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                        followState->followObj = target;
                        if (followState->targetPosPtr != &target->anim.worldPosX) {
                            followState->targetPosPtr = &target->anim.worldPosX;
                            {
                                u32 mask;
                                u32 flags = followState->stateFlags;
                                mask = ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
                                followState->stateFlags = flags & mask;
                            }
                            followState->linkedWalkGroup = 0;
                        }
                        followState->substate = 0;
                        followState->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                    } else {
                        followState->pendingFollowRequest = 1;
                        followState->pendingFollowObj = target;
                        followState->stateFlags |= (u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
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
                        state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                        state->particleTimer = gTrickyFloatZero;
                        trickyDebugPrint(debugTextBase + TRICKY_DBG_IN_WATER);
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
                        trickyDebugPrint(debugTextBase + TRICKY_DBG_OUT_OF_WATER);
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
        resetValue = gTrickyFloatZero;
        state->cooldownA = resetValue;
        state->cooldownB.f = resetValue;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_RECALL_REQUEST;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_HEEL_REQUEST;
        state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GUARD_REQUEST;
        {
            s8 idleCommandPhase;
            idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
            state->commandPhase = idleCommandPhase;
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
        resetValue = gTrickyFloatZero;
        state->prevSpeed = resetValue;
        state->speed = resetValue;
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
            if (debugData->pathPointCollision.substateHandlers[state->substate](obj, state) == 0) {
                inWater = skeetla_isInWater(state);
                if (inWater != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                    state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = gTrickyFloatZero;
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_WANDER, TRICKY_IDLE_WANDER_BLEND_SPEED, 0);
                }
            }
        }
    }
}

int tricky_substateApproachThorntail(GameObject* obj, TrickyState* state) {
    TrickyState* voiceState;
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
        tricky_startRandomIdleMove(obj, state);
    } else if ((u8)trickyUpdateMovementState(obj, TRICKY_TIMER_30_FRAMES, state) != 1) {
        state->thorntailIdleMovePending = 1;
        sfxId = randomGetRange(TRICKY_VOICE_SFX_HELLO, TRICKY_VOICE_SFX_HI_FELLA);
        voiceState = obj->extra;
        if (voiceState->soundSuppressed == 0) {
            move = obj->anim.currentMove;
            if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &voiceState->soundState, sfxId, 1280, -1, 0);
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
                for (spawnIndex = 0, spawnChildCursor = (u8*)state; spawnIndex < TRICKY_FLAME_CHILD_COUNT;
                     spawnChildCursor += sizeof(GameObject*), spawnIndex++) {
                    setup = (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);
                    setup->base.color[0] = 2;
                    setup->base.color[1] = 1;
                    setup->streamIndex = spawnIndex;
                    *trickyFlameChildSlotFromStateCursor(spawnChildCursor) =
                        objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            }
        } else {
            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) {
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                for (cleanupIndex = 0, cleanupChildCursor = (u8*)state; cleanupIndex < TRICKY_FLAME_CHILD_COUNT;
                     cleanupChildCursor += sizeof(GameObject*), cleanupIndex++) {
                    objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(cleanupChildCursor));
                }
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
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
    TrickyState* voiceState;
    int result;
    short move;
    TrickyCommandTypeList commandQuery;

    commandQuery = gTrickyFoodCommandQuery;
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
    result = (*gGameUIInterface)->isOneOfItemsBeingUsed(commandQuery.commandTypes, TRICKY_COMMAND_QUERY_COUNT);
    switch (result) {
    case 0:
    case 1:
    case 3:
    case 4:
    case 5:
        voiceState = obj->extra;
        if (voiceState->soundSuppressed == 0u) {
            move = (obj)->anim.currentMove;
            if (move >= TRICKY_VOICE_MOVE_END || move < TRICKY_VOICE_MOVE_MIN) {
                if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                    objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_IM_NOT_DOING_IT, 1280, -1, 0);
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
        (*gPartfxInterface)->spawnObject((void*)obj, 2022, &spawnBuf, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
        break;
    }
    case TRICKY_ANIM_DIG_FOOD_END:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            b = skeetla_isInWater(state);
            if (b != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
        if (state->questPromptChild != NULL) {
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
    TrickyState* voiceState;
    int eventIndex;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    for (eventIndex = 0; eventIndex < trickyState->animEvents.triggerCount; eventIndex++) {
        if (trickyState->animEvents.triggeredIds[eventIndex] != 0) {
            continue;
        }
        voiceState = obj->extra;
        if (voiceState->soundSuppressed != 0U) {
            continue;
        }
        if ((int)(obj)->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
            (int)(obj)->anim.currentMove < TRICKY_VOICE_MOVE_MIN) {
            if (((int (*)(GameObject*, int))Sfx_IsPlayingFromObjectChannel)(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_SNIFF, 0, 0xffffffff, 0);
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
    char triggerId;
    short move;
    float sparkleTimer;
    int inWater[1];
    int eventIndex;
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
                eventIndex = (*gSkyInterface)->getSunPosition(0);
                if (eventIndex == 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_HOWL_IDLE_PICK, TRICKY_IDLE_PICK_BLEND_SPEED, 0);
                    trickyState->substate = 9;
                }
            }
        }
        for (eventIndex = 0; eventIndex < trickyState->animEvents.triggerCount; eventIndex++) {
            triggerId = trickyState->animEvents.triggeredIds[eventIndex];
            if (triggerId == '\0') {
                objSoundStartTimed(obj, &trickyState->soundState, TRICKY_VOICE_SFX_SNORE_IN, 0x500, -1, 0);
            } else if (triggerId == '\a') {
                objSoundStartTimed(obj, &trickyState->soundState, TRICKY_VOICE_SFX_SNORE_OUT, 0x100, -1, 0);
            }
        }
        sparkleTimer = trickyState->howlSparkleTimer - timeDelta;
        trickyState->howlSparkleTimer = sparkleTimer;
        if (sparkleTimer <= gTrickyFloatZero) {
            if (((obj)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                fxBuf.posX = trickyState->renderPosX;
                fxBuf.posY = 2.0f + trickyState->renderPosY;
                fxBuf.posZ = trickyState->renderPosZ;
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, TRICKY_PARTFX_HOWL_SPARKLE, &fxBuf, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS,
                                  -1, NULL);
            }
            trickyState->howlSparkleTimer = TRICKY_TIMER_30_FRAMES;
        }
        break;
    case TRICKY_ANIM_HOWL_END:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ADVANCING) != 0) {
            inWater[0] = skeetla_isInWater(trickyState);
            if (inWater[0] != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_BLEND_SPEED, 0);
                trickyState->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
    s8 occupiedSlots[4];
    TrickyState* sfxState;
    ObjPlacement* setup;
    int freeSlot;
    f32 childTimerReset;

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
            objSoundStartTimed(obj, &sfxState->soundState, TRICKY_VOICE_SFX_SLEEP_BREATH, 0x100, -1, 0);
        }
        state->sfxRepeatTimer = TRICKY_TIMER_600_FRAMES;
    }
    if (state->foodChild == NULL && (u8)Obj_CanSetupObject() != 0) {
        setup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_FOOD);
        occupiedSlots[0] = -1;
        occupiedSlots[1] = -1;
        occupiedSlots[2] = -1;
        if (state->exclamationPromptChild != NULL) {
            occupiedSlots[state->packedSlots.exclamationPromptSlot] = 1;
        }
        if (state->questPromptChild != NULL) {
            occupiedSlots[state->packedSlots.questPromptSlot] = 1;
        }
        if (state->foodChild != NULL) {
            occupiedSlots[state->packedSlots.foodChildSlot] = 1;
        }
        if (occupiedSlots[0] == -1) {
            freeSlot = 0;
        } else if (occupiedSlots[1] == -1) {
            freeSlot = 1;
        } else if (occupiedSlots[2] == -1) {
            freeSlot = 2;
        } else if (occupiedSlots[3] == -1) {
            freeSlot = 3;
        } else {
            freeSlot = -1;
        }
        state->packedSlots.foodChildSlot = freeSlot;
        state->foodChild = objSetupObject(setup, 4, -1, -1, (obj)->anim.parent);
        ObjLink_AttachChild(obj, state->foodChild, state->packedSlots.foodChildSlot);
        childTimerReset = gTrickyFloatZero;
        state->foodVoiceTimer = childTimerReset;
        state->foodForceBlinkTimer = childTimerReset;
        state->foodBlinkTimer = childTimerReset;
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
    int result;

    result = tricky_handleFeedOrTalk(obj, trickyState);
    if (result != 0) {
        return 1;
    }
    result = trickyUpdateMovementState(obj, TRICKY_TIMER_20_FRAMES, (TrickyState*)trickyState);
    if (result == 1) {
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
            s8 idleCommandPhase;
            idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
            state->commandPhase = idleCommandPhase;
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
                            objSoundStartTimed(obj, &voiceState->soundState, TRICKY_VOICE_SFX_IM_NOT_DOING_IT, 1280, -1,
                                               0);
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

    handled = tricky_handleFeedOrTalk(obj, trickyState);
    if (handled != 0) {
        return 1;
    }
    if (trickyState->waterIdleTimer > gTrickyFloatZero) {
        trickyRequestMove(obj, TRICKY_ANIM_WATER_IDLE, 0.01f, 0);
        trickyState->substate = 2;
        trickyState->waterIdleTimer = gTrickyFloatZero;
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
            tricky_startRandomIdleMove(obj, trickyState);
        } else {
            if (trickyState->questPromptChild != NULL) {
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
                        interactionState->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                        interactionState->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
                    interactionState->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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

/* child/reward objects spawned by this DLL (retail OBJECTS.bin remap-source names) */
#define TRICKY_SPAWN_ROMDEF_BADGE_A       0x244 /* TrickyBadge */
#define TRICKY_SPAWN_ROMDEF_BADGE_B       0x254 /* TrickyBadge */
#define TRICKY_SPAWN_ROMDEF_QUEST         0x17c /* TrickyQuest */
#define TRICKY_SPAWN_ROMDEF_EXCLAMATION   0x175 /* TrickyExcla */
#define TRICKY_SPAWN_ROMDEF_SIDEKICK_BALL 0x112 /* SidekickBal (DLL 0xF5) */
#define TRICKY_ROMDEF_BLUE_MUSHROOM       0x6a  /* BlueMushroo */

/* Values compared against GameObject.anim.romDefNo in the sidekick command dispatcher.
 * Most are object-catalog remap-source IDs rather than OBJECTS.bin def_id rows. */
#define TRICKY_COMMAND_TARGET_WCTEMPLEPRE      0x36
#define TRICKY_COMMAND_TARGET_SH_BEACON        0x3c
#define TRICKY_COMMAND_TARGET_CCEYE_VINES      0x102
#define TRICKY_COMMAND_TARGET_STAY_POINT       0x104
#define TRICKY_COMMAND_TARGET_CF_DOOR_LIGHT    0x131
#define TRICKY_COMMAND_TARGET_DIM_LOG_FIRE     0x191
#define TRICKY_COMMAND_TARGET_LINK_BLUE_MUSH   0x193
#define TRICKY_COMMAND_TARGET_BURNABLE_VINE    0x194
#define TRICKY_COMMAND_TARGET_NW_MAMMOTH_G     0x195
#define TRICKY_COMMAND_TARGET_LINK_SNOW_PRESS  0x19f
#define TRICKY_COMMAND_TARGET_DIM_ICE_WALL     0x1c9
#define TRICKY_COMMAND_TARGET_SH_PRESSURE      0x26c
#define TRICKY_COMMAND_TARGET_DFP_TRANSLA      0x352
#define TRICKY_COMMAND_TARGET_DFP_TARGET_B     0x358
#define TRICKY_COMMAND_TARGET_DR_CHIMMEY       0x470
#define TRICKY_COMMAND_TARGET_DR_COLLAPSE      0x475
#define TRICKY_COMMAND_TARGET_VFP_PUZZLE_POINT 0x546
#define TRICKY_COMMAND_TARGET_VFP_FLAMEPOINT   0x551
#define TRICKY_COMMAND_TARGET_MS_PLANTING_SEED 0x54c
#define TRICKY_COMMAND_TARGET_SH_WHITEMUSH     0x658
#define TRICKY_COMMAND_TARGET_ICE_HOLE         0x6f9
#define TRICKY_COMMAND_TARGET_TRICKY_GUARD     0x6f0
#define TRICKY_COMMAND_TARGET_DIM_TRUTH_HORN   0x718
#define TRICKY_COMMAND_TARGET_SC_PRESSURE      0x7c3
#define TRICKY_COMMAND_TARGET_TUMBLEWEED2      0x3fb
#define TRICKY_COMMAND_TARGET_WC_BEACON        0x50f
#define TRICKY_COMMAND_TARGET_ARW_TIMED_MIN    0x542

#define TRICKY_OBJGROUP              1
#define TRICKY_BBOX_HIT_SCRATCH_SIZE 84
#define TRICKY_HELPER_WARP_OBJECT_ID 0x25 /* "warp" transporter / WarpPoint */

typedef enum TrickySequenceEvent {
    TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN = 1,
    TRICKY_SEQUENCE_EVENT_SPAWN_BADGE = 2,
    TRICKY_SEQUENCE_EVENT_STORE_ENERGY = 3,
    TRICKY_SEQUENCE_EVENT_HIDE_SHADOW = 0x2B,
    TRICKY_SEQUENCE_EVENT_SHOW_SHADOW = 0x2C,
} TrickySequenceEvent;

int gTrickyUnusedSbss;
GameObject* gTrickyWarpHelperObject;

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
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
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
        ObjPlacement* setup = Obj_AllocObjectSetup(sizeof(ObjPlacement), TRICKY_HELPER_WARP_OBJECT_ID);
        gTrickyWarpHelperObject = objSetupObject(setup, 4, -1, -1, obj->anim.parent);
    }
    state->ownsWarpHelperObject = 1;
}

int tricky_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    TrickyState* state;
    int i;
    ObjSeqState* sequence = animUpdate;
    u8* childSlot;
    int secondChildIndex;
    int childIndex;
    u8* spawnSlot;
    ObjPlacement* setup;
    u8 blockFlags[120];

    state = obj->extra;
    if ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0) {
        ObjHits_DisableObject(obj);
        Sfx_StopObjectChannel(obj, SFX_OBJECT_CHANNEL_MASK_ALL);
        if ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
            state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
            state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
            for (childIndex = 0, childSlot = (u8*)state; childIndex < TRICKY_FLAME_CHILD_COUNT;
                 childSlot += sizeof(GameObject*), childIndex++) {
                objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(childSlot));
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
        state->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_LATCHED;
        if ((sequence->flags & OBJSEQ_TARGET_MOTION_FLAGS) == 0) {
            state->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
        }
        if (state->sequencePreserveBlend == 0) {
            ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
            state->blendActive = 0;
        }
    }

    for (i = 0; i < sequence->eventCount; i++) {
        switch (sequence->eventIds[i]) {
        case TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN:
            if ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                state->stateFlags &= ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                for (secondChildIndex = 0, childSlot = (u8*)state; secondChildIndex < TRICKY_FLAME_CHILD_COUNT;
                     childSlot += sizeof(GameObject*), secondChildIndex++) {
                    objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(childSlot));
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
                state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                for (childIndex = 0, spawnSlot = (u8*)state; childIndex < TRICKY_FLAME_CHILD_COUNT;
                     spawnSlot += sizeof(GameObject*), childIndex++) {
                    setup = Obj_AllocObjectSetup(sizeof(FlameblastPlacement), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);
                    ((FlameblastPlacement*)setup)->base.color[0] = 2;
                    ((FlameblastPlacement*)setup)->base.color[1] = 1;
                    ((FlameblastPlacement*)setup)->streamIndex = childIndex;
                    *trickyFlameChildSlotFromStateCursor(spawnSlot) =
                        objSetupObject(setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
                }
                Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_SPAWN_BADGE:
            mainSetBits(GAMEBIT_Tricky_LoadBadge, 1);
            if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && state->spawnedChild == NULL && (u8)Obj_CanSetupObject()) {
                mapGetLoadedMapFlags(blockFlags);
                if (blockFlags[0xd] != 0) {
                    setup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_A);
                } else {
                    setup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_B);
                }
                state->spawnedChild = objSetupObject(setup, 4, -1, -1, obj->anim.parent);
                ObjLink_AttachChild(obj, state->spawnedChild, 3);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_STORE_ENERGY:
            state->stats->energy = state->pendingEnergy;
            break;
        case TRICKY_SEQUENCE_EVENT_HIDE_SHADOW:
            obj->anim.modelState->flags &= ~(u64)OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        case TRICKY_SEQUENCE_EVENT_SHOW_SHADOW:
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        }
    }

    objAnimFreeChildren(obj, state, &state->exclamationPromptChild);
    objAnimFreeChildren(obj, state, &state->questPromptChild);
    objAnimFreeChildren(obj, state, &state->foodChild);
    trickyUpdateColorVariant(obj, state);
    Tricky_updateBlendChannelWeight(obj, state);
    objAudioDispatchAnimEvents(obj, &sequence->animEvents, 1, state->footPoints, &state->pathControlFlags, 1.0f, 1.0f);
    if ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_CALLBACK) != 0) {
        sequence->flags &= ~OBJSEQ_FLAG_TEXTURE_ANIM_TRACKS;
        characterDoEyeAnims(obj, &state->eyeAnimState);
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
    TrickyState* state = obj->extra;
    u8 mode = state->stateIndex;
    if (mode == 8 || mode == 0xe) {
        return 1;
    }
    return 0;
}

int Tricky_isPlayingBall(GameObject* obj) {
    TrickyState* state;
    u8 mode;
    int result;

    state = obj->extra;
    mode = state->stateIndex;
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
    s32 objBlocked = obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK;

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
    TrickyState* state = obj->extra;
    return state->stats->maxEnergy;
}
u8 Tricky_getEnergy(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->stats->energy;
}

void sideCommandEnable(GameObject* obj, GameObject* targetObj, enum TrickyCommandKind commandKind,
                       enum TrickyCommandType commandType) {
    int remaining;
    TrickyState* commandCursor;
    u32 count;
    int commandIndex;
    TrickyState* state;

    state = obj->extra;
    if (state->commandCount == ARRAY_COUNT(state->commands)) {
        trickyReportError(sSidekickCommandDebugTextBlock);
        return;
    }
    state->sideCommandPromptMask = (u8)(state->sideCommandPromptMask | TRICKY_COMMAND_TYPE_TO_FLAG(commandType));
    commandIndex = 0;
    commandCursor = state;
    count = state->commandCount;
    for (remaining = count; remaining > 0; remaining--) {
        if (commandCursor->commands[0].targetObj == targetObj) {
            state->commands[commandIndex].ttlFrames = TRICKY_COMMAND_TTL_FRAMES;
            return;
        }
        commandCursor = (TrickyState*)((u8*)commandCursor + sizeof(TrickyCommand));
        commandIndex++;
    }
    state->commands[count].targetObj = targetObj;
    state->commands[state->commandCount].commandKind = commandKind;
    state->commands[state->commandCount].commandType = commandType;
    state->commands[state->commandCount].ttlFrames = TRICKY_COMMAND_TTL_FRAMES;
    state->commandCount++;
}

int Tricky_getCurrentCommandPhase(GameObject* obj, int* outCommandPhase) {
    TrickyState* state = obj->extra;
    *outCommandPhase = state->commandPhase;
    return 1;
}

int Tricky_updateSideCommandPrompts(GameObject* obj) {
    TrickyState* state;
    u32 commandMask;
    s8 commandKind;
    u16 questPromptSfxId;
    u8 showQuestPrompt;
    u8 showExclamationPrompt;
    u8 showFoodVoicePrompt;
    u8 showBaddieVoicePrompt;
    u32 promptValue;
    int promptScratch;
    TrickyState* foodVoiceState;
    TrickyState* baddieVoiceState;
    ObjPlacement* promptSetup;
    GameObject* promptObj;
    u8 commandIndex;
    char questPromptOccupiedSlots[4];
    char exclamationPromptOccupiedSlots[4];
    u32 questPromptSfxIds[4];

    state = obj->extra;
    showQuestPrompt = false;
    showExclamationPrompt = false;
    showFoodVoicePrompt = false;
    showBaddieVoicePrompt = false;
    questPromptSfxIds[0] = *(u32*)gTrickyQuestPromptSfxIds;
    promptValue = mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands);
    if (promptValue != 0) {
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            state->sideCommandPromptMask = 0;
        }
        commandMask = state->sideCommandPromptMask | (TRICKY_COMMAND_FLAG_CALL | TRICKY_COMMAND_FLAG_STAY);
        if (((state->stateIndex == TRICKY_STATE_GUARD) || (state->stateIndex == TRICKY_STATE_CIRCLING)) ||
            ((state->stateIndex == TRICKY_STATE_GROWL && (state->substate == 1)))) {
            commandMask |= TRICKY_COMMAND_FLAG_FLAME;
            showExclamationPrompt = true;
        } else {
            if (trickyFindNearestUsableBaddie(state->playerObj, TRICKY_AMBIENT_ACTIVITY_BASE, 1) != NULL) {
                showExclamationPrompt = true;
                showBaddieVoicePrompt = true;
            }
        }
        if (state->sideCommandPromptMask != 0) {
            for (commandIndex = 0; commandIndex < state->commandCount; commandIndex++) {
                promptScratch = (int)state + commandIndex * sizeof(TrickyCommand);
                commandKind = ((TrickyState*)promptScratch)->commands[0].commandKind;
                if (commandKind == TRICKY_COMMAND_KIND_NORMAL) {
                    if (((TrickyState*)promptScratch)->commands[0].targetObj->anim.romDefNo ==
                        TRICKY_ROMDEF_BLUE_MUSHROOM) {
                        showFoodVoicePrompt = true;
                    }
                    showExclamationPrompt = true;
                } else if (commandKind == TRICKY_COMMAND_KIND_PRIORITY) {
                    showQuestPrompt = true;
                }
            }
        }
        if (((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) &&
            (promptValue = mainGetBit(GAMEBIT_ITEM_TrickyBall_Usable), promptValue != 0)) {
            promptScratch = (int)Obj_GetPlayerObject();
            promptScratch = playerIsInNormalControlUndisguisedOnLand((GameObject*)(promptScratch));
            if ((promptScratch != 0) && (promptValue = mainGetBit(GAMEBIT_NoBallsAllowed), promptValue == 0)) {
                if (playerGetFlags3F0Bit5(state->playerObj) == 0) {
                    commandMask |= TRICKY_COMMAND_FLAG_PLAY_BALL;
                }
            }
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0) {
            commandMask &= ~TRICKY_COMMAND_FLAG_CALL;
        }
        if (mainGetBit(GAMEBIT_Tricky_Learned_Distract) == 0) {
            commandMask &= ~TRICKY_COMMAND_FLAG_DISTRACT;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) == 0) {
            commandMask &= ~TRICKY_COMMAND_FLAG_FLAME;
        }
        state->sideCommandPromptMask = 0;
        if ((showQuestPrompt) && ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0)) {
            state->questPromptTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
            if ((state->questPromptChild == NULL) && ((u8)Obj_CanSetupObject() != 0)) {
                promptValue = randomGetRange(0, 1);
                questPromptSfxId = ((u16*)questPromptSfxIds)[promptValue];
                promptScratch = (int)obj->extra;
                if ((((TrickyState*)promptScratch)->soundSuppressed == 0) &&
                    (((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                       (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
                      !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)))) {
                    objSoundStartTimed(obj, &((TrickyState*)promptScratch)->soundState, questPromptSfxId, 0x500,
                                       0xffffffff, 0);
                }
                promptSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_QUEST);
                questPromptOccupiedSlots[0] = -1;
                questPromptOccupiedSlots[1] = -1;
                questPromptOccupiedSlots[2] = -1;
                if (state->exclamationPromptChild != NULL) {
                    questPromptOccupiedSlots[state->packedSlots.exclamationPromptSlot] = '\x01';
                }
                if (state->questPromptChild != NULL) {
                    questPromptOccupiedSlots[state->packedSlots.questPromptSlot] = '\x01';
                }
                if (state->foodChild != NULL) {
                    questPromptOccupiedSlots[state->packedSlots.foodChildSlot] = '\x01';
                }
                if (questPromptOccupiedSlots[0] == -1) {
                    promptValue = 0;
                } else if (questPromptOccupiedSlots[1] == -1) {
                    promptValue = 1;
                } else if (questPromptOccupiedSlots[2] == -1) {
                    promptValue = 2;
                } else if (questPromptOccupiedSlots[3] == -1) {
                    promptValue = 3;
                } else {
                    promptValue = 0xffffffff;
                }
                state->packedSlots.questPromptSlot = promptValue;
                promptObj = objSetupObject(promptSetup, 4, -1, 0xffffffff, obj->anim.parent);
                state->questPromptChild = promptObj;
                ObjLink_AttachChild(obj, state->questPromptChild, state->packedSlots.questPromptSlot);
            }
        } else if (state->questPromptChild != NULL) {
            state->questPromptTimer = state->questPromptTimer - timeDelta;
            if (state->questPromptTimer <= gTrickyFloatZero) {
                objAnimFreeChildren(obj, state, &state->questPromptChild);
            }
        }
        if ((showExclamationPrompt) && ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0)) {
            state->exclamationPromptTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
            if ((state->exclamationPromptChild == NULL) && ((u8)Obj_CanSetupObject() != 0)) {
                if (randomGetRange(0, 3) == 0) {
                    if (showFoodVoicePrompt) {
                        foodVoiceState = obj->extra;
                        if ((foodVoiceState->soundSuppressed == 0) &&
                            (((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                               (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
                              !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)))) {
                            objSoundStartTimed(obj, &foodVoiceState->soundState, TRICKY_VOICE_SFX_FOOD, 0x500,
                                               0xffffffff, 0);
                        }
                    } else if ((((showBaddieVoicePrompt) &&
                                 (baddieVoiceState = obj->extra, baddieVoiceState->soundSuppressed == 0)) &&
                                ((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END ||
                                  (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)))) &&
                               !Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)) {
                        objSoundStartTimed(obj, &baddieVoiceState->soundState, TRICKY_VOICE_SFX_BAD_GUY, 0x500,
                                           0xffffffff, 0);
                    }
                }
                promptSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_EXCLAMATION);
                exclamationPromptOccupiedSlots[0] = -1;
                exclamationPromptOccupiedSlots[1] = -1;
                exclamationPromptOccupiedSlots[2] = -1;
                if (state->exclamationPromptChild != NULL) {
                    exclamationPromptOccupiedSlots[state->packedSlots.exclamationPromptSlot] = '\x01';
                }
                if (state->questPromptChild != NULL) {
                    exclamationPromptOccupiedSlots[state->packedSlots.questPromptSlot] = '\x01';
                }
                if (state->foodChild != NULL) {
                    exclamationPromptOccupiedSlots[state->packedSlots.foodChildSlot] = '\x01';
                }
                if (exclamationPromptOccupiedSlots[0] == -1) {
                    promptValue = 0;
                } else if (exclamationPromptOccupiedSlots[1] == -1) {
                    promptValue = 1;
                } else if (exclamationPromptOccupiedSlots[2] == -1) {
                    promptValue = 2;
                } else if (exclamationPromptOccupiedSlots[3] == -1) {
                    promptValue = 3;
                } else {
                    promptValue = 0xffffffff;
                }
                state->packedSlots.exclamationPromptSlot = promptValue;
                promptObj = objSetupObject(promptSetup, 4, -1, 0xffffffff, obj->anim.parent);
                state->exclamationPromptChild = promptObj;
                ObjLink_AttachChild(obj, state->exclamationPromptChild, state->packedSlots.exclamationPromptSlot);
            }
        } else if (state->exclamationPromptChild != NULL) {
            state->exclamationPromptTimer = state->exclamationPromptTimer - timeDelta;
            if (state->exclamationPromptTimer <= gTrickyFloatZero) {
                objAnimFreeChildren(obj, state, &state->exclamationPromptChild);
            }
        }
        return commandMask;
    }
    return -1;
}

int Tricky_getAvailableCommands(GameObject* obj) {
    int commandMask = 0;
    if (mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0) {
        commandMask = TRICKY_COMMAND_FLAG_FIND_SECRET | TRICKY_COMMAND_FLAG_STAY;
        if (mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0) {
            commandMask |= TRICKY_COMMAND_FLAG_CALL;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
            commandMask |= TRICKY_COMMAND_FLAG_PLAY_BALL;
        }
        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0) {
            commandMask |= TRICKY_COMMAND_FLAG_FLAME;
        }
    }
    return commandMask;
}

int Tricky_getExtraSize(void) {
    return offsetof(TrickyState, pad83C);
}

void Tricky_free(GameObject* obj, int shouldKeepFlameChildren) {
    int childIndex;
    u8* flameChildCursor;
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
        childIndex = 0;
        flameChildCursor = (u8*)state;
        do {
            objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(flameChildCursor));
            flameChildCursor = flameChildCursor + sizeof(GameObject*);
            childIndex = childIndex + 1;
        } while (childIndex < TRICKY_FLAME_CHILD_COUNT);
        Sfx_RemoveLoopedObjectSound((GameObject*)objId, SFXTRIG_trpopn_c);
        flameChildCursor = obj->extra;
        if ((((TrickyState*)flameChildCursor)->soundSuppressed == 0) &&
            (((obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || (obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN)) &&
              (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0)))) {
            objSoundStartTimed(obj, &((TrickyState*)flameChildCursor)->soundState, TRICKY_VOICE_SFX_FINISH_FLAME, 0,
                               0xffffffff, 0);
        }
    }
    doNothing_onTrickyFree();
    objAnimFreeChildren(obj, state, &state->exclamationPromptChild);
    objAnimFreeChildren(obj, state, &state->questPromptChild);
    objAnimFreeChildren(obj, state, &state->foodChild);
    if (state->spawnedChild != NULL) {
        ObjLink_DetachChild(obj, state->spawnedChild);
        Obj_FreeObject(state->spawnedChild);
    }
    if ((state->ownsWarpHelperObject != 0u) && (gTrickyWarpHelperObject != 0)) {
        Obj_FreeObject(gTrickyWarpHelperObject);
        gTrickyWarpHelperObject = 0;
    }
    return;
}

void Tricky_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, char doRender) {
    int pathPointIndex;
    TrickyState* renderState;
    int pathPointCursor;
    s16* modelAnchorPose;
    TrickyState* state;

    if (doRender != '\0') {
        state = obj->extra;
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        renderState = obj->extra;
        pathPointIndex = 0;
        pathPointCursor = (int)renderState;
        do {
            ObjPath_GetPointWorldPosition(obj, pathPointIndex + 4,
                                          &((TrickyState*)pathPointCursor)->pathPointPositions[0].x,
                                          &((TrickyState*)pathPointCursor)->pathPointPositions[0].y,
                                          &((TrickyState*)pathPointCursor)->pathPointPositions[0].z, 0);
            pathPointCursor = pathPointCursor + 0xc;
            pathPointIndex = pathPointIndex + 1;
        } while (pathPointIndex < 4);
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
                objRenderModelAndHitVolumes(state->fetchBallObj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
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
    GameObject** xyzAnimatorCursor;
    int animatorIndex;
    GameObject* firepipeObj;
    TrickyState* state;
    f32 animatorHeight;
    f32 trackedHeightReset;
    f32 previousTrackedHeight;
    int animatorCount[2];

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
        firepipeObj = ObjList_FindObjectById(XYZ_ANIMATOR_DRAGON_ROCK_FIREPIPE_IDENT);
        if ((firepipeObj != 0) && (getXZDistanceSquared(&obj->anim.worldPosX, &firepipeObj->anim.worldPosX) <
                                   TRICKY_FIREPIPE_HEIGHT_DIST_SQ)) {
            state->heightTracking = 1;
            state->heightTrackObjId = XYZ_ANIMATOR_DRAGON_ROCK_FIREPIPE_IDENT;
            state->trackedHeight = gTrickyFloatZero;
        }
    }
    if (state->heightTracking != 0u) {
        {
            GameObject** objectList = (GameObject**)objGetAllOfType(XYZ_ANIMATOR_OBJECT_GROUP, animatorCount);
            animatorIndex = 0;
            xyzAnimatorCursor = objectList;
        }
        for (; animatorIndex < animatorCount[0]; animatorIndex++) {
            animatorHeight = XyzAnimator_getCoordinate(*xyzAnimatorCursor, XYZ_ANIMATOR_COORD_WORLD_Y);
            if (state->heightTrackObjId == -1) {
                dy = (animatorHeight - obj->anim.localPosY >= gTrickyFloatZero)
                         ? animatorHeight - obj->anim.localPosY
                         : -(animatorHeight - obj->anim.localPosY);
                if (dy < TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    state->heightTrackObjId = (*xyzAnimatorCursor)->anim.placement->ident;
                }
            }
            if ((u32)state->heightTrackObjId == (u32)(*xyzAnimatorCursor)->anim.placement->ident) {
                previousTrackedHeight = state->trackedHeight;
                trackedHeightReset = gTrickyFloatZero;
                if ((previousTrackedHeight != trackedHeightReset) && (previousTrackedHeight == animatorHeight)) {
                    state->heightTracking = 0;
                } else {
                    obj->anim.localPosY = animatorHeight;
                    state->trackedHeight = animatorHeight;
                }
                break;
            }
            xyzAnimatorCursor = xyzAnimatorCursor + 1;
        }
        if (animatorIndex == animatorCount[0]) {
            state->heightTracking = 0;
        }
    }
    return;
}

/* Tricky sidekick command state machine and per-frame update. */
static inline f32 trickyResetCommandState(TrickyState* state) {
    f32 resetValue;

    state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
    state->substate = 0;
    resetValue = gTrickyFloatZero;
    state->cooldownA = resetValue;
    state->cooldownB.f = resetValue;
    state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
    state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_RECALL_REQUEST;
    state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_HEEL_REQUEST;
    state->stateFlags = state->stateFlags & (u64)~TRICKY_STATE_FLAG_GUARD_REQUEST;
    state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
    return resetValue;
}

static inline void trickyPlaySidekickVoice(GameObject* obj, u16 sfxId, int volume) {
    TrickyState* voiceState;

    voiceState = obj->extra;
    if (voiceState->soundSuppressed == 0) {
        if (obj->anim.currentMove >= TRICKY_VOICE_MOVE_END || obj->anim.currentMove < TRICKY_VOICE_MOVE_MIN) {
            if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                objSoundStartTimed(obj, &voiceState->soundState, sfxId, volume, 0xffffffff, 0);
            }
        }
    }
}

static inline void trickySpawnFoodBubble(GameObject* obj, TrickyState* state) {
    if (state->foodChild == NULL) {
        TrickyPromptChildSetup* setup;
        s8 occupiedSlots[4];
        int freeSlot;
        f32 childTimerReset;

        setup = (TrickyPromptChildSetup*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_SPAWN_ROMDEF_FOOD);
        occupiedSlots[0] = -1;
        occupiedSlots[1] = -1;
        occupiedSlots[2] = -1;
        if (state->exclamationPromptChild != NULL) {
            occupiedSlots[state->packedSlots.exclamationPromptSlot] = 1;
        }
        if (state->questPromptChild != NULL) {
            occupiedSlots[state->packedSlots.questPromptSlot] = 1;
        }
        if (state->foodChild != NULL) {
            occupiedSlots[state->packedSlots.foodChildSlot] = 1;
        }
        if (occupiedSlots[0] == -1) {
            freeSlot = 0;
        } else if (occupiedSlots[1] == -1) {
            freeSlot = 1;
        } else if (occupiedSlots[2] == -1) {
            freeSlot = 2;
        } else if (occupiedSlots[3] == -1) {
            freeSlot = 3;
        } else {
            freeSlot = -1;
        }
        state->packedSlots.foodChildSlot = freeSlot;
        state->foodChild = objSetupObject(&setup->base, 4, -1, -1, obj->anim.parent);
        ObjLink_AttachChild(obj, state->foodChild, state->packedSlots.foodChildSlot);
        childTimerReset = gTrickyFloatZero;
        state->foodVoiceTimer = childTimerReset;
        state->foodForceBlinkTimer = childTimerReset;
        state->foodBlinkTimer = childTimerReset;
    }
}

void Tricky_update(GameObject* obj) {
    char* debugTextBase;
    TrickyDebugCollisionData* debugData;
    TrickyState* trickyState;
    int commandAlreadyQueued;
    int impressSfxId;
    TrickyState* voiceState;
    struct {
        int index;
    } childLoop;
    int i;
    TrickyState* commandCursor;
    ObjPlacement* placementSetup;
    int count;
    u32 flags;
    GameObject* nearestBaddie;
    int accepted;
    int waterFootstepActive;
    f32* targetPos;
    f32 resetValue;
    f32 moveProgress;
    u8 loadedMapFlags[120];
    TrickyCommandTypeList sideCommandQuery;
    TrickySfxPair impressSfxPair;

    debugTextBase = gTrickyDebugStringTable;
    debugData = (TrickyDebugCollisionData*)debugTextBase;
    trickyState = obj->extra;
    commandAlreadyQueued = 0;
    sideCommandQuery = gTrickyCommandQueryInit;
    impressSfxPair = sTrickyImpressSfxPair;
    Objfsa_UpdateWalkGroupPatches();
    if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && (void*)trickyState->spawnedChild == NULL &&
        (u8)Obj_CanSetupObject()) {
        mapGetLoadedMapFlags(loadedMapFlags);
        if (loadedMapFlags[0xd] != 0) {
            placementSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_A);
        } else {
            placementSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_B);
        }
        trickyState->spawnedChild = objSetupObject(placementSetup, 4, -1, -1, obj->anim.parent);
        ObjLink_AttachChild(obj, trickyState->spawnedChild, 3);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FEED_VOICE_PENDING_U32) != 0) {
        TrickyStats* stats = trickyState->stats;

        if (stats->energy == stats->maxEnergy) {
            trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_IM_STUFFED, 0x500);
        } else {
            trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_MMMM_TASTY, 0x500);
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
            resetValue = trickyResetCommandState(trickyState);
            trickyState->movementState = TRICKY_MOVE_WALK_WAIT;
            trickyState->prevSpeed = resetValue;
            trickyState->speed = resetValue;
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
            resetValue = gTrickyFloatZero;
            trickyState->prevSpeed = resetValue;
            trickyState->speed = resetValue;
            trickyState->stateFlags |= (u64)TRICKY_STATE_FLAG_POSITION_RELOCATED;
            trickyState->stateFlags &= ~(u64)TRICKY_STATE_FLAG_GROUND_SNAP;
            if ((trickyState->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                u8* childCursor;

                trickyState->stateFlags = trickyState->stateFlags & ~(u64)TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
                trickyState->stateFlags = trickyState->stateFlags | TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
                childCursor = (u8*)trickyState;
                for (; childLoop.index < TRICKY_FLAME_CHILD_COUNT;
                     childCursor += sizeof(GameObject*), childLoop.index++) {
                    objSetAnimSpeedTo1(*trickyFlameChildSlotFromStateCursor(childCursor));
                }
                Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
                trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_FINISH_FLAME, 0);
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        }
        resetValue = trickyResetCommandState(trickyState);
        trickyState->followObj = NULL;
    }
    {
        int requestedCommand;

        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0 &&
            (*gGameUIInterface)->isItemBeingUsed(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
            requestedCommand = 0;
        } else {
            requestedCommand =
                (*gGameUIInterface)->isOneOfItemsBeingUsed(sideCommandQuery.commandTypes, TRICKY_COMMAND_QUERY_COUNT);
        }
        commandCursor = trickyState;
        count = trickyState->commandCount;
        for (i = 0; i < count; i++, commandCursor = (TrickyState*)((u8*)commandCursor + sizeof(TrickyCommand))) {
            if (commandCursor->commands[0].commandType == requestedCommand) {
                commandAlreadyQueued = 1;
                break;
            }
        }
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0 &&
            trickyShouldGoToWarpPoint(obj, trickyState) == 2) {
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
                    trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_FIND_SECRET_SNIFF, 0);
                    switch (trickyState->followObj->anim.romDefNo) {
                    case SKEETLA_LINKED_SOURCE_ROMDEF_GROUND_ANIMA:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                resetValue = trickyResetCommandState(trickyState);
                                trickySpawnFoodBubble(obj, trickyState);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case SKEETLA_LINKED_SOURCE_ROMDEF_WALL_ANIMATO:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                resetValue = trickyResetCommandState(trickyState);
                                trickySpawnFoodBubble(obj, trickyState);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_DIG_TUNNEL;
                        }
                        break;
                    case TRICKY_ROMDEF_BLUE_MUSHROOM:
                    case TRICKY_COMMAND_TARGET_LINK_BLUE_MUSH:
                    case TRICKY_COMMAND_TARGET_TUMBLEWEED2:
                    case TRICKY_COMMAND_TARGET_SH_WHITEMUSH:
                        trickyState->stateIndex = TRICKY_STATE_MOVE_TO_FOLLOW_TARGET;
                        break;
                    case TRICKY_COMMAND_TARGET_NW_MAMMOTH_G:
                        if (trickyState->stats->energy < 2) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                resetValue = trickyResetCommandState(trickyState);
                                trickySpawnFoodBubble(obj, trickyState);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_TRACK_TUMBLEWEED;
                        }
                        break;
                    case TRICKY_COMMAND_TARGET_DFP_TRANSLA:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                resetValue = trickyResetCommandState(trickyState);
                                trickySpawnFoodBubble(obj, trickyState);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case TRICKY_COMMAND_TARGET_DFP_TARGET_B:
                        trickyState->stateIndex = TRICKY_STATE_GROWL;
                        break;
                    default:
                        resetValue = trickyResetCommandState(trickyState);
                        trickyReportError(debugTextBase + TRICKY_DBG_COMMAND_WRONG_OBJECT);
                        break;
                    }
                    break;
                case TRICKY_COMMAND_TYPE_STAY:
                    accepted = 0;
                    if (trickyState->commandPhase == TRICKY_COMMAND_PHASE_GUARD) {
                        commandCursor = trickyState;
                        count = trickyState->commandCount;
                        for (i = 0; i < count;
                             i++, commandCursor = (TrickyState*)((u8*)commandCursor + sizeof(TrickyCommand))) {
                            if (commandCursor->commands[0].commandType == TRICKY_COMMAND_TYPE_STAY) {
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
                            case TRICKY_COMMAND_TARGET_WCTEMPLEPRE:
                            case TRICKY_COMMAND_TARGET_STAY_POINT:
                            case TRICKY_COMMAND_TARGET_CF_DOOR_LIGHT:
                            case TRICKY_COMMAND_TARGET_LINK_SNOW_PRESS:
                            case TRICKY_COMMAND_TARGET_SH_PRESSURE:
                            case TRICKY_COMMAND_TARGET_DR_COLLAPSE:
                            case TRICKY_COMMAND_TARGET_VFP_PUZZLE_POINT:
                            case TRICKY_COMMAND_TARGET_SC_PRESSURE:
                                trickyState->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                                trickyState->idleSfxTimer = (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES,
                                                                                     TRICKY_IDLE_VOICE_MAX_FRAMES);
                                break;
                            case TRICKY_COMMAND_TARGET_TRICKY_GUARD:
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
                            resetValue = trickyResetCommandState(trickyState);
                            trickySpawnFoodBubble(obj, trickyState);
                        }
                    } else {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_FLAME;
                        trickySelectQueuedCommandTarget(trickyState, TRICKY_COMMAND_TYPE_FLAME);
                        trickyState->stateIndex = TRICKY_STATE_FLAME;
                        switch (trickyState->followObj->anim.romDefNo) {
                        case TRICKY_COMMAND_TARGET_DIM_ICE_WALL:
                            trickyState->actionCallback = dimicewall_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_DIM_TRUTH_HORN:
                            trickyState->actionCallback = dimtruthhornice_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_VFP_FLAMEPOINT:
                            trickyState->actionCallback = vfpflamepoint_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_DIM_LOG_FIRE:
                            trickyState->actionCallback = dimlogfire_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_DR_CHIMMEY:
                            trickyState->actionCallback = drchimmey_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_CCEYE_VINES:
                        case TRICKY_COMMAND_TARGET_BURNABLE_VINE:
                        case TRICKY_COMMAND_TARGET_ARW_TIMED_MIN:
                        case TRICKY_COMMAND_TARGET_MS_PLANTING_SEED:
                        case TRICKY_COMMAND_TARGET_ICE_HOLE:
                            trickyState->actionCallback = NULL;
                            break;
                        case TRICKY_COMMAND_TARGET_SH_BEACON:
                            trickyState->actionCallback = (TrickyActionCallback)sh_beacon_resetFadeTimerCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_WC_BEACON:
                            trickyState->actionCallback = (TrickyActionCallback)wcbeacon_aButtonCallback;
                            break;
                        default:
                            resetValue = trickyResetCommandState(trickyState);
                            trickyReportError(debugTextBase + TRICKY_DBG_COMMAND_WRONG_OBJECT);
                            break;
                        }
                    }
                    break;
                case TRICKY_COMMAND_TYPE_PLAY_BALL:
                    if ((u8)Obj_CanSetupObject()) {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_PLAY_BALL;
                        placementSetup = Obj_AllocObjectSetup(sizeof(ObjPlacement), TRICKY_SPAWN_ROMDEF_SIDEKICK_BALL);
                        placementSetup->color[3] = 0xff;
                        placementSetup->color[0] = 2;
                        placementSetup->posX = obj->anim.worldPosX;
                        placementSetup->posY = obj->anim.worldPosY;
                        placementSetup->posZ = obj->anim.worldPosZ;
                        trickyState->followObj = objSetupObject(placementSetup, 5, -1, -1, obj->anim.parent);
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
                resetValue = trickyResetCommandState(trickyState);
                trickyState->commandPhase = TRICKY_COMMAND_PHASE_NONE;
            } else {
                resetValue = trickyResetCommandState(trickyState);
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
    debugData->pathPointCollision.stateHandlers[trickyState->stateIndex](obj, trickyState);
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
    resetValue = gTrickyFloatZero;
    if (moveProgress == resetValue) {
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
    if (obj->anim.currentMove == TRICKY_ANIM_HOWL_HOLD) {
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
        TrickyState* expiringCommandCursor = (TrickyState*)((u8*)trickyState + i * sizeof(TrickyCommand));

        for (; i >= 0;
             expiringCommandCursor = (TrickyState*)((u8*)expiringCommandCursor - sizeof(TrickyCommand)), i--) {
            s8* ttlFrames = (s8*)&expiringCommandCursor->commands[0].ttlFrames;

            *ttlFrames -= 1;
            if (*ttlFrames == 0) {
                memmove(&expiringCommandCursor->commands[0],
                        &((TrickyState*)((u8*)trickyState + (i + 1) * sizeof(TrickyCommand)))->commands[0],
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
    trickyState->waterIdleTimer -= timeDelta;
    if (trickyState->waterIdleTimer < gTrickyFloatZero) {
        trickyState->waterIdleTimer = gTrickyFloatZero;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FOOD_WARNING_PENDING) != 0) {
        voiceState = obj->extra;
        if (voiceState->soundSuppressed != 0) {
            accepted = 0;
        } else {
            switch (obj->anim.currentMove) {
            case TRICKY_ANIM_HOWL_START:
            case TRICKY_ANIM_HOWL_HOLD:
            case TRICKY_ANIM_HOWL_END:
            case TRICKY_ANIM_DIG_FOOD_START_A:
            case TRICKY_ANIM_DIG_FOOD_START_B:
            case TRICKY_ANIM_DIG_FOOD_LOOP:
            case TRICKY_ANIM_DIG_FOOD_END:
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
        trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_TOY_BARK, 0x100);
    }
    trickyUpdateCollisionAndPathState(obj);
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_IMPRESS_PENDING_U32) != 0) {
        trickyState->impressTimer -= timeDelta;
        if (trickyState->impressTimer <= gTrickyFloatZero) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_IMPRESS_PENDING_U32;
            impressSfxId = ((u16*)&impressSfxPair)[randomGetRange(0, 1)];
            trickyPlaySidekickVoice(obj, impressSfxId, 0x500);
        }
    }
    trickyUpdateColorVariant(obj, trickyState);
    Tricky_updateBlendChannelWeight(obj, trickyState);
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
                waterFootstepSfxId = TRICKY_WATER_FOOTSTEP_SFX_ID;
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
    if (trickyState->foodChild != NULL) {
        trickyState->foodVoiceTimer += timeDelta;
        trickyState->foodForceBlinkTimer += timeDelta;
        trickyState->foodBlinkTimer += timeDelta;
        {
            f32 blinkTimer = trickyState->foodBlinkTimer;

            if (blinkTimer > TRICKY_CHILD_BLINK_PERIOD_FRAMES) {
                trickyState->foodBlinkTimer = blinkTimer - TRICKY_CHILD_BLINK_PERIOD_FRAMES;
            }
        }
        if (trickyState->foodBlinkTimer >= TRICKY_CHILD_BLINK_HOLD_FRAMES) {
            trickyState->foodChild->anim.flags = trickyState->foodChild->anim.flags | OBJANIM_FLAG_HIDDEN;
        } else {
            trickyState->foodChild->anim.flags = trickyState->foodChild->anim.flags & ~OBJANIM_FLAG_HIDDEN;
        }
        if (trickyState->foodForceBlinkTimer > TRICKY_CHILD_BLINK_FORCE_FRAMES) {
            if (trickyState->foodForceBlinkTimer > TRICKY_TIMER_600_FRAMES) {
                trickyState->foodForceBlinkTimer -= TRICKY_TIMER_600_FRAMES;
            }
            trickyState->foodChild->anim.flags = trickyState->foodChild->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        if (trickyState->foodVoiceTimer > TRICKY_CHILD_VOICE_PERIOD_FRAMES) {
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
                trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_SCARED, 0x500);
            } else {
                trickyPlaySidekickVoice(obj, TRICKY_VOICE_SFX_TIRED, 0x500);
            }
            trickyState->foodVoiceTimer -= TRICKY_CHILD_VOICE_PERIOD_FRAMES;
        }
        ObjAnim_AdvanceCurrentMove(trickyState->foodChild, TRICKY_FLOAT_0_01, timeDelta, 0);
    }
    if (trickyState->questPromptChild != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->questPromptChild, TRICKY_FLOAT_0_01, timeDelta, 0);
    }
    if (trickyState->exclamationPromptChild != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->exclamationPromptChild, TRICKY_FLOAT_0_01, timeDelta, 0);
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
    state->sideCommandPromptMask = 0;
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
