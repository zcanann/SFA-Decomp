/*
 * Tricky companion DLL.
 *
 * Blend-channel weight animation (Tricky_updateBlendChannelWeight), the
 * color-variant fade (trickyUpdateColorVariant), impress reaction (trickyImpress), queued-path particle emission
 * (Tricky_emitQueuedPathParticles), baddie target search
 * (trickyFindNearestUsableBaddie) and queued-command target selection
 * (trickySelectQueuedCommandTarget), plus small state accessors.
 */

#include "dlls/objects/196_Tricky.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_001E_effect5.h"
#include "main/vecmath.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/dll/baddie_control_interface.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "main/model.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/dll_0019_dll19func0.h"
#include "main/track_dolphin_api.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/rom_curve_def.h"
#include "main/dll/dll_0015_curves.h"
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
#include "main/objprint_sound_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/objfsa_query_api.h"
#include "main/dll/modgfx.h"
#include "main/dll/dll_0014_api.h"
#include "main/dll/Hcurves_api.h"
#include "main/vecmath_distance_api.h"
#include "main/audio/sfx.h"
#include "dlls/objects/243_flameblast.h"
#include "dlls/objects/235.h"
#include "dlls/objects/312_GroundAnima.h"
#include "dlls/objects/315_WallAnimato.h"
#include "main/dll/tumbleweedbush.h"
#include "main/audio/sfx_looped_object_api.h"
#include "main/dll/player_target.h"
#include "game/objects/object_setup.h"
#include "main/trig.h"
#include "main/frustum.h"
#include "dlls/objects/245_SidekickBal.h"
#include "dlls/objects/417_NW_mammoth.h"
#include "dlls/objects/429_SH_thorntai.h"
#include "dlls/objects/209_TumbleWeedB.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
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

static int trickyIsInDeepWater(TrickyState* state);
static f32 trickyDecelerate(f32 speed, f32 minSpeed);
static f32 trickyAccelerate(f32 speed, f32 maxSpeed);
static void trickyAdvanceToSegmentEnd(RomCurveWalker* route);
static void trickyRequestIdleMove(GameObject* obj, TrickyState* state);
static inline f32 trickyGetTargetDistanceRate(GameObject* obj);
static void trickyUpdateFacingFromMoveVector(GameObject* obj, TrickyState* state, s16* turnDeltaOut);
static inline void trickyTurnAlongMoveDirection(GameObject* obj);
static inline RomCurveDef* trickyValidateRouteEntry(RomCurveDef* entry);
static inline int trickyApproachTarget(GameObject* obj, f32 stoppingRadius, TrickyState* state, f32* targetPos);
static inline void trickySetTargetPosition(TrickyState* state, f32* targetPos);
static inline void trickyRestoreRecoveryPosition(GameObject* obj, TrickyState* state);
void trickyGrowl(GameObject* obj, TrickyState* trickyState);
static inline int trickyAcquireBaddieAlertTarget(TrickyState* state);
void trickyUpdateBaddieAlert(GameObject* obj, TrickyState* state);
GameObject* trickyFindCirclingTarget(GameObject* obj, TrickyState* state);
void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state);
void tricky_fetchBall(GameObject* obj, TrickyState* state);
void tricky_idleAndEat(GameObject* obj, TrickyState* state);
void tricky_trackTumbleweed(GameObject* obj, TrickyState* state);
void tricky_moveToFollowTarget(GameObject* obj, TrickyState* state);
static inline int trickyGuardIsBaddieTargetValid(GameObject* target);
static inline void trickyStopFlameChildren(GameObject* obj, TrickyState* state);
static inline void trickySpawnFlameChildren(GameObject* obj, TrickyState* state);
void trickyGuard(GameObject* obj, TrickyState* trickyState);
int trickyGuardFindBaddieTarget(TrickyState* trickyState);
void trickyFlame(GameObject* obj, TrickyState* trickyState);
void tricky_state06_nop(void);
void tricky_handlePlayerContact(GameObject* obj, TrickyState* state);
static inline void trickyResetCommandState(TrickyState* state);
static inline void trickySpawnFoodBubble(GameObject* obj, TrickyState* state);

typedef struct TrickyBaddieTargetPlacement {
    ObjPlacement base;
    s16 disableGameBit;
    s16 enableGameBit;
} TrickyBaddieTargetPlacement;

STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, base.ident) == 0x14);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, disableGameBit) == 0x18);
STATIC_ASSERT(offsetof(TrickyBaddieTargetPlacement, enableGameBit) == 0x1A);

/* Tricky voice trigger ids, with unnamed ids decoded against retail audio/data/Sfx.bin. */
typedef enum TrickyVoiceSfxId {
    TRICKY_VOICE_SFX_FIND_SECRET_SNIFF = 0x13c, /* SFXnewtricky_01j, distinct trigger params */
    TRICKY_VOICE_SFX_TIRED = 0x298,
    TRICKY_VOICE_SFX_GROWL = 0x299,
    TRICKY_VOICE_SFX_SLEEP_BREATH = 0x29a, /* SFXsk_trbrth2/3, SFXsk_trgrwl1/2 */
    TRICKY_VOICE_SFX_ROLLING = 0x29b,
    TRICKY_VOICE_SFX_TOY_BARK = 0x29c, /* SFXsk_toysq2_c, SFXsk_trbark1/2 */
    TRICKY_VOICE_SFX_FINISH_FLAME = 0x29d,
    TRICKY_VOICE_SFX_WAIT_UP_FOX = 0x34d,
    TRICKY_VOICE_SFX_WAIT_FOR_ME = 0x34e,
    TRICKY_VOICE_SFX_HEY = 0x34f,
    TRICKY_VOICE_SFX_GET_OFF = 0x350,
    TRICKY_VOICE_SFX_LOOK_AT_THIS = 0x351,
    TRICKY_VOICE_SFX_IM_HUNGRY = 0x352,
    TRICKY_VOICE_SFX_YAWN2 = 0x353,
    TRICKY_VOICE_SFX_YAWN = 0x354,
    TRICKY_VOICE_SFX_LETS_PLAY = 0x355,
    TRICKY_VOICE_SFX_COOL = 0x356,
    TRICKY_VOICE_SFX_SNIFF = 0x357,
    TRICKY_VOICE_SFX_BAD_GUY = 0x358,
    TRICKY_VOICE_SFX_FOOD = 0x359,
    TRICKY_VOICE_SFX_THERES_SOMETHING_NEAR = 0x35a,
    TRICKY_VOICE_SFX_GET_MFOX = 0x35b,
    TRICKY_VOICE_SFX_YEAH = 0x35c,
    TRICKY_VOICE_SFX_IM_NOT_DOING_IT = 0x35d,
    TRICKY_VOICE_SFX_HELLO = 0x35e,
    TRICKY_VOICE_SFX_HI_FELLA = 0x35f,
    TRICKY_VOICE_SFX_DUM_DE_DUM = 0x360,
    TRICKY_VOICE_SFX_LAUGH = 0x361,
    TRICKY_VOICE_SFX_CHEWING = 0x362,
    TRICKY_VOICE_SFX_MMMM_TASTY = 0x363,
    TRICKY_VOICE_SFX_IM_STUFFED = 0x364,
    TRICKY_VOICE_SFX_WHERE_ARE_WE_GOING = 0x365,
    TRICKY_VOICE_SFX_SNORE_IN = 0x390,
    TRICKY_VOICE_SFX_SNORE_OUT = 0x391,
    TRICKY_VOICE_SFX_SCARED = 0x392,
} TrickyVoiceSfxId;

#define TRICKY_COLOR_FADE_ALPHA_SCALE 196.0f

/* Repeated Tricky movement-animation contract values. */
#define TRICKY_WATER_COOLDOWN_FRAMES     600.0f
#define TRICKY_CHILD_BLINK_PERIOD_FRAMES 30.0f
#define TRICKY_CHILD_BLINK_HOLD_FRAMES   20.0f
#define TRICKY_CHILD_BLINK_FORCE_FRAMES  150.0f
#define TRICKY_CHILD_VOICE_PERIOD_FRAMES 2400.0f
#define TRICKY_REMOTE_RECALL_DISTANCE_SQ 360000.0f
#define TRICKY_VISIBILITY_PROBE_RADIUS   19.0f
#define TRICKY_RECALL_COOLDOWN_FRAMES    1200.0f
#define TRICKY_AUDIO_EVENT_MIN_SPEED     0.2f
#define TRICKY_AMBIENT_ACTIVITY_BASE     200.0f
#define TRICKY_AMBIENT_WANDER_SCALE      0.1
#define TRICKY_PATH_SEARCH_BULK_STEPS    0x1f4
#define TRICKY_IDLE_VOICE_MIN_FRAMES     500
#define TRICKY_IDLE_VOICE_MAX_FRAMES     750
#define TRICKY_VOICE_MOVE_MIN            0x29
#define TRICKY_VOICE_MOVE_END            0x30
#define TRICKY_VOICE_CHANNEL             0x10
#define TRICKY_VOICE_MOUTH_ANGLE_NONE    0
#define TRICKY_VOICE_MOUTH_ANGLE_SMALL   0x100
#define TRICKY_VOICE_MOUTH_ANGLE_NORMAL  0x500
#define TRICKY_VOICE_MOUTH_ANGLE_LARGE   0x1000
typedef enum TrickyAnimId {
    TRICKY_ANIM_LAND_IDLE = 0,
    TRICKY_ANIM_WALK_SLOW = 1,
    TRICKY_ANIM_WALK_MEDIUM = 2,
    TRICKY_ANIM_WALK_FAST = 4,
    TRICKY_ANIM_RUN = 5,
    TRICKY_ANIM_SWIM = 7,
    TRICKY_ANIM_SWIM_TURN = 8,
    TRICKY_ANIM_TURN_LEFT_SMALL = 9,
    TRICKY_ANIM_TURN_RIGHT_SMALL = 10,
    TRICKY_ANIM_TURN_LEFT_MEDIUM = 11,
    TRICKY_ANIM_TURN_RIGHT_MEDIUM = 12,
    TRICKY_ANIM_IDLE_FOOD_WAIT = 0x0d,
    TRICKY_ANIM_FOLLOW_ARC_RETURN = 0x0e,
    TRICKY_ANIM_FETCH_THROW_READY = 0x10,
    TRICKY_ANIM_FETCH_PICKUP_LAND = 0x11,
    TRICKY_ANIM_FETCH_THROW_LAND = 0x13,
    TRICKY_ANIM_HUNGRY_IDLE = 0x14,
    TRICKY_ANIM_FOLLOW_JUMP_PREP = 0x15,
    TRICKY_ANIM_FOLLOW_JUMP = 0x16,
    TRICKY_ANIM_FOLLOW_JUMPUP_FAST = 0x17,
    TRICKY_ANIM_FOLLOW_JUMPUP_SLOW = 0x18,
    TRICKY_ANIM_FOLLOW_JUMPDOWN = 0x19,
    TRICKY_ANIM_FLAME_BREATH = 0x1a,
    TRICKY_ANIM_WATER_IDLE = 0x1b,
    TRICKY_ANIM_FETCH_PICKUP_WATER = 0x1c,
    TRICKY_ANIM_FETCH_THROW_WATER = 0x1d,
    TRICKY_ANIM_IDLE_FIDGET_B_START = 0x21,
    TRICKY_ANIM_IDLE_FIDGET_B_END = 0x22,
    TRICKY_ANIM_IDLE_FIDGET_A_START = 0x23,
    TRICKY_ANIM_IDLE_FIDGET_A_END = 0x24,
    TRICKY_ANIM_IDLE_WANDER = 0x25,
    TRICKY_ANIM_IDLE_PICK = 0x26,
    TRICKY_ANIM_TURN_LEFT_LARGE = 0x27,
    TRICKY_ANIM_TURN_RIGHT_LARGE = 0x28,
    TRICKY_ANIM_HOWL_START = 0x29,
    TRICKY_ANIM_HOWL_HOLD = 0x2a,
    TRICKY_ANIM_HOWL_END = 0x2b,
    TRICKY_ANIM_HOWL_IDLE_PICK = 0x2c,
    TRICKY_ANIM_DIG_FOOD_START_A = 0x2c,
    TRICKY_ANIM_AMBIENT_HOWL = 0x2d,
    TRICKY_ANIM_DIG_FOOD_START_B = 0x2d,
    TRICKY_ANIM_DIG_FOOD_LOOP = 0x2e,
    TRICKY_ANIM_DIG_FOOD_END = 0x2f,
    TRICKY_ANIM_LAND_RUN_LOOP = 0x30,
    TRICKY_ANIM_IDLE_FOOD_CHEW = 0x31,
    TRICKY_ANIM_GUARD_GROWL = 0x32,
    TRICKY_ANIM_GROWL_WINDUP = 0x33,
    TRICKY_ANIM_FLAME_ATTACK = 0x34,
} TrickyAnimId;
#define TRICKY_PARTFX_HOWL_SPARKLE       0x7f0
#define TRICKY_YAW_HALF_TURN             0x8000
#define TRICKY_YAW_QUARTER_TURN          0x4000
#define TRICKY_YAW_WRAP_RANGE            0xffff
#define TRICKY_TURN_REQUEST_DEADBAND     0x10
#define TRICKY_TURN_STEP_DEADBAND        0x200
#define TRICKY_ROUTE_TURN_SLOWDOWN_ANGLE 0x1000
#define TRICKY_TURN_LARGE_ANGLE          0x3555
#define TRICKY_TURN_MEDIUM_ANGLE         0x2000
#define TRICKY_WATER_FOOTSTEP_SFX_ID     0x433
#define TRICKY_COMMAND_TTL_FRAMES        3
#define TRICKY_TALK_SEQUENCE_NONE        0xff
#define TRICKY_HOWL_HOLD_MIN_FRAMES      0x78
#define TRICKY_HOWL_HOLD_MAX_FRAMES      0xf0

#define TRICKY_STATE_FLAG_SIDESTEP                0x20  /* apply sidestepDelta lateral offset */
#define TRICKY_STATE_FLAG_BACKSTEP                0x40  /* apply backstepDelta offset */
#define TRICKY_STATE_FLAG_VERTICAL_MOVE           0x80  /* apply verticalDelta to localPosY */
#define TRICKY_STATE_FLAG_ROTATE                  0x100 /* interpolate rotation toward targetYaw target */
#define TRICKY_STATE_FLAG_SEQUENCE_CALLBACK       0x1
#define TRICKY_STATE_FLAG_STUCK_VOICE_PENDING     0x2
#define TRICKY_STATE_FLAG_FOOD_WARNING_PENDING    0x4
#define TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED 0x8
#define TRICKY_STATE_FLAG_SEQUENCE_LATCHED        0x200
#define TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE     0x4000
#define TRICKY_STATE_FLAG_GROUND_SNAP             0x2000
#define TRICKY_STATE_FLAG_POSITION_RELOCATED      0x80000
#define TRICKY_STATE_FLAG_TURN_REQUEST            0x100000
#define TRICKY_STATE_FLAG_TURN_REQUEST_PREV       0x200000
#define TRICKY_STATE_FLAG_TURN_LEFT               0x400000
#define TRICKY_STATE_FLAG_TURN_RIGHT              0x800000
#define TRICKY_STATE_FLAG_TURNING                 0x10000000
#define TRICKY_STATE_FLAG_SUN_VOICE_PLAYED        0x20000000
#define TRICKY_STATE_FLAG_FEED_VOICE_PENDING      0x40000000
#define TRICKY_STATE_FLAG_IMPRESS_PENDING         0x80000000
#define TRICKY_STATE_CHILD_ACTIVITY_FLAGS         (TRICKY_STATE_FLAG_CHILDREN_ACTIVE | TRICKY_STATE_FLAG_CHILDREN_CLEANUP)

#define TRICKY_MOVE_FLAG_KEEP_PROGRESS        0x01000000
#define TRICKY_MOVE_FLAG_ROOT_TRANSLATE       0x02000000
#define TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION 0x04000000
#define TRICKY_MOVE_FLAG_WALK_LOOP            (TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_MOVE_FLAG_ROOT_TRANSLATE)
#define TRICKY_MOVE_FLAG_JUMP_ARC                                                                                      \
    (TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION | TRICKY_STATE_FLAG_BACKSTEP | TRICKY_STATE_FLAG_VERTICAL_MOVE)

/* The one partfx effect emitted along Tricky's queued impress path. */
#define TRICKY_PATH_PARTFX             0x533
#define TRICKY_PATH_PARTFX_BURST_COUNT 0x14
#define TRICKY_PATH_PARTFX_SPAWN_FLAGS 2

#define TRICKY_PROMPT_CHILD_SLOT_COUNT    4
#define TRICKY_PROMPT_CHILD_SLOT_FREE     -1
#define TRICKY_PROMPT_CHILD_SLOT_OCCUPIED 1

#define TRICKY_BADDIE_OBJGROUP       3
#define TRICKY_INTERACTABLE_OBJGROUP 49 /* things Tricky can activate; excluded from baddie targeting */
/* creatures excluded from Tricky's baddie targeting (retail OBJECTS.bin names). */
#define TRICKY_SEQID_WHIRLPOOL 2129 /* "Whirlpool" (DLL 0xC9) */
#define TRICKY_SEQID_VAMBAT    1022 /* "Vambat" (DLL 0xC9) */
#define TRICKY_SEQID_WB        1239 /* "WB" (DLL 0xC9) */
#define TRICKY_SEQID_PINPON    593  /* "PinPon" (DLL 0xC9) */

#define TRICKY_NO_FLOOR_Y                -100000.0f
#define TRICKY_SWIM_MIN_DEPTH            8.0f
#define TRICKY_MAX_DISTANCE              340282346638528859811704183484516925440.0f
#define TRICKY_SPEED_DECAY_STEP          -0.15f
#define TRICKY_SMALL_SPEED_STEP          0.05f
#define TRICKY_FAST_MOVE_ANIM_RATE       0.02f
#define TRICKY_LAND_MOVE_ANIM_RATE       0.005f
#define TRICKY_ROUTE_REVERSE_STEP        -2.0f
#define TRICKY_ROUTE_LOOKAHEAD_SCALE     1.5f
#define TRICKY_YAW_STEP_RATE             512.0f
#define TRICKY_PI                        3.1415927f
#define TRICKY_ANGLE_HALF_TURN_UNITS     32768.0f
#define TRICKY_BALL_RETURNS_PER_COLOR    10
#define TRICKY_BALL_RETURN_COUNT_MAX     0xef
#define TRICKY_COLOR_CHANGE_SEEN_GAMEBIT 1005
#define TRICKY_COLOR_CHANGE_SEQUENCE_ID  5

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
#define SIDEREPEL_OBJGROUP             0x40 /* DLL 0xEB siderepel */
#define SKEETLA_TARGET_OBJGROUP        5
#define TRICKY_DIG_ROMDEF_GROUND_ANIMA 0x1ca
#define TRICKY_DIG_ROMDEF_WALL_ANIMATO 0x160
#define SKEETLA_CONTACT_OBJ_PROJBALL   0x1f /* "projball" (DLL 0xE3) */

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
#define TRICKY_DIG_PARTICLE_RANDOM_RATE 4
void tricky_state06_nop(void);
void trickyFlame(GameObject* obj, TrickyState* trickyState);
void trickyGuard(GameObject* obj, TrickyState* trickyState);
void tricky_moveToFollowTarget(GameObject* obj, TrickyState* state);
void tricky_idleAndEat(GameObject* obj, TrickyState* state);
void tricky_fetchBall(GameObject* obj, TrickyState* state);
void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state);
void trickyUpdateBaddieAlert(GameObject* obj, TrickyState* state);
void tricky_trackTumbleweed(GameObject* obj, TrickyState* state);

typedef void (*TrickyStateHandler)(GameObject* obj, TrickyState* state);
typedef int (*TrickySubstateHandler)(GameObject* obj, TrickyState* state);

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
    TRICKY_STATE_CIRCLE_TARGET = 12,
    TRICKY_STATE_BADDIE_ALERT = 13,
    TRICKY_STATE_GROWL = 14,
    TRICKY_STATE_IDLE_WANDER = 15,
    TRICKY_STATE_TRACK_TUMBLEWEED = 16,
    TRICKY_STATE_GO_TO_WARP_POINT = 17,
} TrickyStateId;

typedef enum TrickyMovementResult {
    TRICKY_MOVEMENT_REACHED_TARGET = 0,
    TRICKY_MOVEMENT_IN_PROGRESS = 1,
    TRICKY_MOVEMENT_BLOCKED = 2,
} TrickyMovementResult;

typedef enum TrickyDigTunnelSubstate {
    TRICKY_DIG_TUNNEL_INIT = 0,
    TRICKY_DIG_TUNNEL_FINDING_ENTRY = 1,
    TRICKY_DIG_TUNNEL_GOING_TO_START = 2,
    TRICKY_DIG_TUNNEL_START_DIGGING = 3,
    TRICKY_DIG_TUNNEL_DIGGING = 4,
    TRICKY_DIG_TUNNEL_TO_EXIT_1 = 5,
    TRICKY_DIG_TUNNEL_TO_EXIT_2 = 6,
    TRICKY_DIG_TUNNEL_WAIT_FOR_PLAYER_GROUP = 7,
} TrickyDigTunnelSubstate;

typedef enum TrickySecretDigSubstate {
    TRICKY_SECRET_DIG_SCAN_CURVE = 0,
    TRICKY_SECRET_DIG_APPROACH_TARGET = 1,
    TRICKY_SECRET_DIG_APPROACH_CURVE = 2,
    TRICKY_SECRET_DIG_START_PRESS = 3,
    TRICKY_SECRET_DIG_PRESSING = 4,
} TrickySecretDigSubstate;

typedef enum TrickyFetchBallSubstate {
    TRICKY_FETCH_BALL_INIT = 0,
    TRICKY_FETCH_BALL_CHASE = 1,
    TRICKY_FETCH_BALL_THROW_DONE = 2,
    TRICKY_FETCH_BALL_PICKUP_START = 3,
    TRICKY_FETCH_BALL_CARRY_TO_PLAYER = 4,
    TRICKY_FETCH_BALL_APPROACH_THROW_POINT = 5,
    TRICKY_FETCH_BALL_LAUNCH = 6,
    TRICKY_FETCH_BALL_WAIT_FOR_IDLE = 7,
} TrickyFetchBallSubstate;

typedef enum TrickyCannonballSubstate {
    TRICKY_CANNONBALL_INIT = 0,
    TRICKY_CANNONBALL_ROLLING = 1,
} TrickyCannonballSubstate;

typedef enum TrickyTumbleweedSubstate {
    TRICKY_TUMBLEWEED_INIT = 0,
    TRICKY_TUMBLEWEED_CHASE = 1,
} TrickyTumbleweedSubstate;

typedef enum TrickyFollowSubstate {
    TRICKY_FOLLOW_SUBSTATE_IDLE = 0,
    TRICKY_FOLLOW_SUBSTATE_RETURN_TO_HEEL = 1,
    TRICKY_FOLLOW_SUBSTATE_WAIT_QUEUED_MOVE = 2,
    TRICKY_FOLLOW_SUBSTATE_SLEEP = 3,
    TRICKY_FOLLOW_SUBSTATE_HOWL_CALL = 4,
    TRICKY_FOLLOW_SUBSTATE_WAIT_MOVE_END = 5,
    TRICKY_FOLLOW_SUBSTATE_FIDGET_B = 6,
    TRICKY_FOLLOW_SUBSTATE_FIDGET_A = 7,
    TRICKY_FOLLOW_SUBSTATE_IDLE_PICK = 8,
    TRICKY_FOLLOW_SUBSTATE_DIG_FOR_FOOD = 9,
    TRICKY_FOLLOW_SUBSTATE_BEG_FOR_FOOD = 10,
    TRICKY_FOLLOW_SUBSTATE_FLAME_BREATH = 11,
    TRICKY_FOLLOW_SUBSTATE_APPROACH_THORNTAIL = 12,
} TrickyFollowSubstate;

typedef enum TrickyAmbientActivity {
    TRICKY_AMBIENT_ACTIVITY_APPROACH_THORNTAIL = 0,
    TRICKY_AMBIENT_ACTIVITY_WANDER = 1,
    TRICKY_AMBIENT_ACTIVITY_DIG_FOR_FOOD = 2,
    TRICKY_AMBIENT_ACTIVITY_HOWL = 3,
} TrickyAmbientActivity;

typedef enum TrickyRandomIdleMove {
    TRICKY_RANDOM_IDLE_LAND_IDLE = 0,
    TRICKY_RANDOM_IDLE_PICK = 1,
    TRICKY_RANDOM_IDLE_FIDGET_B = 2,
    TRICKY_RANDOM_IDLE_FIDGET_A = 3,
    TRICKY_RANDOM_IDLE_WANDER = 4,
} TrickyRandomIdleMove;

typedef enum TrickyPendingFollowRequest {
    TRICKY_PENDING_FOLLOW_NONE = 0,
    TRICKY_PENDING_FOLLOW_HANDOFF = 1,
} TrickyPendingFollowRequest;

static Vec gTrickyCollisionSegmentPoints[2] = {
    {0.0f, 0.0f, 0.0f},
    {0.0f, 17.0f, 0.0f},
};

static Vec gTrickyPathPointCollision = {0.0f, 0.0f, 0.0f};

static TrickyStateHandler sTrickyStateHandlers[18] = {
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
    trickyUpdateBaddieAlert,
    trickyGrowl,
    tricky_stateIdleWander,
    tricky_trackTumbleweed,
    tricky_stateGoToWarpPoint,
};

static TrickySubstateHandler sTrickySubstateHandlers[13] = {
    (TrickySubstateHandler)tricky_substateFollowIdle,        (TrickySubstateHandler)tricky_substateReturnToHeel,
    (TrickySubstateHandler)tricky_substateWaitQueuedMove,    (TrickySubstateHandler)tricky_substateSleep,
    (TrickySubstateHandler)tricky_substateHowlCall,          (TrickySubstateHandler)tricky_substateWaitMoveEnd,
    (TrickySubstateHandler)tricky_substateFidgetB,           (TrickySubstateHandler)tricky_substateFidgetA,
    (TrickySubstateHandler)tricky_substateIdlePick,          (TrickySubstateHandler)tricky_substateDigForFood,
    (TrickySubstateHandler)tricky_substateBegForFood,        (TrickySubstateHandler)tricky_substateFlameBreath,
    (TrickySubstateHandler)tricky_substateApproachThorntail,
};

/*
 * Tricky steering, animation selection and RomCurve route walking.
 *
 * moveTricky steers toward a target point with object-avoidance
 * (trickyApplyObjectAvoidanceToStep) and picks a walk/run/turn anim plus
 * follow voice barks by speed. The RomCurve helpers (trickySelectRouteEntry and
 * friends) choose and walk the spline route Tricky follows, gated by game
 * bits on each curve. Tricky_emitDigParticles emits the digging
 * particles for the object Tricky is linked to.
 */

f32 gTrickyCollisionSegmentRadii[2] = {0.05f, 8.5f};
f32 gTrickyPathPointCollisionRadius = 8.0f;
char sTrickyVelocityDebugFmt[] = "Vel %f\n";

#define TRICKY_AVOIDANCE_REPATH_EPSILON_SQ 0.0001f
#define TRICKY_TINY_MOVE_ANIM_RATE         0.0001f
#define TRICKY_RUN_MOVE_THRESHOLD          2.5f
#define TRICKY_FAST_WALK_MOVE_THRESHOLD    0.66f
#define TRICKY_SLOW_WALK_MOVE_THRESHOLD    0.33f
#define TRICKY_TURN_MOVE_ANIM_RATE         0.04f
#define TRICKY_ANIM_TRANSITION_FRAMES      15.0f
#define TRICKY_FOLLOW_VOICE_MIN_FRAMES     600
#define TRICKY_FOLLOW_VOICE_MAX_FRAMES     1200
#define TRICKY_FAST_FOLLOW_VOICE_THRESHOLD 1.0f

#define TRICKY_POSITION_OFFSET_SCALE 0.1f

/*
 * Tricky sidekick follow/path-walk movement. trickyUpdateMovementState is
 * the per-frame movement step that resolves the target's walk/patch group and
 * drives motion through a substate machine and RomCurveWalker route;
 * trickyUpdateApproachSpeed ramps the follow speed toward a target point.
 */

#define TRICKY_FOLLOW_MAX_SPEED                 3.0f
#define TRICKY_FOLLOW_JUMPUP_FAST_ANIM_RATE     0.0135f
#define TRICKY_FOLLOW_JUMPUP_SLOW_ANIM_RATE     0.00975f
#define TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR   32.865f
#define TRICKY_FOLLOW_JUMPDOWN_ANIM_RATE        0.0125f
#define TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR 33.114f
#define TRICKY_FOLLOW_ARC_SPEED                 2.3f
#define TRICKY_FOLLOW_ARC_HALF_PROGRESS         0.5f
#define TRICKY_FOLLOW_ARC_QUARTER_PROGRESS      0.25f
#define TRICKY_FOLLOW_ARC_COEFFICIENT           -0.017f
#define TRICKY_FOLLOW_ARC_PROGRESS_WINDOW       24.0f
#define TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW       6.0f
#define TRICKY_FOLLOW_ARC_MIDDLE_WINDOW         12.0f
#define TRICKY_FOLLOW_JUMP_LAND_SPEED           0.75f

#define TRICKY_DEFAULT_STOPPING_RADIUS 5.0f

#define TRICKY_CLOSE_DISTANCE_SQ              2500.0f
#define TRICKY_GROWL_FLAME_RADIUS             25.0f
#define TRICKY_FLAME_DONE_PROGRESS            0.95f
#define TRICKY_CIRCLING_APPROACH_RADIUS       50.0f
#define TRICKY_BADDIE_ALERT_CLOSE_DISTANCE_SQ 3600.0f
#define TRICKY_BADDIE_ALERT_FAR_DISTANCE_SQ   5625.0f
#define TRICKY_BADDIE_ALERT_FLAME_RADIUS      55.0f
#define TRICKY_BADDIE_ALERT_SPAWN_PROGRESS    0.3f
#define TRICKY_FETCH_CARRY_DELAY_FRAMES       180.0f
#define TRICKY_FETCH_BALL_REACH_RADIUS        13.0f
#define TRICKY_FETCH_PICKUP_ANIM_RATE         0.03f
#define TRICKY_FETCH_THROW_DELAY_FRAMES       60.0f
#define TRICKY_FETCH_LAUNCH_PROGRESS          0.65f
#define TRICKY_FETCH_VOICE_MIN_FRAMES         150
#define TRICKY_FETCH_VOICE_MAX_FRAMES         300
#define TRICKY_FLAME_HELPER_RELEASE_PROGRESS  0.8f
#define TRICKY_DIG_TUNNEL_ANIM_RATE           0.033f
#define TRICKY_SECRET_DIG_SCAN_DISTANCE_SQ    10000.0f
#define TRICKY_IDLE_WANDER_ANIM_RATE          0.0025f
#define TRICKY_IDLE_PICK_ANIM_RATE            0.0075f
#define TRICKY_IDLE_ACTIVITY_DELAY_MIN_FRAMES 200
#define TRICKY_IDLE_ACTIVITY_DELAY_MAX_FRAMES 500
#define TRICKY_HOWL_CALL_ANIM_RATE            0.003f
#define TRICKY_AMBIENT_HOWL_ANIM_RATE         0.015f
#define TRICKY_CONTACT_FLAME_THRESHOLD        3000.0f
#define TRICKY_PATH_PARTICLE_SCALE            0.4f
#define TRICKY_FIREPIPE_HEIGHT_DIST_SQ        841.0f
#define TRICKY_SWIM_SEED_FLOOR_Y              -10000.0f

#define TRICKYWARP_OBJ_GROUP 0x4b

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

#define PRESSURESWITCHFB_REMOVE_GROUP_ID 0x53

#define TRICKY_SPAWN_ROMDEF_FLAMEBLAST 0x4f0 /* flameblast remap-source romDefNo (DLL 0xF3) */

enum {
    TRICKYGROWL_WINDUP = 0,
    TRICKYGROWL_FACE_TARGET = 1,
    TRICKYGROWL_GOTO_FLAME = 2,
    TRICKYGROWL_FLAME = 3
};

/* The priority actor bypasses the player's lock-on target when choosing what to circle. */
#define TRICKY_CIRCLING_PRIORITY_ROMDEF 0x6a3
#define TRICKY_SPAWN_ROMDEF_FOOD        0x17b /* TrickyFood */

/* State 13 is named BADDIEALERT by retail diagnostics; state 12 handles circling separately. */
enum TrickyBaddieAlertSubstate {
    TRICKY_BADDIE_ALERT_GOTO = 0,
    TRICKY_BADDIE_ALERT_BARK = 1,
    TRICKY_BADDIE_ALERT_GOTO_FLAME = 2,
    TRICKY_BADDIE_ALERT_SPAWN_FLAME = 3,
    TRICKY_BADDIE_ALERT_FLAME = 4,
    TRICKY_BADDIE_ALERT_TRACK_TARGET = 5
};

enum TrickyCirclingPhase {
    TRICKY_CIRCLE_INITIALIZE = 0,
    TRICKY_CIRCLE_ACTIVE = 1,
};

/* Head-only prompt child setup used for TrickyFood, quest, exclamation, and badge bubbles. */
typedef struct TrickyPromptChildSetup {
    ObjPlacement base; /* 0x00 */
    u8 pad18[0x20 - 0x18];
} TrickyPromptChildSetup;

STATIC_ASSERT(sizeof(TrickyPromptChildSetup) == 0x20);

GameObject* trickyFindCirclingTarget(GameObject* obj, TrickyState* state);

/* Tricky flame/guard AI. Spawns Tricky's flameblast (def 0x4F0) for the
 * fire-breath/guard behaviour. */

#define TRICKY_GUARD_APPROACH_GROUP 3

int trickyGuardFindBaddieTarget(TrickyState* state);

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

#define TRICKY_GUARD_POST_DISTANCE       15.0f
#define TRICKY_GUARD_APPROACH_RADIUS     TRICKY_DEFAULT_STOPPING_RADIUS
#define TRICKY_GUARD_BADDIE_RADIUS       15.0f
#define TRICKY_GUARD_FLAME_DONE_PROGRESS TRICKY_FLAME_DONE_PROGRESS
#define TRICKY_GUARD_GROWL_RANDOM_RATE   10
#define TRICKY_GUARD_GROWL_MAX_FRAMES    150.0f
#define TRICKY_GUARD_GROWL_LEASH_DIST_SQ TRICKY_CLOSE_DISTANCE_SQ
#define TRICKY_GUARD_GROWL_DOWN_BLEND    0.01f
#define TRICKY_GUARD_GROWL_UP_BLEND      -0.01f

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

/* Cannonball route movement starts away from the player, then chooses branches
 * nearest to followObj. Outside a walk group, the command remains active. */
#define CANNONBALL_ROLL_DECAY_STEP -0.01f
#define CANNONBALL_ROUTE_FORESTEP  10.0f
#define CANNONBALL_SFX_TIMER_MIN   200
#define CANNONBALL_SFX_TIMER_MAX   600

#define CANNONBALL_ROLL_SPEED_LIMIT 1.2f
#define CANNONBALL_ROUTE_BACKSTEP   -10.0f

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
 * collision water-depth/floor-height test) chooses swim vs walk anims throughout.
 */

/* child objects spawned by this TU (retail OBJECTS.bin remap-source names) */
#define TRICKY_DIG_TUNNEL_WHINE_MIN_FRAMES 0x14
#define TRICKY_DIG_TUNNEL_WHINE_MAX_FRAMES 0xb4
#define TRICKY_SECRET_DIG_WHINE_MIN_FRAMES 0x28
#define TRICKY_SECRET_DIG_WHINE_MAX_FRAMES 0x50

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

/* child/reward objects spawned by this DLL (retail OBJECTS.bin remap-source names) */
typedef enum TrickySpawnRomDefNo {
    TRICKY_SPAWN_ROMDEF_SIDEKICK_BALL = 0x112, /* SidekickBal (DLL 0xF5) */
    TRICKY_SPAWN_ROMDEF_EXCLAMATION = 0x175,   /* TrickyExcla */
    TRICKY_SPAWN_ROMDEF_QUEST = 0x17c,         /* TrickyQuest */
    TRICKY_SPAWN_ROMDEF_BADGE_A = 0x244,       /* TrickyBadge */
    TRICKY_SPAWN_ROMDEF_BADGE_B = 0x254,       /* TrickyBadge */
} TrickySpawnRomDefNo;

typedef enum TrickyPromptAttachment {
    TRICKY_BADGE_MAP_FLAG_INDEX = 0x0d,
    TRICKY_BADGE_CHILD_SLOT = 3,
} TrickyPromptAttachment;

typedef enum TrickyCommandTargetRomDefNo {
    TRICKY_ROMDEF_BLUE_MUSHROOM = 0x6a,        /* BlueMushroo */
    TRICKY_COMMAND_TARGET_WCTEMPLEPRE = 0x36,  /* WCTemplePre */
    TRICKY_COMMAND_TARGET_SH_BEACON = 0x3c,    /* SH_Beacon */
    TRICKY_COMMAND_TARGET_CCEYE_VINES = 0x102, /* CCeyeVines */
    TRICKY_COMMAND_TARGET_STAY_POINT = 0x104,  /* StayPoint */
    TRICKY_COMMAND_TARGET_CF_DOOR_LIGHT = 0x131,
    TRICKY_COMMAND_TARGET_DIM_LOG_FIRE = 0x191,   /* DIMLogFire */
    TRICKY_COMMAND_TARGET_LINK_BLUE_MUSH = 0x193, /* LINK_BlueMu */
    TRICKY_COMMAND_TARGET_BURNABLE_VINE = 0x194,  /* BurnableVin */
    TRICKY_COMMAND_TARGET_NW_MAMMOTH_G = 0x195,
    TRICKY_COMMAND_TARGET_LINK_SNOW_PRESS = 0x19f, /* LINK_SnowPr */
    TRICKY_COMMAND_TARGET_DIM_ICE_WALL = 0x1c9,    /* DIMIceWall */
    TRICKY_COMMAND_TARGET_SH_PRESSURE = 0x26c,     /* SH_Pressure */
    TRICKY_COMMAND_TARGET_DFP_TRANSLA = 0x352,     /* DFP_transla */
    TRICKY_COMMAND_TARGET_DFP_TARGET_B = 0x358,
    TRICKY_COMMAND_TARGET_TUMBLEWEED2 = 0x3fb, /* Tumbleweed2 */
    TRICKY_COMMAND_TARGET_DR_CHIMMEY = 0x470,  /* DR_Chimmey */
    TRICKY_COMMAND_TARGET_DR_COLLAPSE = 0x475,
    TRICKY_COMMAND_TARGET_WC_BEACON = 0x50f, /* WCBeacon */
    TRICKY_COMMAND_TARGET_ARW_TIMED_MIN = 0x542,
    TRICKY_COMMAND_TARGET_VFP_PUZZLE_POINT = 0x546, /* VFP_PuzzleP */
    TRICKY_COMMAND_TARGET_MS_PLANTING_SEED = 0x54c, /* MSPlantingS */
    TRICKY_COMMAND_TARGET_VFP_FLAMEPOINT = 0x551,   /* VFP_flamepo */
    TRICKY_COMMAND_TARGET_SH_WHITEMUSH = 0x658,     /* SH_whitemus */
    TRICKY_COMMAND_TARGET_TRICKY_GUARD = 0x6f0,     /* TrickyGuard */
    TRICKY_COMMAND_TARGET_ICE_HOLE = 0x6f9,
    TRICKY_COMMAND_TARGET_DIM_TRUTH_HORN = 0x718, /* DIMTruthHor */
    TRICKY_COMMAND_TARGET_SC_PRESSURE = 0x7c3,    /* SC_Pressure */
} TrickyCommandTargetRomDefNo;

typedef enum TrickyObjectGroup {
    TRICKY_OBJGROUP = 1,
} TrickyObjectGroup;

typedef enum TrickySpawnObjectId {
    TRICKY_HELPER_WARP_OBJECT_ID = 0x25, /* "warp" transporter / WarpPoint */
} TrickySpawnObjectId;

typedef enum TrickySidekickBallSetupValue {
    TRICKY_SIDEKICK_BALL_COLOR_VARIANT = 2,
    TRICKY_SIDEKICK_BALL_ALPHA = 0xff,
} TrickySidekickBallSetupValue;

#define TRICKY_BBOX_HIT_SCRATCH_SIZE 84

typedef enum TrickySequenceEvent {
    TRICKY_SEQUENCE_EVENT_TOGGLE_FLAME_CHILDREN = 1,
    TRICKY_SEQUENCE_EVENT_SPAWN_BADGE = 2,
    TRICKY_SEQUENCE_EVENT_STORE_ENERGY = 3,
    TRICKY_SEQUENCE_EVENT_HIDE_SHADOW = 0x2B,
    TRICKY_SEQUENCE_EVENT_SHOW_SHADOW = 0x2C,
} TrickySequenceEvent;

int gTrickyUnusedSbss;
GameObject* gTrickyWarpHelperObject;

void trickyDebugPrint(const char* fmt, ...) {
}

void trickyReportError(const char* fmt, ...) {
}

void Tricky_init(GameObject* obj) {
    TrickyState* state = obj->extra;
    ObjModel* model;
    CurvesCollisionState* collision;
    u32 colorVariant;
    s8 queryTypes[2] = {0x0A, 0x08};

    mainSetBits(GAMEBIT_TrickyTalk, TRICKY_TALK_SEQUENCE_NONE);
    if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
        mainSetBits(GAMEBIT_ITEM_TrickyBall_Usable, 1);
    }
    (obj)->animEventCallback = tricky_SeqFn;
    objAddObjectType(obj, TRICKY_OBJGROUP);
    pathSearchInit(&state->candidateSearches[0]);
    pathSearchInit(&state->candidateSearches[1]);
    pathSearchInit(&state->candidateSearches[2]);
    pathSearchInit(&state->candidateSearches[3]);
    pathSearchInit(&state->candidateSearches[4]);
    pathSearchInit(&state->candidateSearches[5]);
    pathSearchInit(&state->candidateSearches[6]);
    pathSearchInit(&state->candidateSearches[7]);
    pathSearchInit(&state->cachedPathSearch);
    state->stats = (*gMapEventInterface)->getTrickyStats();
    state->playerObj = Obj_GetPlayerObject();
    state->stateIndex = TRICKY_STATE_ATTACH_TO_WALKGROUP;
    state->sideCommandPromptMask = 0;
    state->previousTargetPosPtr = NULL;
    state->lastWalkGroup = 0;
    state->recoveryPos.x = (obj)->anim.worldPosX;
    state->recoveryPos.y = (obj)->anim.worldPosY;
    state->recoveryPos.z = (obj)->anim.worldPosZ;
    colorVariant = state->stats->ballReturnCount / TRICKY_BALL_RETURNS_PER_COLOR;
    state->colorVariant = colorVariant;
    model = Obj_GetActiveModel(obj);
    model->textureRefs->swapSelector = state->colorVariant;
    collision = &state->curvesCollision;
    (*gPathControlInterface)->init(collision, 1, 0xa7, CURVES_COLLISION_SUBTYPE_OBJECT);
    (*gPathControlInterface)
        ->setLocalPointCollision(collision, 1, &gTrickyPathPointCollision, &gTrickyPathPointCollisionRadius, 2);
    (*gPathControlInterface)
        ->setup(collision, 2, gTrickyCollisionSegmentPoints, gTrickyCollisionSegmentRadii, queryTypes);
    (*gPathControlInterface)->attachObject(obj, collision);
    doNothing_onTrickyInit();
    Objfsa_UpdateWalkGroupPatches();
    state->groundSnapCounter = 2;
    state->blendPending = 1;
    state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
}

static inline int trickyWrapYawDelta(int delta) {
    if (delta > TRICKY_YAW_HALF_TURN) {
        delta -= TRICKY_YAW_WRAP_RANGE;
    }
    if (delta < -TRICKY_YAW_HALF_TURN) {
        delta += TRICKY_YAW_WRAP_RANGE;
    }
    return delta;
}

void Tricky_update(GameObject* obj) {
    TrickyState* trickyState = obj->extra;
    int commandAlreadyQueued = 0;
    int i;
    ObjPlacement* placementSetup;
    int count;
    u32 flags;
    GameObject* nearestBaddie;
    int accepted;
    int waterFootstepActive;
    f32 resetValue;
    f32 animRate;
    u8 loadedMapFlags[120];
    TrickyCommandTypeList sideCommandQuery = gTrickyCommandQueryInit;
    u16 impressSfxIds[2] = {TRICKY_VOICE_SFX_COOL, TRICKY_VOICE_SFX_YEAH};
    Objfsa_UpdateWalkGroupPatches();
    if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && trickyState->spawnedChild == NULL && (u8)Obj_CanSetupObject()) {
        mapGetLoadedMapFlags(loadedMapFlags);
        if (loadedMapFlags[TRICKY_BADGE_MAP_FLAG_INDEX] != 0) {
            placementSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_A);
        } else {
            placementSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_B);
        }
        trickyState->spawnedChild = objSetupObject(placementSetup, 4, -1, -1, obj->anim.parent);
        ObjLink_AttachChild(obj, trickyState->spawnedChild, TRICKY_BADGE_CHILD_SLOT);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FEED_VOICE_PENDING) != 0) {
        TrickyStats* stats = trickyState->stats;

        if (stats->energy == stats->maxEnergy) {
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_IM_STUFFED, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        } else {
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_MMMM_TASTY, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        }
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_FEED_VOICE_PENDING;
    }
    {
        int flagsByte = trickyState->curvesCollision.surfaceFlags;
        trickyDebugPrint("hits: %d %d %d %d %d %d %d %d", flagsByte & 1, flagsByte & 2, flagsByte & 4, flagsByte & 8,
                         flagsByte & 0x10, flagsByte & 0x20, flagsByte & 0x40, flagsByte & 0x80);
    }
    {
        TrickyStats* stats = trickyState->stats;

        trickyDebugPrint("\nEnergy: %d/%d\n", stats->energy, stats->maxEnergy);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) != 0) {
        ObjHits_EnableObject(obj);
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE) == 0) {
            trickyResetCommandState(trickyState);
            resetValue = 0.0f;
            trickyState->movementState = TRICKY_MOVE_WALK_WAIT;
            trickyState->prevSpeed = resetValue;
            trickyState->speed = resetValue;
            trickyState->recoveryPos.x = obj->anim.worldPosX;
            trickyState->recoveryPos.y = obj->anim.worldPosY;
            trickyState->recoveryPos.z = obj->anim.worldPosZ;
            (*gPathControlInterface)->attachObject(obj, &trickyState->curvesCollision);
            if (obj->anim.currentMove == TRICKY_ANIM_SWIM_TURN || obj->anim.currentMove == TRICKY_ANIM_SWIM) {
                trickyState->curvesCollision.resultWaterDepth = TRICKY_SWIM_MIN_DEPTH;
                trickyState->curvesCollision.resultFloorY = TRICKY_SWIM_SEED_FLOOR_Y;
            } else {
                trickyState->curvesCollision.resultWaterDepth = 0.0f;
            }
        }
        trickyState->stateFlags &= ~(TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE | TRICKY_STATE_FLAG_SEQUENCE_LATCHED |
                                     TRICKY_STATE_FLAG_SEQUENCE_CALLBACK);
        if (trickyState->sequencePreserveBlend != 0) {
            trickyState->sequencePreserveBlend = 0;
        } else {
            trickyState->blendPending = 1;
        }
    }
    if (trickyState->followObj != NULL && (trickyState->followObj->objectFlags & OBJECT_OBJFLAG_FREED) != 0) {
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->groundSnapCounter = 2;
            trickyRestoreRecoveryPosition(obj, trickyState);
            trickyState->movementState = TRICKY_MOVE_WALK_WAIT;
            resetValue = 0.0f;
            trickyState->prevSpeed = resetValue;
            trickyState->speed = resetValue;
            trickyState->stateFlags |= TRICKY_STATE_FLAG_POSITION_RELOCATED;
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_GROUND_SNAP;
            if ((trickyState->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
                trickyStopFlameChildren(obj, trickyState);
            }
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
        }
        trickyResetCommandState(trickyState);
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
        for (i = 0; i < trickyState->commandCount; i++) {
            if (trickyState->commands[i].commandType == requestedCommand) {
                commandAlreadyQueued = 1;
                break;
            }
        }
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0 &&
            trickyShouldGoToWarpPoint(obj, trickyState) == 2) {
            trickyState->stateIndex = TRICKY_STATE_GO_TO_WARP_POINT;
        } else if (trickyState->stateIndex == TRICKY_STATE_GUARD && requestedCommand == TRICKY_COMMAND_TYPE_FLAME) {
            trickyState->guardCanSpawnHelpers = trickyState->guardCanSpawnHelpers ^ 1;
        } else if (trickyState->stateIndex == TRICKY_STATE_BADDIE_ALERT &&
                   requestedCommand == TRICKY_COMMAND_TYPE_FLAME && commandAlreadyQueued == 0) {
            trickyState->flameCommandPending = 1;
        } else if (trickyState->stateIndex == TRICKY_STATE_GROWL && requestedCommand == TRICKY_COMMAND_TYPE_FLAME) {
            trickyState->flameCommandPending = 1;
        } else if (requestedCommand == TRICKY_COMMAND_TYPE_CALL) {
            trickyState->stateFlags |= TRICKY_STATE_FLAG_HEEL_REQUEST | TRICKY_STATE_FLAG_RECALL_REQUEST |
                                       TRICKY_STATE_FLAG_STUCK_VOICE_PENDING;
        } else {
            flags = trickyState->stateFlags;
            if ((flags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                switch (requestedCommand) {
                case TRICKY_COMMAND_TYPE_FIND_SECRET:
                    trickyState->commandPhase = TRICKY_COMMAND_PHASE_DIG;
                    trickySelectQueuedCommandTarget(trickyState, TRICKY_COMMAND_TYPE_FIND_SECRET);
                    trickyTryPlaySound(obj, TRICKY_VOICE_SFX_FIND_SECRET_SNIFF, TRICKY_VOICE_MOUTH_ANGLE_NONE);
                    switch (trickyState->followObj->anim.romDefNo) {
                    case TRICKY_DIG_ROMDEF_GROUND_ANIMA:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                trickyResetCommandState(trickyState);
                                trickySpawnFoodBubble(obj, trickyState);
                            }
                        } else {
                            trickyState->stateIndex = TRICKY_STATE_FIND_SECRET_DIG;
                        }
                        break;
                    case TRICKY_DIG_ROMDEF_WALL_ANIMATO:
                        if (trickyState->stats->energy < 4) {
                            if ((u8)Obj_CanSetupObject()) {
                                trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                                trickyResetCommandState(trickyState);
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
                                trickyResetCommandState(trickyState);
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
                                trickyResetCommandState(trickyState);
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
                        trickyResetCommandState(trickyState);
                        trickyReportError("find command used on the wrong object\n");
                        break;
                    }
                    break;
                case TRICKY_COMMAND_TYPE_STAY:
                    accepted = 0;
                    if (trickyState->commandPhase == TRICKY_COMMAND_PHASE_GUARD) {
                        for (i = 0; i < trickyState->commandCount; i++) {
                            if (trickyState->commands[i].commandType == TRICKY_COMMAND_TYPE_STAY) {
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
                            trickyState->stateFlags |= TRICKY_STATE_FLAG_GUARD_REQUEST;
                        }
                    }
                    break;
                case TRICKY_COMMAND_TYPE_FLAME:
                    if (trickyState->stats->energy < 4) {
                        if ((u8)Obj_CanSetupObject()) {
                            trickyState->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                            trickyResetCommandState(trickyState);
                            trickySpawnFoodBubble(obj, trickyState);
                        }
                    } else {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_FLAME;
                        trickySelectQueuedCommandTarget(trickyState, TRICKY_COMMAND_TYPE_FLAME);
                        trickyState->stateIndex = TRICKY_STATE_FLAME;
                        switch (trickyState->followObj->anim.romDefNo) {
                        case TRICKY_COMMAND_TARGET_DIM_ICE_WALL:
                            trickyState->flameTargetCallback = dimicewall_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_DIM_TRUTH_HORN:
                            trickyState->flameTargetCallback = dimtruthhornice_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_VFP_FLAMEPOINT:
                            trickyState->flameTargetCallback = vfpflamepoint_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_DIM_LOG_FIRE:
                            trickyState->flameTargetCallback = dimlogfire_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_DR_CHIMMEY:
                            trickyState->flameTargetCallback = drchimmey_countdownCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_CCEYE_VINES:
                        case TRICKY_COMMAND_TARGET_BURNABLE_VINE:
                        case TRICKY_COMMAND_TARGET_ARW_TIMED_MIN:
                        case TRICKY_COMMAND_TARGET_MS_PLANTING_SEED:
                        case TRICKY_COMMAND_TARGET_ICE_HOLE:
                            trickyState->flameTargetCallback = NULL;
                            break;
                        case TRICKY_COMMAND_TARGET_SH_BEACON:
                            trickyState->flameTargetCallback =
                                (TrickyFlameTargetCallback)sh_beacon_resetFadeTimerCallback;
                            break;
                        case TRICKY_COMMAND_TARGET_WC_BEACON:
                            trickyState->flameTargetCallback = (TrickyFlameTargetCallback)wcbeacon_aButtonCallback;
                            break;
                        default:
                            trickyResetCommandState(trickyState);
                            trickyReportError("find command used on the wrong object\n");
                            break;
                        }
                    }
                    break;
                case TRICKY_COMMAND_TYPE_PLAY_BALL:
                    if ((u8)Obj_CanSetupObject()) {
                        trickyState->commandPhase = TRICKY_COMMAND_PHASE_PLAY_BALL;
                        placementSetup = Obj_AllocObjectSetup(sizeof(ObjPlacement), TRICKY_SPAWN_ROMDEF_SIDEKICK_BALL);
                        placementSetup->color[3] = TRICKY_SIDEKICK_BALL_ALPHA;
                        placementSetup->color[0] = TRICKY_SIDEKICK_BALL_COLOR_VARIANT;
                        placementSetup->posX = obj->anim.worldPosX;
                        placementSetup->posY = obj->anim.worldPosY;
                        placementSetup->posZ = obj->anim.worldPosZ;
                        trickyState->followObj = objSetupObject(placementSetup, 5, -1, -1, obj->anim.parent);
                        trickySetTargetPosition(trickyState, &trickyState->followObj->anim.worldPosX);
                        trickyState->substate = TRICKY_FETCH_BALL_INIT;
                        trickyState->stateIndex = TRICKY_STATE_FETCH_BALL;
                    }
                    break;
                default:
                    if (trickyState->stateIndex == TRICKY_STATE_FOLLOW_PLAYER &&
                        trickyState->commandPhase != TRICKY_COMMAND_PHASE_NONE &&
                        (flags & TRICKY_STATE_FLAG_HEEL_REQUEST) == 0) {
                        nearestBaddie = trickyFindNearestUsableBaddie(trickyState->playerObj, 150.0f, 0);
                        if (nearestBaddie != NULL) {
                            trickyState->followObj = nearestBaddie;
                            trickySetTargetPosition(trickyState, &nearestBaddie->anim.worldPosX);
                            trickyState->stateIndex = TRICKY_STATE_BADDIE_ALERT;
                            trickyState->substate = TRICKY_BADDIE_ALERT_GOTO;
                            trickyState->flameCommandPending = 0;
                        }
                    }
                    break;
                }
            } else if (requestedCommand == TRICKY_COMMAND_TYPE_STAY) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_GUARD_REQUEST;
            }
        }
    }
    flags = trickyState->stateFlags;
    if ((flags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if ((flags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) {
            if ((flags & TRICKY_STATE_FLAG_HEEL_REQUEST) != 0) {
                trickyResetCommandState(trickyState);
                trickyState->commandPhase = TRICKY_COMMAND_PHASE_NONE;
            } else {
                trickyResetCommandState(trickyState);
            }
            trickyState->followHeelTimer = TRICKY_RECALL_COOLDOWN_FRAMES;
        } else if ((flags & TRICKY_STATE_FLAG_GUARD_REQUEST) != 0) {
            trickyState->followObj = obj;
            trickyState->stateIndex = TRICKY_STATE_IDLE_WANDER;
            trickyState->idleSfxTimer =
                (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_GUARD_REQUEST;
            trickyState->commandPhase = TRICKY_COMMAND_PHASE_GUARD;
            trickySetTargetPosition(trickyState, &trickyState->wanderTargetPos.x);
        }
    }
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    trickyState->curvesCollision.subtype = CURVES_COLLISION_SUBTYPE_OBJECT;
    sTrickyStateHandlers[trickyState->stateIndex](obj, trickyState);
    trickyState->stateFlags &= ~TRICKY_STATE_FLAG_STUCK_VOICE_PENDING;
    trickyState->animTransitionTimer += timeDelta;
    if (trickyState->animTransitionTimer > TRICKY_ANIM_TRANSITION_FRAMES) {
        if (obj->anim.currentMove != trickyState->moveId) {
            if ((trickyState->pendingStateFlags & TRICKY_MOVE_FLAG_KEEP_PROGRESS) != 0 &&
                (trickyState->stateFlags & TRICKY_MOVE_FLAG_KEEP_PROGRESS) != 0) {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, obj->anim.currentMoveProgress, 0);
            } else {
                ObjAnim_SetCurrentMove(obj, trickyState->moveId, 0.0f, 0);
            }
            trickyState->stateFlags &=
                ~(TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION | TRICKY_MOVE_FLAG_ROOT_TRANSLATE | TRICKY_STATE_FLAG_ROTATE |
                  TRICKY_STATE_FLAG_VERTICAL_MOVE | TRICKY_STATE_FLAG_BACKSTEP | TRICKY_STATE_FLAG_SIDESTEP);
            trickyState->stateFlags |= trickyState->pendingStateFlags;
            trickyState->animTransitionTimer = 0.0f;
            trickyState->animRate = trickyState->pendingAnimRate;
        }
    }
    if ((trickyState->stateFlags & TRICKY_MOVE_FLAG_ROOT_TRANSLATE) != 0) {
        obj->anim.localPosX += timeDelta * (trickyState->moveVector.x * trickyState->speed);
        obj->anim.localPosZ += timeDelta * (trickyState->moveVector.z * trickyState->speed);
        ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, trickyState->speed, &trickyState->animRate);
    }
    animRate = trickyState->animRate;
    resetValue = 0.0f;
    if (animRate == resetValue) {
        ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, trickyState->arcMoveProgress);
    }
    if (ObjAnim_AdvanceCurrentMove(obj, trickyState->animRate, timeDelta, &trickyState->animEvents) != 0) {
        trickyState->stateFlags |= TRICKY_STATE_FLAG_MOVE_ENDED;
    } else {
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_MOVE_ENDED;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_ROTATE) != 0) {
        int rotationDiff;
        int rotationStep;

        rotationDiff = trickyWrapYawDelta(trickyState->targetYaw - (u16)obj->anim.rotX);
        rotationStep =
            (int)((f32)trickyState->animEvents.rootRotation[OBJANIM_ROOT_ROTATION_YAW] * trickyState->rotStepScale);
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
        obj->anim.localPosX +=
            trickyState->backstepDelta * (trickyState->moveVector.x * -trickyState->animEvents.rootDeltaZ);
        obj->anim.localPosZ +=
            trickyState->backstepDelta * (trickyState->moveVector.z * -trickyState->animEvents.rootDeltaZ);
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_VERTICAL_MOVE) != 0) {
        obj->anim.localPosY += trickyState->animEvents.rootDeltaY * trickyState->verticalDelta;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_SIDESTEP) != 0) {
        obj->anim.localPosX +=
            trickyState->sidestepDelta * (trickyState->moveVector.z * trickyState->animEvents.rootDeltaX);
        obj->anim.localPosZ +=
            trickyState->sidestepDelta * (trickyState->moveVector.x * -trickyState->animEvents.rootDeltaX);
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
        characterUpdateHeadLook(obj, &trickyState->eyeAnimState, 0.0f);
        characterDoEyeAnims(obj, &trickyState->eyeAnimState);
    }
    objSoundUpdateMouth(obj, &trickyState->soundState);
    {
        f32* targetSnapshotPos;
        TrickyState* targetSnapshotState;

        targetSnapshotState = obj->extra;
        targetSnapshotPos = targetSnapshotState->targetPosPtr;
        targetSnapshotState->previousTargetPosPtr = targetSnapshotPos;
        if (targetSnapshotState->previousTargetPosPtr != NULL) {
            targetSnapshotState->previousTargetPos.x = targetSnapshotPos[0];
            targetSnapshotState->previousTargetPos.y = targetSnapshotPos[1];
            targetSnapshotState->previousTargetPos.z = targetSnapshotPos[2];
        }
    }
    trickyState->prevSpeed = trickyState->speed;
    i = trickyState->commandCount - 1;
    for (; i >= 0; i--) {
        trickyState->commands[i].ttlFrames -= 1;
        if (trickyState->commands[i].ttlFrames == 0) {
            memmove(&trickyState->commands[i], &trickyState->commands[i + 1],
                    (trickyState->commandCount - i - 1) * sizeof(TrickyCommand));
            trickyState->commandCount -= 1;
        }
    }
    if (getXZDistanceSquared(&obj->anim.worldPosX, &trickyState->playerObj->anim.worldPosX) >=
            TRICKY_REMOTE_RECALL_DISTANCE_SQ &&
        mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0) {
        trickyState->stateFlags |= TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
    trickyState->waterIdleTimer -= timeDelta;
    if (trickyState->waterIdleTimer < 0.0f) {
        trickyState->waterIdleTimer = 0.0f;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_FOOD_WARNING_PENDING) != 0) {
        accepted = trickyTryPlaySound(obj, TRICKY_VOICE_SFX_TIRED, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        if (accepted != 0) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
        }
    }
    trickyState->movementBarkTimer -= timeDelta;
    if (trickyState->movementBarkTimer < 0.0f) {
        trickyState->movementBarkTimer = 0.0f;
    }
    if (trickyState->movementBarkTimer > 0.0f) {
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_TOY_BARK, TRICKY_VOICE_MOUTH_ANGLE_SMALL);
    }
    trickyUpdateCollisionAndPathState(obj);
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_IMPRESS_PENDING) != 0) {
        trickyState->impressTimer -= timeDelta;
        if (trickyState->impressTimer <= 0.0f) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_IMPRESS_PENDING;
            trickyTryPlaySound(obj, impressSfxIds[randomGetRange(0, 1)], TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        }
    }
    trickyUpdateColorVariant(obj, trickyState);
    Tricky_updateBlendChannelWeight(obj, trickyState);
    if (trickyState->speed > TRICKY_AUDIO_EVENT_MIN_SPEED) {
        objAudioDispatchAnimEvents(obj, &trickyState->animEvents, 1, trickyState->footPoints,
                                   &trickyState->curvesCollision, trickyState->speed, 1.0f);
    }
    if (0.0f == trickyState->curvesCollision.resultWaterDepth) {
        waterFootstepActive = 0;
    } else if (TRICKY_NO_FLOOR_Y == trickyState->curvesCollision.resultFloorY) {
        waterFootstepActive = 1;
    } else if (trickyState->curvesCollision.resultWaterY - trickyState->curvesCollision.resultFloorY >
               TRICKY_SWIM_MIN_DEPTH) {
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
    trickyState->prevLocalPos.x = obj->anim.previousLocalPosX;
    trickyState->prevLocalPos.y = obj->anim.previousLocalPosY;
    trickyState->prevLocalPos.z = obj->anim.previousLocalPosZ;
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
            if (trickyState->foodForceBlinkTimer > 600.0f) {
                trickyState->foodForceBlinkTimer -= 600.0f;
            }
            trickyState->foodChild->anim.flags = trickyState->foodChild->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        if (trickyState->foodVoiceTimer > TRICKY_CHILD_VOICE_PERIOD_FRAMES) {
            if (mainGetBit(GAMEBIT_ITEM_TrickyFood_Count) != 0) {
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_SCARED, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
            } else {
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_TIRED, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
            }
            trickyState->foodVoiceTimer -= TRICKY_CHILD_VOICE_PERIOD_FRAMES;
        }
        ObjAnim_AdvanceCurrentMove(trickyState->foodChild, 0.01f, timeDelta, 0);
    }
    if (trickyState->questPromptChild != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->questPromptChild, 0.01f, timeDelta, 0);
    }
    if (trickyState->exclamationPromptChild != NULL) {
        ObjAnim_AdvanceCurrentMove(trickyState->exclamationPromptChild, 0.01f, timeDelta, 0);
    }
}

static inline int trickyFindFreePromptSlot(TrickyState* state) {
    s8 occupiedSlots[TRICKY_PROMPT_CHILD_SLOT_COUNT];
    int slot;

    /* Retail initializes three slots but searches all four packed slot values. */
    occupiedSlots[0] = TRICKY_PROMPT_CHILD_SLOT_FREE;
    occupiedSlots[1] = TRICKY_PROMPT_CHILD_SLOT_FREE;
    occupiedSlots[2] = TRICKY_PROMPT_CHILD_SLOT_FREE;
    if (state->exclamationPromptChild != NULL) {
        occupiedSlots[state->packedSlots.exclamationPromptSlot] = TRICKY_PROMPT_CHILD_SLOT_OCCUPIED;
    }
    if (state->questPromptChild != NULL) {
        occupiedSlots[state->packedSlots.questPromptSlot] = TRICKY_PROMPT_CHILD_SLOT_OCCUPIED;
    }
    if (state->foodChild != NULL) {
        occupiedSlots[state->packedSlots.foodChildSlot] = TRICKY_PROMPT_CHILD_SLOT_OCCUPIED;
    }
    for (slot = 0; slot < TRICKY_PROMPT_CHILD_SLOT_COUNT; slot++) {
        if (occupiedSlots[slot] == TRICKY_PROMPT_CHILD_SLOT_FREE) {
            return slot;
        }
    }
    return TRICKY_PROMPT_CHILD_SLOT_FREE;
}

static inline void trickySpawnFoodBubble(GameObject* obj, TrickyState* state) {
    if (state->foodChild == NULL) {
        TrickyPromptChildSetup* setup;
        int freeSlot;
        f32 childTimerReset;

        setup = (TrickyPromptChildSetup*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_SPAWN_ROMDEF_FOOD);
        freeSlot = trickyFindFreePromptSlot(state);
        state->packedSlots.foodChildSlot = freeSlot;
        state->foodChild = objSetupObject(&setup->base, 4, -1, -1, obj->anim.parent);
        ObjLink_AttachChild(obj, state->foodChild, state->packedSlots.foodChildSlot);
        childTimerReset = 0.0f;
        state->foodVoiceTimer = childTimerReset;
        state->foodForceBlinkTimer = childTimerReset;
        state->foodBlinkTimer = childTimerReset;
    }
}

static inline void trickyResetCommandState(TrickyState* state) {
    state->stateIndex = TRICKY_STATE_FOLLOW_PLAYER;
    state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
    state->followHeelTimer = 0.0f;
    state->playerContactTimer = 0.0f;
    state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
    state->stateFlags &= ~TRICKY_STATE_FLAG_RECALL_REQUEST;
    state->stateFlags &= ~TRICKY_STATE_FLAG_HEEL_REQUEST;
    state->stateFlags &= ~TRICKY_STATE_FLAG_GUARD_REQUEST;
    state->commandPhase = TRICKY_COMMAND_PHASE_IDLE;
}

void Tricky_hitDetect(GameObject* obj) {
    f32 dy;
    f32 y;
    GameObject** xyzAnimators;
    int animatorIndex;
    GameObject* firepipeObj;
    TrickyState* state;
    f32 animatorHeight;
    f32 trackedHeightReset;
    f32 previousTrackedHeight;
    int animatorCount;

    state = obj->extra;
    y = obj->anim.localPosY;
    dy = (y - obj->anim.previousLocalPosY >= 0.0f) ? y - obj->anim.previousLocalPosY
                                                   : -(y - obj->anim.previousLocalPosY);
    if (1.0f == dy) {
        if (y == obj->anim.worldPosY) {
            state->heightTracking = 1;
            state->heightTrackObjId = -1;
            state->trackedHeight = 0.0f;
        }
    } else {
        firepipeObj = ObjList_FindObjectById(XYZ_ANIMATOR_DRAGON_ROCK_FIREPIPE_IDENT);
        if ((firepipeObj != 0) && (getXZDistanceSquared(&obj->anim.worldPosX, &firepipeObj->anim.worldPosX) <
                                   TRICKY_FIREPIPE_HEIGHT_DIST_SQ)) {
            state->heightTracking = 1;
            state->heightTrackObjId = XYZ_ANIMATOR_DRAGON_ROCK_FIREPIPE_IDENT;
            state->trackedHeight = 0.0f;
        }
    }
    if (state->heightTracking != 0u) {
        xyzAnimators = objGetAllOfType(XYZ_ANIMATOR_OBJECT_GROUP, &animatorCount);
        animatorIndex = 0;
        for (; animatorIndex < animatorCount; animatorIndex++) {
            animatorHeight = XyzAnimator_getCoordinate(xyzAnimators[animatorIndex], XYZ_ANIMATOR_COORD_WORLD_Y);
            if (state->heightTrackObjId == -1) {
                dy = (animatorHeight - obj->anim.localPosY >= 0.0f) ? animatorHeight - obj->anim.localPosY
                                                                    : -(animatorHeight - obj->anim.localPosY);
                if (dy < TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    state->heightTrackObjId = xyzAnimators[animatorIndex]->anim.placement->ident;
                }
            }
            if ((u32)state->heightTrackObjId == (u32)xyzAnimators[animatorIndex]->anim.placement->ident) {
                previousTrackedHeight = state->trackedHeight;
                trackedHeightReset = 0.0f;
                if ((previousTrackedHeight != trackedHeightReset) && (previousTrackedHeight == animatorHeight)) {
                    state->heightTracking = 0;
                } else {
                    obj->anim.localPosY = animatorHeight;
                    state->trackedHeight = animatorHeight;
                }
                break;
            }
        }
        if (animatorIndex == animatorCount) {
            state->heightTracking = 0;
        }
    }
    return;
}

static inline void trickyUpdateAttachmentPoints(GameObject* obj, TrickyState* state) {
    int pathPointIndex;
    s16* mouthPose;

    for (pathPointIndex = 0; pathPointIndex < 4; pathPointIndex++) {
        ObjPath_GetPointWorldPosition(obj, pathPointIndex + 4, &state->pathPointPositions[pathPointIndex].x,
                                      &state->pathPointPositions[pathPointIndex].y,
                                      &state->pathPointPositions[pathPointIndex].z, 0);
    }
    ObjPath_GetPointWorldPosition(obj, 8, &state->mouthPos.x, &state->mouthPos.y, &state->mouthPos.z, 0);
    mouthPose = objFindJointPoseVector(obj, 0);
    state->mouthYawOffset = mouthPose[1];
}

void Tricky_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, char doRender) {
    TrickyState* state;

    if (doRender != '\0') {
        state = obj->extra;
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        trickyUpdateAttachmentPoints(obj, obj->extra);
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            switch (state->stateIndex) {
            case TRICKY_STATE_FIND_SECRET_DIG:
                Tricky_emitDigParticles(obj);
                break;
            case TRICKY_STATE_DIG_TUNNEL:
                if (state->substate == TRICKY_DIG_TUNNEL_DIGGING) {
                    Tricky_emitDigParticles(obj);
                }
                break;
            }
            if ((((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0) &&
                 (state->stateIndex == TRICKY_STATE_FETCH_BALL)) &&
                (state->substate >= TRICKY_FETCH_BALL_PICKUP_START)) {
                if (state->substate != TRICKY_FETCH_BALL_PICKUP_START) {
                    state->fetchBallObj->anim.localPosX = state->mouthPos.x;
                    state->fetchBallObj->anim.localPosY = state->mouthPos.y;
                    state->fetchBallObj->anim.localPosZ = state->mouthPos.z;
                }
                objRenderModelAndHitVolumes(state->fetchBallObj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
            }
        }
        Tricky_emitQueuedPathParticles(obj, state);
        ObjPath_GetPointWorldPositionArray(obj, 4, 4, &state->footPoints[0].x);
        state->particleTimer = state->particleTimer - timeDelta;
        if (state->particleTimer > 0.0f) {
            objDoParticleFx(obj, TRICKY_PATH_PARTICLE_SCALE, 6, 1.0f, 0);
        }
    }
    return;
}

void Tricky_free(GameObject* obj, int shouldKeepFlameChildren) {
    TrickyState* state;
    u32 objId = (u32)obj;

    state = obj->extra;
    freeAndNull((void**)&state->candidateSearches[0].nodes);
    freeAndNull((void**)&state->candidateSearches[1].nodes);
    freeAndNull((void**)&state->candidateSearches[2].nodes);
    freeAndNull((void**)&state->candidateSearches[3].nodes);
    freeAndNull((void**)&state->candidateSearches[4].nodes);
    freeAndNull((void**)&state->candidateSearches[5].nodes);
    freeAndNull((void**)&state->candidateSearches[6].nodes);
    freeAndNull((void**)&state->candidateSearches[7].nodes);
    freeAndNull((void**)&state->cachedPathSearch.nodes);
    objFreeObjectType(obj, TRICKY_OBJGROUP);
    (*gExpgfxInterface)->freeSource(objId);
    if ((shouldKeepFlameChildren == 0) && ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0)) {
        trickyStopFlameChildren(obj, state);
    }
    doNothing_onTrickyFree();
    trickyFreePromptChild(obj, state, &state->exclamationPromptChild);
    trickyFreePromptChild(obj, state, &state->questPromptChild);
    trickyFreePromptChild(obj, state, &state->foodChild);
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

int Tricky_getExtraSize(void) {
    return sizeof(TrickyState);
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

int Tricky_updateSideCommandPrompts(GameObject* obj) {
    TrickyState* state = obj->extra;
    u32 commandMask;
    s8 commandKind;
    u8 showQuestPrompt = false;
    u8 showExclamationPrompt = false;
    u8 showFoodVoicePrompt = false;
    u8 showBaddieVoicePrompt = false;
    ObjPlacement* promptSetup;
    GameObject* promptObj;
    u8 commandIndex;
    u16 questPromptSfxIds[2] = {TRICKY_VOICE_SFX_THERES_SOMETHING_NEAR, TRICKY_VOICE_SFX_LOOK_AT_THIS};

    if (mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0) {
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0) {
            state->sideCommandPromptMask = 0;
        }
        commandMask = state->sideCommandPromptMask | (TRICKY_COMMAND_FLAG_CALL | TRICKY_COMMAND_FLAG_STAY);
        if (((state->stateIndex == TRICKY_STATE_GUARD) || (state->stateIndex == TRICKY_STATE_BADDIE_ALERT)) ||
            ((state->stateIndex == TRICKY_STATE_GROWL && (state->substate == TRICKYGROWL_FACE_TARGET)))) {
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
                commandKind = state->commands[commandIndex].commandKind;
                if (commandKind == TRICKY_COMMAND_KIND_NORMAL) {
                    if (state->commands[commandIndex].targetObj->anim.romDefNo == TRICKY_ROMDEF_BLUE_MUSHROOM) {
                        showFoodVoicePrompt = true;
                    }
                    showExclamationPrompt = true;
                } else if (commandKind == TRICKY_COMMAND_KIND_PRIORITY) {
                    showQuestPrompt = true;
                }
            }
        }
        if (((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) &&
            (mainGetBit(GAMEBIT_ITEM_TrickyBall_Usable) != 0)) {
            GameObject* player = Obj_GetPlayerObject();
            if ((playerIsInNormalControlUndisguisedOnLand(player) != 0) && (mainGetBit(GAMEBIT_NoBallsAllowed) == 0)) {
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
            state->questPromptTimer = 60.0f;
            if ((state->questPromptChild == NULL) && ((u8)Obj_CanSetupObject() != 0)) {
                trickyTryPlaySound(obj, questPromptSfxIds[randomGetRange(0, 1)], TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                promptSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_QUEST);
                state->packedSlots.questPromptSlot = trickyFindFreePromptSlot(state);
                promptObj = objSetupObject(promptSetup, 4, -1, 0xffffffff, obj->anim.parent);
                state->questPromptChild = promptObj;
                ObjLink_AttachChild(obj, state->questPromptChild, state->packedSlots.questPromptSlot);
            }
        } else if (state->questPromptChild != NULL) {
            state->questPromptTimer = state->questPromptTimer - timeDelta;
            if (state->questPromptTimer <= 0.0f) {
                trickyFreePromptChild(obj, state, &state->questPromptChild);
            }
        }
        if ((showExclamationPrompt) && ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0)) {
            state->exclamationPromptTimer = 60.0f;
            if ((state->exclamationPromptChild == NULL) && ((u8)Obj_CanSetupObject() != 0)) {
                if (randomGetRange(0, 3) == 0) {
                    if (showFoodVoicePrompt) {
                        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_FOOD, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                    } else if (showBaddieVoicePrompt) {
                        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_BAD_GUY, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                    }
                }
                promptSetup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_EXCLAMATION);
                state->packedSlots.exclamationPromptSlot = trickyFindFreePromptSlot(state);
                promptObj = objSetupObject(promptSetup, 4, -1, 0xffffffff, obj->anim.parent);
                state->exclamationPromptChild = promptObj;
                ObjLink_AttachChild(obj, state->exclamationPromptChild, state->packedSlots.exclamationPromptSlot);
            }
        } else if (state->exclamationPromptChild != NULL) {
            state->exclamationPromptTimer = state->exclamationPromptTimer - timeDelta;
            if (state->exclamationPromptTimer <= 0.0f) {
                trickyFreePromptChild(obj, state, &state->exclamationPromptChild);
            }
        }
        return commandMask;
    }
    return -1;
}

int Tricky_getCurrentCommandPhase(GameObject* obj, int* outCommandPhase) {
    TrickyState* state = obj->extra;
    *outCommandPhase = state->commandPhase;
    return 1;
}

void sideCommandEnable(GameObject* obj, GameObject* targetObj, enum TrickyCommandKind commandKind,
                       enum TrickyCommandType commandType) {
    int commandIndex;
    TrickyState* state;

    state = obj->extra;
    if (state->commandCount == ARRAY_COUNT(state->commands)) {
        trickyReportError("sideCommandEnable warning: need to increase MAX_COMM_PRESENT\n");
        return;
    }
    state->sideCommandPromptMask = (u8)(state->sideCommandPromptMask | TRICKY_COMMAND_TYPE_TO_FLAG(commandType));
    for (commandIndex = 0; commandIndex < state->commandCount; commandIndex++) {
        if (state->commands[commandIndex].targetObj == targetObj) {
            state->commands[commandIndex].ttlFrames = TRICKY_COMMAND_TTL_FRAMES;
            return;
        }
    }
    state->commands[state->commandCount].targetObj = targetObj;
    state->commands[state->commandCount].commandKind = commandKind;
    state->commands[state->commandCount].commandType = commandType;
    state->commands[state->commandCount].ttlFrames = TRICKY_COMMAND_TTL_FRAMES;
    state->commandCount++;
}

u8 Tricky_getEnergy(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->stats->energy;
}

u8 Tricky_getEnergyMax(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->stats->maxEnergy;
}

void Tricky_commandPlayBall(GameObject* obj, int commandEnabled, GameObject* targetObj) {
    TrickyState* state = obj->extra;

    if (commandEnabled != 0) {
        if (state->stateIndex == TRICKY_STATE_BALL_ROLL) {
            if (state->substate != TRICKY_CANNONBALL_INIT) {
                state->followObj = targetObj;
            }
        } else {
            u32 busy = state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (busy != 0) {
                return;
            }
            state->cannonballStartCurve = Objfsa_FindNearestEnabledCurveType24(
                &targetObj->anim.worldPosX, -1, ROMCURVE_TRICKY_SUBTYPE_CANNONBALL_ROUTE);
            state->cannonballRandomValue = (f32)(int)randomGetRange(0x168, 0x28);
            state->stateIndex = TRICKY_STATE_BALL_ROLL;
            state->followObj = targetObj;
            trickySetTargetPosition(state, &state->cannonballStartCurve->x);
            state->substate = TRICKY_CANNONBALL_INIT;
        }
    } else {
        state->stateFlags |= TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
}

int Tricky_requestMoveToObject(GameObject* obj, GameObject* targetObj) {
    TrickyState* state = obj->extra;
    s32 objBlocked = obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK;

    if (objBlocked != 0) {
        return 0;
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        state->followObj = targetObj;
        trickySetTargetPosition(state, &targetObj->anim.worldPosX);
        state->substate = 0;
        state->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
    } else {
        state->pendingFollowRequest = TRICKY_PENDING_FOLLOW_HANDOFF;
        state->pendingFollowObj = targetObj;
        state->stateFlags |= TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
    return 1;
}

u8 Tricky_isPlayingBall(GameObject* obj) {
    TrickyState* state;
    u8 mode;

    state = obj->extra;
    mode = state->stateIndex;
    switch (mode) {
    case TRICKY_STATE_BALL_ROLL:
        return 1;
    default:
        return 0;
    }
}

u8 Tricky_isGuarding(GameObject* obj) {
    TrickyState* state = obj->extra;
    u8 mode = state->stateIndex;
    if (mode == TRICKY_STATE_GUARD || mode == TRICKY_STATE_GROWL) {
        return 1;
    }
    return 0;
}

void Tricky_requestRecall(GameObject* obj) {
    TrickyState* state = obj->extra;
    if (mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands)) {
        state->stateFlags |= TRICKY_STATE_FLAG_RECALL_REQUEST;
    }
}

int tricky_SeqFn(GameObject* obj, int unused, ObjSeqState* sequence) {
    TrickyState* state;
    int i;
    ObjPlacement* setup;
    u8 blockFlags[120];

    state = obj->extra;
    if ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_LATCHED) == 0) {
        ObjHits_DisableObject(obj);
        Sfx_StopObjectChannel(obj, SFX_OBJECT_CHANNEL_MASK_ALL);
        if ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) != 0) {
            trickyStopFlameChildren(obj, state);
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
                trickyStopFlameChildren(obj, state);
            } else if ((u8)Obj_CanSetupObject()) {
                trickySpawnFlameChildren(obj, state);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_SPAWN_BADGE:
            mainSetBits(GAMEBIT_Tricky_LoadBadge, 1);
            if (mainGetBit(GAMEBIT_Tricky_LoadBadge) != 0 && state->spawnedChild == NULL && (u8)Obj_CanSetupObject()) {
                mapGetLoadedMapFlags(blockFlags);
                if (blockFlags[TRICKY_BADGE_MAP_FLAG_INDEX] != 0) {
                    setup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_A);
                } else {
                    setup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_BADGE_B);
                }
                state->spawnedChild = objSetupObject(setup, 4, -1, -1, obj->anim.parent);
                ObjLink_AttachChild(obj, state->spawnedChild, TRICKY_BADGE_CHILD_SLOT);
            }
            break;
        case TRICKY_SEQUENCE_EVENT_STORE_ENERGY:
            state->stats->energy = state->pendingEnergy;
            break;
        case TRICKY_SEQUENCE_EVENT_HIDE_SHADOW:
            obj->anim.modelState->flags &= ~OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        case TRICKY_SEQUENCE_EVENT_SHOW_SHADOW:
            obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
            break;
        }
    }

    trickyFreePromptChild(obj, state, &state->exclamationPromptChild);
    trickyFreePromptChild(obj, state, &state->questPromptChild);
    trickyFreePromptChild(obj, state, &state->foodChild);
    trickyUpdateColorVariant(obj, state);
    Tricky_updateBlendChannelWeight(obj, state);
    objAudioDispatchAnimEvents(obj, &sequence->animEvents, 1, state->footPoints, &state->curvesCollision, 1.0f, 1.0f);
    if ((state->stateFlags & TRICKY_STATE_FLAG_SEQUENCE_CALLBACK) != 0) {
        sequence->flags &= ~OBJSEQ_FLAG_TEXTURE_ANIM_TRACKS;
        characterDoEyeAnims(obj, &state->eyeAnimState);
        return (*gObjectTriggerInterface)->turnToFacePlayer(obj, sequence, 1, 0xf, 0x1e, 0, 0);
    }
    return 0;
}

void tricky_attachToWalkGroup(GameObject* obj, TrickyState* state) {
    u8 walkGroupPair[2];
    u32 walkGroup = (u8)Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);

    walkGroupPair[0] = walkGroup;
    if (walkGroup == 0) {
        int patchGroup = Objfsa_GetPatchGroupIdAtPoint(&obj->anim.worldPosX);
        if (patchGroup != 0) {
            walkPath_writeU16LE(patchGroup, walkGroupPair);
        }
    }
    if (walkGroupPair[0] != 0) {
        state->walkGroup = walkGroupPair[0];
        trickyResetCommandState(state);
    }
    if (gTrickyWarpHelperObject == 0) {
        ObjPlacement* setup = Obj_AllocObjectSetup(sizeof(ObjPlacement), TRICKY_HELPER_WARP_OBJECT_ID);
        gTrickyWarpHelperObject = objSetupObject(setup, 4, -1, -1, obj->anim.parent);
    }
    state->ownsWarpHelperObject = 1;
}

void tricky_stateIdleWander(GameObject* obj, TrickyState* state) {
    int isInWater;
    u32 moveEnded;

    if (tricky_handleFeedOrTalk(obj, state) == 0) {
        state->wanderTargetPos.x =
            obj->anim.worldPosX - mathSinf((TRICKY_PI * (f32)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);
        state->wanderTargetPos.y = (obj)->anim.worldPosY;
        state->wanderTargetPos.z =
            obj->anim.worldPosZ - mathCosf((TRICKY_PI * (f32)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);

        if (trickyUpdateMovementState(obj, 15.0f, state) != TRICKY_MOVEMENT_IN_PROGRESS) {
            state->idleSfxTimer -= timeDelta;
            if (state->idleSfxTimer <= 0.0f) {
                state->idleSfxTimer =
                    (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_DUM_DE_DUM, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
            }

            isInWater = trickyIsInDeepWater(state);

            if (isInWater) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint("in water\n");
            } else {
                switch ((obj)->anim.currentMove) {
                case TRICKY_ANIM_IDLE_FOOD_CHEW:
                    break;
                case TRICKY_ANIM_IDLE_FOOD_WAIT:
                    moveEnded = state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED;
                    if (moveEnded != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_CHEW, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                    }
                    break;
                default:
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_WAIT, TRICKY_LAND_MOVE_ANIM_RATE, 0);
                    break;
                }
                trickyDebugPrint("out of water\n");
            }
        }
    }
}

GameObject* trickyFindRecallWarp(GameObject* obj, TrickyState* state) {
    GameObject** warpObjects;
    int warpCount;
    GameObject* nearestWarp;
    f32 trickyToPlayerSq;
    f32 nearestWarpToPlayerSq;
    int warpIndex;

    nearestWarp = 0;
    warpObjects = objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
    trickyToPlayerSq = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &obj->anim.worldPosX);
    if ((trickyToPlayerSq >= TRICKY_REMOTE_RECALL_DISTANCE_SQ) || (state->followHeelTimer > 0.0f)) {
        if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX, TRICKY_VISIBILITY_PROBE_RADIUS) == 0) {
            nearestWarpToPlayerSq = TRICKY_MAX_DISTANCE;
            for (warpIndex = 0; warpIndex < warpCount; warpIndex++) {
                f32 warpToPlayerSq =
                    getXZDistanceSquared(&state->playerObj->anim.worldPosX, &warpObjects[warpIndex]->anim.worldPosX);
                if (warpToPlayerSq < trickyToPlayerSq && warpToPlayerSq < nearestWarpToPlayerSq) {
                    nearestWarpToPlayerSq = warpToPlayerSq;
                    nearestWarp = warpObjects[warpIndex];
                }
            }
        }
    }
    return nearestWarp;
}

void tricky_handlePlayerContact(GameObject* obj, TrickyState* state) {
    GameObject* hit;
    f32 fv;
    int inWater;

    state->playerContactTimer -= timeDelta;
    if (state->playerContactTimer < 0.0f) {
        state->playerContactTimer = 0.0f;
    }
    if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0 && hit->ownerObj != NULL &&
        ((GameObject*)hit->ownerObj)->anim.classId == 1) {
        fv = state->playerContactTimer;
        if (fv <= 0.0f) {
            state->playerContactTimer += 180.0f;
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_HEY, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        } else {
            state->playerContactTimer += 600.0f;
            if (state->substate != TRICKY_FOLLOW_SUBSTATE_FLAME_BREATH) {
                if (state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) {
                    if (state->playerContactTimer > TRICKY_CONTACT_FLAME_THRESHOLD) {
                        state->playerContactTimer *= 0.5f;
                        if (mainGetBit(GAMEBIT_ITEM_TrickyFlame_Got) != 0) {
                            inWater = trickyIsInDeepWater(state);
                            if (inWater == 0) {
                                state->substate = TRICKY_FOLLOW_SUBSTATE_FLAME_BREATH;
                                return;
                            }
                        }
                        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GET_OFF, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                    } else {
                        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GET_OFF, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                    }
                } else {
                    trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GET_OFF, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                    state->substate = TRICKY_FOLLOW_SUBSTATE_BEG_FOR_FOOD;
                    state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                }
            }
        }
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
    s16 yButtonItem;

    canFeed = 0;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    foodCount = mainGetBit(GAMEBIT_ITEM_TrickyFood_Count);
    if (foodCount != 0) {
        getYButtonItem(&yButtonItem);
        if (yButtonItem == GAMEBIT_ITEM_TrickyFood_Count) {
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
                    trickyRequestIdleMove(obj, interactionState);
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
                    trickyRequestIdleMove(obj, interactionState);
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
        if (talkSequenceId != TRICKY_TALK_SEQUENCE_NONE && cMenuGetSelectedItem() == -1) {
            if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
                mainSetBits(GAMEBIT_TrickyTalk, TRICKY_TALK_SEQUENCE_NONE);
                interactionState = obj->extra;
                sequenceId = talkSequenceId;
                interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
                if (sequenceId != 2) {
                    interactionState->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_CALLBACK;
                }
                trickyRequestIdleMove(obj, interactionState);
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

void tricky_startRandomIdleMove(GameObject* obj, TrickyState* trickyState) {
    int idleChoice;

    idleChoice = randomGetRange(TRICKY_RANDOM_IDLE_LAND_IDLE, TRICKY_RANDOM_IDLE_WANDER);
    switch (idleChoice) {
    case TRICKY_RANDOM_IDLE_LAND_IDLE:
        trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_ANIM_RATE, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_WAIT_QUEUED_MOVE;
        break;
    case TRICKY_RANDOM_IDLE_PICK:
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_SNIFF, TRICKY_VOICE_MOUTH_ANGLE_NONE);
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_PICK, TRICKY_IDLE_PICK_ANIM_RATE, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_WAIT_MOVE_END;
        break;
    case TRICKY_RANDOM_IDLE_FIDGET_B:
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_B_START, TRICKY_TURN_MOVE_ANIM_RATE, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_FIDGET_B;
        break;
    case TRICKY_RANDOM_IDLE_FIDGET_A:
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_A_START, TRICKY_TURN_MOVE_ANIM_RATE, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_FIDGET_A;
        break;
    case TRICKY_RANDOM_IDLE_WANDER:
        trickyRequestMove(obj, TRICKY_ANIM_IDLE_WANDER, TRICKY_IDLE_WANDER_ANIM_RATE, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_WAIT_QUEUED_MOVE;
        break;
    }
}

void tricky_pickAmbientActivity(GameObject* obj, TrickyState* state) {
    f32 searchRadius;
    u8 minActivity;
    u8 maxActivity;
    GameObject* found;
    int wanderYaw;
    f32 wanderAngle;

    minActivity = TRICKY_AMBIENT_ACTIVITY_WANDER;
    maxActivity = TRICKY_AMBIENT_ACTIVITY_HOWL;
    searchRadius = TRICKY_AMBIENT_ACTIVITY_BASE;
    found = objGetNearestTypeTo(SHTHORNTAIL_OBJECT_GROUP, obj, &searchRadius);
    if (found != NULL && ((found)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
        minActivity = TRICKY_AMBIENT_ACTIVITY_APPROACH_THORNTAIL;
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0 || mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) == 0) {
        maxActivity = TRICKY_AMBIENT_ACTIVITY_DIG_FOR_FOOD;
    }
    switch (randomGetRange(minActivity, maxActivity)) {
    case TRICKY_AMBIENT_ACTIVITY_APPROACH_THORNTAIL:
        state->followObj = found;
        objGetJointWorldPosition(found, 0, &state->wanderTargetPos.x);
        trickySetTargetPosition(state, &state->wanderTargetPos.x);
        state->thorntailIdleMovePending = 0;
        state->substate = TRICKY_FOLLOW_SUBSTATE_APPROACH_THORNTAIL;
        break;
    case TRICKY_AMBIENT_ACTIVITY_WANDER:
        wanderYaw = randomGetRange(0x20, 0xff);
        wanderYaw = (s16)((obj->anim.rotX + wanderYaw) * 0x100);
        wanderAngle = TRICKY_PI * (f32)wanderYaw / TRICKY_ANGLE_HALF_TURN_UNITS;
        state->wanderTargetPos.x = (f32)(TRICKY_AMBIENT_WANDER_SCALE * -mathSinf(wanderAngle) + obj->anim.localPosX);
        state->wanderTargetPos.y = obj->anim.localPosY;
        state->wanderTargetPos.z = (f32)(TRICKY_POSITION_OFFSET_SCALE * -mathCosf(wanderAngle) + obj->anim.localPosZ);
        trickySetTargetPosition(state, &state->wanderTargetPos.x);
        state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE_PICK;
        break;
    case TRICKY_AMBIENT_ACTIVITY_DIG_FOR_FOOD:
        trickyRequestMove(obj, TRICKY_ANIM_AMBIENT_HOWL, TRICKY_AMBIENT_HOWL_ANIM_RATE, 0);
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = TRICKY_FOLLOW_SUBSTATE_DIG_FOR_FOOD;
        break;
    case TRICKY_AMBIENT_ACTIVITY_HOWL:
        trickyRequestMove(obj, TRICKY_ANIM_HOWL_START, TRICKY_LAND_MOVE_ANIM_RATE, 0);
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_YAWN, TRICKY_VOICE_MOUTH_ANGLE_LARGE);
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = TRICKY_FOLLOW_SUBSTATE_HOWL_CALL;
        state->moveHoldTimer = (f32)(int)randomGetRange(TRICKY_HOWL_HOLD_MIN_FRAMES, TRICKY_HOWL_HOLD_MAX_FRAMES);
        break;
    }
}

u32 tricky_updateIdleBehavior(GameObject* obj, TrickyState* trickyState) {
    int handled;
    u32 randomDelay;

    handled = tricky_handleFeedOrTalk(obj, trickyState);
    if (handled != 0) {
        return 1;
    }
    if (trickyState->waterIdleTimer > 0.0f) {
        trickyRequestMove(obj, TRICKY_ANIM_WATER_IDLE, 0.01f, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_WAIT_QUEUED_MOVE;
        trickyState->waterIdleTimer = 0.0f;
        return 1;
    }
    if (trickyState->idleActivityPending != 0U) {
        trickyState->idleTimer = TRICKY_AMBIENT_ACTIVITY_BASE;
        trickyState->idleActivityPending = 0;
        trickyState->idleActivityDelayActive = 1;
    }
    if (trickyState->idleActivityDelayActive != 0U) {
        trickyState->idleTimer -= timeDelta;
        if (trickyState->idleTimer <= 0.0f) {
            trickyState->followHeelTimer = 300.0f;
            randomDelay = randomGetRange(TRICKY_IDLE_ACTIVITY_DELAY_MIN_FRAMES, TRICKY_IDLE_ACTIVITY_DELAY_MAX_FRAMES);
            trickyState->idleTimer = (f32)(s32)randomDelay;
            trickyState->idleActivityDelayActive = 0;
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_RETURN_TO_HEEL;
        }
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL)) {
        return 1;
    }
    handled = (*gSkyInterface)->getSunPosition(0);
    if (handled == 0) {
        trickyState->stateFlags &= ~TRICKY_STATE_FLAG_SUN_VOICE_PLAYED;
    }
    handled = (*gSkyInterface)->getSunPosition(0);
    if ((handled != 0) && ((trickyState->stateFlags & TRICKY_STATE_FLAG_SUN_VOICE_PLAYED) == 0)) {
        trickyState->stateFlags |= TRICKY_STATE_FLAG_SUN_VOICE_PLAYED;
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_YAWN2, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        return 0;
    }
    if (trickyState->stats->energy <= 3) {
        trickyRequestMove(obj, TRICKY_ANIM_HUNGRY_IDLE, TRICKY_LAND_MOVE_ANIM_RATE, 0);
        trickyState->substate = TRICKY_FOLLOW_SUBSTATE_SLEEP;
        trickyState->sfxRepeatTimer = 600.0f;
        return 1;
    }
    trickyState->idleTimer -= timeDelta;
    if (trickyState->idleTimer <= 0.0f) {
        randomDelay = randomGetRange(TRICKY_IDLE_ACTIVITY_DELAY_MIN_FRAMES, TRICKY_IDLE_ACTIVITY_DELAY_MAX_FRAMES);
        trickyState->idleTimer = (f32)(s32)randomDelay;
        if (trickyState->stats->energy <= 7) {
            trickyRequestMove(obj, TRICKY_ANIM_HUNGRY_IDLE, TRICKY_LAND_MOVE_ANIM_RATE, 0);
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_SLEEP;
            trickyState->sfxRepeatTimer = 600.0f;
            return 1;
        }
        if (trickyState->followHeelTimer > 0.0f) {
            tricky_startRandomIdleMove(obj, trickyState);
        } else {
            if (trickyState->questPromptChild != NULL) {
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_SNIFF, TRICKY_VOICE_MOUTH_ANGLE_NONE);
                trickyRequestMove(obj, TRICKY_ANIM_IDLE_PICK, TRICKY_IDLE_PICK_ANIM_RATE, 0);
                trickyState->substate = TRICKY_FOLLOW_SUBSTATE_WAIT_MOVE_END;
            } else {
                randomDelay = randomGetRange(0, 6);
                switch ((int)randomDelay) {
                case TRICKY_RANDOM_IDLE_LAND_IDLE:
                case TRICKY_RANDOM_IDLE_PICK:
                case TRICKY_RANDOM_IDLE_FIDGET_B:
                case TRICKY_RANDOM_IDLE_FIDGET_A:
                case TRICKY_RANDOM_IDLE_WANDER:
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

int tricky_substateFollowIdle(GameObject* obj, TrickyState* state) {
    u8 movementResult;
    int inWater;
    float stoppingRadius;

    state->followObj = state->playerObj;
    trickySetTargetPosition(state, &state->followObj->anim.worldPosX);
    if (0.0f == state->followHeelTimer) {
        {
            s8 idleCommandPhase;
            idleCommandPhase = TRICKY_COMMAND_PHASE_IDLE;
            state->commandPhase = idleCommandPhase;
        }
        stoppingRadius = 30.0f;
    } else {
        if ((state->stateFlags & TRICKY_STATE_FLAG_HEEL_REQUEST) != 0) {
            state->commandPhase = TRICKY_COMMAND_PHASE_NONE;
            state->stateFlags &= ~TRICKY_STATE_FLAG_HEEL_REQUEST;
        }
        stoppingRadius = 20.0f;
    }
    movementResult = trickyUpdateMovementState(obj, stoppingRadius, state);
    if (movementResult != TRICKY_MOVEMENT_IN_PROGRESS) {
        if (movementResult == TRICKY_MOVEMENT_BLOCKED) {
            if ((state->stateFlags & TRICKY_STATE_FLAG_STUCK_VOICE_PENDING) != 0) {
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_IM_NOT_DOING_IT, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
            }
        }
        inWater = trickyIsInDeepWater(state);
        if (inWater != 0) {
            return 0;
        }
        return tricky_updateIdleBehavior(obj, state);
    }
    state->idleActivityPending = 1;
    return 1;
}

u32 tricky_substateReturnToHeel(GameObject* obj, TrickyState* trickyState) {
    int result;

    result = tricky_handleFeedOrTalk(obj, trickyState);
    if (result != 0) {
        return 1;
    }
    result = trickyUpdateMovementState(obj, 20.0f, (TrickyState*)trickyState);
    if (result == 1) {
        if (0.0f == trickyState->followHeelTimer) {
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
        return 1;
    }
    trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
    return 0;
}

u32 tricky_substateWaitQueuedMove(GameObject* obj, TrickyState* trickyState) {
    int val;

    val = tricky_handleFeedOrTalk(obj, trickyState);
    if (val != 0) {
        return 1;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
        if (trickyState->moveId == (int)(obj)->anim.currentMove) {
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
    }
    return 1;
}

int tricky_substateSleep(GameObject* obj, TrickyState* state) {
    ObjPlacement* setup;
    int freeSlot;
    f32 childTimerReset;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        return 1;
    }
    if (cMenuGetSelectedItem() == GAMEBIT_ITEM_TrickyFood_Count) {
        state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        return 1;
    }
    state->sfxRepeatTimer -= timeDelta;
    if (state->sfxRepeatTimer < 0.0f) {
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_SLEEP_BREATH, TRICKY_VOICE_MOUTH_ANGLE_SMALL);
        state->sfxRepeatTimer = 600.0f;
    }
    if (state->foodChild == NULL && (u8)Obj_CanSetupObject() != 0) {
        setup = Obj_AllocObjectSetup(sizeof(TrickyPromptChildSetup), TRICKY_SPAWN_ROMDEF_FOOD);
        freeSlot = trickyFindFreePromptSlot(state);
        state->packedSlots.foodChildSlot = freeSlot;
        state->foodChild = objSetupObject(setup, 4, -1, -1, (obj)->anim.parent);
        ObjLink_AttachChild(obj, state->foodChild, state->packedSlots.foodChildSlot);
        childTimerReset = 0.0f;
        state->foodVoiceTimer = childTimerReset;
        state->foodForceBlinkTimer = childTimerReset;
        state->foodBlinkTimer = childTimerReset;
    }
    if ((*gSkyInterface)->getSunPosition(0) != 0 && state->followHeelTimer <= 0.0f &&
        mainGetBit(GAMEBIT_ITEM_TrickyCall_Got) != 0) {
        trickyRequestMove(obj, TRICKY_ANIM_HOWL_START, TRICKY_LAND_MOVE_ANIM_RATE, 0);
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_YAWN, TRICKY_VOICE_MOUTH_ANGLE_LARGE);
        state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = TRICKY_FOLLOW_SUBSTATE_HOWL_CALL;
        state->moveHoldTimer = (f32)(int)randomGetRange(TRICKY_HOWL_HOLD_MIN_FRAMES, TRICKY_HOWL_HOLD_MAX_FRAMES);
    }
    return 1;
}

int tricky_substateHowlCall(GameObject* obj, TrickyState* trickyState) {
    char triggerId;
    short move;
    float sparkleTimer;
    int eventIndex;
    PartFxSpawnParams fxBuf;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    (obj)->anim.resetHitboxFlags = (obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = (obj)->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_HOWL_START:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_HOWL_HOLD, TRICKY_HOWL_CALL_ANIM_RATE, 0);
        }
        break;
    case TRICKY_ANIM_HOWL_HOLD:
        trickyState->moveHoldTimer = trickyState->moveHoldTimer - timeDelta;
        if (trickyState->moveHoldTimer <= 0.0f) {
            if (((trickyState->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0) ||
                (trickyState->playerContactTimer > 0.0f)) {
                trickyRequestMove(obj, TRICKY_ANIM_HOWL_END, 0.01f, 0);
            } else {
                eventIndex = (*gSkyInterface)->getSunPosition(0);
                if (eventIndex == 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_HOWL_IDLE_PICK, TRICKY_IDLE_PICK_ANIM_RATE, 0);
                    trickyState->substate = TRICKY_FOLLOW_SUBSTATE_DIG_FOR_FOOD;
                }
            }
        }
        for (eventIndex = 0; eventIndex < trickyState->animEvents.triggerCount; eventIndex++) {
            triggerId = trickyState->animEvents.triggeredIds[eventIndex];
            if (triggerId == '\0') {
                objSoundStartTimed(obj, &trickyState->soundState, TRICKY_VOICE_SFX_SNORE_IN,
                                   TRICKY_VOICE_MOUTH_ANGLE_NORMAL, -1, 0);
            } else if (triggerId == '\a') {
                objSoundStartTimed(obj, &trickyState->soundState, TRICKY_VOICE_SFX_SNORE_OUT,
                                   TRICKY_VOICE_MOUTH_ANGLE_SMALL, -1, 0);
            }
        }
        sparkleTimer = trickyState->howlSparkleTimer - timeDelta;
        trickyState->howlSparkleTimer = sparkleTimer;
        if (sparkleTimer <= 0.0f) {
            if (((obj)->objectFlags & OBJECT_OBJFLAG_RENDERED) != 0) {
                fxBuf.posX = trickyState->mouthPos.x;
                fxBuf.posY = 2.0f + trickyState->mouthPos.y;
                fxBuf.posZ = trickyState->mouthPos.z;
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, TRICKY_PARTFX_HOWL_SPARKLE, &fxBuf, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS,
                                  -1, NULL);
            }
            trickyState->howlSparkleTimer = 30.0f;
        }
        break;
    case TRICKY_ANIM_HOWL_END:
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            trickyRequestIdleMove(obj, trickyState);
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
        break;
    }
    return 1;
}

u32 tricky_substateWaitMoveEnd(GameObject* obj, TrickyState* trickyState) {
    int eventIndex;

    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    for (eventIndex = 0; eventIndex < trickyState->animEvents.triggerCount; eventIndex++) {
        if (trickyState->animEvents.triggeredIds[eventIndex] != 0) {
            continue;
        }
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_SNIFF, TRICKY_VOICE_MOUTH_ANGLE_NONE);
    }
    if (tricky_handleFeedOrTalk(obj, trickyState) != 0) {
        return 1;
    }
    if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
        if (trickyState->moveId == (int)(obj)->anim.currentMove) {
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
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
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_B_END, TRICKY_TURN_MOVE_ANIM_RATE, 0);
        }
        break;
    case TRICKY_ANIM_IDLE_FIDGET_B_END:
        if (((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) && ((int)randomGetRange(0, 3) == 0)) {
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
        break;
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
        if ((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_IDLE_FIDGET_A_END, TRICKY_TURN_MOVE_ANIM_RATE, 0);
        }
        break;
    case TRICKY_ANIM_IDLE_FIDGET_A_END:
        if (((trickyState->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) && ((int)randomGetRange(0, 3) == 0)) {
            trickyState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
        break;
    }
    return 1;
}

int tricky_substateIdlePick(GameObject* obj, TrickyState* state) {
    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        return 1;
    }
    if ((u8)trickyUpdateMovementState(obj, TRICKY_MAX_DISTANCE, state) != TRICKY_MOVEMENT_IN_PROGRESS) {
        if (state->questPromptChild != NULL) {
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_SNIFF, TRICKY_VOICE_MOUTH_ANGLE_NONE);
            trickyRequestMove(obj, TRICKY_ANIM_IDLE_PICK, TRICKY_IDLE_PICK_ANIM_RATE, 0);
            state->substate = TRICKY_FOLLOW_SUBSTATE_WAIT_MOVE_END;
        } else {
            switch (randomGetRange(0, 6)) {
            case TRICKY_RANDOM_IDLE_LAND_IDLE:
            case TRICKY_RANDOM_IDLE_PICK:
            case TRICKY_RANDOM_IDLE_FIDGET_B:
            case TRICKY_RANDOM_IDLE_FIDGET_A:
            case TRICKY_RANDOM_IDLE_WANDER:
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

int tricky_substateDigForFood(GameObject* obj, TrickyState* state) {
    short move;
    PartFxSpawnParams spawnBuf;

    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        return 1;
    }
    (obj)->anim.resetHitboxFlags = (obj)->anim.resetHitboxFlags | INTERACT_FLAG_PROMPT_SUPPRESSED;
    move = (obj)->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_DIG_FOOD_START_A:
    case TRICKY_ANIM_DIG_FOOD_START_B:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_DIG_FOOD_LOOP, TRICKY_FOLLOW_JUMPDOWN_ANIM_RATE, 0);
        }
        break;
    case TRICKY_ANIM_DIG_FOOD_LOOP: {
        if (((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) &&
            (((state->stateFlags & TRICKY_STATE_FLAG_RECALL_REQUEST) != 0 || randomGetRange(0, 2) == 0) ||
             state->playerContactTimer > 0.0f)) {
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
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            trickyRequestIdleMove(obj, state);
            state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        }
        break;
    }
    return 1;
}

int tricky_substateBegForFood(GameObject* obj, TrickyState* state) {
    int result;
    TrickyCommandTypeList commandQuery;

    commandQuery = gTrickyFoodCommandQuery;
    if (tricky_handleFeedOrTalk(obj, state) != 0) {
        state->playerContactTimer = 0.0f;
        state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
        return 1;
    }
    result = (*gGameUIInterface)->isOneOfItemsBeingUsed(commandQuery.commandTypes, TRICKY_COMMAND_QUERY_COUNT);
    switch (result) {
    case 0:
    case 1:
    case 3:
    case 4:
    case 5:
        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_IM_NOT_DOING_IT, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        break;
    }
    if (0.0f == state->playerContactTimer) {
        state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        state->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
    }
    if ((u8)trickyUpdateMovementState(obj, 20.0f, state) == TRICKY_MOVEMENT_IN_PROGRESS) {
        return 1;
    }
    return 0;
}

int tricky_substateFlameBreath(GameObject* obj, TrickyState* state) {

    switch (obj->anim.currentMove) {
    case TRICKY_ANIM_FLAME_BREATH:
        if (obj->anim.currentMoveProgress > 0.25f && (state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
            if ((u8)Obj_CanSetupObject() != 0) {
                trickySpawnFlameChildren(obj, state);
            }
        } else {
            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) {
                trickyStopFlameChildren(obj, state);
                state->substate = TRICKY_FOLLOW_SUBSTATE_BEG_FOR_FOOD;
            }
        }
        break;
    default:
        trickyRequestMove(obj, TRICKY_ANIM_FLAME_BREATH, 0.004f, 0);
    }
    return 1;
}

int tricky_substateApproachThorntail(GameObject* obj, TrickyState* state) {
    float pos[3];

    objGetJointWorldPosition(state->followObj, 0, pos);
    if (getXZDistanceSquared(pos, &state->wanderTargetPos.x) > 100.0f) {
        state->wanderTargetPos.x = pos[0];
        state->wanderTargetPos.y = pos[1];
        state->wanderTargetPos.z = pos[2];
    }
    if (state->thorntailIdleMovePending != 0) {
        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) != 0) {
            return 0;
        }
        tricky_startRandomIdleMove(obj, state);
    } else if ((u8)trickyUpdateMovementState(obj, 30.0f, state) != TRICKY_MOVEMENT_IN_PROGRESS) {
        state->thorntailIdleMovePending = 1;
        trickyTryPlaySound(obj, randomGetRange(TRICKY_VOICE_SFX_HELLO, TRICKY_VOICE_SFX_HI_FELLA),
                           TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        return 0;
    }
    return 1;
}

void tricky_stateFollowPlayer(GameObject* obj, TrickyState* state) {
    GameObject* found;
    TrickyState* followState;
    GameObject* target;
    int inWater;
    f32 resetValue;

    found = NULL;
    if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
        if (state->pendingFollowRequest != TRICKY_PENDING_FOLLOW_NONE) {
            switch ((int)state->pendingFollowRequest) {
            case TRICKY_PENDING_FOLLOW_HANDOFF: {
                target = state->pendingFollowObj;
                followState = obj->extra;
                if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0) {
                    if ((followState->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) == 0) {
                        followState->followObj = target;
                        trickySetTargetPosition(followState, &target->anim.worldPosX);
                        followState->substate = TRICKY_FOLLOW_SUBSTATE_IDLE;
                        followState->stateIndex = TRICKY_STATE_IDLE_AND_EAT;
                    } else {
                        followState->pendingFollowRequest = TRICKY_PENDING_FOLLOW_HANDOFF;
                        followState->pendingFollowObj = target;
                        followState->stateFlags |= TRICKY_STATE_FLAG_RECALL_REQUEST;
                    }
                }
                if (tricky_handleFeedOrTalk(obj, state) == 0 &&
                    trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) ==
                        TRICKY_MOVEMENT_REACHED_TARGET) {
                    state->idleSfxTimer -= timeDelta;
                    if (state->idleSfxTimer <= 0.0f) {
                        state->idleSfxTimer =
                            (f32)(int)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
                        trickyTryPlaySound(obj, TRICKY_VOICE_SFX_DUM_DE_DUM, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                    }
                    inWater = trickyIsInDeepWater(state);
                    if (inWater != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                        state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                        state->particleTimer = 0.0f;
                        trickyDebugPrint("in water\n");
                    } else {
                        switch (obj->anim.currentMove) {
                        case TRICKY_ANIM_IDLE_FOOD_WAIT:
                            if (state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) {
                                trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_CHEW, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                            }
                            break;
                        default:
                            trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_WAIT, TRICKY_LAND_MOVE_ANIM_RATE, 0);
                        case TRICKY_ANIM_IDLE_FOOD_CHEW:
                            break;
                        }
                        trickyDebugPrint("out of water\n");
                    }
                }
            } break;
            default:
                break;
            }
            state->pendingFollowRequest = TRICKY_PENDING_FOLLOW_NONE;
            return;
        }
        found = trickyFindRecallWarp(obj, state);
    }
    if (found != NULL) {
        state->groundSnapCounter = 2;
        (*gPathControlInterface)->attachObject(obj, &state->curvesCollision);
        trickyResetCommandState(state);
        obj->anim.localPosX = found->anim.localPosX;
        obj->anim.localPosY = found->anim.localPosY;
        obj->anim.localPosZ = found->anim.localPosZ;
        obj->anim.worldPosX = found->anim.worldPosX;
        obj->anim.worldPosY = found->anim.worldPosY;
        obj->anim.worldPosZ = found->anim.worldPosZ;
        ObjHits_SyncObjectPosition(obj);
        obj->anim.rotX = found->anim.rotX;
        state->movementState = TRICKY_MOVE_WALK_WAIT;
        resetValue = 0.0f;
        state->prevSpeed = resetValue;
        state->speed = resetValue;
        state->recoveryPos.x = found->anim.worldPosX;
        state->recoveryPos.y = found->anim.worldPosY;
        state->recoveryPos.z = found->anim.worldPosZ;
        state->stateFlags |= TRICKY_STATE_FLAG_POSITION_RELOCATED;
        state->stateFlags &= ~TRICKY_STATE_FLAG_GROUND_SNAP;
    } else {
        state->followHeelTimer -= timeDelta;
        if (state->followHeelTimer < 0.0f) {
            state->followHeelTimer = 0.0f;
        }
        tricky_handlePlayerContact(obj, state);
        {
            if (sTrickySubstateHandlers[state->substate](obj, state) == 0) {
                inWater = trickyIsInDeepWater(state);
                if (inWater != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                    state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                    state->particleTimer = 0.0f;
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_WANDER, TRICKY_IDLE_WANDER_ANIM_RATE, 0);
                }
            }
        }
    }
}

static inline void trickyNormalizeMoveDirection(TrickyState* state) {
    f32 length = sqrtf(state->moveVector.x * state->moveVector.x + state->moveVector.z * state->moveVector.z);
    if (0.0f != length) {
        state->moveVector.x /= length;
        state->moveVector.z /= length;
    }
}

void tricky_stateFindSecretDig(GameObject* obj, TrickyState* state) {
    u16 sfxTable[2] = {TRICKY_VOICE_SFX_YEAH, TRICKY_VOICE_SFX_LAUGH};
    RomCurveDef* curve;
    GameObject* followObj;
    int movementResult;
    f32 pressDistance;

    followObj = state->followObj;
    switch (state->substate) {
    case TRICKY_SECRET_DIG_SCAN_CURVE:
        state->secretDigCurve = Objfsa_FindNearestEnabledCurveType24(&state->followObj->anim.worldPosX, -1,
                                                                     ROMCURVE_TRICKY_SUBTYPE_DIG_TUNNEL);
        if (state->secretDigCurve != NULL &&
            getXZDistanceSquared(&state->followObj->anim.worldPosX, &state->secretDigCurve->x) >
                TRICKY_SECRET_DIG_SCAN_DISTANCE_SQ) {
            state->secretDigCurve = NULL;
        }
        state->substate = TRICKY_SECRET_DIG_APPROACH_TARGET;
    case TRICKY_SECRET_DIG_APPROACH_TARGET:
        movementResult = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        if (movementResult == TRICKY_MOVEMENT_REACHED_TARGET) {
            if (state->secretDigCurve != NULL) {
                state->substate = TRICKY_SECRET_DIG_APPROACH_CURVE;
                trickySetTargetPosition(state, &state->secretDigCurve->x);
            } else {
                state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->substate = TRICKY_SECRET_DIG_START_PRESS;
                state->secretDigPressTimer = 0.0f;
                state->secretDigWhineTimer =
                    (f32)(int)randomGetRange(TRICKY_SECRET_DIG_WHINE_MIN_FRAMES, TRICKY_SECRET_DIG_WHINE_MAX_FRAMES);
                Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
                trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_ARC_RETURN, TRICKY_DIG_TUNNEL_ANIM_RATE,
                                  TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            }
        } else if (movementResult == TRICKY_MOVEMENT_BLOCKED) {
            trickyResetCommandState(state);
        }
        break;
    case TRICKY_SECRET_DIG_APPROACH_CURVE:
        if (trickyUpdateMovementState(obj, TRICKY_MAX_DISTANCE, state) == TRICKY_MOVEMENT_REACHED_TARGET) {
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = TRICKY_SECRET_DIG_START_PRESS;
            state->secretDigPressTimer = 0.0f;
            Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
            trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_ARC_RETURN, TRICKY_DIG_TUNNEL_ANIM_RATE,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        }
        break;
    case TRICKY_SECRET_DIG_START_PRESS:
        state->secretDigPressTimer += timeDelta;
        state->secretDigWhineTimer -= timeDelta;
        if (state->secretDigPressTimer >= 60.0f) {
            state->substate = TRICKY_SECRET_DIG_PRESSING;
            state->secretDigOriginX = obj->anim.worldPosX;
            state->secretDigOriginZ = obj->anim.worldPosZ;
            curve = state->secretDigCurve;
            if (curve != NULL) {
                followObj = state->followObj;
                state->moveVector.x = curve->x - followObj->anim.worldPosX;
                state->moveVector.z = curve->z - followObj->anim.worldPosZ;
                trickyNormalizeMoveDirection(state);
            }
        }
        break;
    case TRICKY_SECRET_DIG_PRESSING:
        state->secretDigWhineTimer -= timeDelta;
        if (state->secretDigWhineTimer <= 0.0f) {
            state->secretDigWhineTimer =
                (f32)(int)randomGetRange(TRICKY_SECRET_DIG_WHINE_MIN_FRAMES, TRICKY_SECRET_DIG_WHINE_MAX_FRAMES);
            state->secretDigWhineTimer *= 100.0f;
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_DUM_DE_DUM, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        }
        pressDistance = GROUND_ANIMATOR_INTERFACE(followObj)->applyPress(followObj, obj);
        obj->anim.localPosX = state->secretDigOriginX - state->moveVector.x * pressDistance;
        obj->anim.localPosZ = state->secretDigOriginZ - state->moveVector.z * pressDistance;
        if (GROUND_ANIMATOR_INTERFACE(followObj)->isFullySunk(followObj) != 0) {
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            state->stats->energy -= 4;
            trickyResetCommandState(state);
            trickyTryPlaySound(obj, sfxTable[randomGetRange(0, 1)], TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        }
        break;
    }
}

void trickyDigTunnel(GameObject* obj, TrickyState* state) {
    u16 sfxTable[2] = {TRICKY_VOICE_SFX_YEAH, TRICKY_VOICE_SFX_LAUGH};
    RomCurveDef* tunnelNode;
    int walkGroup;
    f32 digProgress;

    switch (state->substate) {
    case TRICKY_DIG_TUNNEL_INIT:
        tunnelNode = Objfsa_FindNearestCurveType24(state->targetPosPtr, -1, ROMCURVE_TRICKY_SUBTYPE_DIG_TUNNEL);
        state->digTunnelEntryNode.curve = (*gRomCurveInterface)->getById(tunnelNode->linkIds[0]);
        state->digTunnelStartNode = tunnelNode;
        state->digTunnelExitNode.curve = (*gRomCurveInterface)->getById(tunnelNode->linkIds[1]);
        if (state->digTunnelExitNode.curve->walkGroup != 0) {
            state->digTunnelExitNode.bits = state->digTunnelExitNode.bits ^ state->digTunnelEntryNode.bits;
            state->digTunnelEntryNode.bits = state->digTunnelEntryNode.bits ^ state->digTunnelExitNode.bits;
            state->digTunnelExitNode.bits = state->digTunnelExitNode.bits ^ state->digTunnelEntryNode.bits;
        }
        trickySetTargetPosition(state, &state->digTunnelEntryNode.curve->x);
        state->substate = TRICKY_DIG_TUNNEL_FINDING_ENTRY;
    case TRICKY_DIG_TUNNEL_FINDING_ENTRY:
        trickyDebugPrint("DIGTUNNEL_FINDING\n");
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        walkGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
        if (state->digTunnelEntryNode.curve->walkGroup == walkGroup) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
            state->substate = TRICKY_DIG_TUNNEL_GOING_TO_START;
        }
        break;
    case TRICKY_DIG_TUNNEL_GOING_TO_START:
        trickyDebugPrint("DIGTUNNEL_GOINGTOSTART\n");
        if (trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->digTunnelStartNode->x) == 0) {
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE | TRICKY_STATE_FLAG_GROUND_SNAP;
            state->substate = TRICKY_DIG_TUNNEL_START_DIGGING;
        } else {
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
                state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE | TRICKY_STATE_FLAG_GROUND_SNAP;
            }
        }
        break;
    case TRICKY_DIG_TUNNEL_START_DIGGING:
        trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_ARC_RETURN, TRICKY_DIG_TUNNEL_ANIM_RATE,
                          TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        state->moveVector.x = state->digTunnelExitNode.curve->x - state->digTunnelStartNode->x;
        state->moveVector.z = state->digTunnelExitNode.curve->z - state->digTunnelStartNode->z;
        Sfx_AddLoopedObjectSound(obj, SFXTRIG_trwhin1);
        state->digTunnelWhineTimer =
            (f32)(int)randomGetRange(TRICKY_DIG_TUNNEL_WHINE_MIN_FRAMES, TRICKY_DIG_TUNNEL_WHINE_MAX_FRAMES);
        state->substate = TRICKY_DIG_TUNNEL_DIGGING;
    case TRICKY_DIG_TUNNEL_DIGGING:
        trickyDebugPrint("DIGTUNNEL_DIGGING\n");
        state->digTunnelWhineTimer -= timeDelta;
        if (state->digTunnelWhineTimer <= 0.0f) {
            state->digTunnelWhineTimer =
                (f32)(int)randomGetRange(TRICKY_DIG_TUNNEL_WHINE_MIN_FRAMES, TRICKY_DIG_TUNNEL_WHINE_MAX_FRAMES);
            state->digTunnelWhineTimer *= 100.0f;
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_DUM_DE_DUM, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        }
        digProgress = WALL_ANIMATOR_INTERFACE(state->followObj)->applyImpact(state->followObj, obj);
        obj->anim.localPosX = state->moveVector.x * digProgress + state->digTunnelStartNode->x;
        obj->anim.localPosZ = state->moveVector.z * digProgress + state->digTunnelStartNode->z;
        trickyTurnAlongMoveDirection(obj);
        if (WALL_ANIMATOR_INTERFACE(state->followObj)->isComplete(state->followObj) != 0) {
            s32 linkId;
            RomCurveDef* linkNode;
            s32 linkIndex;

            for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
                linkNode = state->digTunnelExitNode.curve;
                linkId = linkNode->linkIds[linkIndex];
                if (linkId > -1 && linkId != state->digTunnelStartNode->id) {
                    state->digTunnelStartNode = linkNode;
                    state->digTunnelExitNode.curve =
                        (*gRomCurveInterface)->getById(state->digTunnelExitNode.curve->linkIds[linkIndex]);
                    break;
                }
            }
            state->stats->energy -= 4;
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trwhin1);
            state->substate = TRICKY_DIG_TUNNEL_TO_EXIT_1;
            trickyTryPlaySound(obj, sfxTable[randomGetRange(0, 1)], TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
        }
        break;
    case TRICKY_DIG_TUNNEL_TO_EXIT_1:
        trickyDebugPrint("DIGTUNNEL_TOEND1 %f\n",
                         Vec_xzDistance(&obj->anim.worldPosX, &state->digTunnelExitNode.curve->x));
        if (trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->digTunnelExitNode.curve->x) == 0) {
            s32 linkId;
            RomCurveDef* linkNode;
            s32 linkIndex;

            for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
                linkNode = state->digTunnelExitNode.curve;
                linkId = linkNode->linkIds[linkIndex];
                if (linkId > -1 && linkId != state->digTunnelStartNode->id) {
                    state->digTunnelStartNode = linkNode;
                    state->digTunnelExitNode.curve =
                        (*gRomCurveInterface)->getById(state->digTunnelExitNode.curve->linkIds[linkIndex]);
                    break;
                }
            }
            state->substate = TRICKY_DIG_TUNNEL_TO_EXIT_2;
        }
        break;
    case TRICKY_DIG_TUNNEL_TO_EXIT_2:
        trickyDebugPrint("DIGTUNNEL_TOEND2\n");
        if (trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->digTunnelExitNode.curve->x) == 0) {
            trickyRequestIdleMove(obj, state);
            state->stateFlags &= ~(TRICKY_STATE_FLAG_COMMAND_ACTIVE | TRICKY_STATE_FLAG_GROUND_SNAP);
            state->substate = TRICKY_DIG_TUNNEL_WAIT_FOR_PLAYER_GROUP;
        }
        break;
    case TRICKY_DIG_TUNNEL_WAIT_FOR_PLAYER_GROUP:
        trickyDebugPrint("DIGTUNNEL_WAIT\n");
        walkGroup = Objfsa_GetWalkGroupIndexAtPoint(&state->playerObj->anim.worldPosX, NULL);
        {
            int currentGroup;

            currentGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL);
            if (currentGroup == walkGroup) {
                trickyResetCommandState(state);
            }
        }
        break;
    }
}

void tricky_state04_nop(void) {
}

void tricky_updateBallRoll(GameObject* obj, TrickyState* state) {
    RomCurveDef* backwardNode;
    RomCurveDef* startCurve;
    u8 nodeCount = 0;
    int branchCurveId;
    RomCurveDef* branchNode;
    u32 branchMask;
    int branchIndex;
    int i;
    RomCurveDef* forwardNode;
    RomCurveDef* segmentNode;
    s32 nodeIds[ROMCURVE_LINK_COUNT];
    RomCurveDef* branchCandidateNode;
    RomCurveDef* nextSegmentNode;
    f32 speed;
    f32 distance;
    f32 bestDistance;

    if (state->substate != TRICKY_CANNONBALL_INIT) {
        if (state->route.reverse == 0) {
            if (state->route.atSegmentEnd != 0) {
                branchNode = state->route.nextNode;
                branchMask = 1;
                for (branchIndex = 0; branchIndex < ROMCURVE_LINK_COUNT; branchIndex++) {
                    branchCurveId = branchNode->linkIds[branchIndex];
                    if (branchCurveId > -1 && ((branchNode->backwardLinkMask & branchMask) == 0)) {
                        nodeIds[nodeCount++] = branchCurveId;
                    }
                    branchMask <<= 1;
                }
            }
        } else if (state->route.atSegmentEnd == 0) {
            int reverseBranchCurveId;
            RomCurveDef* reverseBranchNode;
            u32 reverseBranchMask;
            reverseBranchNode = state->route.nextNode;
            reverseBranchMask = 1;
            for (branchIndex = 0; branchIndex < ROMCURVE_LINK_COUNT; branchIndex++) {
                reverseBranchCurveId = reverseBranchNode->linkIds[branchIndex];
                if (reverseBranchCurveId > -1 && ((reverseBranchNode->backwardLinkMask & reverseBranchMask) != 0)) {
                    nodeIds[nodeCount++] = reverseBranchCurveId;
                }
                reverseBranchMask <<= 1;
            }
        }

        if (nodeCount != 0) {
            nextSegmentNode = (*gRomCurveInterface)->getById(nodeIds[0]);
            bestDistance = getXZDistanceSquared(&state->followObj->anim.worldPosX, &nextSegmentNode->x);

            for (i = 1; i < nodeCount; i++) {
                branchCandidateNode = (*gRomCurveInterface)->getById(nodeIds[i]);
                distance = getXZDistanceSquared(&state->followObj->anim.worldPosX, &branchCandidateNode->x);
                if (distance < bestDistance) {
                    nextSegmentNode = branchCandidateNode;
                    bestDistance = distance;
                }
            }

            RomCurve_advanceToNextSegment(&state->route, nextSegmentNode);
        }

        speed = state->speed;
        if ((u8)(state->stateFlags & TRICKY_STATE_FLAG_TURNING) != 0) {
            speed += CANNONBALL_ROLL_DECAY_STEP * timeDelta;
            if (speed < 0.0f) {
                speed = 0.0f;
            }
        } else if (speed > CANNONBALL_ROLL_SPEED_LIMIT) {
            speed += TRICKY_SPEED_DECAY_STEP * timeDelta;
            if (speed < CANNONBALL_ROLL_SPEED_LIMIT) {
                speed = CANNONBALL_ROLL_SPEED_LIMIT;
            }
        } else {
            speed += TRICKY_SMALL_SPEED_STEP * timeDelta;
            if (speed > CANNONBALL_ROLL_SPEED_LIMIT) {
                speed = CANNONBALL_ROLL_SPEED_LIMIT;
            }
        }

        state->speed = speed;
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);

        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
            state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        } else {
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
        }

        state->cannonballRollSfxTimer -= timeDelta;
        if (state->cannonballRollSfxTimer < 0.0f) {
            state->cannonballRollSfxTimer =
                (f32)(int)randomGetRange(CANNONBALL_SFX_TIMER_MIN, CANNONBALL_SFX_TIMER_MAX);
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_ROLLING, TRICKY_VOICE_MOUTH_ANGLE_LARGE);
        }
    } else {
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) ==
            Objfsa_GetWalkGroupIndexAtPoint(&state->cannonballStartCurve->x, NULL)) {
            startCurve = state->cannonballStartCurve;

            forwardNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomForwardLink(startCurve, 0));
            backwardNode = (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBackwardLink(startCurve, 0));

            bestDistance = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &forwardNode->x);
            distance = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &backwardNode->x);

            if (bestDistance > distance) {
                segmentNode = forwardNode;
                nextSegmentNode =
                    (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomForwardLink(forwardNode, 0));
                state->route.reverse = 0;
            } else {
                segmentNode = backwardNode;
                nextSegmentNode =
                    (*gRomCurveInterface)->getById((*gRomCurveInterface)->getRandomBackwardLink(backwardNode, 0));
                state->route.reverse = 1;
            }

            RomCurve_setupHermiteSegment(&state->route, startCurve, segmentNode, nextSegmentNode);
            if (state->route.reverse != 0) {
                RomCurve_stepClamped(&state->route, CANNONBALL_ROUTE_BACKSTEP);
            } else {
                RomCurve_stepClamped(&state->route, CANNONBALL_ROUTE_FORESTEP);
            }

            state->cannonballRollSfxTimer = 0.0f;
            state->substate = TRICKY_CANNONBALL_ROLLING;
        }
    }
}

void tricky_state06_nop(void) {
}

static inline int trickyApproachTarget(GameObject* obj, f32 stoppingRadius, TrickyState* state, f32* targetPos) {
    trickyUpdateApproachSpeed(obj, stoppingRadius, state, targetPos, 1);
    return moveTricky(obj, targetPos);
}

static inline int trickyUpdateFlameAction(GameObject* obj, TrickyState* state) {
    if (obj->anim.currentMoveProgress > 0.25f) {
        if ((state->stateFlags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
            if ((u8)Obj_CanSetupObject() != 0) {
                trickySpawnFlameChildren(obj, state);
            }
        } else {
            TrickyFlameTargetCallback callback = state->flameTargetCallback;
            if (callback == NULL || callback(state->followObj, 1) != 0) {
                if (obj->anim.currentMoveProgress > TRICKY_FLAME_HELPER_RELEASE_PROGRESS) {
                    trickyStopFlameChildren(obj, state);
                    return 0;
                }
            }
        }
    }
    return 1;
}

void trickyFlame(GameObject* obj, TrickyState* trickyState) {
    switch (trickyState->substate) {
    case TRICKY_FLAME_NONE:
        trickyDebugPrint("FLAME_NONE\n");
        trickyState->flameEdgeNode = Objfsa_FindNearestCurveType24(&trickyState->followObj->anim.worldPosX, -1,
                                                                   ROMCURVE_TRICKY_SUBTYPE_FLAME_EDGE);
        if (trickyState->flameEdgeNode->walkGroup != 0) {
            trickySetTargetPosition(trickyState, &trickyState->flameEdgeNode->x);
            trickyState->substate = TRICKY_FLAME_FINDING_IN;
        } else {
            trickyState->flameReturnNode = (*gRomCurveInterface)->getById(trickyState->flameEdgeNode->linkIds[0]);
            trickySetTargetPosition(trickyState, &trickyState->flameReturnNode->x);
            trickyState->substate = TRICKY_FLAME_FINDING_OUT;
        }
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
        break;
    case TRICKY_FLAME_FINDING_OUT:
        trickyDebugPrint("FLAME_FINDING_OUT\n");
        trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
        if ((u8)trickyState->flameReturnNode->walkGroup ==
            Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL)) {
            trickyState->movementState = TRICKY_MOVE_WALK_FREE;
            trickyState->substate = TRICKY_FLAME_GOING_TO_EDGE;
        }
        break;
    case TRICKY_FLAME_GOING_TO_EDGE:
        trickyDebugPrint("FLAME_GOINGTOEDGE\n");
        trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, &trickyState->flameEdgeNode->x);
        if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) == 0) {
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKY_FLAME_TO_START;
        }
        break;
    case TRICKY_FLAME_TO_START:
        trickyDebugPrint("FLAME_TOSTART\n");
        if (trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, &trickyState->flameEdgeNode->x) !=
            0) {
            break;
        }
        trickyRequestMove(obj, TRICKY_ANIM_FLAME_BREATH, 0.004f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
        trickyState->substate = TRICKY_FLAME_OUT;
        trickyState->stats->energy -= 4;
        /* fall through */
    case TRICKY_FLAME_OUT:
        trickyDebugPrint("FLAME_OUT\n");
        {
            s16 flameYaw = (s16)(trickyState->flameEdgeNode->yaw << 8);
            s16 turnDelta = (s16)(flameYaw - (u16)obj->anim.rotX);
            int turnDeltaAbs;
            if (turnDelta > TRICKY_YAW_HALF_TURN) {
                turnDelta = (s16)(turnDelta - TRICKY_YAW_WRAP_RANGE);
            }
            if (turnDelta < -TRICKY_YAW_HALF_TURN) {
                turnDelta = (s16)(turnDelta + TRICKY_YAW_WRAP_RANGE);
            }
            turnDeltaAbs = turnDelta;
            turnDeltaAbs = (turnDeltaAbs >= 0) ? turnDeltaAbs : -turnDeltaAbs;
            if (turnDeltaAbs >= TRICKY_YAW_QUARTER_TURN) {
                flameYaw = (s16)(flameYaw + TRICKY_YAW_HALF_TURN);
            }
            trickyTurnTowardYaw(obj, flameYaw);
        }
        if (trickyUpdateFlameAction(obj, trickyState) == 0) {
            trickyState->substate = TRICKY_FLAME_TO_END;
            (trickyState)->guardTimer = 60.0f;
        }
        break;
    case TRICKY_FLAME_FINDING_IN:
        trickyDebugPrint("FLAME_FINDING_IN\n");
        {
            int movementResult = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState);
            if (movementResult == TRICKY_MOVEMENT_REACHED_TARGET) {
                trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                trickyState->substate = TRICKY_FLAME_TURNING_IN;
            } else if (movementResult == TRICKY_MOVEMENT_BLOCKED) {
                trickyResetCommandState(trickyState);
            }
        }
        break;
    case TRICKY_FLAME_TURNING_IN:
        trickyDebugPrint("FLAME_TURNING_IN\n");
        if (trickyApproachTarget(obj, TRICKY_MAX_DISTANCE, trickyState, &trickyState->followObj->anim.worldPosX) == 0) {
            trickyRequestMove(obj, TRICKY_ANIM_FLAME_BREATH, 0.004f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->substate = TRICKY_FLAME_IN;
            trickyState->stats->energy -= 4;
        }
        break;
    case TRICKY_FLAME_IN:
        trickyDebugPrint("FLAME_IN\n");
        if (trickyUpdateFlameAction(obj, trickyState) == 0) {
            trickyResetCommandState(trickyState);
        }
        break;
    case TRICKY_FLAME_TO_END:
        trickyDebugPrint("FLAME_TOEND\n");
        trickyState->guardTimer -= timeDelta;
        if (trickyState->guardTimer <= 0.0f) {
            trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, trickyState, &trickyState->flameReturnNode->x);
            if (Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, NULL) != 0) {
                trickyResetCommandState(trickyState);
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
        trickySetTargetPosition(trickyState, &bestTarget->anim.worldPosX);
        trickyState->substate = TRICKY_GUARD_TO_BADDIE;
        return 1;
    }
    return 0;
}

void trickyGuard(GameObject* obj, TrickyState* trickyState) {
    switch (trickyState->substate) {
    case TRICKY_GUARD_INIT:
        trickyDebugPrint("GUARD_INIT\n");
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
        trickyDebugPrint("GUARD_FINDING\n");
        trickyUpdateMovementState(obj, TRICKY_GUARD_APPROACH_RADIUS, trickyState);
        if (trickyState->guardWalkGroup == Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0x0)) {
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
        }
        break;
    case TRICKY_GUARD_TO_SPOT:
        trickyDebugPrint("GUARD_TOSPOT\n");
        if (trickyUpdateMovementState(obj, TRICKY_GUARD_APPROACH_RADIUS, trickyState) ==
            TRICKY_MOVEMENT_REACHED_TARGET) {
            trickySetTargetPosition(trickyState, trickyState->guardPoint);
            trickyState->substate = TRICKY_GUARD_TO_FRONT;
        } else {
            trickyGuardFindBaddieTarget(trickyState);
            break;
        }
    case TRICKY_GUARD_TO_FRONT:
        trickyDebugPrint("GUARD_TOFRONT\n");
        if (trickyUpdateMovementState(obj, TRICKY_GUARD_APPROACH_RADIUS, trickyState) ==
            TRICKY_MOVEMENT_REACHED_TARGET) {
            if (trickyIsInDeepWater(trickyState) != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                (trickyState)->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                (trickyState)->particleTimer = 0.0f;
                trickyDebugPrint("in water\n");
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_ANIM_RATE, 0);
                trickyDebugPrint("out of water\n");
            }
        }
        trickyGuardFindBaddieTarget(trickyState);
        break;
    case TRICKY_GUARD_TO_BADDIE:
        trickyDebugPrint("GUARD_TOBADDIE\n");
        if (trickyUpdateMovementState(obj, TRICKY_GUARD_BADDIE_RADIUS, trickyState) == TRICKY_MOVEMENT_REACHED_TARGET) {
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (trickyState->stats->energy != 0 && trickyState->guardCanSpawnHelpers != 0) {
                if ((u8)Obj_CanSetupObject() != 0) {
                    trickySpawnFlameChildren(obj, trickyState);
                }
                trickyState->stats->energy--;
                trickyRequestMove(obj, TRICKY_ANIM_FLAME_ATTACK, TRICKY_LAND_MOVE_ANIM_RATE,
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
            trickySetTargetPosition(trickyState, &trickyState->followObj->anim.worldPosX);
            trickyState->substate = TRICKY_GUARD_TO_SPOT;
            break;
        }
    case TRICKY_GUARD_FLAME:
        trickyDebugPrint("GUARD_FLAME\n");
        if (obj->anim.currentMoveProgress >= TRICKY_GUARD_FLAME_DONE_PROGRESS) {
            trickyStopFlameChildren(obj, trickyState);
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (trickyGuardFindBaddieTarget(trickyState) == 0) {
                trickySetTargetPosition(trickyState, &trickyState->followObj->anim.worldPosX);
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        } else if (trickyGuardIsBaddieTargetValid(trickyState->guardTarget) != 0) {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_DOWN_TO_GROWL:
        trickyDebugPrint("GUARD_DOWNTOGROWL\n");
        if (obj->anim.currentMoveProgress >= TRICKY_GUARD_FLAME_DONE_PROGRESS) {
            trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_LAND_MOVE_ANIM_RATE,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->guardTimer = 0.0f;
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GROWL, TRICKY_VOICE_MOUTH_ANGLE_SMALL);
            trickyState->substate = TRICKY_GUARD_GROWL;
        } else if (trickyGuardIsBaddieTargetValid(trickyState->guardTarget) != 0) {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;

            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    case TRICKY_GUARD_GROWL:
        trickyDebugPrint("GUARD_GROWL\n");
        if (randomGetRange(0, TRICKY_GUARD_GROWL_RANDOM_RATE) == 0) {
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GROWL, TRICKY_VOICE_MOUTH_ANGLE_SMALL);
        }
        trickyState->guardTimer = trickyState->guardTimer + timeDelta;
        if ((trickyState->guardTimer >= TRICKY_GUARD_GROWL_MAX_FRAMES &&
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
        trickyDebugPrint("GUARD_UPFROMGROWL\n");
        if (obj->anim.currentMoveProgress <= 0.05f) {
            trickyState->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            if (trickyGuardFindBaddieTarget(trickyState) == 0) {
                trickySetTargetPosition(trickyState, &trickyState->followObj->anim.worldPosX);
                trickyState->substate = TRICKY_GUARD_TO_SPOT;
            }
        }
        break;
    }
}

static inline void trickySpawnFlameChildren(GameObject* obj, TrickyState* state) {
    int childIndex;

    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    for (childIndex = 0; childIndex < TRICKY_FLAME_CHILD_COUNT; childIndex++) {
        FlameblastPlacement* setup =
            (FlameblastPlacement*)Obj_AllocObjectSetup(sizeof(*setup), TRICKY_SPAWN_ROMDEF_FLAMEBLAST);

        setup->base.color[0] = 2;
        setup->base.color[1] = 1;
        setup->streamIndex = childIndex;
        state->flameChildren[childIndex] =
            objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
    }
    Sfx_PlayFromObject(obj, SFXTRIG_en_cvdrip1c_3db);
    Sfx_AddLoopedObjectSound(obj, SFXTRIG_trpopn_c);
}

static inline void trickyStopFlameChildren(GameObject* obj, TrickyState* state) {
    int childIndex;

    state->stateFlags &= ~TRICKY_STATE_FLAG_CHILDREN_ACTIVE;
    state->stateFlags |= TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
    for (childIndex = 0; childIndex < TRICKY_FLAME_CHILD_COUNT; childIndex++) {
        flameblast_requestFree(state->flameChildren[childIndex]);
    }
    Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_trpopn_c);
    trickyTryPlaySound(obj, TRICKY_VOICE_SFX_FINISH_FLAME, TRICKY_VOICE_MOUTH_ANGLE_NONE);
}

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

void tricky_moveToFollowTarget(GameObject* obj, TrickyState* state) {
    int result;

    result = trickyUpdateMovementState(obj, 15.0f, state);
    if (result == TRICKY_MOVEMENT_REACHED_TARGET) {
        trickyRequestIdleMove(obj, state);
    }
}

void tricky_trackTumbleweed(GameObject* obj, TrickyState* state) {
    float dx;
    float dz;
    float distance;
    float* targetPos;
    GameObject* trackedObj;
    u32 currentBit;
    u8 bitIndex;
    u8 newBit;

    switch (state->substate) {
    case TRICKY_TUMBLEWEED_INIT:
        newBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        state->tumbleweedCount = newBit;
        state->tumbleweedTargetObj = NULL;
        state->substate = TRICKY_TUMBLEWEED_CHASE;
    case TRICKY_TUMBLEWEED_CHASE:
        currentBit = mainGetBit(GAMEBIT_NW_MammothTumbleweedCount);
        bitIndex = state->tumbleweedCount;
        if (bitIndex != currentBit) {
            state->tumbleweedCount++;
            state->stats->energy -= 2;
        }
        targetPos = NW_mammoth_getSpawnPosition(state->followObj);
        trackedObj = tumbleweedbush_findNearestActive(targetPos);
        if (trackedObj != 0 && state->stats->energy != 0) {
            if (trackedObj != state->tumbleweedTargetObj) {
                trickySetTargetPosition(state, &state->tumbleweedTargetPos.x);
            }
            dx = *targetPos - obj->anim.worldPosX;
            dz = targetPos[2] - obj->anim.worldPosZ;
            distance = sqrtf(dx * dx + dz * dz);
            if (0.0f != distance) {
                dx = dx / distance;
                dz = dz / distance;
            }
            distance = TRICKY_CIRCLING_APPROACH_RADIUS;
            state->tumbleweedTargetPos.x = -(distance * dx - trackedObj->anim.worldPosX);
            state->tumbleweedTargetPos.y = trackedObj->anim.worldPosY;
            state->tumbleweedTargetPos.z = -(distance * dz - trackedObj->anim.worldPosZ);
            if (trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) ==
                TRICKY_MOVEMENT_REACHED_TARGET) {
                trickyRequestIdleMove(obj, state);
            }
        } else {
            trickyResetCommandState(state);
        }
        break;
    }
}

void tricky_idleAndEat(GameObject* obj, TrickyState* state) {
    int inWater;

    if (tricky_handleFeedOrTalk(obj, state) == 0) {
        if (trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) == TRICKY_MOVEMENT_REACHED_TARGET) {
            state->idleSfxTimer -= timeDelta;
            if (state->idleSfxTimer <= 0.0f) {
                state->idleSfxTimer =
                    (f32)(s32)randomGetRange(TRICKY_IDLE_VOICE_MIN_FRAMES, TRICKY_IDLE_VOICE_MAX_FRAMES);
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_DUM_DE_DUM, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
            }
            inWater = trickyIsInDeepWater(state);
            if (inWater != 0) {
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
                trickyDebugPrint("in water\n");
            } else {
                switch (obj->anim.currentMove) {
                case TRICKY_ANIM_IDLE_FOOD_WAIT:
                    if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
                        trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_CHEW, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                    }
                    break;
                case TRICKY_ANIM_IDLE_FOOD_CHEW:
                    break;
                default:
                    trickyRequestMove(obj, TRICKY_ANIM_IDLE_FOOD_WAIT, TRICKY_LAND_MOVE_ANIM_RATE, 0);
                    break;
                }
                trickyDebugPrint("out of water\n");
            }
        }
    }
}

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
 * Common to all: the collision results' water depth and floor/water heights
 * select swim versus ground animations. tricky_fetchBall and tricky_idleAndEat play a
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
    int movementStatus;
    int useSwimAnim;
    f32 launchDirZ;

    switch (state->substate) {
    case TRICKY_FETCH_BALL_INIT:
        state->fetchBallObj = state->followObj;
        state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
        state->substate = TRICKY_FETCH_BALL_CHASE;
        state->sfxIntervalTimer =
            (f32)(s32)randomGetRange(TRICKY_FETCH_VOICE_MIN_FRAMES, TRICKY_FETCH_VOICE_MAX_FRAMES);
        /* fall through */
    case TRICKY_FETCH_BALL_CHASE:
        if (sidekickBall_isHeldOrMoving(state->fetchBallObj) != 0) {
            movementStatus = trickyUpdateMovementState(obj, TRICKY_FETCH_BALL_REACH_RADIUS, state);
            if (movementStatus == TRICKY_MOVEMENT_REACHED_TARGET) {
                useSwimAnim = trickyIsInDeepWater(state);
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_PICKUP_WATER, TRICKY_FETCH_PICKUP_ANIM_RATE,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_PICKUP_LAND, TRICKY_FETCH_PICKUP_ANIM_RATE,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                }
                state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
                state->substate = TRICKY_FETCH_BALL_PICKUP_START;
                sidekickBall_setIdle(state->fetchBallObj, obj);
            } else if (movementStatus == TRICKY_MOVEMENT_BLOCKED) {
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_IM_NOT_DOING_IT, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                trickyResetCommandState(state);
            }
        } else {
            movementStatus = trickyUpdateMovementState(obj, 20.0f, state);
            if (movementStatus == TRICKY_MOVEMENT_REACHED_TARGET) {
                if (state->fetchCarryDelayTimer > 0.0f) {
                    trickyRequestIdleMove(obj, state);
                    state->fetchCarryDelayTimer -= timeDelta;
                    if (state->fetchCarryDelayTimer <= 0.0f) {
                        useSwimAnim = trickyIsInDeepWater(state);
                        if (useSwimAnim != 0) {
                            state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
                        } else {
                            state->fetchThrowRetryTimer = TRICKY_FETCH_THROW_DELAY_FRAMES;
                        }
                    }
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_THROW_READY, TRICKY_FAST_MOVE_ANIM_RATE,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                    state->fetchThrowRetryTimer -= timeDelta;
                    if (state->fetchThrowRetryTimer <= 0.0f) {
                        state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
                    }
                }
            } else if (movementStatus == TRICKY_MOVEMENT_IN_PROGRESS) {
                state->sfxIntervalTimer -= timeDelta;
                if (state->sfxIntervalTimer <= 0.0f) {
                    state->sfxIntervalTimer =
                        (f32)(s32)randomGetRange(TRICKY_FETCH_VOICE_MIN_FRAMES, TRICKY_FETCH_VOICE_MAX_FRAMES);
                    trickyTryPlaySound(obj, TRICKY_VOICE_SFX_LAUGH, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                }
            } else {
                trickyRequestIdleMove(obj, state);
            }
        }
        break;
    case TRICKY_FETCH_BALL_LAUNCH:
        if ((obj)->anim.currentMoveProgress >= TRICKY_FETCH_LAUNCH_PROGRESS) {
            state->fetchBallObj->anim.localPosY += TRICKY_DEFAULT_STOPPING_RADIUS;
            launchDirZ = -mathCosf(TRICKY_PI * (f32)obj->anim.rotX / TRICKY_ANGLE_HALF_TURN_UNITS);
            sidekickBall_launch(state->fetchBallObj, obj,
                                -mathSinf(TRICKY_PI * (f32)obj->anim.rotX / TRICKY_ANGLE_HALF_TURN_UNITS), 1.0f,
                                launchDirZ);
            state->substate = TRICKY_FETCH_BALL_THROW_DONE;
        }
        break;
    case TRICKY_FETCH_BALL_THROW_DONE:
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            state->colorFadeTimer = 20.0f;
            if (state->stats->ballReturnCount >= TRICKY_BALL_RETURN_COUNT_MAX) {
                state->stats->ballReturnCount = 0;
            } else {
                state->stats->ballReturnCount++;
            }
            state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = TRICKY_FETCH_BALL_WAIT_FOR_IDLE;
            trickySetTargetPosition(state, &state->followObj->anim.worldPosX);
        }
        break;
    case TRICKY_FETCH_BALL_WAIT_FOR_IDLE:
        movementStatus = trickyUpdateMovementState(obj, 20.0f, state);
        if (movementStatus != TRICKY_MOVEMENT_IN_PROGRESS) {
            trickyRequestIdleMove(obj, state);
            return;
        }
        if (sidekickBall_isIdle(state->followObj) != 0) {
            state->fetchCarryDelayTimer = TRICKY_FETCH_CARRY_DELAY_FRAMES;
            state->substate = TRICKY_FETCH_BALL_CHASE;
        }
        break;
    case TRICKY_FETCH_BALL_PICKUP_START:
        if ((obj)->anim.currentMoveProgress >= 0.5f) {
            state->substate = TRICKY_FETCH_BALL_CARRY_TO_PLAYER;
        }
        break;
    case TRICKY_FETCH_BALL_CARRY_TO_PLAYER:
        if ((obj)->anim.currentMoveProgress >= TRICKY_FLAME_DONE_PROGRESS) {
            trickySetTargetPosition(state, &state->playerObj->anim.worldPosX);
            state->substate = TRICKY_FETCH_BALL_APPROACH_THROW_POINT;
        case TRICKY_FETCH_BALL_APPROACH_THROW_POINT:
            if (trickyUpdateMovementState(obj, 30.0f, state) == TRICKY_MOVEMENT_REACHED_TARGET) {
                useSwimAnim = trickyIsInDeepWater(state);
                if (useSwimAnim != 0) {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_THROW_WATER, TRICKY_FETCH_PICKUP_ANIM_RATE,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                } else {
                    trickyRequestMove(obj, TRICKY_ANIM_FETCH_THROW_LAND, TRICKY_FETCH_PICKUP_ANIM_RATE,
                                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
                }
                state->substate = TRICKY_FETCH_BALL_LAUNCH;
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

void trickyUpdateCirclingTargetPosition(GameObject* obj, TrickyState* state) {
    GameObject* target = state->followObj;
    f32 dx = target->anim.worldPosX - obj->anim.worldPosX;
    f32 dz = target->anim.worldPosZ - obj->anim.worldPosZ;
    int targetAngle = atan2Angle16(dx, dz);
    s32 angleDelta;
    s32 absAngleDelta;

    if (state->substate == TRICKY_CIRCLE_INITIALIZE) {
        state->circlingDirection = randomGetRange(0, 1);
        if (state->circlingDirection == 0) {
            state->circlingDirection = -1;
        }
        state->circlingAngle = targetAngle;
        state->substate = TRICKY_CIRCLE_ACTIVE;
    }

    angleDelta = trickyWrapYawDelta(targetAngle - (s32)(u16)state->circlingAngleBits);

    if (angleDelta >= 0) {
        absAngleDelta = angleDelta;
    } else {
        absAngleDelta = -angleDelta;
    }
    if (absAngleDelta < 0x2000) {
        state->circlingAngle = state->circlingAngle + (state->circlingDirection << 11);
    }

    state->circlingTargetPos.x =
        state->followObj->anim.worldPosX - TRICKY_CIRCLING_APPROACH_RADIUS * fsin16Precise((u16)state->circlingAngle);
    state->circlingTargetPos.y = state->followObj->anim.worldPosY;
    state->circlingTargetPos.z =
        state->followObj->anim.worldPosZ - TRICKY_CIRCLING_APPROACH_RADIUS * fcos16Precise((u16)state->circlingAngle);

    if (trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state) == TRICKY_MOVEMENT_REACHED_TARGET) {
        trickyReportError("error tricky should never stop when circling\n");
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
    if (target->anim.romDefNo == TRICKY_CIRCLING_PRIORITY_ROMDEF) {
        return target;
    }

    target = playerGetTargetObject(state->playerObj);
    if (target != NULL) {
        baddieList = objGetAllOfType(TRICKY_BADDIE_OBJGROUP, &baddieCount);
        for (baddieIndex = 0; baddieIndex < baddieCount; baddieIndex++) {
            if (baddieList[baddieIndex] == target) {
                trickyToTarget = Vec_xzDistance(&obj->anim.worldPosX, &target->anim.worldPosX);
                trickyToPlayer = Vec_xzDistance(&obj->anim.worldPosX, &state->playerObj->anim.worldPosX);
                targetToPlayer = Vec_xzDistance(&target->anim.worldPosX, &state->playerObj->anim.worldPosX);
                if ((trickyToTarget + trickyToPlayer) < 2.0f * targetToPlayer) {
                    return target;
                }
                break;
            }
        }
    }
    return NULL;
}

void trickyUpdateBaddieAlert(GameObject* obj, TrickyState* state) {
    u8 movementStatus;
    GameObject* bestDetourWarp = NULL;
    f32 bestDetourSavings = 0.0f;
    int warpCount;

    switch (state->substate) {
    case TRICKY_BADDIE_ALERT_GOTO: {
        trickyDebugPrint("BADDIEALERT_GOTO\n");
        movementStatus = trickyUpdateMovementState(obj, TRICKY_CIRCLING_APPROACH_RADIUS, state);
        if (trickyAcquireBaddieAlertTarget(state) != 0) {
            if (state->flameCommandPending == 0) {
                {
                    GameObject* circlingTarget = trickyFindCirclingTarget(obj, state);
                    state->baddieAlertTarget = circlingTarget;
                    if (circlingTarget != NULL) {
                        state->followObj = state->baddieAlertTarget;
                        state->baddieAlertWarp = NULL;
                        state->substate = TRICKY_BADDIE_ALERT_TRACK_TARGET;
                        break;
                    }
                }
            }
            if (movementStatus == TRICKY_MOVEMENT_BLOCKED) {
                trickyResetCommandState(state);
                break;
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) <
                TRICKY_BADDIE_ALERT_CLOSE_DISTANCE_SQ) {
                f32 resetValue;
                state->substate = TRICKY_BADDIE_ALERT_BARK;
                resetValue = 0.0f;
                state->baddieBarkTimer = resetValue;
                trickyRequestIdleMove(obj, state);
            }
        }
        break;
    }
    case TRICKY_BADDIE_ALERT_BARK: {
        trickyDebugPrint("BADDIEALERT_BARK %d %d\n", state->stats->energy, state->flameCommandPending);
        movementStatus = trickyUpdateMovementState(obj, TRICKY_CIRCLING_APPROACH_RADIUS, state);
        if (trickyAcquireBaddieAlertTarget(state) != 0) {
            if (state->flameCommandPending == 0) {
                {
                    GameObject* circlingTarget = trickyFindCirclingTarget(obj, state);
                    state->baddieAlertTarget = circlingTarget;
                    if (circlingTarget != NULL) {
                        state->followObj = state->baddieAlertTarget;
                        state->baddieAlertWarp = NULL;
                        state->substate = TRICKY_BADDIE_ALERT_TRACK_TARGET;
                        break;
                    }
                }
            }
            if (movementStatus == TRICKY_MOVEMENT_BLOCKED) {
                trickyResetCommandState(state);
                break;
            }
            if (movementStatus == TRICKY_MOVEMENT_REACHED_TARGET) {
                trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_FAST_MOVE_ANIM_RATE, 0);
            }
            if (state->flameCommandPending != 0) {
                if (state->stats->energy < 2) {
                    state->flameCommandPending = 0;
                    if ((u8)Obj_CanSetupObject() != 0) {
                        state->stateFlags |= TRICKY_STATE_FLAG_FOOD_WARNING_PENDING;
                        trickyResetCommandState(state);
                        if (state->foodChild == NULL) {
                            TrickyPromptChildSetup* promptSetup = (TrickyPromptChildSetup*)Obj_AllocObjectSetup(
                                sizeof(*promptSetup), TRICKY_SPAWN_ROMDEF_FOOD);
                            int freePromptSlot;
                            freePromptSlot = trickyFindFreePromptSlot(state);
                            state->packedSlots.foodChildSlot = freePromptSlot;
                            state->foodChild = objSetupObject(&promptSetup->base, 4, -1, -1, obj->anim.parent);
                            ObjLink_AttachChild(obj, state->foodChild, state->packedSlots.foodChildSlot);
                            {
                                f32 resetValue = 0.0f;
                                state->foodVoiceTimer = resetValue;
                                state->foodForceBlinkTimer = resetValue;
                                state->foodBlinkTimer = resetValue;
                            }
                        }
                    }
                } else {
                    state->substate = TRICKY_BADDIE_ALERT_GOTO_FLAME;
                    break;
                }
            }
            if (getXZDistanceSquared(&obj->anim.worldPosX, &state->followObj->anim.worldPosX) >
                TRICKY_BADDIE_ALERT_FAR_DISTANCE_SQ) {
                state->substate = TRICKY_BADDIE_ALERT_GOTO;
                break;
            }
            state->baddieBarkTimer -= timeDelta;
            if (state->baddieBarkTimer < 0.0f) {
                f32 rv;
                rv = (s32)randomGetRange(0xc8, 0x258);
                state->baddieBarkTimer = rv / 2.0f;
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_ROLLING, TRICKY_VOICE_MOUTH_ANGLE_LARGE);
            }
        }
        break;
    }
    case TRICKY_BADDIE_ALERT_GOTO_FLAME: {
        trickyDebugPrint("BADDIEALLERT_GOTOFLAME\n");
        movementStatus = trickyUpdateMovementState(obj, TRICKY_BADDIE_ALERT_FLAME_RADIUS, state);
        if (trickyAcquireBaddieAlertTarget(state) != 0 && movementStatus != TRICKY_MOVEMENT_IN_PROGRESS) {
            trickyRequestMove(obj, TRICKY_ANIM_FLAME_ATTACK, TRICKY_LAND_MOVE_ANIM_RATE,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = TRICKY_BADDIE_ALERT_SPAWN_FLAME;
            state->flameCommandPending = 0;
        }
        break;
    }
    case TRICKY_BADDIE_ALERT_SPAWN_FLAME:
        if (obj->anim.currentMove != TRICKY_ANIM_FLAME_ATTACK) {
            break;
        }
        if (obj->anim.currentMoveProgress > TRICKY_BADDIE_ALERT_SPAWN_PROGRESS) {
            if ((u8)Obj_CanSetupObject() != 0) {
                trickySpawnFlameChildren(obj, state);
            }
            state->stats->energy -= 2;
            state->substate = TRICKY_BADDIE_ALERT_FLAME;
        }
        break;
    case TRICKY_BADDIE_ALERT_FLAME: {
        u32 flags;
        trickyDebugPrint("BADDIEALLERT_FLAME\n");
        flags = state->stateFlags;
        if (flags & TRICKY_STATE_FLAG_MOVE_ENDED) {
            trickyStopFlameChildren(obj, state);
            state->stateFlags &= ~TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            state->substate = TRICKY_BADDIE_ALERT_GOTO;
        }
        break;
    }
    case TRICKY_BADDIE_ALERT_TRACK_TARGET: {
        GameObject* target;
        GameObject* nearestBaddie = trickyFindNearestUsableBaddie(state->playerObj, 150.0f, 0);
        if (nearestBaddie != NULL && nearestBaddie->anim.romDefNo == TRICKY_CIRCLING_PRIORITY_ROMDEF) {
            target = nearestBaddie;
        } else {
            target = playerGetTargetObject(state->playerObj);
        }
        if (target != state->baddieAlertTarget || state->flameCommandPending != 0) {
            trickySetTargetPosition(state, &state->followObj->anim.worldPosX);
            state->substate = TRICKY_BADDIE_ALERT_GOTO;
        } else {
            GameObject** warpList = objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
            int warpIndex = 0;
            for (; warpIndex < warpCount; warpIndex++) {
                f32 warpToTarget = Vec_xzDistance(&warpList[warpIndex]->anim.worldPosX, &target->anim.worldPosX);
                f32 warpToPlayer =
                    Vec_xzDistance(&warpList[warpIndex]->anim.worldPosX, &state->playerObj->anim.worldPosX);
                f32 targetToPlayer = Vec_xzDistance(&target->anim.worldPosX, &state->playerObj->anim.worldPosX);
                if (warpToTarget + warpToPlayer > 2.0f * targetToPlayer) {
                    f32 warpToTricky = Vec_xzDistance(&warpList[warpIndex]->anim.worldPosX, &obj->anim.worldPosX);
                    if (warpToPlayer - warpToTricky > bestDetourSavings) {
                        bestDetourSavings = warpToPlayer - warpToTricky;
                        bestDetourWarp = warpList[warpIndex];
                    }
                }
            }
            {
                GameObject* baddieAlertWarp = state->baddieAlertWarp;
                if (baddieAlertWarp != NULL && (baddieAlertWarp->objectFlags & OBJECT_OBJFLAG_FREED)) {
                    state->baddieAlertWarp = NULL;
                    trickySetTargetPosition(state, &state->playerObj->anim.worldPosX);
                }
            }
            if (bestDetourWarp != NULL) {
                if (state->baddieAlertWarp == NULL) {
                    trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GET_MFOX, TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
                }
                if (state->baddieAlertWarp == NULL || state->baddieAlertWarp != bestDetourWarp) {
                    state->baddieAlertWarp = bestDetourWarp;
                    trickySetTargetPosition(state, &state->baddieAlertWarp->anim.worldPosX);
                }
            }
        }
        {
            u8 orbitMovementStatus;
            if (state->baddieAlertWarp != NULL) {
                orbitMovementStatus = trickyUpdateMovementState(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state);
            } else {
                orbitMovementStatus = trickyUpdateMovementState(obj, TRICKY_MAX_DISTANCE, state);
            }
            if (orbitMovementStatus != TRICKY_MOVEMENT_IN_PROGRESS) {
                trickyRequestIdleMove(obj, state);
            }
        }
        break;
    }
    }
}

static inline int trickyAcquireBaddieAlertTarget(TrickyState* state) {
    if ((state->followObj = trickyFindNearestUsableBaddie(state->playerObj, 150.0f, 0)) != NULL) {
        trickySetTargetPosition(state, &state->followObj->anim.worldPosX);
        return 1;
    }
    trickyResetCommandState(state);
    return 0;
}

void trickyGrowl(GameObject* obj, TrickyState* trickyState) {
    switch (trickyState->substate) {
    case TRICKYGROWL_WINDUP:
        trickyDebugPrint("GROWLAT_GOTO\n");
        if (trickyUpdateMovementState(obj, 30.0f, trickyState) == TRICKY_MOVEMENT_REACHED_TARGET) {
            trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GROWL, TRICKY_VOICE_MOUTH_ANGLE_SMALL);
            trickyState->substate = TRICKYGROWL_FACE_TARGET;
            trickyRequestMove(obj, TRICKY_ANIM_GROWL_WINDUP, TRICKY_LAND_MOVE_ANIM_RATE,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->flameCommandPending = 0;
        }
        break;
    case TRICKYGROWL_FACE_TARGET:
        trickyDebugPrint("GROWLAT_GROWLING\n");
        if (trickyState->stats->energy != 0 && trickyState->flameCommandPending != 0) {
            trickyState->substate = TRICKYGROWL_GOTO_FLAME;
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;
            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
            if (randomGetRange(0, 10) == 0) {
                trickyTryPlaySound(obj, TRICKY_VOICE_SFX_GROWL, TRICKY_VOICE_MOUTH_ANGLE_SMALL);
            }
        }
        break;
    case TRICKYGROWL_GOTO_FLAME:
        trickyDebugPrint("GROWLAT_GOTOFLAME\n");
        if (trickyUpdateMovementState(obj, TRICKY_GROWL_FLAME_RADIUS, trickyState) == TRICKY_MOVEMENT_REACHED_TARGET) {
            if ((u8)Obj_CanSetupObject() != 0) {
                trickySpawnFlameChildren(obj, trickyState);
            }
            trickyState->stats->energy--;
            trickyRequestMove(obj, TRICKY_ANIM_FLAME_ATTACK, TRICKY_LAND_MOVE_ANIM_RATE,
                              TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            trickyState->stateFlags |= TRICKY_STATE_FLAG_COMMAND_ACTIVE;
            trickyState->substate = TRICKYGROWL_FLAME;
            trickyState->flameCommandPending = 0;
        }
        break;
    case TRICKYGROWL_FLAME:
        trickyDebugPrint("GROWLAT_FLAME\n");
        if (obj->anim.currentMoveProgress >= TRICKY_FLAME_DONE_PROGRESS) {
            trickyStopFlameChildren(obj, trickyState);
            trickyResetCommandState(trickyState);
        } else {
            f32* target = ((TrickyState*)obj->extra)->targetPosPtr;
            trickyTurnTowardYaw(obj, getAngle(-(target[0] - obj->anim.worldPosX), -(target[2] - obj->anim.worldPosZ)));
        }
        break;
    }
}

/* DLL 0xFB pressureswitchfb (self-registers) */

int trickyShouldGoToWarpPoint(GameObject* tricky, TrickyState* state) {
    int result = 0;
    f32 pressureSwitchRadius = 40.0f;
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

/* DLL 0x100 trickywarp */

void tricky_stateGoToWarpPoint(GameObject* obj, TrickyState* state) {
    GameObject* selectedWarp;
    f32 playerRejectDistSq;
    f32 bestTrickyDistSq;
    f32 distSq;
    GameObject** warpList;
    int warpCount;
    int warpIndex;
    GameObject* bestWarp;

    selectedWarp = NULL;
    bestWarp = NULL;
    bestTrickyDistSq = TRICKY_MAX_DISTANCE;

    if (trickyShouldGoToWarpPoint(obj, state) == 0) {
        trickyResetCommandState(state);
        return;
    }

    warpList = objGetAllOfType(TRICKYWARP_OBJ_GROUP, &warpCount);
    warpIndex = 0;
    playerRejectDistSq = TRICKY_CLOSE_DISTANCE_SQ;
    for (; warpIndex < warpCount; warpIndex++) {
        distSq = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &warpList[warpIndex]->anim.worldPosX);
        if (distSq > playerRejectDistSq) {
            distSq = getXZDistanceSquared(&obj->anim.worldPosX, &warpList[warpIndex]->anim.worldPosX);
            if (distSq < bestTrickyDistSq) {
                bestWarp = warpList[warpIndex];
                bestTrickyDistSq = distSq;
            }
        }
    }

    selectedWarp = bestWarp;
    if (selectedWarp != NULL) {
        state->followObj = selectedWarp;
        trickySetTargetPosition(state, &selectedWarp->anim.worldPosX);
        if (trickyUpdateMovementState(obj, 15.0f, state) == TRICKY_MOVEMENT_IN_PROGRESS) {
            return;
        }
    }

    trickyRequestIdleMove(obj, state);
}

void trickyUpdateApproachSpeed(GameObject* obj, f32 stoppingRadius, TrickyState* state, f32* targetPos,
                               u8 slowWhenFacingAway) {
    S16Vec rotation;
    f32 targetDelta[3];
    f32 decelerationStep;
    f32 deltaTime;
    f32 projectedSpeed;
    f32 stoppingDistance;
    f32 stoppingDistanceSq;
    f32 targetDistanceSq;
    f32 candidateSpeed;

    stoppingDistance = 0.05f;
    projectedSpeed = state->speed;
    decelerationStep = deltaTime = timeDelta;
    decelerationStep = TRICKY_SPEED_DECAY_STEP * decelerationStep;
    while (projectedSpeed > 0.0f) {
        stoppingDistance = projectedSpeed * deltaTime + stoppingDistance;
        projectedSpeed = projectedSpeed + decelerationStep;
    }
    stoppingDistance = stoppingRadius + stoppingDistance;
    stoppingDistanceSq = stoppingDistance;
    stoppingDistanceSq *= stoppingDistanceSq;
    targetDistanceSq = getXZDistanceSquared(targetPos, &obj->anim.worldPosX);
    if (targetDistanceSq < stoppingDistanceSq) {
        candidateSpeed = state->speed;
        candidateSpeed = candidateSpeed + TRICKY_SPEED_DECAY_STEP * timeDelta;
        state->speed = (candidateSpeed < 0.0f) ? 0.0f : candidateSpeed;
        return;
    }
    if (slowWhenFacingAway != 0) {
        targetDelta[0] = targetPos[0] - obj->anim.worldPosX;
        targetDelta[1] = targetPos[1] - obj->anim.worldPosY;
        targetDelta[2] = targetPos[2] - obj->anim.worldPosZ;
        rotation.x = -obj->anim.rotX;
        rotation.y = 0;
        rotation.z = 0;
        vecRotateZXY(&rotation.x, targetDelta);
        if (targetDelta[2] > 0.0f) {
            candidateSpeed = state->speed;
            candidateSpeed = candidateSpeed + TRICKY_SPEED_DECAY_STEP * timeDelta;
            state->speed = (candidateSpeed < 0.0f) ? 0.0f : candidateSpeed;
            return;
        }
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_TURNING) != 0) {
        state->speed = -0.01f * timeDelta + state->speed;
        if (state->speed < 0.0f) {
            state->speed = 0.0f;
        }
        return;
    }
    {
        f32 targetSpeedMatchRadius = 5.0f + stoppingDistance;
        f32 targetSpeedMatchRadiusSq = targetSpeedMatchRadius * targetSpeedMatchRadius;
        candidateSpeed = trickyGetTargetDistanceRate(obj);
        if (targetDistanceSq < targetSpeedMatchRadiusSq) {
            if (candidateSpeed > 0.0f) {
                f32 curSpeed = state->speed;
                if (candidateSpeed < curSpeed) {
                    f32 step = TRICKY_SPEED_DECAY_STEP * timeDelta + curSpeed;
                    state->speed = (step < candidateSpeed) ? candidateSpeed : step;
                    return;
                } else {
                    f32 step;
                    if (candidateSpeed > TRICKY_FOLLOW_MAX_SPEED) {
                        step = TRICKY_SMALL_SPEED_STEP * timeDelta + curSpeed;
                        state->speed = (step > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : step;
                        return;
                    }
                    step = TRICKY_SMALL_SPEED_STEP * timeDelta + curSpeed;
                    state->speed = (step > candidateSpeed) ? candidateSpeed : step;
                    return;
                }
            }
        }
    }
    if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) != 0) {
        f32 speed = 0.02f * timeDelta + state->speed;
        state->speed = speed;
        speed = state->speed;
        if (speed > TRICKY_FOLLOW_MAX_SPEED) {
            state->speed = TRICKY_FOLLOW_MAX_SPEED;
        }
        return;
    }
    {
        f32 step = state->speed;
        step = step + TRICKY_SMALL_SPEED_STEP * timeDelta;
        state->speed = (step > TRICKY_FOLLOW_MAX_SPEED) ? TRICKY_FOLLOW_MAX_SPEED : step;
    }
}

static inline int trickyGetRouteTurnMagnitude(s16 previousYaw, s16 routeYaw) {
    s16 yawDelta = previousYaw - (u16)routeYaw;
    if (yawDelta > TRICKY_YAW_HALF_TURN) {
        yawDelta = yawDelta - TRICKY_YAW_WRAP_RANGE;
    }
    if (yawDelta < -TRICKY_YAW_HALF_TURN) {
        yawDelta = yawDelta + TRICKY_YAW_WRAP_RANGE;
    }
    if (yawDelta > TRICKY_YAW_QUARTER_TURN) {
        yawDelta -= TRICKY_YAW_HALF_TURN;
    } else if (yawDelta < -TRICKY_YAW_QUARTER_TURN) {
        yawDelta += TRICKY_YAW_HALF_TURN;
    }
    return (yawDelta >= 0) ? yawDelta : -yawDelta;
}

static inline void trickyTurnAlongMoveDirection(GameObject* obj) {
    TrickyState* state = obj->extra;
    f32 dx, dz;
    f32 dxSq, dzSq;

    dx = state->moveVector.x;
    dxSq = dx;
    dxSq *= dxSq;
    dz = state->moveVector.z;
    dzSq = dz;
    dzSq *= dzSq;
    if (dxSq + dzSq > 0.01f) {
        trickyTurnTowardYaw(obj, (s16)getAngle(-dx, -dz));
    }
}

static inline void trickySetDirectionAlongRoute(GameObject* obj, TrickyState* state) {
    RomCurveDef* node = state->route.currentNode;
    f32 length;
    f32 dxSq;
    f32 dzSq;

    state->moveVector.x = node->x - obj->anim.worldPosX;
    state->moveVector.z = node->z - obj->anim.worldPosZ;
    dxSq = state->moveVector.x * state->moveVector.x;
    dzSq = state->moveVector.z * state->moveVector.z;
    length = sqrtf(dxSq + dzSq);
    if (0.0f != length) {
        state->moveVector.x /= length;
        state->moveVector.z /= length;
    }
}

static inline void trickyRestoreRecoveryPosition(GameObject* obj, TrickyState* state) {
    (*gPathControlInterface)->attachObject(obj, &state->curvesCollision);
    obj->anim.localPosX = state->recoveryPos.x;
    obj->anim.localPosY = state->recoveryPos.y;
    obj->anim.localPosZ = state->recoveryPos.z;
    obj->anim.worldPosX = state->recoveryPos.x;
    obj->anim.worldPosY = state->recoveryPos.y;
    obj->anim.worldPosZ = state->recoveryPos.z;
    ObjHits_SyncObjectPosition(obj);
}

static inline void trickyInvalidatePatchCache(TrickyState* state) {
    int patchIndex;

    state->stateFlags &= ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
    for (patchIndex = 0; patchIndex < OBJFSA_PATCHGROUP_PATCH_COUNT; patchIndex++) {
        state->cachedPatchGroups[patchIndex] = 0;
    }
}

static inline void trickyPrepareRouteJump(GameObject* obj, TrickyState* state) {
    trickySetDirectionAlongRoute(obj, state);
    state->speed = TRICKY_FOLLOW_MAX_SPEED;
    trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMP_PREP, TRICKY_TINY_MOVE_ANIM_RATE,
                      TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
    state->movementState = TRICKY_MOVE_JUMP_PREP;
    state->movementBarkTimer = 600.0f;
}

static inline void trickyStartRouteJumpUp(GameObject* obj, TrickyState* state) {
    trickySetDirectionAlongRoute(obj, state);
    if ((int)randomGetRange(0, 1) != 0) {
        trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPUP_FAST, TRICKY_FOLLOW_JUMPUP_FAST_ANIM_RATE,
                          TRICKY_MOVE_FLAG_JUMP_ARC);
    } else {
        trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPUP_SLOW, TRICKY_FOLLOW_JUMPUP_SLOW_ANIM_RATE,
                          TRICKY_MOVE_FLAG_JUMP_ARC);
    }
    state->verticalDelta = (state->route.currentNode->y - obj->anim.worldPosY) / TRICKY_FOLLOW_JUMPUP_VERTICAL_DIVISOR;
    state->movementState = TRICKY_MOVE_JUMPUP;
    trickyAdvanceToSegmentEnd(&state->route);
    state->movementBarkTimer = 600.0f;
}

static inline void trickyStartRouteJumpDown(GameObject* obj, TrickyState* state) {
    trickySetDirectionAlongRoute(obj, state);
    trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMPDOWN, TRICKY_FOLLOW_JUMPDOWN_ANIM_RATE, TRICKY_MOVE_FLAG_JUMP_ARC);
    state->verticalDelta =
        (obj->anim.worldPosY - state->route.currentNode->y) / TRICKY_FOLLOW_JUMPDOWN_VERTICAL_DIVISOR;
    state->movementState = TRICKY_MOVE_JUMPDOWN;
    trickyAdvanceToSegmentEnd(&state->route);
    state->movementBarkTimer = 600.0f;
}

int trickyUpdateMovementState(GameObject* obj, f32 stoppingRadius, TrickyState* state) {
    u16 targetPatchGroup;
    RomCurveDef* routeNode;
    f32* target;
    int objectWalkGroup;
    int targetWalkGroup;
    u8 moveResult = TRICKY_MOVEMENT_IN_PROGRESS;
    RomCurveDef* prevNode;
    u32 patchGroupForCheck;
    u8 reverseDirection;
    int routeDirection;
    int i;
    u8 patchSlot;
    f32* patchTarget;
    u16 walkGroupLink;
    u8 patchMaskBit;
    f32 speed;
    f32 dist;
    u8 walkGroupPair[2];
    u8 routeDirections[TRICKY_ROUTE_CANDIDATE_COUNT];
    S16Vec rotation;
    f32 delta[3];
    ObjfsaWalkGroupPatchInfo patchInfo;
    RomCurveDef* routePtrs[TRICKY_ROUTE_CANDIDATE_COUNT];

    if ((state->movementState < 5) && (isInWalkGroupOrPatch(&obj->anim.worldPosX) == 0)) {
        trickyRestoreRecoveryPosition(obj, state);
    }
    target = state->targetPosPtr;
    objectWalkGroup = Objfsa_GetWalkGroupIndexAtPoint(&obj->anim.worldPosX, 0);
    if ((objectWalkGroup != 0) && (state->lastWalkGroup != objectWalkGroup)) {
        state->lastWalkGroup = objectWalkGroup;
        trickyInvalidatePatchCache(state);
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
    trickyDebugPrint("tricky wg %d->%d target wg %d, dest wg %d\n", state->lastWalkGroup, objectWalkGroup,
                     targetWalkGroup, state->walkGroup);
    if (state->lastWalkGroup == 0) {
        trickyReportError("tricky last walk group is zero. Has he been loaded within a walk group? %f %f %f\n",
                          obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ);
    }
    speed = state->speed;
    trickyUpdateApproachSpeed(obj, stoppingRadius, state, target, 0);
    trickyDebugPrint("velbefore %f, vel now %f\n", speed, state->speed);
    if (targetWalkGroup == state->lastWalkGroup) {

        state->stateFlags |= TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
        for (i = 0, patchMaskBit = 1; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++, patchMaskBit <<= 1) {
            if (patchInfo.patchMask & patchMaskBit) {
                state->cachedPatchGroups[i] = patchInfo.patchGroupIds[i];
                state->cachedPatchPositions[i].x = target[0];
                state->cachedPatchPositions[i].y = target[1];
                state->cachedPatchPositions[i].z = target[2];
            }
        }
    }
    if ((targetWalkGroup != 0) && (targetWalkGroup == state->lastWalkGroup)) {
        state->linkedPatchGroup = 0;
    } else {
        u16 patchGroupProduct;

        /* Retail multiplies indices, although Hcurves packs patch IDs into two bytes. */
        patchGroupProduct = targetWalkGroup * state->lastWalkGroup;
        if (patchGroupProduct != 0) {
            for (i = 0; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++) {
                if ((patchGroupProduct == patchInfo.patchGroupIds[i]) && (((1 << i) & patchInfo.patchMask) != 0)) {
                    state->linkedPatchGroup = patchGroupProduct;
                    state->linkedPatchPos.x = target[0];
                    state->linkedPatchPos.y = target[1];
                    state->linkedPatchPos.z = target[2];
                }
            }
        }
    }
    if (isInWalkGroupOrPatch(target) != 0) {
        trickyDebugPrint("target is within a walkGroup or its patch\n");
    } else {
        trickyDebugPrint("target is not within a walkGroup or any patches\n");
    }
    trickyDebugPrint("target is within patch group %d\n", getPatchGroup(target, state->lastWalkGroup));
    if ((state->stateFlags & TRICKY_STATE_FLAG_PATH_PATCHES_VALID) != 0) {
        int slotIdx;

        for (slotIdx = 0; slotIdx < OBJFSA_PATCHGROUP_PATCH_COUNT; slotIdx++) {
            if (state->cachedPatchGroups[slotIdx] != 0) {
                trickyDebugPrint("Patch %d: Last xyz %f %f %f\n", slotIdx, state->cachedPatchPositions[slotIdx].x,
                                 state->cachedPatchPositions[slotIdx].y, state->cachedPatchPositions[slotIdx].z);
            }
        }
    }
    if (state->linkedPatchGroup != 0) {
        trickyDebugPrint("Last Patch Point %f %f %f\n", state->linkedPatchPos.x, state->linkedPatchPos.y,
                         state->linkedPatchPos.z);
    }
    {
        u16 trickyPatch;

        targetPatchGroup = getPatchGroup(target, state->lastWalkGroup);
        trickyPatch = getPatchGroup(&obj->anim.worldPosX, state->lastWalkGroup);
        if ((targetWalkGroup != 0) && (objectWalkGroup == targetWalkGroup)) {
            state->movementState = TRICKY_MOVE_WALK_FREE;
        } else {
            walkGroupLink = Objfsa_GetWalkGroupIndexForMove(&obj->anim.worldPosX, target, state->lastWalkGroup);
            if (walkGroupLink != 0) {
                state->movementState = TRICKY_MOVE_WALK_FREE;
                if (walkGroupLink != state->lastWalkGroup) {
                    state->lastWalkGroup = walkGroupLink;
                    trickyInvalidatePatchCache(state);
                }
            } else if (state->movementState < 5) {
                int i;

                if (targetPatchGroup != 0) {
                    if (targetWalkGroup == 0) {
                        if (objectWalkGroup != 0) {
                            for (i = 0; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++) {
                                if (state->cachedPatchGroups[i] == targetPatchGroup) {
                                    patchSlot = i;
                                    state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                    break;
                                }
                            }
                            if (i == OBJFSA_PATCHGROUP_PATCH_COUNT) {
                                if (targetPatchGroup & (state->cachedWalkGroup == 0xff)) {
                                    state->walkGroup = (targetPatchGroup & 0xff00) >> 8;
                                } else {
                                    state->walkGroup = targetPatchGroup & 0xff;
                                }
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            if (trickyPatch != 0) {
                                for (i = 0; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++) {
                                    if (state->cachedPatchGroups[i] == trickyPatch) {
                                        /* Retail overwrites the group here, leaving patchSlot uninitialized. */
                                        trickyPatch = i;
                                        state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                        break;
                                    }
                                }
                                if (i == OBJFSA_PATCHGROUP_PATCH_COUNT) {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, trickyPatch);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                trickyReportError("Tricky is neither in a walkgroup or in a patch\n");
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    } else {
                        if (objectWalkGroup != 0) {
                            for (i = 0; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++) {
                                if (state->cachedPatchGroups[i] == targetPatchGroup) {
                                    patchSlot = i;
                                    state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                    break;
                                }
                            }
                            if (i == OBJFSA_PATCHGROUP_PATCH_COUNT) {
                                state->movementState = TRICKY_MOVE_CURVE_SETUP;
                            }
                        } else {
                            if (objectWalkGroup == 0 &&
                                (targetPatchGroup = getPatchGroup(&obj->anim.worldPosX, state->lastWalkGroup)) != 0) {
                                if (state->linkedPatchGroup == targetPatchGroup) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, targetPatchGroup);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                patchGroupForCheck = targetPatchGroup;
                                i = isPointWithinPatchGroup(&obj->anim.worldPosX, state->lastWalkGroup,
                                                            patchGroupForCheck);
                                trickyReportError("tricky error, target patch %d, targetWalkGroup %d, trickyWalkGroup "
                                                  "%d, tricky last walkGroup %d, tricky in patch %d\n",
                                                  patchGroupForCheck, targetWalkGroup, objectWalkGroup,
                                                  state->lastWalkGroup, i);
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
                            int patchGroup;
                            if (isPointWithinPatchGroup(&obj->anim.worldPosX, state->lastWalkGroup,
                                                        (patchGroup = (u16)(targetWalkGroup * objectWalkGroup))) != 0) {
                                if (state->linkedPatchGroup == patchGroup) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    state->movementState = TRICKY_MOVE_CURVE_SETUP;
                                }
                            } else {
                                for (i = 0; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++) {
                                    if (state->cachedPatchGroups[i] == patchGroup) {
                                        patchSlot = i;
                                        state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                        break;
                                    }
                                }
                                if ((i == OBJFSA_PATCHGROUP_PATCH_COUNT) || (patchGroup != state->linkedPatchGroup)) {
                                    state->movementState = TRICKY_MOVE_CURVE_SETUP;
                                }
                            }
                        } else {
                            u16 p = getPatchGroup(&obj->anim.worldPosX, state->lastWalkGroup);
                            if (p != 0) {
                                if (targetWalkGroup == state->lastWalkGroup) {
                                    for (i = 0; i < OBJFSA_PATCHGROUP_PATCH_COUNT; i++) {
                                        if (state->cachedPatchGroups[i] == p) {
                                            patchSlot = i;
                                            state->movementState = TRICKY_MOVE_WALK_START_PATCH;
                                            break;
                                        }
                                    }
                                    if (i == OBJFSA_PATCHGROUP_PATCH_COUNT) {
                                        Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, p);
                                        state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                    }
                                } else if (state->linkedPatchGroup == p) {
                                    state->movementState = TRICKY_MOVE_WALK_END_PATCH;
                                } else {
                                    Objfsa_GetNearestPatchExit(target, &state->patchExitPos.x, p);
                                    state->movementState = TRICKY_MOVE_WALK_PATCH_EXIT;
                                }
                            } else {
                                trickyReportError("tricky error 2!!!!!\n");
                                state->movementState = TRICKY_MOVE_WALK_WAIT;
                            }
                        }
                    }
                }
            }
        }
    }
    if (state->movementState < 5) {
        state->stateFlags &= ~TRICKY_STATE_FLAG_GROUND_SNAP;
    }
    trickyDebugPrint("movement state is %d\n", state->movementState);
    switch (state->movementState) {
        char routeNodeType;
        RomCurveDef* node;
    case TRICKY_MOVE_WALK_WAIT:
        trickyDebugPrint("walk wait\n");
        state->speed = trickyDecelerate(speed, 0.0f);
        if (0.0f == state->speed) {
            moveResult = TRICKY_MOVEMENT_REACHED_TARGET;
        } else {
            moveResult = moveTricky(obj, target);
        }
        break;
    case TRICKY_MOVE_WALK_FREE:
        trickyDebugPrint("walk free\n");
        moveResult = moveTricky(obj, target);
        break;
    case TRICKY_MOVE_WALK_START_PATCH:
        trickyDebugPrint("walk start patch\n");
        state->speed = speed;
        trickyUpdateApproachSpeed(obj, 0.0f, state, patchTarget = &state->cachedPatchPositions[patchSlot].x, 1);
        moveResult = moveTricky(obj, patchTarget);
        break;
    case TRICKY_MOVE_WALK_PATCH_EXIT:
        trickyDebugPrint("walk patch exit\n");
        state->speed = speed;
        moveResult = trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->patchExitPos.x);
        break;
    case TRICKY_MOVE_WALK_END_PATCH:
        trickyDebugPrint("walk end patch\n");
        state->speed = speed;
        moveResult = trickyApproachTarget(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->linkedPatchPos.x);
        break;
    case TRICKY_MOVE_WALK_TO_NODE:
        trickyDebugPrint("walk to node %d %d\n", 10,
                         (int)getXZDistanceSquared(&state->routeSeedNode->x, &obj->anim.worldPosX));
        dist = getXZDistanceSquared(&state->routeSeedNode->x, &obj->anim.worldPosX);
        if (10.0f > dist) {
            state->route.reverse = state->routeSeedDirection;
            prevNode = state->routeSeedNode;
            node = trickySelectRouteEntry(state, prevNode, state->routeSeedDirection);
            if (node == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurveDef* nextNode = trickySelectRouteEntry(state, node, state->routeSeedDirection);
                if (nextNode == 0) {
                    state->movementState = TRICKY_MOVE_WALK_WAIT;
                } else {
                    RomCurve_setupHermiteSegment(&state->route, prevNode, node, nextNode);
                    RomCurve_stepClamped(&state->route, 0.1f);
                    {
                        s16 previousYaw = getAngle(state->prevLocalPos.x - obj->anim.localPosX,
                                                   state->prevLocalPos.z - obj->anim.localPosZ);
                        s16 routeYaw = getAngle(state->prevLocalPos.x - state->route.posX,
                                                state->prevLocalPos.z - state->route.posZ);
                        if (trickyGetRouteTurnMagnitude(previousYaw, routeYaw) > TRICKY_ROUTE_TURN_SLOWDOWN_ANGLE) {
                            state->speed = speed;
                            trickyUpdateApproachSpeed(obj, 2.5f, state, &state->route.posX, 1);
                        }
                    }
                    trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
                    moveResult = moveTricky(obj, &state->route.posX);
                    switch (prevNode->subtype) {
                    case ROMCURVE_TRICKY_SUBTYPE_JUMP:
                        trickyPrepareRouteJump(obj, state);
                        break;
                    case ROMCURVE_TRICKY_SUBTYPE_JUMPUP:
                        trickyStartRouteJumpUp(obj, state);
                        break;
                    case ROMCURVE_TRICKY_SUBTYPE_JUMPDOWN:
                        trickyStartRouteJumpDown(obj, state);
                        break;
                    case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_A:
                    case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_B:
                        state->stateFlags |= TRICKY_STATE_FLAG_GROUND_SNAP;
                    default:
                        state->movementState = TRICKY_MOVE_WALK_NODES;
                    }
                }
            }
        } else {
            node = trickyValidateRouteEntry(state->routeSeedNode);
            if ((node != 0) || (objectWalkGroup == 0)) {
                state->speed = speed;
                trickyUpdateApproachSpeed(obj, 2.5f, state, &state->routeSeedNode->x, 1);
                moveResult = moveTricky(obj, &state->routeSeedNode->x);
            } else {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            }
        }
        break;
    case TRICKY_MOVE_CURVE_SETUP:
        trickyDebugPrint("curve setup\n");
        trickyRankLinkedRouteCandidates(obj, routeDirections, (s16)objectWalkGroup, routePtrs);
        i = trickyFindReachableRouteIndex(state, routePtrs, routeDirections, state->walkGroup);
        if (i == -1) {
            state->speed = speed;
            return TRICKY_MOVEMENT_BLOCKED;
        }
        state->routeSeedDirection = routeDirections[i];
        state->routeSeedNode = routePtrs[i];
        state->speed = speed;
        trickyUpdateApproachSpeed(obj, TRICKY_DEFAULT_STOPPING_RADIUS, state, &state->routeSeedNode->x, 1);
        moveResult = moveTricky(obj, &state->routeSeedNode->x);
        state->movementState = TRICKY_MOVE_WALK_TO_NODE;
        break;
    case TRICKY_MOVE_WALK_NODES:
        trickyDebugPrint("walk nodes\n");
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            state->speed = trickyDecelerate(speed, 0.0f);
        }
        routeNode = state->route.currentNode;
        if ((state->route.previousNode->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B) &&
            (routeNode->subtype != ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B)) {
            u8 searchPass;
            u8 linkIndex;
            s8 searchResult;
            f32* targetPos = state->targetPosPtr;
            delta[0] = targetPos[0] - obj->anim.worldPosX;
            delta[1] = targetPos[1] - obj->anim.worldPosY;
            delta[2] = targetPos[2] - obj->anim.worldPosZ;
            rotation.x = -obj->anim.rotX;
            rotation.y = 0;
            rotation.z = 0;
            vecRotateZXY(&rotation.x, delta);
            if ((delta[2] > 0.0f) && (0.0f != state->speed)) {
                for (linkIndex = 0; linkIndex < ROMCURVE_LINK_COUNT; linkIndex++) {
                    u8 linkWalkGroup = routeNode->linkWalkGroups[linkIndex];
                    if (linkWalkGroup == state->walkGroup) {
                        break;
                    }
                }
                if (linkIndex == ROMCURVE_LINK_COUNT) {
                    pathSearchBegin(&state->candidateSearches[0], state->route.nextNode, state->targetPosPtr,
                                    state->walkGroup, state->route.reverse);
                    pathSearchBegin(&state->candidateSearches[1], state->route.previousNode, state->targetPosPtr,
                                    state->walkGroup, state->route.reverse ^ 1);
                    searchResult = PATH_SEARCH_PENDING;
                    searchPass = 0;
                    while (++searchPass < 100 && searchResult != PATH_SEARCH_REACHED_TARGET) {
                        searchResult = pathSearchStep(&state->candidateSearches[0], 1);
                        if (searchResult != PATH_SEARCH_REACHED_TARGET) {
                            searchResult = pathSearchStep(&state->candidateSearches[1], 1);
                            switch (searchResult) {
                            case PATH_SEARCH_PENDING:
                                break;
                            case PATH_SEARCH_REACHED_TARGET:
                                reverseDirection = state->route.reverse ^ 1;
                                if (reverseDirection == 0) {
                                    RomCurve_stepClamped(&state->route, 2.0f);
                                } else {
                                    RomCurve_stepClamped(&state->route, TRICKY_ROUTE_REVERSE_STEP);
                                }
                                state->route.reverse = reverseDirection;
                                RomCurve_swapEndpointNodes(&state->route);
                                break;
                            case PATH_SEARCH_EXHAUSTED:
                                /* End this direction probe even without a path. */
                                searchResult = 1;
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
            node = trickySelectRouteEntry(state, state->route.nextNode, routeDirection);
            if (node != 0) {
                RomCurve_advanceToNextSegment(&state->route, node);
                routeNodeType = state->route.previousNode->subtype;
                switch (routeNodeType) {
                case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_A:
                case ROMCURVE_TRICKY_SUBTYPE_GROUND_SNAP_B: {
                    u32 stateFlags = state->stateFlags;
                    if ((stateFlags & TRICKY_STATE_FLAG_GROUND_SNAP) != 0) {
                        state->stateFlags &= ~TRICKY_STATE_FLAG_GROUND_SNAP;
                    } else {
                        state->stateFlags = stateFlags | TRICKY_STATE_FLAG_GROUND_SNAP;
                    }
                    break;
                }
                }
            } else {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
                break;
            }
        } else {
            node = trickySelectRouteEntry(state, state->route.currentNode, routeDirection);
            if (node == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
                break;
            }
            if (node != state->route.nextNode) {
                RomCurve_setSegmentEndNode(&state->route, node);
            }
        }
        if ((state->savedWalkGroup == 0) || (objectWalkGroup != state->savedWalkGroup)) {
            s16 previousYaw =
                getAngle(state->prevLocalPos.x - obj->anim.localPosX, state->prevLocalPos.z - obj->anim.localPosZ);
            s16 routeYaw =
                getAngle(state->prevLocalPos.x - state->route.posX, state->prevLocalPos.z - state->route.posZ);
            if (trickyGetRouteTurnMagnitude(previousYaw, routeYaw) > TRICKY_ROUTE_TURN_SLOWDOWN_ANGLE) {
                state->speed = speed;
                trickyUpdateApproachSpeed(obj, 2.5f, state, &state->route.posX, 1);
            }
        }
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveResult = moveTricky(obj, &state->route.posX);
        routeNodeType = state->route.currentNode->subtype;
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
        trickyDebugPrint("Jump run up\n");
        state->speed = trickyAccelerate(speed, TRICKY_FOLLOW_MAX_SPEED);
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            state->speed = trickyDecelerate(speed, 0.0f);
        }
        {
            s16 previousYaw =
                getAngle(state->prevLocalPos.x - obj->anim.localPosX, state->prevLocalPos.z - obj->anim.localPosZ);
            s16 routeYaw =
                getAngle(state->prevLocalPos.x - state->route.posX, state->prevLocalPos.z - state->route.posZ);
            if (trickyGetRouteTurnMagnitude(previousYaw, routeYaw) > TRICKY_ROUTE_TURN_SLOWDOWN_ANGLE) {
                state->speed = speed;
                trickyUpdateApproachSpeed(obj, 2.5f, state, &state->route.posX, 1);
            }
        }
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            RomCurveDef* nextRouteNode = trickySelectRouteEntry(state, state->route.nextNode, routeDirection);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                trickyPrepareRouteJump(obj, state);
            }
        }
        break;
    case TRICKY_MOVE_JUMP_PREP:
        trickyDebugPrint("Jump prep\n");
        if ((u8)(state->stateFlags & TRICKY_STATE_FLAG_TURNING)) {
            speed = -0.01f * timeDelta + speed;
            if (speed < 0.0f) {
                speed = 0.0f;
            }
        } else if (speed > TRICKY_FOLLOW_ARC_SPEED) {
            speed = trickyDecelerate(speed, TRICKY_FOLLOW_ARC_SPEED);
        } else {
            speed = trickyAccelerate(speed, TRICKY_FOLLOW_ARC_SPEED);
        }
        state->speed = speed;
        trickyTurnAlongMoveDirection(obj);
        if (obj->anim.currentMoveProgress < TRICKY_FOLLOW_ARC_HALF_PROGRESS) {
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed, &state->animRate);
            obj->anim.localPosX = timeDelta * (state->moveVector.x * state->speed) + obj->anim.localPosX;
            obj->anim.localPosZ = timeDelta * (state->moveVector.z * state->speed) + obj->anim.localPosZ;
        } else {
            f32 speedScale = 0.25f;
            ObjAnim_SampleRootCurvePhase(&obj->anim, state->speed * speedScale, &state->animRate);
            obj->anim.localPosX = timeDelta * (state->moveVector.x * (state->speed * speedScale)) + obj->anim.localPosX;
            obj->anim.localPosZ = timeDelta * (state->moveVector.z * (state->speed * speedScale)) + obj->anim.localPosZ;
        }
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            f32 horizontalDistance;
            f32 xDistanceSq;
            f32 componentDelta;
            f32 duration;
            TrickyJumpArc* arc = &state->jumpArc;
            RomCurveDef* landNode = state->route.currentNode;
            componentDelta = landNode->x - obj->anim.worldPosX;
            xDistanceSq = componentDelta * componentDelta;
            componentDelta = landNode->z - obj->anim.worldPosZ;
            componentDelta = componentDelta * componentDelta;
            horizontalDistance = sqrtf(xDistanceSq + componentDelta);
            arc->duration = horizontalDistance / TRICKY_FOLLOW_ARC_SPEED;
            arc->time = 0.0f;
            arc->baseX = obj->anim.worldPosX;
            arc->baseY = obj->anim.worldPosY;
            arc->baseZ = obj->anim.worldPosZ;
            arc->landX = landNode->x;
            arc->landZ = landNode->z;
            duration = arc->duration;
            arc->initialVelocityY =
                -(TRICKY_FOLLOW_ARC_COEFFICIENT * duration * duration - (landNode->y - obj->anim.worldPosY)) / duration;
            trickyRequestMove(obj, TRICKY_ANIM_FOLLOW_JUMP, 0.0f, TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION);
            state->arcMoveProgress = arc->time / arc->duration;
            state->speed = TRICKY_FOLLOW_ARC_SPEED;
            state->movementState = TRICKY_MOVE_JUMPING;
            trickyAdvanceToSegmentEnd(&state->route);
        }
        break;
    case TRICKY_MOVE_JUMPING: {
        TrickyJumpArc* arc = &state->jumpArc;
        f32 duration;
        f32 elapsedTime;
        trickyDebugPrint("Jumping\n");
        arc->time = arc->time + timeDelta;
        if (arc->time >= arc->duration) {
            obj->anim.localPosY = state->route.currentNode->y;
            state->arcMoveProgress = 1.0f;
            state->movementState = TRICKY_MOVE_WALK_NODES;
        } else {
            f32 baseX = arc->baseX;
            f32 baseZ;
            obj->anim.localPosX = (arc->landX - baseX) * (arc->time / arc->duration) + baseX;
            elapsedTime = arc->time;
            obj->anim.localPosY = TRICKY_FOLLOW_ARC_COEFFICIENT * elapsedTime * elapsedTime +
                                  (arc->initialVelocityY * elapsedTime + arc->baseY);
            baseZ = arc->baseZ;
            obj->anim.localPosZ = (arc->landZ - baseZ) * (arc->time / arc->duration) + baseZ;
            duration = arc->duration;
            if (duration <= TRICKY_FOLLOW_ARC_PROGRESS_WINDOW) {
                state->arcMoveProgress = arc->time / duration;
            } else {
                f32 progressTime = arc->time;
                if (progressTime <= TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    state->arcMoveProgress = progressTime / TRICKY_FOLLOW_ARC_PROGRESS_WINDOW;
                } else if (progressTime >= duration - TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) {
                    f32 landingTimeOffset;
                    landingTimeOffset = TRICKY_FOLLOW_ARC_PROGRESS_WINDOW - duration;
                    state->arcMoveProgress = (landingTimeOffset + progressTime) / TRICKY_FOLLOW_ARC_PROGRESS_WINDOW;
                } else {
                    f32 middleProgress = (progressTime - TRICKY_FOLLOW_ARC_ENDPOINT_WINDOW) /
                                         (duration - TRICKY_FOLLOW_ARC_MIDDLE_WINDOW);
                    state->arcMoveProgress = TRICKY_FOLLOW_ARC_QUARTER_PROGRESS + middleProgress / 2.0f;
                }
            }
            Obj_SetParent(obj, NULL, 0);
            state->curvesCollision.subtype = CURVES_COLLISION_SUBTYPE_NONE;
        }
        break;
    }
    case TRICKY_MOVE_JUMPUP_RUNUP:
        trickyDebugPrint("Jump up run up\n");
        state->speed = trickyAccelerate(speed, TRICKY_FOLLOW_MAX_SPEED);
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            state->speed = trickyDecelerate(speed, 0.0f);
        }
        {
            s16 previousYaw =
                getAngle(state->prevLocalPos.x - obj->anim.localPosX, state->prevLocalPos.z - obj->anim.localPosZ);
            s16 routeYaw =
                getAngle(state->prevLocalPos.x - state->route.posX, state->prevLocalPos.z - state->route.posZ);
            if (trickyGetRouteTurnMagnitude(previousYaw, routeYaw) > TRICKY_ROUTE_TURN_SLOWDOWN_ANGLE) {
                state->speed = speed;
                trickyUpdateApproachSpeed(obj, 2.5f, state, &state->route.posX, 1);
            }
        }
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            RomCurveDef* nextRouteNode = trickySelectRouteEntry(state, state->route.nextNode, routeDirection);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                trickyStartRouteJumpUp(obj, state);
            }
        }
        break;
    case TRICKY_MOVE_JUMPUP:
    case TRICKY_MOVE_JUMPDOWN:
        trickyDebugPrint("JUMPDOWN or JUMPUP\n");
        state->curvesCollision.subtype = CURVES_COLLISION_SUBTYPE_NONE;
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        trickyTurnAlongMoveDirection(obj);
        if ((state->stateFlags & TRICKY_STATE_FLAG_MOVE_ENDED) != 0) {
            state->speed = TRICKY_FOLLOW_JUMP_LAND_SPEED;
            moveTricky(obj, &state->route.posX);
            state->movementState = TRICKY_MOVE_WALK_NODES;
        }
        break;
    case TRICKY_MOVE_JUMPDOWN_RUNUP:
        trickyDebugPrint("JUMPDOWN_RUNUP\n");
        state->speed = trickyAccelerate(speed, TRICKY_FOLLOW_MAX_SPEED);
        if ((state->savedWalkGroup != 0) && (objectWalkGroup == state->savedWalkGroup)) {
            state->speed = trickyDecelerate(speed, 0.0f);
        }
        {
            s16 previousYaw =
                getAngle(state->prevLocalPos.x - obj->anim.localPosX, state->prevLocalPos.z - obj->anim.localPosZ);
            s16 routeYaw =
                getAngle(state->prevLocalPos.x - state->route.posX, state->prevLocalPos.z - state->route.posZ);
            if (trickyGetRouteTurnMagnitude(previousYaw, routeYaw) > TRICKY_ROUTE_TURN_SLOWDOWN_ANGLE) {
                state->speed = speed;
                trickyUpdateApproachSpeed(obj, 2.5f, state, &state->route.posX, 1);
            }
        }
        trickyAdvanceRouteTargetAhead(obj, &state->route, state->speed);
        moveTricky(obj, &state->route.posX);
        routeDirection = state->route.reverse;
        if (((routeDirection == 0) && (state->route.atSegmentEnd != 0)) ||
            ((routeDirection != 0 && (state->route.atSegmentEnd == 0)))) {
            RomCurveDef* nextRouteNode = trickySelectRouteEntry(state, state->route.nextNode, routeDirection);
            if (nextRouteNode == 0) {
                state->movementState = TRICKY_MOVE_WALK_WAIT;
            } else {
                RomCurve_advanceToNextSegment(&state->route, nextRouteNode);
                trickyStartRouteJumpDown(obj, state);
            }
        }
        break;
    default:
        trickyDebugPrint("entered a non valid movementstate\n");
    }
    if (state->movementState < 5) {
        if (isInWalkGroupOrPatch(&obj->anim.worldPosX) != 0) {
            state->recoveryPos.x = obj->anim.worldPosX;
            state->recoveryPos.y = obj->anim.worldPosY;
            state->recoveryPos.z = obj->anim.worldPosZ;
        } else {
            trickyRestoreRecoveryPosition(obj, state);
        }
    }
    {
        u8 movementState = state->movementState;

        if (((((movementState == TRICKY_MOVE_WALK_WAIT) || (movementState == TRICKY_MOVE_WALK_START_PATCH)) ||
              (movementState == TRICKY_MOVE_WALK_PATCH_EXIT)) ||
             (movementState == TRICKY_MOVE_WALK_END_PATCH)) &&
            (0.0f == state->speed)) {
            return TRICKY_MOVEMENT_BLOCKED;
        }
    }
    if (moveResult != TRICKY_MOVEMENT_REACHED_TARGET) {
        return TRICKY_MOVEMENT_IN_PROGRESS;
    }
    return TRICKY_MOVEMENT_REACHED_TARGET;
}

/* group owned by another DLL, queried here */

void trickyApplyObjectAvoidanceToStep(f32* start, f32* end, f32* targetPos) {
    int count;
    int startIndex;
    int objectCount;
    GameObject** objects;
    GameObject* obj;
    SideRepelPlacement* repelPlacement;
    ObjDef* modelDef;
    ObjHitsPriorityState* hitState;
    u16 minDistance;
    f32 scale;
    int i;

    objects = objGetAllOfType(SIDEREPEL_OBJGROUP, &count);
    for (i = 0, scale = TRICKY_POSITION_OFFSET_SCALE; i < count; i++) {
        obj = objects[i];
        repelPlacement = (SideRepelPlacement*)obj->anim.placementData;
        trickyAdjustStepAroundPoint(start, end, targetPos, &obj->anim.worldPosX,
                                    scale * (f32)(u32)repelPlacement->minDistance,
                                    scale * (f32)(u32)repelPlacement->moveDistance);
    }

    objects = ObjList_GetObjects(&startIndex, &objectCount);
    for (i = startIndex; i < objectCount; i++) {
        obj = objects[i];
        modelDef = obj->anim.modelInstance;
        minDistance = modelDef->avoidMinDistance;
        if (minDistance != 0) {
            hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
            if ((hitState != NULL) && ((hitState->flags & OBJHITS_PRIORITY_STATE_ENABLED) != 0)) {
                trickyAdjustStepAroundPoint(start, end, targetPos, &obj->anim.worldPosX,
                                            TRICKY_POSITION_OFFSET_SCALE * (f32)(u32)minDistance,
                                            TRICKY_POSITION_OFFSET_SCALE * (f32)(u32)modelDef->avoidMoveDistance);
            }
        }
    }
}

void trickyAdjustStepAroundPoint(f32* start, f32* end, f32* targetPos, f32* center, f32 minDistance, f32 moveDistance) {
    Vec projection;
    f32 dx;
    f32 centerToEndSq;
    f32 minDistanceSq;
    f32 limitDistanceSq;
    f32 targetToCenterSq;
    f32 startToTargetSq;
    struct {
        f32 slope;
        f32 intercept;
    } stepLine;
    f32 perpSlope;
    f32 dz;
    f32 centerToStartSq;
    f32 length;
    int useBlendedDistance;

    useBlendedDistance = 0;
    centerToStartSq = getXZDistanceSquared(center, start);
    centerToEndSq = getXZDistanceSquared(center, end);
    minDistanceSq = minDistance * minDistance;
    limitDistanceSq = moveDistance * moveDistance;

    if (centerToEndSq > centerToStartSq) {
        return;
    }

    targetToCenterSq = getXZDistanceSquared(targetPos, center);
    if (targetToCenterSq < minDistanceSq) {
        return;
    }

    startToTargetSq = getXZDistanceSquared(start, targetPos);
    if (getXZDistanceSquared(start, center) > startToTargetSq) {
        return;
    }

    if (centerToStartSq < limitDistanceSq) {
        limitDistanceSq = centerToStartSq;
        useBlendedDistance = 1;
    }

    if (!(centerToEndSq < limitDistanceSq)) {
        return;
    }

    /* Intersect z = slope * x + intercept with the perpendicular through center. */
    stepLine.slope = (end[2] - start[2]) / (end[0] - start[0]);
    stepLine.intercept = start[2] - (stepLine.slope * start[0]);
    perpSlope = (start[0] - end[0]) / (end[2] - start[2]);
    projection.x = ((center[2] - (perpSlope * center[0])) - stepLine.intercept) / (stepLine.slope - perpSlope);
    projection.z = (stepLine.slope * projection.x) + stepLine.intercept;

    if (!(getXZDistanceSquared(center, &projection.x) < minDistanceSq)) {
        return;
    }

    dx = end[0] - center[0];
    dz = end[2] - center[2];
    length = sqrtf((dx * dx) + (dz * dz));
    if (0.0f != length) {
        dx /= length;
        dz /= length;
    }

    if (useBlendedDistance != 0) {
        moveDistance = sqrtf(limitDistanceSq);
        {
            f32 blend = moveDistance - sqrtf(centerToEndSq);
            moveDistance = moveDistance - blend / 8.0f;
        }
    }

    end[0] = center[0] + (dx * moveDistance);
    end[2] = center[2] + (dz * moveDistance);
}

void Tricky_emitDigParticles(GameObject* obj) {
    TrickyState* state;
    GameObject* linkedObj;
    PartFxSpawnParams args;

    state = obj->extra;
    linkedObj = state->followObj;

    args.posX = state->pathPointPositions[0].x;
    args.posY = state->pathPointPositions[0].y;
    args.posZ = state->pathPointPositions[0].z;
    args.dig.yaw = obj->anim.rotX;
    if (linkedObj->anim.romDefNo == TRICKY_DIG_ROMDEF_GROUND_ANIMA) {
        args.dig.variant = GROUND_ANIMATOR_INTERFACE(linkedObj)->getDigParticleVariant(linkedObj);
    } else if (linkedObj->anim.romDefNo == TRICKY_DIG_ROMDEF_WALL_ANIMATO) {
        args.dig.variant = WALL_ANIMATOR_INTERFACE(linkedObj)->getDigParticleVariant(linkedObj);
    } else {
        args.dig.variant = 0;
    }

    if ((int)randomGetRange(0, TRICKY_DIG_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, PARTFX_DIG_DEBRIS, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, TRICKY_DIG_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, PARTFX_DIG_DUST, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }

    args.posX = state->pathPointPositions[1].x;
    args.posY = state->pathPointPositions[1].y;
    args.posZ = state->pathPointPositions[1].z;
    args.dig.yaw = obj->anim.rotX;

    if ((int)randomGetRange(0, TRICKY_DIG_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, PARTFX_DIG_DEBRIS, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }
    if ((int)randomGetRange(0, TRICKY_DIG_PARTICLE_RANDOM_RATE) == 0) {
        (*gPartfxInterface)->spawnObject(obj, PARTFX_DIG_DUST, &args, TRICKY_ATTACHED_PARTFX_SPAWN_FLAGS, -1, NULL);
    }
}

void trickyRankLinkedRouteCandidates(GameObject* obj, u8* outRouteDirections, s16 objectWalkGroup,
                                     RomCurveDef** outRoutes) {
    f32 bestDistances[TRICKY_ROUTE_CANDIDATE_COUNT];
    int candidateSlot;
    RomCurveDef** allCurves;
    int linkCurveId;
    int curveCount;
    int curveIdx;
    RomCurveDef* linkedCurve;
    f32 targetXDistanceSquared;
    f32 targetZDistanceSquared;
    f32 curveZ;
    f32* targetPos;
    f32 score;
    f32 initialBestDistance;
    RomCurveDef* curve;
    u8 routeSlot;
    u8 linkDirectionBits;
    u8 shiftSlot;
    TrickyState* state;

    state = obj->extra;
    allCurves = (*gRomCurveInterface)->getCurves(&curveCount);

    initialBestDistance = TRICKY_MAX_DISTANCE;
    for (candidateSlot = 0; candidateSlot < TRICKY_ROUTE_CANDIDATE_COUNT; candidateSlot++) {
        bestDistances[candidateSlot] = initialBestDistance;
        outRoutes[candidateSlot] = NULL;
    }

    if (objectWalkGroup == 0) {
        return;
    }

    for (curveIdx = 0; curveIdx < curveCount; curveIdx++) {
        curve = allCurves[curveIdx];
        if ((curve->type != ROMCURVE_TYPE_TRICKY) || (curve->walkGroup != 0)) {
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
            targetXDistanceSquared = (targetPos[0] - curve->x) * (targetPos[0] - curve->x);
            {
                f32 objectXDistanceSquared = (obj->anim.worldPosX - curve->x) * (obj->anim.worldPosX - curve->x);
                f32 objectZDistanceSquared = (obj->anim.worldPosZ - curveZ) * (obj->anim.worldPosZ - curveZ);
                score = targetZDistanceSquared +
                        (targetXDistanceSquared + (objectXDistanceSquared + objectZDistanceSquared));
            }
        }
        if (score < bestDistances[TRICKY_ROUTE_CANDIDATE_COUNT - 1]) {
            for (routeSlot = 0; routeSlot < ROMCURVE_LINK_COUNT; routeSlot++) {
                linkCurveId = curve->linkIds[routeSlot];
                if ((linkCurveId > -1) && (curve->linkWalkGroups[routeSlot] == objectWalkGroup)) {
                    if (curve->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_A) {
                        linkedCurve = (*gRomCurveInterface)->getById(linkCurveId);
                        if ((linkedCurve != NULL) && (linkedCurve->subtype == ROMCURVE_TRICKY_SUBTYPE_BLOCKED_PAIR_B)) {
                            continue;
                        }
                    }

                    linkDirectionBits = (u8)(curve->backwardLinkMask >> routeSlot);
                    break;
                }
            }

            if (routeSlot == ROMCURVE_LINK_COUNT) {
                continue;
            }

            for (routeSlot = 0; routeSlot < TRICKY_ROUTE_CANDIDATE_COUNT; routeSlot++) {
                if (score < bestDistances[routeSlot]) {
                    for (shiftSlot = TRICKY_ROUTE_CANDIDATE_COUNT - 1; shiftSlot > routeSlot; shiftSlot--) {
                        outRouteDirections[shiftSlot] = outRouteDirections[shiftSlot - 1];
                        outRoutes[shiftSlot] = outRoutes[shiftSlot - 1];
                        bestDistances[shiftSlot] = bestDistances[shiftSlot - 1];
                    }

                    outRouteDirections[routeSlot] = (linkDirectionBits & 1) ^ 1;
                    outRoutes[routeSlot] = curve;
                    bestDistances[routeSlot] = score;
                    break;
                }
            }
        }
    }
}

RomCurveDef* trickySelectRouteEntry(TrickyState* state, RomCurveDef* routeDef, u8 routeDirection) {
    RomCurveDef* entry;

    entry = NULL;

    if ((state->cachedRouteDef == routeDef) && (state->cachedWalkGroup == state->walkGroup) &&
        (state->cachedRouteDirection == routeDirection)) {
        entry = trickyValidateRouteEntry(state->validatedRouteEntry);
    }

    if (entry == NULL) {
        entry = trickyFindNearestLinkedRouteEntry(state, routeDef, state->walkGroup, routeDirection);
        if (entry == NULL) {
            entry = trickyFindPathRouteEntry(state, routeDef, state->walkGroup);
        }

        if (entry == NULL) {
            if (state->savedWalkGroup != 0) {
                entry = trickyFindNearestLinkedRouteEntry(state, routeDef, state->savedWalkGroup, routeDirection);
                if (entry == NULL) {
                    entry = trickyFindPathRouteEntry(state, routeDef, state->savedWalkGroup);
                }
                if (entry != NULL) {
                    state->walkGroup = state->savedWalkGroup;
                }
            }

            if (entry == NULL) {
                entry = trickyFindNearestLinkedRouteEntry(state, routeDef, 0, routeDirection);
                state->walkGroup = 0;
            }
        }
    }

    state->cachedRouteDef = routeDef;
    state->validatedRouteEntry = entry;
    state->cachedWalkGroup = state->walkGroup;
    state->cachedRouteDirection = routeDirection;
    return entry;
}

int trickyFindReachableRouteIndex(TrickyState* state, RomCurveDef** candidateRoutes, u8* candidateRouteDirections,
                                  int targetWalkGroup) {
    s8 searchIndex;
    s8 routeStatus[TRICKY_ROUTE_CANDIDATE_COUNT];
    s8 routeIndex;
    s8 candidateIndex;
    s8 inactiveCandidateCount;

    for (routeIndex = 0; routeIndex < TRICKY_ROUTE_CANDIDATE_COUNT; routeIndex++) {
        if (candidateRoutes[routeIndex] != NULL) {
            pathSearchBegin(&state->candidateSearches[routeIndex], candidateRoutes[routeIndex], state->targetPosPtr,
                            targetWalkGroup, candidateRouteDirections[routeIndex]);
        }
    }

    for (searchIndex = 0; searchIndex < 100; searchIndex++) {
        inactiveCandidateCount = 0;
        for (candidateIndex = 0; candidateIndex < TRICKY_ROUTE_CANDIDATE_COUNT; candidateIndex++) {
            if (candidateRoutes[candidateIndex] != NULL) {
                routeStatus[candidateIndex] = pathSearchStep(&state->candidateSearches[candidateIndex], 1);
            } else {
                routeStatus[candidateIndex] = PATH_SEARCH_EXHAUSTED;
            }

            switch (routeStatus[candidateIndex]) {
            case PATH_SEARCH_REACHED_TARGET:
                return candidateIndex;
            case PATH_SEARCH_EXHAUSTED:
                candidateRoutes[candidateIndex] = NULL;
                inactiveCandidateCount++;
                break;
            }
        }

        switch (inactiveCandidateCount) {
        case TRICKY_ROUTE_CANDIDATE_COUNT - 1:
            for (searchIndex = 0; searchIndex < TRICKY_ROUTE_CANDIDATE_COUNT; searchIndex++) {
                if (candidateRoutes[searchIndex] != NULL) {
                    routeStatus[searchIndex] =
                        pathSearchStep(&state->candidateSearches[searchIndex], TRICKY_PATH_SEARCH_BULK_STEPS);
                    if (routeStatus[searchIndex] == PATH_SEARCH_REACHED_TARGET) {
                        return searchIndex;
                    }
                    return -1;
                }
            }
        case TRICKY_ROUTE_CANDIDATE_COUNT:
            return -1;
        }
    }

    return -1;
}

RomCurveDef* trickyFindPathRouteEntry(TrickyState* state, RomCurveDef* route, int targetWalkGroup) {
    if (targetWalkGroup == 0) {
        return NULL;
    }

    if ((state->cachedTargetWalkGroup == targetWalkGroup) && (state->cachedRouteEntry == route)) {
        state->cachedRouteEntry = pathSearchGetNextPoint(&state->cachedPathSearch);
        if (state->cachedRouteEntry == NULL) {
            return NULL;
        }

        state->cachedRouteEntry = trickyValidateRouteEntry(state->cachedRouteEntry);
        if (state->cachedRouteEntry != NULL) {
            return state->cachedRouteEntry;
        }
    }

    pathSearchBegin(&state->cachedPathSearch, route, state->targetPosPtr, targetWalkGroup, state->route.reverse);
    if (pathSearchStep(&state->cachedPathSearch, TRICKY_PATH_SEARCH_BULK_STEPS) != PATH_SEARCH_REACHED_TARGET) {
        return NULL;
    }

    pathSearchBuildPath(&state->cachedPathSearch);
    state->cachedRouteEntry = pathSearchGetNextPoint(&state->cachedPathSearch);
    state->cachedTargetWalkGroup = targetWalkGroup;
    return state->cachedRouteEntry;
}

RomCurveDef* trickyFindNearestLinkedRouteEntry(TrickyState* state, RomCurveDef* routeDef, int targetWalkGroup,
                                               int directionBits) {
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
        if ((curveId > -1) && ((((routeDef->backwardLinkMask & mask) ^ directionBits) == 0))) {
            candidates[candidateCount] = (*gRomCurveInterface)->getById(curveId);
            if (candidates[candidateCount] != NULL) {
                entry = candidates[candidateCount];
                /* Retail indexes the group by compacted candidate count, not linkSlot. */
                if ((targetWalkGroup == 0) || (routeDef->linkWalkGroups[candidateCount] == targetWalkGroup)) {
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
        directionBits <<= 1;
    }

    if (candidateCount != 0) {
        bestDistance = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &candidates[0]->x);
        bestIndex = 0;
        for (linkSlot = 1; linkSlot < candidateCount; linkSlot++) {
            distance = getXZDistanceSquared(&state->playerObj->anim.worldPosX, &candidates[linkSlot]->x);
            if (distance < bestDistance) {
                bestDistance = distance;
                bestIndex = linkSlot;
            }
        }

        return candidates[bestIndex];
    }
    return NULL;
}

static inline RomCurveDef* trickyValidateRouteEntry(RomCurveDef* entry) {
    if (entry == NULL) {
        return NULL;
    }
    if (((entry->requiredBit == -1) || (mainGetBit(entry->requiredBit) != 0)) &&
        ((entry->forbiddenBit == -1) || (mainGetBit(entry->forbiddenBit) == 0))) {
        return entry;
    }

    return NULL;
}

int trickyRequestMove(GameObject* obj, int newMoveId, f32 animRate, u32 flags) {
    TrickyState* state = obj->extra;
    f32 rootMotionScale;
    if (state->moveId == newMoveId) {
        if (obj->anim.currentMove == newMoveId) {
            state->animRate = animRate;
            state->stateFlags |= flags;
        }
        return 1;
    }
    if ((flags & TRICKY_MOVE_FLAG_IMMEDIATE_TRANSITION) != 0) {
        state->animTransitionTimer = TRICKY_ANIM_TRANSITION_FRAMES;
    }
    state->moveId = newMoveId;
    state->pendingAnimRate = animRate;
    state->pendingStateFlags = flags;
    if ((flags & TRICKY_STATE_FLAG_SIDESTEP) == 0) {
        state->stateFlags &= ~TRICKY_STATE_FLAG_SIDESTEP;
    }
    if ((flags & TRICKY_STATE_FLAG_BACKSTEP) == 0) {
        state->stateFlags &= ~TRICKY_STATE_FLAG_BACKSTEP;
    }
    if ((flags & TRICKY_STATE_FLAG_VERTICAL_MOVE) == 0) {
        state->stateFlags &= ~TRICKY_STATE_FLAG_VERTICAL_MOVE;
    }
    if ((flags & TRICKY_STATE_FLAG_ROTATE) == 0) {
        state->stateFlags &= ~TRICKY_STATE_FLAG_ROTATE;
    }
    rootMotionScale = 1.0f;
    state->sidestepDelta = rootMotionScale;
    state->backstepDelta = rootMotionScale;
    state->verticalDelta = rootMotionScale;
    state->rotStepScale = rootMotionScale;
    if (state->animTransitionTimer >= TRICKY_ANIM_TRANSITION_FRAMES) {
        return 1;
    }
    return 0;
}

static inline void trickyPlayFollowVoice(GameObject* obj, f32 speed) {
    if (speed > TRICKY_FAST_FOLLOW_VOICE_THRESHOLD) {
        trickyTryPlaySound(obj, randomGetRange(TRICKY_VOICE_SFX_WAIT_UP_FOX, TRICKY_VOICE_SFX_WAIT_FOR_ME),
                           TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
    } else {
        u16 slowFollowVoiceSfxIds[3] = {TRICKY_VOICE_SFX_LAUGH, TRICKY_VOICE_SFX_WHERE_ARE_WE_GOING,
                                        TRICKY_VOICE_SFX_LETS_PLAY};
        if (mainGetBit(GAMEBIT_ITEM_TrickyBall_Bought) != 0) {
            randomGetRange(0, 2);
        } else {
            randomGetRange(0, 1);
        }
        trickyTryPlaySound(obj, slowFollowVoiceSfxIds[randomGetRange(0, 2)], TRICKY_VOICE_MOUTH_ANGLE_NORMAL);
    }
}

int moveTricky(GameObject* obj, f32* targetPos) {
    f32 desiredNextPos[3];
    f32 avoidanceNextPos[3];
    TrickyState* state;
    f32 currentSpeed;
    f32 targetDistanceRateAbs;
    int turnDeltaAbs;

    state = obj->extra;
    currentSpeed = state->speed;
    trickyDebugPrint(sTrickyVelocityDebugFmt, currentSpeed);

    state->moveVector.x = targetPos[0] - obj->anim.worldPosX;
    state->moveVector.z = targetPos[2] - obj->anim.worldPosZ;
    trickyNormalizeMoveDirection(state);

    if (currentSpeed < 0.05f) {
        desiredNextPos[0] = (0.05f * state->moveVector.x) * timeDelta + obj->anim.worldPosX;
        desiredNextPos[1] = obj->anim.worldPosY;
        desiredNextPos[2] = (0.05f * state->moveVector.z) * timeDelta + obj->anim.worldPosZ;
    } else {
        desiredNextPos[0] = timeDelta * (state->moveVector.x * currentSpeed) + obj->anim.worldPosX;
        desiredNextPos[1] = obj->anim.worldPosY;
        desiredNextPos[2] = timeDelta * (state->moveVector.z * currentSpeed) + obj->anim.worldPosZ;
    }

    avoidanceNextPos[0] = desiredNextPos[0];
    avoidanceNextPos[1] = desiredNextPos[1];
    avoidanceNextPos[2] = desiredNextPos[2];
    trickyApplyObjectAvoidanceToStep(&obj->anim.worldPosX, avoidanceNextPos, targetPos);
    if (vec3f_distanceSquared(desiredNextPos, avoidanceNextPos) > TRICKY_AVOIDANCE_REPATH_EPSILON_SQ) {
        state->moveVector.x = avoidanceNextPos[0] - obj->anim.worldPosX;
        state->moveVector.z = avoidanceNextPos[2] - obj->anim.worldPosZ;
        trickyNormalizeMoveDirection(state);
    }

    if (currentSpeed >= 0.05f) {
        s16 turnDelta;
        TrickyState* facingState = obj->extra;
        trickyUpdateFacingFromMoveVector(obj, facingState, &turnDelta);
        if (trickyIsInDeepWater(state) != 0) {
            trickyRequestMove(obj, TRICKY_ANIM_SWIM, TRICKY_TINY_MOVE_ANIM_RATE, TRICKY_MOVE_FLAG_ROOT_TRANSLATE);
            state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
            state->particleTimer = 0.0f;
            trickyDebugPrint("in water\n");
        } else {
            if (state->stateIndex == TRICKY_STATE_FOLLOW_PLAYER) {
                targetDistanceRateAbs = trickyGetTargetDistanceRate(obj) >= 0.0f ? trickyGetTargetDistanceRate(obj)
                                                                                 : -trickyGetTargetDistanceRate(obj);

                if (targetDistanceRateAbs > 0.0f) {
                    state->sfxIntervalTimer -= timeDelta;
                    if (state->sfxIntervalTimer <= 0.0f) {
                        state->sfxIntervalTimer =
                            (f32)(int)randomGetRange(TRICKY_FOLLOW_VOICE_MIN_FRAMES, TRICKY_FOLLOW_VOICE_MAX_FRAMES);
                        if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) == 0) {
                            trickyPlayFollowVoice(obj, currentSpeed);
                        }
                    }
                }
            }

            if (currentSpeed > TRICKY_RUN_MOVE_THRESHOLD) {
                state->movementBarkTimer = 600.0f;
                trickyRequestMove(obj, TRICKY_ANIM_LAND_RUN_LOOP, TRICKY_TINY_MOVE_ANIM_RATE,
                                  TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (currentSpeed > TRICKY_FAST_FOLLOW_VOICE_THRESHOLD) {
                trickyRequestMove(obj, TRICKY_ANIM_RUN, TRICKY_TINY_MOVE_ANIM_RATE, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (currentSpeed > TRICKY_FAST_WALK_MOVE_THRESHOLD) {
                trickyRequestMove(obj, TRICKY_ANIM_WALK_FAST, TRICKY_TINY_MOVE_ANIM_RATE, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else if (currentSpeed > TRICKY_SLOW_WALK_MOVE_THRESHOLD) {
                trickyRequestMove(obj, TRICKY_ANIM_WALK_MEDIUM, TRICKY_TINY_MOVE_ANIM_RATE, TRICKY_MOVE_FLAG_WALK_LOOP);
            } else {
                trickyRequestMove(obj, TRICKY_ANIM_WALK_SLOW, TRICKY_TINY_MOVE_ANIM_RATE, TRICKY_MOVE_FLAG_WALK_LOOP);
            }
            trickyDebugPrint("moveTricky: out of water\n");
        }
    } else {
        s16 previousYaw;
        s16 turnDelta;

        previousYaw = obj->anim.rotX;
        turnDelta = 0;
        trickyUpdateFacingFromMoveVector(obj, obj->extra, &turnDelta);
        turnDeltaAbs = turnDelta;

        if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) != 0) {
            if (trickyIsInDeepWater(state) != 0) {
                trickyDebugPrint("Turning in water\n");
                trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
                state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
                state->particleTimer = 0.0f;
            } else {
                int animId;

                trickyDebugPrint("Turning out of water\n");
                if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_LEFT) != 0) {
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
                } else if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_RIGHT) != 0) {
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
                trickyRequestMove(obj, animId, TRICKY_TURN_MOVE_ANIM_RATE,
                                  TRICKY_MOVE_FLAG_KEEP_PROGRESS | TRICKY_STATE_FLAG_ROTATE);
            }
        }

        state->speed = 0.05f;
        if (((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) == 0) &&
            ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST_PREV) == 0)) {
            return TRICKY_MOVEMENT_REACHED_TARGET;
        }
    }
    return TRICKY_MOVEMENT_IN_PROGRESS;
}

static void trickyUpdateFacingFromMoveVector(GameObject* obj, TrickyState* state, s16* turnDeltaOut) {
    int yaw;

    if (((state->moveVector.x * state->moveVector.x) + (state->moveVector.z * state->moveVector.z)) > 0.01f) {
        yaw = (s16)getAngle(-state->moveVector.x, -state->moveVector.z);
        *turnDeltaOut = trickyTurnTowardYaw(obj, yaw);
        state->moveVector.x = -mathSinf((TRICKY_PI * (f32)(int)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);
        state->moveVector.z = -mathCosf((TRICKY_PI * (f32)(int)obj->anim.rotX) / TRICKY_ANGLE_HALF_TURN_UNITS);
    }
}

static inline void trickySetTargetPosition(TrickyState* state, f32* targetPos) {
    if (state->targetPosPtr != targetPos) {
        state->targetPosPtr = targetPos;
        state->stateFlags &= ~TRICKY_STATE_FLAG_PATH_PATCHES_VALID;
        state->linkedPatchGroup = 0;
    }
}

static inline f32 trickyGetTargetDistanceRate(GameObject* obj) {
    TrickyState* state = (TrickyState*)obj->extra;
    f32* currentTargetPos;
    f32 dx;
    f32 dz;
    f32 previousScaledDistance;
    f32 currentScaledDistance;
    f32 delta;

    /* Both samples use Tricky's current position, isolating the target's radial motion. */
    currentTargetPos = state->targetPosPtr;
    if (state->targetPosPtr == state->previousTargetPosPtr) {
        dx = state->previousTargetPos.x - obj->anim.worldPosX;
        dz = state->previousTargetPos.z - obj->anim.worldPosZ;
        previousScaledDistance = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));

        dx = currentTargetPos[0] - obj->anim.worldPosX;
        dz = currentTargetPos[2] - obj->anim.worldPosZ;
        currentScaledDistance = oneOverTimeDelta * sqrtf((dx * dx) + (dz * dz));
        delta = currentScaledDistance - previousScaledDistance;
    } else {
        delta = 0.0f;
    }

    return delta;
}

int trickyTurnTowardYaw(GameObject* obj, s16 targetYaw) {
    TrickyState* state;
    int targetYawBits;
    int currentYaw;
    int delta;
    int step;

    state = obj->extra;
    state->targetYaw = targetYaw;

    targetYawBits = (u16)(s16)targetYaw;
    delta = (currentYaw = obj->anim.rotX) - targetYawBits;
    if (delta > TRICKY_YAW_HALF_TURN) {
        delta -= TRICKY_YAW_WRAP_RANGE;
    }
    if (delta < -TRICKY_YAW_HALF_TURN) {
        delta += TRICKY_YAW_WRAP_RANGE;
    }

    if ((state->stateFlags & TRICKY_STATE_FLAG_TURN_REQUEST) != 0) {
        state->stateFlags |= TRICKY_STATE_FLAG_TURN_REQUEST_PREV;
    } else {
        state->stateFlags &= ~TRICKY_STATE_FLAG_TURN_REQUEST_PREV;
    }
    state->stateFlags &= ~(u32)(TRICKY_STATE_FLAG_TURNING | TRICKY_STATE_FLAG_TURN_REQUEST |
                                TRICKY_STATE_FLAG_TURN_LEFT | TRICKY_STATE_FLAG_TURN_RIGHT);

    if (delta > TRICKY_TURN_REQUEST_DEADBAND) {
        state->stateFlags |= TRICKY_STATE_FLAG_TURN_REQUEST | TRICKY_STATE_FLAG_TURN_RIGHT;
    } else if (delta < -TRICKY_TURN_REQUEST_DEADBAND) {
        state->stateFlags |= TRICKY_STATE_FLAG_TURN_REQUEST | TRICKY_STATE_FLAG_TURN_LEFT;
    } else {
        obj->anim.rotX = targetYaw;
        return 0;
    }

    if (delta > TRICKY_TURN_STEP_DEADBAND) {
        step = (s32)(TRICKY_YAW_STEP_RATE * timeDelta);
        obj->anim.rotX = currentYaw - step;
        state->stateFlags |= TRICKY_STATE_FLAG_TURNING;
    } else if (delta < -TRICKY_TURN_STEP_DEADBAND) {
        step = (s32)(TRICKY_YAW_STEP_RATE * timeDelta);
        obj->anim.rotX = currentYaw + step;
        state->stateFlags |= TRICKY_STATE_FLAG_TURNING;
    } else {
        obj->anim.rotX = targetYaw;
    }

    return delta;
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
    limit = 100.0f;
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

static void trickyAdvanceToSegmentEnd(RomCurveWalker* route) {
    if (route->reverse != 0) {
        while (route->atSegmentEnd != 0) {
            RomCurve_stepClamped(route, TRICKY_ROUTE_REVERSE_STEP);
        }
    } else {
        while (route->atSegmentEnd == 0) {
            RomCurve_stepClamped(route, 2.0f);
        }
    }
}

static void trickyRequestIdleMove(GameObject* obj, TrickyState* state) {
    int inWater = trickyIsInDeepWater(state);
    if (inWater != 0) {
        trickyRequestMove(obj, TRICKY_ANIM_SWIM_TURN, TRICKY_FAST_MOVE_ANIM_RATE, 0);
        state->waterIdleTimer = TRICKY_WATER_COOLDOWN_FRAMES;
        state->particleTimer = 0.0f;
        trickyDebugPrint("in water\n");
    } else {
        trickyRequestMove(obj, TRICKY_ANIM_LAND_IDLE, TRICKY_LAND_MOVE_ANIM_RATE, 0);
        trickyDebugPrint("out of water\n");
    }
}

void trickyUpdateCollisionAndPathState(GameObject* obj) {
    TrickyState* state;
    f32 hitOffsetY;
    GameObject* hitObj;
    f32 nearestDistance;
    PartFxSpawnParams hitEffectParams;
    f32* hitPosPtr;
    u8 doGroundSnap;
    int doHeightSnap;
    int hitType;
    f32 contactTimer;

    state = (TrickyState*)obj->extra;
    doGroundSnap = 0;
    nearestDistance = 100.0f;

    if ((objPosToMapBlockIdx(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ) == -1) &&
        ((state->stateFlags & TRICKY_STATE_FLAG_POSITION_RELOCATED) == 0)) {
        state->curvesCollision.subtype = CURVES_COLLISION_SUBTYPE_NONE;
        obj->anim.localPosX = obj->anim.previousLocalPosX;
        obj->anim.localPosY = obj->anim.previousLocalPosY;
        obj->anim.localPosZ = obj->anim.previousLocalPosZ;
    }

    state->stateFlags &= ~TRICKY_STATE_FLAG_POSITION_RELOCATED;

    if (state->groundSnapCounter != 0) {
        state->groundSnapCounter -= 1;
        doGroundSnap = 1;
    } else if ((state->stateFlags & TRICKY_STATE_FLAG_GROUND_SNAP) != 0) {
        doGroundSnap = 1;
    }

    if (doGroundSnap != 0) {
        trackGetNearestGroundOffset(obj, obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ, &hitOffsetY, 0);
        obj->anim.localPosY -= hitOffsetY;
        state->curvesCollision.subtype = CURVES_COLLISION_SUBTYPE_NONE;
    }

    if ((state->curvesCollision.subtype != CURVES_COLLISION_SUBTYPE_NONE) && (state->heightTracking == 0u)) {
        doHeightSnap = trickyIsInDeepWater(state);

        if (doHeightSnap != 0) {
            obj->anim.velocityY = 0.0f;
            obj->anim.localPosY = state->curvesCollision.resultWaterY - 0.01f;
        } else {
            obj->anim.velocityY += -0.17f * timeDelta;
            obj->anim.localPosY += obj->anim.velocityY * timeDelta;
        }
    } else {
        obj->anim.velocityY = 0.0f;
    }

    hitObj = ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitObject;
    if (((((ObjHitsPriorityState*)obj->anim.hitReactState)->flags & OBJHITS_PRIORITY_STATE_PAIR_RESPONSE_APPLIED) ==
         0) ||
        (hitObj->anim.romDefNo == SKEETLA_CONTACT_OBJ_PROJBALL)) {
        hitObj = NULL;
    }

    if ((state->stateFlags & TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED) != 0) {
        state->contactTimer += timeDelta;
        if (state->contactTimer >= 40.0f) {
            if (vec3f_distanceSquared(&obj->anim.worldPosX, &Obj_GetPlayerObject()->anim.worldPosX) > 400.0f) {
                state->contactTimer -= 40.0f;
                obj->anim.modelInstance->runtimeSourceHitMask = TRICKY_HITMASK_ALL_SOURCES;
                state->stateFlags &= ~TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED;
            }
        }
    } else if ((state->lastContactObj != NULL) && (hitObj == state->lastContactObj)) {
        state->contactTimer += timeDelta;
        contactTimer = state->contactTimer;
        if (contactTimer >= 10.0f) {
            state->contactTimer = contactTimer - 10.0f;
            state->stateFlags |= TRICKY_STATE_FLAG_CONTACT_MASK_SUPPRESSED;
            obj->anim.modelInstance->runtimeSourceHitMask = TRICKY_HITMASK_NO_LOW_SOURCE;
        }
    } else {
        state->contactTimer = 0.0f;
    }

    state->lastContactObj = hitObj;
    hitType =
        ObjHits_PollPriorityHitWithCooldown(obj, &state->hitCooldown, &hitObj, (hitPosPtr = &hitEffectParams.posX));
    state->hitType = hitType;

    switch (state->hitType) {
    case TRICKY_DAMAGE_INSTANT_DEATH:
    case 2:
    case TRICKY_DAMAGE_DIM2_SNOWBALL:
    case TRICKY_DAMAGE_BOMB_PLANT_EXPLOSION:
    case TRICKY_DAMAGE_PROJBALL:
    case 0xf:
    case 0x11:
    case 0x13:
        objDoHitParticleFx(obj, 0.014f, &hitEffectParams, 1, 0);
        break;
    case 7:
    case 8:
    case TRICKY_DAMAGE_MMP_CRATERF:
    case TRICKY_DAMAGE_MMP_BARREL:
    case 0xb:
    case 0xc:
        objfx_spawnHitEmitterAtPos(hitPosPtr, 8, 0xff, 0x20, 0x20);
        objDoHitParticleFx(obj, 0.014f, &hitEffectParams, 4, 0);
        if (hitObj->anim.romDefNo == SKEETLA_ATTACKER_SEQID_STAFF) {
            Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
        }
        break;
    case TRICKY_DAMAGE_FIRE:
        state->particleTimer = 300.0f;
        break;
    }

    if (state->curvesCollision.subtype == CURVES_COLLISION_SUBTYPE_NONE) {
        (*gPathControlInterface)->attachObject(obj, &state->curvesCollision);
    }

    if ((coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ) == 0xe) ||
        (objGetNearestTypeTo(SKEETLA_TARGET_OBJGROUP, obj, &nearestDistance) != NULL)) {
        state->curvesCollision.flags &= ~4u;
    } else {
        state->curvesCollision.flags |= 4u;
    }

    (*gPathControlInterface)->update(obj, &state->curvesCollision, timeDelta);
    (*gPathControlInterface)->apply(obj, &state->curvesCollision);
    (*gPathControlInterface)->advance(obj, &state->curvesCollision, timeDelta);

    obj->anim.rotY = state->curvesCollision.tiltPitch;
    obj->anim.rotZ = state->curvesCollision.tiltRoll;
}

static f32 trickyAccelerate(f32 speed, f32 maxSpeed) {
    f32 nextSpeed = TRICKY_SMALL_SPEED_STEP * timeDelta + speed;
    return nextSpeed > maxSpeed ? maxSpeed : nextSpeed;
}

static f32 trickyDecelerate(f32 speed, f32 minSpeed) {
    f32 nextSpeed = TRICKY_SPEED_DECAY_STEP * timeDelta + speed;
    return nextSpeed < minSpeed ? minSpeed : nextSpeed;
}

int trickySelectQueuedCommandTarget(TrickyState* state, enum TrickyCommandType commandType) {
    f32 bestPriorityDist;
    f32 bestFallbackDist;
    int commandIndex;
    GameObject* bestPriorityTarget;
    GameObject* bestFallbackTarget;

    bestPriorityDist = TRICKY_MAX_DISTANCE;
    bestPriorityTarget = NULL;
    bestFallbackDist = bestPriorityDist;
    bestFallbackTarget = NULL;

    for (commandIndex = 0; commandIndex < state->commandCount; commandIndex++) {
        if (state->commands[commandIndex].commandType == commandType) {
            f32 dist = getXZDistanceSquared(&state->playerObj->anim.worldPosX,
                                            &state->commands[commandIndex].targetObj->anim.worldPosX);

            if (state->commands[commandIndex].commandKind == TRICKY_COMMAND_KIND_PRIORITY) {
                if (dist < bestPriorityDist) {
                    bestPriorityDist = dist;
                    bestPriorityTarget = state->commands[commandIndex].targetObj;
                }
            } else if (dist < bestFallbackDist) {
                bestFallbackDist = dist;
                bestFallbackTarget = state->commands[commandIndex].targetObj;
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

    trickySetTargetPosition(state, &state->followObj->anim.worldPosX);

    state->substate = 0;
    return 1;
}

void Tricky_emitQueuedPathParticles(GameObject* obj, TrickyState* state) {
    PartFxSpawnParams particleParams;
    u8 spawnCount = TRICKY_PATH_PARTFX_BURST_COUNT;
    u32 flags = state->stateFlags;
    if ((flags & TRICKY_STATE_CHILD_ACTIVITY_FLAGS) == 0) {
        return;
    }
    particleParams.posX = state->mouthPos.x - obj->anim.worldPosX;
    particleParams.posY = state->mouthPos.y - obj->anim.worldPosY;
    particleParams.posZ = state->mouthPos.z - obj->anim.worldPosZ;
    particleParams.scale = 1.0f;
    particleParams.rotX = obj->anim.rotX;
    particleParams.rotY = obj->anim.rotY;
    particleParams.rotZ = obj->anim.rotZ;
    if ((flags & TRICKY_STATE_FLAG_CHILDREN_ACTIVE) == 0) {
        while (spawnCount-- != 0) {
            (*gPartfxInterface)
                ->spawnObject(obj, TRICKY_PATH_PARTFX, &particleParams, TRICKY_PATH_PARTFX_SPAWN_FLAGS, -1, NULL);
        }
        state->stateFlags &= ~TRICKY_STATE_FLAG_CHILDREN_CLEANUP;
    }
}

GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes) {
    GameObject** baddieList;
    GameObject* closestBaddie;
    int baddieIndex;
    f32 bestDistSq;
    int baddieCount;

    bestDistSq = maxRadius;
    closestBaddie = 0;
    baddieList = objGetAllOfType(TRICKY_BADDIE_OBJGROUP, &baddieCount);
    bestDistSq = bestDistSq * bestDistSq;
    baddieIndex = 0;

    for (; baddieIndex < baddieCount; baddieIndex++) {
        TrickyBaddieTargetPlacement* placement;
        f32 healthFraction;
        int disabledByBit, enabledByBit;
        s32 disableGameBit, enableGameBit;

        if (dll_19_isBaddieControlObject(baddieList[baddieIndex]) != 0) {
            healthFraction = (*gBaddieControlInterface)->getHealthFraction(baddieList[baddieIndex]);
        } else {
            healthFraction = enemy_getHealthFraction(baddieList[baddieIndex]);
        }

        placement = (TrickyBaddieTargetPlacement*)baddieList[baddieIndex]->anim.placementData;
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

        if (objIsObjectType(baddieList[baddieIndex], TRICKY_INTERACTABLE_OBJGROUP) == 0 && healthFraction > 0.0f &&
            disabledByBit == 0 && enabledByBit != 0) {
            if (baddieList[baddieIndex]->anim.romDefNo != TRICKY_SEQID_WHIRLPOOL) {
                if ((*gMapEventInterface)->shouldNotSaveTime(placement->base.ident) != 0) {
                    if (allowSpecialTypes == 0) {
                        s16 romDefNo = baddieList[baddieIndex]->anim.romDefNo;
                        if (romDefNo == TRICKY_SEQID_VAMBAT || romDefNo == TRICKY_SEQID_WB ||
                            romDefNo == DLL1B5_SEQUENCE_ID_SC_BABY_LIGHTFOOT || romDefNo == TRICKY_SEQID_PINPON) {
                            continue;
                        }
                    }
                    {
                        f32 dist =
                            vec3f_distanceSquared(&origin->anim.worldPosX, &baddieList[baddieIndex]->anim.worldPosX);
                        if (dist < bestDistSq) {
                            bestDistSq = dist;
                            closestBaddie = baddieList[baddieIndex];
                        }
                    }
                }
            }
        }
    }
    return closestBaddie;
}

f32* trickyGetMouthPosition(GameObject* obj) {
    TrickyState* state = obj->extra;
    return &state->mouthPos.x;
}

int trickyGetMouthYawOffset(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->mouthYawOffset;
}

GameObject* trickyGetStayPoint(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->followObj;
}

f32 trickyGetSpeed(GameObject* obj) {
    TrickyState* state = obj->extra;
    return state->speed;
}

/* GameBit-gated recall request. Returns 1 only when Tricky is already in an active command. */
int Tricky_requestRecallAndCheckBusy(GameObject* obj) {
    TrickyState* state = obj->extra;
    if ((u32)mainGetBit(GAMEBIT_Tricky_Unlocked_Sidekick_Commands) != 0u) {
        state->stateFlags |= TRICKY_STATE_FLAG_RECALL_REQUEST;
        if ((state->stateFlags & TRICKY_STATE_FLAG_COMMAND_ACTIVE) != 0u) {
            return 1;
        }
    }
    return 0;
}

/* Latch the impress move and prime impressTimer. */
void trickyImpress(GameObject* obj) {
    TrickyState* state = obj->extra;
    state->stateFlags |= TRICKY_STATE_FLAG_IMPRESS_PENDING;
    state->impressTimer = 20.0f;
}

static int trickyIsInDeepWater(TrickyState* state) {
    if (0.0f == state->curvesCollision.resultWaterDepth) {
        return 0;
    }
    if (TRICKY_NO_FLOOR_Y == state->curvesCollision.resultFloorY) {
        return 1;
    }
    if (state->curvesCollision.resultWaterY - state->curvesCollision.resultFloorY > TRICKY_SWIM_MIN_DEPTH) {
        return 1;
    }
    return 0;
}

void trickyUpdateColorVariant(GameObject* obj, TrickyState* state) {
    u8 colorVariant = state->stats->ballReturnCount / TRICKY_BALL_RETURNS_PER_COLOR;

    if (state->colorVariant != colorVariant) {
        f32 fadeTimer;
        if (mainGetBit(TRICKY_COLOR_CHANGE_SEEN_GAMEBIT) == 0) {
            mainSetBits(TRICKY_COLOR_CHANGE_SEEN_GAMEBIT, 1);
            (*gObjectTriggerInterface)->runSequence(TRICKY_COLOR_CHANGE_SEQUENCE_ID, obj, -1);
            state->stateFlags |= TRICKY_STATE_FLAG_SEQUENCE_KEEP_STATE;
            state->colorFadeTimer += 20.0f;
        }
        state->colorFadeTimer -= timeDelta;
        fadeTimer = state->colorFadeTimer;
        if (!(fadeTimer > 20.0f)) {
            if (fadeTimer > 0.0f) {
                f32 alpha;
                if (fadeTimer > 10.0f) {
                    alpha = 1.0f - (fadeTimer - 10.0f) / 10.0f;
                } else {
                    Obj_GetActiveModel(obj)->textureRefs->swapSelector = colorVariant;
                    alpha = state->colorFadeTimer / 10.0f;
                }
                Obj_SetModelColorOverrideRecursive(obj, 255, 255, 255, TRICKY_COLOR_FADE_ALPHA_SCALE * alpha, 1);
            } else {
                state->colorVariant = colorVariant;
                Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
            }
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
        ObjModel_SetBlendChannelTargets(model, 1, -1, 0x1a, 0.0f, 0x21);
        state->blendWeight = 10.0f;
        ObjModel_SetBlendChannelWeight(model, 0, 0.0f);
        state->blendPending = 0;
        state->blendActive = 1;
    }
    if (state->blendActive) {
        TrickyStats* stats = state->stats;
        target = (f32)(u32)stats->energy / (f32)(u32)stats->maxEnergy;
        if (target > state->blendWeight) {
            state->blendVelocity = 0.004f * timeDelta + state->blendVelocity;
            state->blendWeight = state->blendVelocity * timeDelta + state->blendWeight;
            if (state->blendWeight > (max = 1.0f)) {
                state->blendVelocity = 0.0f;
                state->blendWeight = max;
            } else if (state->blendWeight > target) {
                if (state->blendVelocity < 0.01f) {
                    state->blendVelocity = 0.0f;
                    state->blendWeight = target;
                } else {
                    state->blendVelocity *= 0.7f;
                }
            }
        } else if (target < state->blendWeight) {
            state->blendVelocity = state->blendVelocity - 0.004f * timeDelta;
            state->blendWeight = state->blendVelocity * timeDelta + state->blendWeight;
            blendWeight = state->blendWeight;
            if (blendWeight < 0.0f) {
                state->blendWeight = state->blendVelocity = 0.0f;
            }
            if (state->blendWeight < target) {
                if (state->blendVelocity > -0.01f) {
                    state->blendVelocity = 0.0f;
                    state->blendWeight = target;
                } else {
                    state->blendVelocity *= 0.7f;
                }
            }
        }
        ObjModel_SetBlendChannelWeight(Obj_GetActiveModel(obj), 1, 2.0f * state->blendWeight - 1.0f);
    }
}

void trickyFreePromptChild(GameObject* obj, TrickyState* state, GameObject** childRef) {
    s8 occupiedSlots[TRICKY_PROMPT_CHILD_SLOT_COUNT];
    GameObject* exclamationPromptChild;
    GameObject* questPromptChild;
    GameObject* foodChild;

    if (*childRef == NULL) {
        return;
    }
    ObjLink_DetachChild(obj, *childRef);
    Obj_FreeObject(*childRef);
    *childRef = NULL;
    occupiedSlots[0] = TRICKY_PROMPT_CHILD_SLOT_FREE;
    occupiedSlots[1] = TRICKY_PROMPT_CHILD_SLOT_FREE;
    occupiedSlots[2] = TRICKY_PROMPT_CHILD_SLOT_FREE;
    exclamationPromptChild = state->exclamationPromptChild;
    if (exclamationPromptChild != NULL) {
        occupiedSlots[state->packedSlots.exclamationPromptSlot] = TRICKY_PROMPT_CHILD_SLOT_OCCUPIED;
    }
    questPromptChild = state->questPromptChild;
    if (questPromptChild != NULL) {
        occupiedSlots[state->packedSlots.questPromptSlot] = TRICKY_PROMPT_CHILD_SLOT_OCCUPIED;
    }
    foodChild = state->foodChild;
    if (foodChild != NULL) {
        occupiedSlots[state->packedSlots.foodChildSlot] = TRICKY_PROMPT_CHILD_SLOT_OCCUPIED;
    }
    /* Keep one remaining prompt at the primary attachment point. */
    if (occupiedSlots[0] == TRICKY_PROMPT_CHILD_SLOT_FREE) {
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

int trickyTryPlaySound(GameObject* obj, u16 sfxId, int mouthOpenAngle) {
    TrickyState* state = obj->extra;
    s16 move;

    if (state->soundSuppressed) {
        return 0;
    }
    move = obj->anim.currentMove;
    switch (move) {
    case TRICKY_ANIM_HOWL_START:
    case TRICKY_ANIM_HOWL_HOLD:
    case TRICKY_ANIM_HOWL_END:
    case TRICKY_ANIM_HOWL_IDLE_PICK:
    case TRICKY_ANIM_AMBIENT_HOWL:
    case TRICKY_ANIM_DIG_FOOD_LOOP:
    case TRICKY_ANIM_DIG_FOOD_END:
        return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, TRICKY_VOICE_CHANNEL) != 0) {
        return 0;
    }
    objSoundStartTimed(obj, &state->soundState, sfxId, mouthOpenAngle, -1, 0);
    return 1;
}

/* Bit setter at bit 6 (0x40) of obj->_b8->_58. */
void trickySetSoundSuppressed(GameObject* obj, int value) {
    ((TrickyState*)obj->extra)->soundSuppressed = value;
}

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
