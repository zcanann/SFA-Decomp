#define BADDIE_MOVE_STATUS_SIGNED

#include "main/dll/player.h"
#include "dlls/object_descriptor.h"

#include "main/dll/modgfx_interface.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_0043_cameramodestaffanim.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/dll_0052_cameramodeforcebehind.h"
#include "main/dll/dll_0053_cameramodecloudrunner.h"
#include "main/dll/partfx_interface.h"
#include "game/objects/object_setup.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "sys/objects/lifecycle.h"
#include "dlls/objects/196_Tricky.h"
#include "main/debug.h"
#include "main/render_envfx_api.h"
#include "game/objects/object.h"
#include "main/model.h"
#include "main/maketex_api.h"
#include "main/objprint_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_render_api.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/player_spirit_api.h"
#include "main/dll/player_state_api.h"
#include "main/dll/player_motion_api.h"
#include "dlls/objects/229_Shield.h"
#include "dlls/objects/239.h"
#include "dlls/objects/284.h"
#include "dlls/objects/315_WallAnimato.h"
#include "dlls/objects/332.h"
#include "dlls/objects/469_DIM2Conveyo.h"
#include "dlls/objects/437.h"
#include "dlls/objects/488_SB_Galleon.h"
#include "dlls/objects/common/vehicle.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/dll/dll_01B5_lightfoot.h"
#include "dlls/objects/226.h"
#include "main/dll/viewfinder.h"
#include "main/sky_api.h"
#include "main/object_render.h"
#include "main/dll/dll_0015_curves.h"
#include "main/dll/dll_02AE_waterflowwe.h"
#include "track/intersect_api.h"
#include "main/track_dolphin_api.h"
#define TRACK_BBOX_MASK_TYPE s8
#include "main/track_bbox_api.h"
#undef TRACK_BBOX_MASK_TYPE
#include "main/vecmath_distance_api.h"

#include "sys/objects.h"
#include "main/curve_eval.h"
#include "main/objhits.h"
#include "main/objHitReact_types.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/stream_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/audio/music_api.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/lightmap_api.h"
#include "main/newshadows_audio_api.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/object_transform.h"
#include "types.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/objseq_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/dll/player_state.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/waterfx_interface.h"

#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/mm.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/dll/player_status.h"
#include "main/dll/player_target.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/frame_timing.h"
#include "main/byte_flags.h"
#include "main/pad.h"
#include "dolphin/mtx.h"
#include "dolphin/pad.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "string.h"
#include "main/dll/dll_002F_carryable.h"
#include "dlls/objects/260_SmallBasket.h"
#define FEAR_TEST_METER_POSITION_INT
#include "main/dll/dll_0000_gameui.h"
#undef FEAR_TEST_METER_POSITION_INT
#include "dlls/objects/201_Baddie.h"
#include "main/objtype.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/player_eye_anim.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/player_data.h"
#include "main/dll/tricky_api.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/player_control_interface.h"
#include "dlls/objects/242_iceblast.h"
#include "main/sky.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "dolphin/mtx/vec.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/gameloop_gamebit_api.h"
#include "track/intersect_render_setup_api.h"

#define CLAMP_EXPR(value, low, high) ((value) < (low) ? (low) : ((value) > (high) ? (high) : (value)))

#undef BADDIE_MOVE_STATUS_SIGNED

typedef struct PlayerSeqPlacement {
    ObjPlacement base;
    u8 pad18[8];
    s8 movementEnabled;
} PlayerSeqPlacement;

STATIC_ASSERT(offsetof(PlayerSeqPlacement, movementEnabled) == 0x20);

typedef struct MoveTable {
    u8 pad[0x7ac];
    s16 moves[8];
    f32 blend[8];
    f32 angles[8];
} MoveTable;

typedef struct EmitPlane {
    f32 nx;
    f32 ny;
    f32 nz;
    f32 d;
} EmitPlane;

typedef struct PlayerEffectPlacement {
    ObjPlacement base;
    u8 pad18;
    s8 mode;
    s16 flag;
    u8 pad1C[0x24 - 0x1C];
} PlayerEffectPlacement;

typedef struct PlayerIntersectLine {
    u8 pad00[3];
    u8 flags;
    s16 pointIndexA;
    s16 pointIndexB;
    u8 pad08[8];
} PlayerIntersectLine;

STATIC_ASSERT(sizeof(MoveTable) == 0x7fc);
STATIC_ASSERT(sizeof(EmitPlane) == 0x10);
STATIC_ASSERT(sizeof(PlayerEffectPlacement) == 0x24);
STATIC_ASSERT(sizeof(PlayerIntersectLine) == 0x10);

/* the player object's own group (joined at init, left on free) */
#define PLAYER_OBJGROUP           0x25
#define CONVEYOR_SURFACE_OBJGROUP 0x16
/* groups owned by other DLLs the player queries */
#define BABYCLOUDRUNNER_OBJGROUP 0x20 /* DLL 0x14C babycloudrunner (secondary) */
#define LANTERNFIREFLY_OBJGROUP  0x30 /* DLL 0x10C lanternfirefly */
#define MAGICPLANT_OBJGROUP_B    0x3e /* DLL 0xFE magicplant (group B) */

void playerUpdateTail(ModelFileHeader* unused1, ObjModel* unused2, f32* vec, int unused3, int mode, f32 angle);
void playerDoTailAnims(int obj, void* statep);
void playerUpdatePathEffectCountdown(GameObject* obj, PlayerState* inner);
int playerStopRidingObject(GameObject* obj);
int playerStateNoOp(void);
int playerState41(GameObject* obj, PlayerState* state, f32 fv);
int playerState40(GameObject* p1, PlayerState* obj);
int playerState3F(GameObject* obj, PlayerState* state);
int playerStateNop3E(void);
void playerStagedEndGuardAndMarkTeleported(GameObject* obj);
int playerState3D(GameObject* obj, PlayerState* state, f32 fv);
int playerState3C(GameObject* obj, PlayerState* state, f32 fv);
int playerState3B(GameObject* obj, PlayerState* state, f32 fv);
int playerState3A(GameObject* obj, PlayerState* state, f32 fv);
int playerState39(GameObject* obj, PlayerState* state, f32 fv);
int playerState38(GameObject* obj, PlayerState* state, f32 fv);
int playerState37(GameObject* obj, PlayerState* state);
void playerStagedResetAnimState(GameObject* obj);
int playerStateSuperQuake(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedSyncHitPosition(GameObject* obj);
int playerState35(GameObject* obj, PlayerState* state);
int playerState34(GameObject* obj, PlayerState* state);
int playerStateStaffLiftRock(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedResetAnimStateAndSyncPosition(GameObject* obj);
int playerStateStaffBoost(GameObject* obj, PlayerState* state, f32 fv);
int playerState31(GameObject* obj, PlayerState* p2);
int playerState30(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedRestoreCameraAndAnimState(GameObject* obj);
void playerStagedEndIceSpellAndRestoreCamera(GameObject* obj, BaddieState* p2);
int playerStateFireLaser(GameObject* obj, PlayerState* state, f32 fv);
int playerStateShootFireball(GameObject* obj, PlayerState* state, f32 fv);
int playerStateTryCastSpell(GameObject* obj, PlayerState* state, f32 fv);
int playerStateStopAimStaff(GameObject* obj, PlayerState* state, f32 fv);
int playerStateStartAimStaff(GameObject* obj, PlayerState* state, f32 fv);
int playerState29(GameObject* obj, PlayerState* state);
int playerState28(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedResetMoveHitState(GameObject* obj);
int playerState27(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedEndIceSpellAndSettleHeading(GameObject* obj, BaddieState* p2);
int playerState25(GameObject* obj, PlayerState* state, f32 updateRate);
int playerState24(GameObject* obj, PlayerState* state, f32 fv);
int playerState23(GameObject* obj, PlayerState* state, f32 fv);
int playerState22(GameObject* obj, PlayerState* state);
int playerState21(GameObject* obj, PlayerState* state, f32 fv);
int playerState20(GameObject* obj, PlayerState* state, f32 fv);
int playerState1F(GameObject* obj, PlayerState* state, f32 fv);
int playerState1E(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedRestoreCameraAndSyncPosition(GameObject* obj, BaddieState* state);
int playerState1C(GameObject* obj, PlayerState* state);
int playerState1B(GameObject* obj, PlayerState* state, f32 fv);
int playerStateOnCloudRunner(GameObject* obj, PlayerState* state);
int playerState19(GameObject* obj, PlayerState* state);
void playerStagedClearActiveMove(GameObject* obj);
int playerStateOnBike(GameObject* obj, PlayerState* state);
int playerState17(GameObject* p1, PlayerState* state);
int playerStateMountBike(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedRestoreCameraUnlessClimbing(GameObject* obj, BaddieState* p2);
void objUpdateHitboxPos(GameObject* obj);
int playerStateClimbDownFromWall(GameObject* obj, PlayerState* state);
int playerStateClimbUpFromWall(GameObject* obj, PlayerState* state);
int playerStateClimbOntoWall(GameObject* obj, PlayerState* state);
void playerPlayClimbingSound(GameObject* obj, PlayerState* p2);
int playerState11(GameObject* obj, PlayerState* state);
int playerStateSlideDownLadder(GameObject* obj, PlayerState* state, f32 fv);
int playerStateClimbOntoLadder(GameObject* obj, PlayerState* state, f32 fv);
int playerState0D(GameObject* obj, PlayerState* p2);
int playerState0B(GameObject* obj, PlayerState* state);
int playerStateGrabLedge(GameObject* obj, PlayerState* state);
int playerState09(GameObject* obj, PlayerState* state);
void playerResetMoveTables(GameObject* obj);
int playerStateThrowing(GameObject* obj, PlayerState* state);
void playerStagedMarkTeleported(GameObject* obj);
int playerState06(GameObject* obj, PlayerState* state);
int playerState05(GameObject* obj, PlayerState* state);
int playerState04(GameObject* obj, PlayerState* state, f32 fv);
int playerStateIceSpell(GameObject* obj, PlayerState* state, f32 fv);
void playerStagedRestoreDefaultControl(GameObject* obj, BaddieState* state);
int playerState00(GameObject* obj, PlayerState* state);
void playerGetMovementOrFacingDirection(GameObject* obj, int state, f32* out);
int playerBuildWallPlaneProbe(int p1, int p2, TrackLineIntersectResult* src, f32* vec, int out, int flag);
int playerBuildLedgeClimbProbe(int a, int b, void* c, int d, f32* e, f32 distance);
void playerRestoreAfterSequence(GameObject* obj, int p2, void* p3);
void playerCastIceSpell(GameObject* unused);
int playerCanUseStaffBooster(GameObject* obj, PlayerState* p2);
int playerCanCastPortalOpenSpell(GameObject* obj, PlayerState* p2);
int playerCanCastQuakeSpell(GameObject* obj, PlayerState* p2);
int playerCanCastBlasterSpell(GameObject* obj, PlayerState* p2, int p3);
int playerIsBlasterSpellAvailable(GameObject* obj, PlayerState* p2, int p3);
void playerSyncTransformToFocusObject(GameObject* p1, PlayerState* p2, GameObject* p3, int p4, int p5, int p6, int p7, int p8);
void playerFireCloudRunnerProjectile(GameObject* obj, PlayerState* state, f32 aimInputZ, f32 zero);
void playerSpawnRapidFireLaser(GameObject* unusedObj, PlayerState* unusedState, f32 unusedAimInput, f32 randomOffset);
void staffShootFireball(GameObject* obj, PlayerState* p2, f32 unused);
void objDoTeleportAnim(GameObject* obj);
void playerDie(GameObject* obj);
void playerCacheMoveRootHeights(GameObject* obj);
void playerDrawTeleportAnim(GameObject* obj);
void playerRenderPostEffects(GameObject* obj, PlayerState* inner, int a, int b, int c);
GameObject* playerFindNearestLookTarget(GameObject* obj);
void playerCastSpell(GameObject* a, PlayerState* b, int c);
void playerRefreshCollisionState(GameObject* obj, int p2, int flags);
void playerCalcWaterCurrent(f32* outX, f32* outZ, f32 p3, GameObject* player);
void playerUpdateLookAndLean(GameObject* obj, BaddieState* baddie, PlayerState* player, f32 turnInput);
void playerUpdateCameraTargetLookAngles(GameObject* obj, PlayerState* state, PlayerState* inner);
void playerUpdateLookAtTarget(GameObject* p1, PlayerState* p2, PlayerState* p3);
void playerSetMovingAnims(GameObject* p1, PlayerState* obj);
int playerUpdateFallingMotion(GameObject* obj, PlayerState* inner, PlayerState* p3);
void playerUpdateWaterMotion(GameObject* obj, PlayerState* inner, PlayerState* state);
int playerUpdateQuickTurn(GameObject* obj, PlayerState* inner, PlayerState* state);
void playerUpdateStaffAttack(GameObject* obj, PlayerState* state, PlayerState* p3);
void playerEnterDeepWater(GameObject* obj, PlayerState* inner, PlayerState* state);
void playerStartWallTransition(GameObject* obj, PlayerState* inner, PlayerState* state);
void playerStartStaffAttack(GameObject* obj, PlayerState* state, PlayerState* p3);
void staffAnimate(GameObject* obj, void* state, f32 dt);
void playerProcessQueuedItemCommand(GameObject* obj, PlayerState* state);
void playerRunActiveSpells(GameObject* obj, PlayerState* state);
void playerUpdateKnockbackTimers(GameObject* obj, PlayerState* state);
void playerStaffInit(GameObject* obj, PlayerState* state);
void playerDoEyeAnims(GameObject* obj, char* state);
void playerUpdateInputTimers(GameObject* obj, PlayerState* state, f32 fv);
void playerDoControls(GameObject* obj, PlayerState* state, f32 fv);
void playerUpdateSurfaceResponse(GameObject* obj, PlayerState* state, PlayerState* cfg, f32 dt);
void playerUpdateTargetSelection(GameObject* obj, PlayerState* inner, PlayerState* inner2);
void playerAnimate(GameObject* obj, PlayerState* state, f32 fv);
void playerInitFuncPtrs(void);
int playerBuildWallTransitionProbe(GameObject* obj, char* cam, f32* out, f32* vec, f32 fa, f32 fb);
int player_probeClimbable(GameObject* obj, int p4, TrackLineIntersectResult* src, int dst, int flag);
int playerStateClimbLedge(int obj, int state, f32 fv);
int player_SeqFn(int obj, int obj2, ObjSeqState* seq, int endFlag);
s16 playerSetMoveBlendFromPlane(GameObject* obj, int baseMoveId, int blendMoveId, int* blendAnchor, int* blendPlane,
                                f32 samplePhase, f32 moveStepScale, int axis, int flags);

static inline int staffCanContinueSpin(void* state)
{
    ByteFlags* bf = &((PlayerState*)state)->flags3F0;
    s16 t;

    if (bf->b10 || bf->b04 || bf->b08 || bf->b20 || ((PlayerState*)state)->baddie.controlMode == 0x36)
    {
        return 0;
    }

    t = ((PlayerState*)state)->baddie.controlMode;
    if ((u16)(t - 1) <= 1 || (u16)(t - 0x24) <= 1 || ((PlayerState*)state)->baddie.targetObj != NULL)
    {
        return 1;
    }
    return 0;
}

int lbl_80332EC0[5] = {0x1D, 0x1E, 0x1F, 0x20, 0x21};
GameObject* gPlayerSpawnedObjects[7] = {NULL};

s16 lbl_80332EF0[30] = {
    0x000E, 0x000E, 0x000F, 0x0010, 0x0046, 0x0046, 0x0047, 0x0014, 0x0014, 0x0014,
    0x000D, 0x0022, 0x000D, 0x0022, 0x0052, 0x0052, 0x0053, 0x0053, 0x0055, 0x0055,
    0x0056, 0x0056, 0x0058, 0x0058, 0x0059, 0x0059, 0x0414, 0x0414, 0x0415, 0x0415,
};

s16 lbl_80332F2C[14] = {
    0x002D, 0x002E, 0x0038, 0x0039, 0x002F, 0x0030, 0x0031,
    0x0032, 0x0025, 0x0029, 0x0033, 0x0034, 0x003A, 0x003E,
};

s16 lbl_80332F48[24] = {
    0x006E, 0x00B9, 0x00BD, 0x00BB, 0x006F, 0x00BA, 0x00BC, 0x00B8,
    0x00BE, 0x0068, 0x006C, 0x006A, 0x00BF, 0x006B, 0x006D, 0x0069,
    0x0066, 0x0071, 0x0072, 0x0403, 0x0404, 0x0070, 0x00C0, 0x0000,
};

s16 lbl_80332F78[8] = {
    0x0025, 0x0026, 0x0027, 0x0028, 0x0029, 0x002A, 0x002B, 0x002C,
};

s16 lbl_80332F88[28] = {
    0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F, 0x0040, 0x0041,
    0x3BA3, 0xD70A, 0x3E08, 0x7FCB, 0x3DDA, 0x6612, 0x3EB8, 0x4620,
    0x3EB1, 0x72EE, 0x3ED3, 0x92E1, 0x3ECC, 0xBFB1, 0x3F50, 0x2949,
    0x3F4C, 0xBFB1, 0x3F99, 0x8FC4,
};

typedef struct PlayerIntPair
{
    int v[2];
} PlayerIntPair;

static const PlayerIntPair sPlayerKnockFxIds = {{6, 8}};
static const CameraModeForceBehindInitParams sPlayerCamRange = {60.0f, 37.0f};
static const CameraModeForceBehindInitParams sPlayerColRange = {65.0f, 35.0f};

const u8 lbl_802C2B30[12][16] = {
    {0x40, 0x02, 0x01}, {0x40, 0x03, 0x01, 0x02}, {0x40, 0x04, 0x05, 0x06},
    {0x40, 0x06, 0x05, 0x07}, {0x40, 0x06, 0x03, 0x02}, {0x40, 0x03, 0x06, 0x07},
    {0x40, 0x03, 0x07, 0x01}, {0x40, 0x07, 0x05, 0x01}, {0x40, 0x04, 0x00, 0x01},
    {0x40, 0x04, 0x01, 0x05}, {0x40, 0x00, 0x04, 0x02}, {0x40, 0x02, 0x04, 0x06},
};

const f32 gPlayerTeleportBoxCorners[24] = {
    -14.5f, 20.0f, -14.5f, 14.5f, 20.0f, -14.5f, -14.5f, 20.0f, 14.5f, 14.5f, 20.0f, 14.5f,
    -14.5f, -7.0f, -14.5f, 14.5f, -7.0f, -14.5f, -14.5f, -7.0f, 14.5f, 14.5f, -7.0f, 14.5f,
};

const int lbl_802C2C50[6] = {0, 1, 2, 3, 4, 5};
const int lbl_802C2C68[4] = {6, 105, 105, 255};

void playerUpdateTail(ModelFileHeader* unused1, ObjModel* unused2, f32* vec, int unused3, int mode, f32 angle)
{
    f32 mtx1[12];
    f32 mtx2[12];

    switch (gPlayerModelChainStyle)
    {
    case 0:
        gPlayerModelChainOriginX = 0.12f;
        gPlayerModelChainOriginY = 0.675f;
        gPlayerModelChainOriginZ = -0.15f;
        break;
    case 1:
        gPlayerModelChainOriginX = 0.12f;
        gPlayerModelChainOriginY = 0.675f;
        gPlayerModelChainOriginZ = -0.15f;
        PSMTXRotRad((MtxPtr)mtx1, 'y', 0.03f * mathCosfHighPrecision(0.04f * angle - 1.1f * (f32)mode));
        PSMTXMultVecSR((MtxPtr)mtx1, (Vec*)vec, (Vec*)vec);
        break;
    case 4:
        gPlayerModelChainOriginX = 0.5f;
        gPlayerModelChainOriginY = 0.675f;
        gPlayerModelChainOriginZ = -0.15f;
        PSMTXRotRad((MtxPtr)mtx1, 'y', 0.03f * mathCosfHighPrecision(0.04f * angle - 1.1f * (f32)mode));
        PSMTXMultVecSR((MtxPtr)mtx1, (Vec*)vec, (Vec*)vec);
        break;
    case 5:
        gPlayerModelChainOriginX = 0.4f;
        gPlayerModelChainOriginY = 0.675f;
        gPlayerModelChainOriginZ = -0.15f;
        PSMTXRotRad((MtxPtr)mtx1, 'y', 0.03f * mathCosfHighPrecision(0.04f * angle - 1.1f * (f32)mode));
        PSMTXMultVecSR((MtxPtr)mtx1, (Vec*)vec, (Vec*)vec);
        break;
    case 2:
        gPlayerModelChainOriginX = 0.75f;
        gPlayerModelChainOriginY = 0.0f;
        gPlayerModelChainOriginZ = -0.1f;
        PSMTXRotRad((MtxPtr)mtx1, 'y', 0.3f * mathCosfHighPrecision(0.5f * angle));
        PSMTXRotRad((MtxPtr)mtx2, 'x', 0.175f);
        PSMTXConcat((MtxPtr)mtx2, (MtxPtr)mtx1, (MtxPtr)mtx1);
        PSMTXMultVecSR((MtxPtr)mtx1, (Vec*)vec, (Vec*)vec);
        break;
    case 3:
        gPlayerModelChainOriginX = 0.12f;
        gPlayerModelChainOriginY = 0.675f;
        gPlayerModelChainOriginZ = -0.15f;
        PSMTXRotRad((MtxPtr)mtx1, 'y', 0.15f * mathCosfHighPrecision(0.15f * angle - 1.3f * (f32)mode));
        if (mode == 1)
        {
            PSMTXRotRad((MtxPtr)mtx2, 'x', 0.125f);
            PSMTXConcat((MtxPtr)mtx2, (MtxPtr)mtx1, (MtxPtr)mtx1);
        }
        PSMTXMultVecSR((MtxPtr)mtx1, (Vec*)vec, (Vec*)vec);
        break;
    }
}

void playerDoTailAnims(int obj, void* statep)
{
    ObjModel* state = (ObjModel*)statep;
    ModelFileHeader* v = state->file;
    if ((void*)gPlayerModelChain != NULL)
    {
        ObjModelChain_SetOrigin((ObjModelChain*)gPlayerModelChain, gPlayerModelChainOriginX, gPlayerModelChainOriginY, gPlayerModelChainOriginZ);
        ObjModelChain_Update(state, v, (ObjModelChain*)gPlayerModelChain, playerUpdateTail);
    }
}

static inline ObjModel* Player_GetActiveModel(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

static inline ObjHitsPriorityState* Player_GetObjHitsState(GameObject* obj)
{
    return (ObjHitsPriorityState*)obj->anim.hitReactState;
}

typedef struct
{
    u8 pad0[0xc];
    f32 fz0;
    f32 fz1;
    u8 pad1[8];
    f32 nx;
    f32 ny;
    f32 nz;
    f32 nw;
    u8 pad2[0x10];
    f32 ga;
    f32 gb;
    u8 pad3[4];
    f32 gt;
    u8 pad4[6];
    s8 flags;
    u8 pad5;
} WallHit;



static inline void playerFreeSpawnedObjects(GameObject** p, int i, GameObject* hi) {
    do {
        if (*p != NULL) {
            Obj_FreeObject(*p);
            *p = hi;
        }
        p++;
        i++;
    } while (i < 7);
}

typedef struct
{
    u8 pad[0x1ba8];
    int moveA[4];
    int moveB[4];
    int moveC[4];
    f32 spdD[4];
    f32 spdE[4];
} HeadMoveTable;

typedef struct
{
    int a[6];
} UiMsgBlock;


typedef struct
{
    s16 rx, ry, rz;
    f32 scale;
    f32 x, y, z;
} HitFxDesc;

static inline void Player_ApplyStatusDamage(GameObject* obj, int param)
{
    PlayerStatus* pc;
    PlayerState* in2;
    int v;

    in2 = obj->extra;
    pc = in2->playerStatus;
    v = pc->health;
    v -= param;
    if (v < 0)
    {
        v = 0;
    }
    else if (v > pc->maxHealth)
    {
        v = pc->maxHealth;
    }
    pc->health = (s8)v;
    if ((in2->playerStatus)->health <= 0)
    {
        playerDie(obj);
    }
}

void playerUpdatePathEffectCountdown(GameObject* obj, PlayerState* inner)
{
    f32 outvec[3];
    struct
    {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 mtx[12];
    u8 cnt = ((PlayerState*)inner)->stepDustCount;

    if (cnt != 0)
    {
        if (cnt & 1)
        {
            int t;
            memcpy(mtx, (void*)ObjPath_GetPointModelMtx(obj, 5), 0x30);
            mtx[3] = 0.0f;
            mtx[7] = 0.0f;
            mtx[11] = 0.0f;
            buf.x = 0.0f;
            buf.y = 0.0f;
            t = ((PlayerState*)inner)->stepDustCount;
            buf.z = -0.015f * (f32)(int)randomGetRange(t + 4, t + 8);
            PSMTXMultVec((MtxPtr)mtx, (Vec*)&buf.x, (Vec*)outvec);
            buf.x = 0.0f;
            buf.y = -1.0f;
            buf.z = -2.5f;
            ObjPath_GetPointWorldPosition(obj, 0xa, &buf.x, &buf.y, &buf.z, 1);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7e5, &buf, 0x200001, -1, outvec);
        }
        ((PlayerState*)inner)->stepDustCount -= 1;
    }
}

int playerStopRidingObject(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    GameObject* sub;

    if ((void*)obj == NULL)
    {
        return 0;
    }
    (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);

    sub = inner->focusObject;
    if ((void*)sub != NULL)
    {
        VEHICLE_INTERFACE(sub)->setMountState(sub, VEHICLE_NoRider);
        (*gCameraInterface)->setFocus((void*)obj, 0);
        obj->anim.flags &= ~8;
        obj->anim.modelState->flags = obj->anim.modelState->flags & 0xFFFFFEFFFLL;
        inner->focusObject = NULL;
        obj->anim.activeMove = -1;
        (*gPlayerInterface)->setState(obj, inner, 1);
        inner->baddie.stateExitFn = (BaddieStateExitFn)playerStagedRestoreDefaultControl;
        Music_Trigger(MUSICTRIG_inside_warlock, 0);
        Music_Trigger(MUSICTRIG_drako_2, 0);
        Music_Trigger(MUSICTRIG_starfox_rwing_1_e6, 0);
        Music_Trigger(MUSICTRIG_WLC_Puzzle, 0);
        return 1;
    }
    return 0;
}

PlayerAnimSpeedTuning gPlayerAnimSpeedThresholds = {
    {0.005f, 0.1f, 0.08f, 0.55f, 0.53f, 2.3993998f},
    {{0.0f, 0.0f, 0.0f}, {0.0f, 17.0f, 0.0f}},
    {0.0f, 5.0f, 0.0f},
    {114, 908, 399, 1046, 1049, 140, 1156, 1048, 1812},
    {1156, 1049, 1048, 1812},
    {0.002f, 0.003f, 0.0015f, 0.008f},
    {0.0022f, 0.002f, 0.0015f, 0.008f},
};

s16 gPlayerMoveTableA[96] = {
    0,    0,    0,    0,    22,   32,   31,   22,
    22,   32,   31,   22,   2,    122,  121,  2,
    3,    36,   35,   3,    3,    3,    3,    3,
    30,   69,   0,    0,    0,    231,  230,  232,
    0,    1072, 1072, 1072, 1073, 1075, 1074, 1073,
    1073, 1075, 1074, 1073, 1053, 1055, 1054, 1053,
    1082, 1084, 1083, 1082, 1082, 1084, 1083, 1082,
    30,   69,   0,    0,    0,    231,  242,  232,
    1043, 1043, 1043, 1043, 76,   76,   76,   76,
    76,   76,   76,   76,   115,  115,  115,  115,
    116,  116,  116,  116,  116,  116,  116,  116,
    1043, 1043, 1043, 1043, 1043, 1043, 1043, 1043,
};

s16 lbl_80333110[128] = {8,    8,    8,    8,    7,    7,    7,    7,    7,    7,    7,    7,    1051, 1051, 1051, 1051,
                         1051, 1051, 1051, 1051, 1051, 1051, 1051, 1051, 1093, 1093, 1457, 1090, 1092, 235,  234,  8,
                         140,  140,  140,  140,  147,  148,  149,  150,  147,  148,  149,  150,  147,  148,  149,  150,
                         147,  148,  149,  150,  147,  148,  149,  150,  1093, 1093, 1457, 1090, 1092, 235,  234,  8,
                         91,   91,   91,   91,   214,  215,  216,  217,  214,  215,  216,  217,  214,  215,  216,  217,
                         214,  215,  216,  217,  214,  215,  216,  217,  1093, 1093, 1457, 1090, 1092, 235,  234,  8,
                         1043, 1043, 1043, 1043, 218,  219,  131,  220,  218,  219,  131,  220,  218,  219,  131,  220,
                         218,  219,  131,  220,  218,  219,  131,  220,  1093, 1093, 1457, 1090, 1092, 235,  234,  8};
s16 gPlayerMoveTableB[14] = {140, 140, 140, 140, 147, 148, 149, 150, 147, 148, 149, 150, 140, 0};
u8 gPlayerSurfacePfxModeTable[36] = {0, 1, 2, 3, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 5, 0, 0, 0,
                                     0, 0, 0, 3, 5, 0, 4, 6, 0, 7, 0, 0, 0, 0, 8, 0, 9, 0};
f32 gPlayerDefaultMoveParams[24] = {
    0.005f, 0.13329999f, 0.106639996f, 0.71982f, 0.69315994f, 1.2530199f,
    1.22636f, 1.8928598f, 1.8661999f, 2.3993998f, 2.3793998f, 2.3993998f,
    0.005f, 0.012f, 0.01f, 0.26f, 0.23f, 0.35f,
    0.3f, 0.52f, 0.5f, 0.7f, 0.68f, 0.7f,
};
PlayerMotionTuning gPlayerMotionTuning = {
    {
        {23, 201, 24, 25, 26, 193, 195, 194, 205, 206, -1, -1},
        {123, 123, 123, 123, 123, 123, 123, 123, 123, 123, -1, -1},
        {248, 248, 248, 248, 248, 248, 246, 247, 249, 250, -1, -1},
        {252, 252, 252, 252, 252, 252, 252, 252, 252, 252, -1, -1},
    },
    {
        12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f,
        12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f, 12.0f,
        12.0f, 12.0f, 13.0f, 14.0f, 15.0f, 16.0f, 16.0f, 16.0f,
        16.0f, 24.0f, 24.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f,
        32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f, 32.0f,
        32.0f,
    },
    {
        8.0f, 8.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f,
    },
    {
        14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f,
        14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 13.0f, 12.0f, 11.0f,
        10.0f, 9.6f, 8.0f, 7.2f, 6.8f, 6.8f, 6.8f, 6.8f,
        6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
        6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
        6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
    },
    {
        8.0f, 8.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f, 5.0f,
        5.0f,
    },
    {
        14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 14.0f,
        14.0f, 14.0f, 14.0f, 14.0f, 14.0f, 13.0f, 12.0f, 11.0f,
        10.0f, 9.6f, 8.0f, 7.2f, 6.8f, 6.8f, 6.8f, 6.8f,
        6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
        6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
        6.8f, 6.8f, 6.8f, 6.8f, 6.8f, 6.8f,
    },
};
s16 lbl_8033366C[24] = {168,   167,    166,   165,    92,    1071,   92,    21,     15692, -13107, 15692, -13107,
                        15692, -13107, 15692, -13107, 15692, -13107, 15820, -13107, 15692, -13107, 0,     0};
f32 lbl_8033369C[8] = {0.01f, 0.02f, 0.02f, 0.015f, 0.015f, 0.01f, 0.02f, 0.005f};
s16 gPlayerMoveSlotTable[44] = {1113, 1114, 0,    0,    0,    0,   0,    1120, 0,    1122, 0,    1124, 1125, 1126, 0,
                                1128, 1129, 151,  152,  153,  154, 1130, 1131, 1109, 0,    0,    1112, 1132, 1133, 1134,
                                1135, 1136, 1137, 1138, 1139, 0,   0,    0,    0,    0,    1145, 1152, 1129, 0};

PlayerMoveSlot gPlayerMoveSlotData[28] = {
    {
        0, 0, 0, 0, 210,
        {20, 20, 20},
        1, {10, 10, 10, 10, 10}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 10, {0, 0, 0},
        {0.1f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        1, 0, 16, 0, 210,
        {4, 4, 4},
        1, {18, 18, 18, 18, 18}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.1f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        2, 0, 27, 0, 210,
        {0, 0, 0},
        1, {21, 21, 21, 21, 21}, {0, 0},
        0.025f, 0.0f, 0.6f, 0.6f, 0.9f,
        {0.42f, -1.0f, -1.0f},
        {0.52f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        3, 0, 33, 0, 210,
        {16, 4, 4},
        1, {14, 14, 14, 14, 14}, {0, 0},
        0.025f, 0.0f, 0.6f, 0.6f, 0.8f,
        {0.35f, -1.0f, -1.0f},
        {0.45f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        4, 0, 31, 0, 210,
        {8, 4, 4},
        1, {14, 14, 14, 14, 14}, {0, 0},
        0.025f, 0.0f, 0.6f, 0.6f, 0.8f,
        {0.35f, -1.0f, -1.0f},
        {0.45f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        5, 0, 17, 0, 210,
        {4, 4, 4},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.5f,
        {-1.0f, -1.0f, -1.0f},
        {-1.0f, -1.0f, -1.0f},
        0.0f, 0.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        6, 0, 19, 0, 210,
        {4, 4, 4},
        1, {16, 13, 16, 13, 16}, {0, 0},
        0.03f, 0.0f, 1.0f, 0.5f, 0.5f,
        {-1.0f, -1.0f, -1.0f},
        {-1.0f, -1.0f, -1.0f},
        0.0f, 0.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        7, 0, 20, 0, 210,
        {4, 4, 4},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.025f, 0.0f, 1.0f, 0.5f, 0.5f,
        {-1.0f, -1.0f, -1.0f},
        {-1.0f, -1.0f, -1.0f},
        0.0f, 0.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        8, 0, 17, 0, 210,
        {4, 4, 4},
        1, {13, 13, 13, 13, 13}, {0, 0},
        0.025f, 0.0f, 0.75f, 0.75f, 0.8f,
        {-1.0f, -1.0f, -1.0f},
        {-1.0f, -1.0f, -1.0f},
        0.0f, 0.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 13, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        9, 0, 18, 0, 210,
        {4, 4, 4},
        1, {13, 13, 13, 13, 13}, {0, 0},
        0.025f, 0.0f, 0.75f, 0.75f, 0.8f,
        {-1.0f, -1.0f, -1.0f},
        {-1.0f, -1.0f, -1.0f},
        0.0f, 0.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 13, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        10, 0, 22, 0, 210,
        {12, 0, 0},
        1, {12, 12, 14, 12, 19}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 1.1f, 11, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        11, 0, 21, 0, 210,
        {20, 0, 0},
        1, {10, 10, 10, 10, 10}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 10, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        12, 0, 11, 0, 210,
        {12, 12, 0},
        1, {15, 15, 15, 15, 15}, {0, 0},
        0.015f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.2f, 0.36f, -1.0f},
        {0.3f, 0.44f, -1.0f},
        0.0f, 0.45f, 0.2f, 0.35f, 0.0f,
        0, {2, 3, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 3.0f, 0.0f},
        {0.9f, 0.9f, 0.0f},
        1, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.1f, 0.2f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        13, 0, 7, 0, 210,
        {0, 0, 0},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.04f, 0.0f, 1.0f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.52f, -1.0f, -1.0f},
        0.0f, 0.87f, 0.2f, 0.35f, 0.0f,
        0, {2, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.0f, 0.0f, 0.0f},
        {0.0f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.3f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        14, 0, 9, 0, 210,
        {20, 12, 0},
        1, {27, 27, 27, 27, 27}, {0, 0},
        0.02f, 0.0f, 1.0f, 0.8f, 0.8f,
        {0.2f, 0.63f, -1.0f},
        {0.27f, 0.7f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {2.5f, 2.0f, 0.0f},
        {0.9f, 0.9f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.2f, 0.2f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        15, 0, 15, 0, 210,
        {20, 0, 0},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.015f, 0.0f, 1.0f, 0.5f, 0.5f,
        {0.4f, -1.0f, -1.0f},
        {0.5f, -1.0f, -1.0f},
        0.0f, 0.65f, 0.2f, 0.35f, 0.0f,
        0, {3, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {10.0f, 0.0f, 0.0f},
        {0.84f, 0.0f, 0.0f},
        1, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.3f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        16, 0, 28, 0, 210,
        {4, 4, 0},
        1, {23, 23, 23, 23, 23}, {0, 0},
        0.017f, 0.0f, 0.6f, 0.6f, 1.0f,
        {0.38f, -1.0f, -1.0f},
        {0.44f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.35f, 0.42f, 0.0f,
        0, {1, 1, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {2.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        1, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.2f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        17, 0, 30, 0, 210,
        {20, 0, 0},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.008f, 0.0f, 1.0f, 0.5f, 0.5f,
        {0.63f, -1.0f, -1.0f},
        {0.7f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {10.0f, 0.0f, 0.0f},
        {0.84f, 0.0f, 0.0f},
        1, {0, 0, 0}, 0.0f, -1, {0, 0, 0},
        {0.3f, 0.0f, 0.0f},
        0.15f, 0.5f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        18, 0, 34, 0, 210,
        {0, 0, 0},
        1, {12, 12, 14, 12, 19}, {0, 0},
        0.022f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.4f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 1.1f, 20, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        19, 0, 12, 0, 210,
        {0, 4, 8},
        1, {17, 17, 17, 17, 17}, {0, 0},
        0.01f, 0.5f, 0.9f, 0.9f, 0.9f,
        {0.15f, 0.42f, 0.68f},
        {0.25f, 0.5f, 0.75f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {4, 4, 4},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 1.0f, 0.0f},
        {0.9f, 0.9f, 0.9f},
        2, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.1f, 0.1f, 0.2f},
        -1.0f, 0.0f,
        {5, 5, 12}, {3, 3, 2}, {0, 0},
    },
    {
        20, 0, 16, 0, 210,
        {4, 4, 4},
        1, {18, 18, 18, 18, 18}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 18, {0, 0, 0},
        {0.1f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        21, 0, 16, 0, 210,
        {4, 4, 4},
        1, {12, 12, 14, 12, 19}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 1.1f, 22, {0, 0, 0},
        {0.1f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        22, 0, 34, 0, 210,
        {0, 0, 0},
        1, {21, 21, 21, 21, 21}, {0, 0},
        0.025f, 0.0f, 0.6f, 0.6f, 0.9f,
        {0.42f, -1.0f, -1.0f},
        {0.52f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 1.1f, 21, {0, 0, 0},
        {0.1f, 0.0f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        23, 0, 13, 0, 210,
        {16, 4, 4},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.01f, 0.0f, 0.8f, 0.8f, 0.8f,
        {0.52f, -1.0f, -1.0f},
        {0.62f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 1, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.2f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        24, 0, 40, 0, 210,
        {16, 4, 4},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.01f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {3, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.2f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        25, 0, 0, 0, 210,
        {20, 20, 20},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.32f, -1.0f, -1.0f},
        {0.42f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {0, 0, 0},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {1.0f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, -1, {0, 0, 0},
        {0.1f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        26, 0, 42, 0, 210,
        {4, 4, 4},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.025f, 0.0f, 0.5f, 0.5f, 0.9f,
        {0.35f, -1.0f, -1.0f},
        {0.45f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 0, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, -1, {0, 0, 0},
        {0.1f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
    {
        27, 0, 41, 0, 210,
        {4, 4, 4},
        1, {-1, -1, -1, -1, -1}, {0, 0},
        0.01f, 0.0f, 0.8f, 0.8f, 0.8f,
        {0.52f, -1.0f, -1.0f},
        {0.62f, -1.0f, -1.0f},
        0.0f, 1.0f, 0.2f, 0.35f, 0.0f,
        0, {1, 1, 1},
        {0, NULL},
        0.0f, 1, {0, 0, 0},
        {0.8f, 0.0f, 0.0f},
        {0.9f, 0.0f, 0.0f},
        0, {0, 0, 0}, 0.0f, 0, {0, 0, 0},
        {0.3f, 0.1f, 0.0f},
        -1.0f, 0.0f,
        {0, 0, 0}, {0, 0, 0}, {0, 0},
    },
};

s16 gPlayerSpellGameBits[52] = {
    45,     64,    471,    1469,  1486,   1532,  1911,   2391,  2392,  263,   3157,  0,      0,
    77,     0,     101,    0,     90,     0,     78,     0,     1024,  0,     1033,  0,      75,
    0,      74,    0,      1025,  0,      99,    0,      73,    0,     72,    15523, -10486, 15523,
    -10486, 15564, -13107, 15564, -13107, 15428, -25690, 15333, 24642, 15379, 29884, 15379,  29884,
};

void playerSetStateValue(GameObject* obj, int sel, f32 fval) {
    PlayerState* state = obj->extra;
    int iv = (int)fval;
    switch (sel) {
    case 1: {
        if (state->queuedBitCount < 4) {
            state->queuedBits[state->queuedBitCount++] = (u8)iv;
        }
        break;
    }
    case 6:
        (*gPlayerInterface)->setState(obj, (void*)state, 0x3f);
        break;
    case 5:
        (*gPlayerInterface)->setState(obj, (void*)state, 1);
        state->baddie.stateExitFn = (BaddieStateExitFn)playerStagedRestoreDefaultControl;
        break;
    case 10:
        state->flags360 |= 0x80000LL;
        break;
    case 11:
        state->flags360 &= ~0x80000LL;
        break;
    }
}

int playerGetStateValue(GameObject* obj, int sel) {
    PlayerState* state = obj->extra;
    switch (sel) {
    case 1:
        if ((state->baddie.queuedBitMask & 0x1000) != 0 || (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0) {
            return 0;
        }
        return 1;
    case 2:
        switch (state->baddie.controlMode) {
        case 1:
            return 0;
        case 2: {
            s16* list;
            s16 key;
            int i;
            i = 0;
            list = state->moveAnimIds;
            key = obj->anim.currentMove;
            while (key != *list && i < 0x14) {
                list += 4;
                i += 4;
            }
            return i / 4;
        }
        default:
            return 5;
        }
    case 9:
        return state->baddie.stateTag == 3;
    case 10:
        return state->flags360 & 0x200;
    case 11:
        return state->flags360 & 0x100;
    case 13:
        return state->baddie.hasTarget == 1;
    case 14:
        return state->animState;
    case 18: {
        GameObject* p = state->focusObject;
        if (p != 0) {
            return p->anim.romDefNo;
        }
        return 0;
    }
    }
    return 0;
}

void objSetPos(GameObject* obj, f32 x, f32 y, f32 z) {
    PlayerState* inner = obj->extra;
    obj->anim.previousWorldPosX = x;
    obj->anim.previousLocalPosX = x;
    obj->anim.worldPosX = x;
    obj->anim.localPosX = x;
    obj->anim.previousWorldPosY = y;
    obj->anim.previousLocalPosY = y;
    obj->anim.worldPosY = y;
    obj->anim.localPosY = y;
    obj->anim.previousWorldPosZ = z;
    obj->anim.previousLocalPosZ = z;
    obj->anim.worldPosZ = z;
    obj->anim.localPosZ = z;
    playerRefreshCollisionState(obj, (int)inner, 7);
    (*gPlayerInterface)->setState(obj, (void*)inner, 1);
    inner->baddie.stateExitFn = (BaddieStateExitFn)playerStagedRestoreDefaultControl;
}

int objIsCurModelNotZero(void* obj)
{
    if (obj != NULL)
    {
        return ((ObjAnimComponent*)obj)->bankIndex != 0;
    }
    return 0;
}

int isTrickyNear(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->curAnimId != 0x44;
}

int playerCanEnterStaffCombatCamera(GameObject* player)
{
    PlayerState* inner = player->extra;
    return inner->flags3F0.b02 == 0;
}

int playerIsTargetSuppressed(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->targetSuppressTimer > 0.0f;
}

int playerIsInWater(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->waterDepth > 2.0f;
}

static int playerIsInDeepWater(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->waterDepth > 10.0f;
}

int playerIsQuakeShockwaveActive(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 0x36 && inner->flags3F3.b10;
}

int playerFindNearestFirefly(GameObject* player)
{
    f32 dist = 300.0f;
    return (int)objGetNearestTypeTo(LANTERNFIREFLY_OBJGROUP, player, &dist);
}

static int playerIsAtFullSpeed(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->targetAnimSpeed >= 1.0f;
}

int playerIsClimbingWall(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 0x13;
}

int playerIsDisguised(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->flags3F3.b08;
}

int playerIsPathFollowing(GameObject* player)
{
    PlayerState* inner = player->extra;
    return inner->flags3F4.b40;
}

void staffToggle(GameObject* obj, int a)
{
    PlayerState* inner = obj->extra;

    if (gPlayerPathObject == NULL)
    {
        return;
    }
    if (inner->flags3F4.b40 == a)
    {
        return;
    }
    if (a == 0)
    {
        if (gPlayerPathObject != NULL)
        {
            gPlayerPathObject->anim.flags |= 0x4000;
            if (gPlayerPathObject != NULL && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 1;
                inner->flags3F4.b08 = 1;
            }
            mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 1);
            mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 1);
        }
    }
    else
    {
        if (gPlayerPathObject != NULL)
        {
            if (gPlayerPathObject != NULL && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 4;
                inner->flags3F4.b08 = 1;
            }
            gPlayerPathObject->anim.flags &= ~0x4000;
            mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 0);
            mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 0);
        }
    }
    inner->flags3F4.b40 = a;
}

void playerSetDisguised(GameObject* obj, int mode)
{
    PlayerState* inner = obj->extra;
    ObjModel* oldModel;
    ObjModel* newModel;
    void* tricky;

    objFindJointPoseVector(obj, 0);
    objFindJointPoseVector(obj, 9);
    if (mode != 0)
    {
        staffToggle(obj, 0);
        inner->flags3F3.b08 = 1;
        tricky = getTrickyObject();
        if (tricky != NULL)
        {
            trickyImpress(tricky);
        }
        mainSetBits(GAMEBIT_PlayerIsDisguised, 1);
        Sfx_PlayFromObject(obj, SFXTRIG_en_lrope_powerup);
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x801, NULL, 0x50, NULL);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 2);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void*)*(int*)((char*)newModel + 0x2c), (void*)*(int*)((char*)oldModel + 0x2c), 0x68);
        memcpy((void*)*(int*)((char*)newModel + 0x30), (void*)*(int*)((char*)oldModel + 0x30), 0x68);
        if (mode == 2)
        {
            inner->flags3F4.b80 = 1;
        }
    }
    else
    {
        staffToggle(obj, 1);
        inner->flags3F3.b08 = 0;
        inner->flags3F4.b80 = 0;
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x801, NULL, 0x50, NULL);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 1);
        newModel = Obj_GetActiveModel(obj);
        memcpy(newModel->animStateA, oldModel->animStateA, 0x68);
        memcpy(newModel->animStateB, oldModel->animStateB, 0x68);
        mainSetBits(GAMEBIT_PlayerIsDisguised, 0);
        Sfx_PlayFromObject(obj, SFXTRIG_en_lrope_powerup);
    }
}

int playerGetAimScreenPos(GameObject* obj, f32* p2, f32* p3)
{
    PlayerState* inner = obj->extra;
    if (inner == NULL || getCurSeqNo() != 0)
    {
        return 0;
    }
    if ((inner->flags360 & 0x400) != 0u)
    {
        *p2 = inner->aimScreenX;
        *p3 = inner->aimScreenY;
        return 1;
    }
    return 0;
}

void playerApplyHorizontalVelocity_nop(int obj, f32 xVelocity, f32 zVelocity)
{
}

void playerSetPendingBoneEffect(GameObject* player, s16 effectId)
{
    PlayerState* inner = player->extra;
    inner->pendingBoneEffectId = effectId;
}

void playerGetFxOffsets(GameObject* obj, f32** outFxOffsets)
{
    PlayerState* inner = obj->extra;
    if (outFxOffsets == NULL)
    {
        return;
    }
    *outFxOffsets = inner->footPoints[0];
}

f32 playerGetAnimSpeed(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.animSpeedA;
}

GameObject* playerGetTargetObject(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.targetObj;
}

void playerTeleport(GameObject* obj, const Vec3f* position, const Vec3s* rotation, int unused)
{
    PlayerState* inner = obj->extra;
    inner->flags360 &= ~0x4000LL;
    if (position != NULL)
    {
        obj->anim.localPosX = position->x;
        obj->anim.localPosY = position->y;
        obj->anim.localPosZ = position->z;
        inner->flags360 |= 0x4000LL;
    }
    if (rotation != NULL)
    {
        s16 t = rotation->x;
        obj->anim.rotX = t;
        inner->targetYaw = t;
        inner->yaw = t;
        inner->yaw = inner->targetYaw;
        obj->anim.rotY = rotation->y;
        obj->anim.rotZ = rotation->z;
        inner->flags360 |= 0x4000LL;
    }
}

void playerGetMoveAndChargeLevel(GameObject* obj, int* outMove, f32* outChargeLevel)
{
    PlayerState* inner = obj->extra;
    *outMove = obj->anim.currentMove;
    if (inner->baddie.controlMode == 0x26)
    {
        *outChargeLevel = inner->boulderChargeLevel;
    }
    else
    {
        *outChargeLevel = inner->chargeLevel;
    }
}

void objSetXRot(GameObject* obj, int v)
{
    PlayerState* inner = obj->extra;
    obj->anim.rotX = v;
    inner->targetYaw = v;
    inner->yaw = v;
    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
}

void playerSetHitReactionVariant(GameObject* unusedPlayer, u8 type)
{
    u8 v = type;
    if (type > 2)
    {
        v = 0;
    }
    gPlayerHitReactionVariant = v;
}

f32 playerGetVerticalVel(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->verticalVel;
}

void playerSetVerticalVel(GameObject* obj, f32 v)
{
    PlayerState* inner = obj->extra;
    inner->verticalVel = v;
}

int Obj_IsParentSlackClear(GameObject* obj)
{
    return (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0;
}

int playerIsInNormalControlUndisguisedOnLand(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ByteFlags* f = &inner->flags3F0;
    s16 s;
    if (f->b04 || f->b08 || f->b20 || f->b10 || inner->flags3F3.b08)
    {
        return 0;
    }
    s = inner->baddie.controlMode;
    if (s == 1 || s == 2)
    {
        return 1;
    }
    return 0;
}

int playerIsInNormalControl(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ByteFlags* f = &inner->flags3F0;
    s16 s;
    if (f->b04 || f->b08 || f->b10)
    {
        return 0;
    }
    s = inner->baddie.controlMode;
    if (s == 1 || s == 2)
    {
        return 1;
    }
    return 0;
}

int playerIsNotAttacking(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode != 0x26;
}

int playerCanUseCombatTargeting(GameObject* player)
{
    PlayerState* state = player->extra;
    if (((player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 &&
         state->flags3F2.b80 == 0) ||
        state->flags3F0.b04 || state->flags3F0.b08 ||
        state->flags3F0.b20 || state->heldObj != NULL ||
        state->flags3F0.b02)
    {
        return 0;
    }
    if (state->baddie.controlMode == 1 || state->baddie.controlMode == 2 || state->baddie.controlMode == 0x26 ||
        (state->baddie.controlMode == 0x18 &&
         (mainGetBit(GAMEBIT_NW_SnowHorn03E3) || state->focusObject->anim.romDefNo == 0x416)) ||
        state->baddie.targetObj != NULL)
    {
        return 1;
    }
    return 0;
}

u8 playerIsPushingObject(GameObject* obj, GameObject* otherObj, u8* out)
{
    PlayerState* inner = obj->extra;
    *out = inner->surfaceDir;
    return inner->baddie.controlMode == 0x1c && inner->contactObject == otherObj;
}

int playerGetFlags3F0Bit5(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->flags3F0.b20;
}

int EmissionController_IsLingering(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->emissionState;
}

int playerIsSequenceRenderSuppressed(GameObject* player)
{
    PlayerState* inner = player->extra;
    return inner->flags360 & 1;
}

void playerSetHaveSpell(GameObject* obj, int spell, int set)
{
    PlayerState* inner = obj->extra;
    if ((u32)spell > 0xb)
    {
        return;
    }
    if (set != 0)
    {
        inner->staffUnlockedFlags |= (1 << spell);
    }
    else
    {
        inner->staffUnlockedFlags &= ~(1 << spell);
    }
    mainSetBits(gPlayerSpellGameBits[spell], set);
}

int playerHasSpell(GameObject* obj, int spell)
{
    PlayerState* inner = obj->extra;
    if ((u32)spell > 0xb)
    {
        return 0;
    }
    return inner->staffUnlockedFlags & (1 << spell);
}

void objSetAnimStateFlags(GameObject* obj, int flag, int set)
{
    PlayerState* inner = obj->extra;
    if (set != 0)
    {
        (inner->playerStatus)->animStateFlags |= flag;
    }
    else
    {
        (inner->playerStatus)->animStateFlags &= ~flag;
    }
}

int objGetAnimStateFlags(GameObject* obj, int flag)
{
    PlayerState* inner = obj->extra;
    return (inner->playerStatus)->animStateFlags & flag;
}

int playerGetTimeScale(GameObject* obj, f32* out)
{
    PlayerState* inner = obj->extra;
    *out = inner->timeScale;
    return inner->timeScaleMode;
}

int playerSetHeldObject(GameObject* obj, GameObject* heldObj)
{
    PlayerState* inner = obj->extra;
    GameObject* sub;

    if (heldObj != NULL)
    {
        inner->heldObj = heldObj;
        (*gPlayerInterface)->setState(obj, inner, 5);
        inner->baddie.stateExitFn = (BaddieStateExitFn)playerStagedMarkTeleported;
    }
    else if (inner->heldObj != NULL)
    {
        inner->isHoldingObject = 0;
        sub = inner->heldObj;
        if (sub != NULL)
        {
            s16 id = sub->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
            {
                SmallBasket_throw(sub);
            }
            else
            {
                Carryable_putDownAndSavePos(sub);
            }
            inner->heldObj->anim.flags &= ~0x4000;
            inner->heldObj->userData2 = 0;
            inner->heldObj = NULL;
        }
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        (*gPlayerInterface)->setState(obj, inner, 1);
        inner->baddie.stateExitFn = (BaddieStateExitFn)playerStagedRestoreDefaultControl;
    }
    return inner->heldObj != NULL;
}

int playerIsThrowing(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 7;
}

int playerIsPuttingDown(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.controlMode == 6;
}

GameObject* objGetFirstChild(GameObject* obj)
{
    return obj->childObjs[0];
}

int playerGetHeldObject(GameObject* obj, GameObject** outHeldObj)
{
    PlayerState* inner = obj->extra;
    *outHeldObj = inner->heldObj;
    return inner->heldObj != NULL;
}

f32 playerGetProbeHitDist(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->probeHitDist;
}

int playerIsStaffActionPending(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (inner->staffGrown != 0 && inner->staffActionRequest != 0)
    {
        return 1;
    }
    return 0;
}

void playerPutAwayStaff(GameObject* obj, int mode)
{
    PlayerState* inner = obj->extra;
    if (mode == 0)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (inner->flags3F4.b40 == 0)
            return;
        inner->staffActionRequest = 0;
        inner->flags3F4.b08 = 0;
    }
    else if (mode == 1)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (inner->flags3F4.b40 == 0)
            return;
        inner->staffActionRequest = 1;
        inner->flags3F4.b08 = 1;
    }
    else
    {
        if (gPlayerPathObject == NULL)
            return;
        if (inner->flags3F4.b40 == 0)
            return;
        inner->staffActionRequest = 1;
        inner->flags3F4.b08 = 0;
    }
}

void playerPullOutStaff(GameObject* obj, int mode)
{
    PlayerState* inner = obj->extra;
    if (mode == 0)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (inner->flags3F4.b40 == 0)
            return;
        inner->staffActionRequest = 2;
        inner->flags3F4.b08 = 0;
    }
    else if (mode == 1)
    {
        if (gPlayerPathObject == NULL)
            return;
        if (inner->flags3F4.b40 == 0)
            return;
        inner->staffActionRequest = 4;
        inner->flags3F4.b08 = 1;
    }
    else
    {
        if (gPlayerPathObject == NULL)
            return;
        if (inner->flags3F4.b40 == 0)
            return;
        inner->staffActionRequest = 4;
        inner->flags3F4.b08 = 0;
    }
}

int playerGetMoney(GameObject* player)
{
    PlayerState* inner = player->extra;
    return (inner->playerStatus)->money;
}

void playerAddMoney(GameObject* obj, int amount)
{
    PlayerState* inner = obj->extra;
    int cap;
    int total;
    if (mainGetBit(GAMEBIT_ITEM_200ScarabBag_Got))
    {
        cap = 0xc8;
    }
    else if (mainGetBit(GAMEBIT_ITEM_100ScarabBag_Got))
    {
        cap = 0x64;
    }
    else if (mainGetBit(GAMEBIT_ITEM_50ScarabBag_Got))
    {
        cap = 0x32;
    }
    else
    {
        cap = 0xa;
    }
    total = (inner->playerStatus)->money;
    total += amount;
    if (amount > inner->maxMagicUsed)
    {
        inner->maxMagicUsed = (u8)amount;
    }
    if (total < 0)
    {
        total = 0;
    }
    else if (total > cap)
    {
        total = cap;
    }
    (inner->playerStatus)->money = (u8)total;
    mainSetBits(GAMEBIT_ITEM_GiveScarabs_Count, total);
}

void playerGetAimAngles(GameObject* obj, s16* out1, s16* out2)
{
    PlayerState* inner = obj->extra;
    *out1 = 10240.0f * inner->aimInputX;
    if (inner->focusObject != NULL)
    {
        *out2 = 8192.0f * inner->aimInputZ;
    }
    else
    {
        *out2 = 14336.0f * inner->aimInputZ;
    }
}

int playerGetSurfaceType(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (inner->flags3F1.b01)
    {
        return inner->surfaceType;
    }
    return -1;
}

int playerGetCurMagic(GameObject* player)
{
    PlayerState* inner = player->extra;
    return (inner->playerStatus)->magic;
}

void playerAddRemoveMagic(GameObject* obj, int amount)
{
    PlayerState* inner = obj->extra;
    PlayerStatus* deref = inner->playerStatus;
    int m = deref->magic;
    m += amount;
    if (m < 0)
    {
        m = 0;
    }
    else if (m > deref->maxMagic)
    {
        m = deref->maxMagic;
    }
    deref->magic = (s16)m;
    if (amount > 0)
    {
        Sfx_PlayFromObject(0, SFXTRIG_id_21c);
    }
}

int playerGetMaxMagic(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->playerStatus)->maxMagic;
}

void playerAddMaxMagic(GameObject* obj, int delta)
{
    PlayerState* inner = obj->extra;
    PlayerStatus* deref = inner->playerStatus;
    int v = deref->maxMagic + delta;
    if (v < 0)
    {
        v = 0;
    }
    else if (v > 0x64)
    {
        v = 0x64;
    }
    deref->maxMagic = (s16)v;
}

int playerGetMaxHealth(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->playerStatus)->maxHealth;
}

int playerGetCurHealth(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->playerStatus)->health;
}

void playerAddHealth(GameObject* obj, int amount)
{
    PlayerState* inner = obj->extra;
    int h = (inner->playerStatus)->health;
    h += amount;
    if (h < 0)
    {
        h = 0;
    }
    else if (h > (inner->playerStatus)->maxHealth)
    {
        h = (inner->playerStatus)->maxHealth;
    }
    (inner->playerStatus)->health = (s8)h;
    if ((inner->playerStatus)->health <= 0)
    {
        playerDie(obj);
    }
}

void saveSetOverrideHealth(int v)
{
    gPlayerPendingHealth = v;
}

void playerCancelSpell(GameObject* obj, int p2)
{
    playerCastSpell(obj, obj->extra, p2);
}

int objGetAnimState80A(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (inner != NULL)
    {
        return inner->animState;
    }
    return 0;
}

void playerDisableHitDetect(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
}

void cameraGetPrevPos2(GameObject* obj, f32* x, f32* y, f32* z)
{
    int inner = (int)obj->extra;
    *x = *(f32*)((char*)inner + 0x24);
    *y = *(f32*)((char*)inner + 0x28);
    *z = *(f32*)((char*)inner + 0x2c);
}

void playerLock(GameObject* obj, int lock)
{
    PlayerState* inner = obj->extra;
    if (lock != 0)
    {
        inner->flags360 |= PLAYER_FLAG_LOCKED;
    }
    else
    {
        inner->flags360 &= ~PLAYER_FLAG_LOCKED;
    }
}

int playerStatusIsPositive(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return (inner->playerStatus)->health > 0;
}

int playerIsDead(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->flags3F3.b02;
}

int playerHasRevived(GameObject* player)
{
    PlayerState* inner = player->extra;
    return inner->flags3F3.b04;
}

void playerSetIsDead(GameObject* obj, int flag)
{
    PlayerState* inner = obj->extra;
    inner->flags3F3.b02 = flag;
}

void playerHeal(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    int deref = (int)inner->playerStatus;
    int v = *(s8*)((char*)deref + 1);
    if (v < 0)
    {
        v = 0;
    }
    else
    {
        int hi = *(s8*)(deref + 1);
        if (v > hi)
        {
            v = hi;
        }
    }
    *(s8*)((char*)*(int*)((char*)inner + 0x35C)) = (s8)v;
    Obj_SetModelColorFadeRecursive(obj, 0x168, 0xc8, 0, 0, 1);
    inner->flags3F3.b04 = 1;
    inner->knockbackTimer = 0.0f;
    inner->moveVariantIndex = 0xff;
}

void playerReleaseLedgeGrabOn(GameObject* obj, GameObject* parentObj)
{
    PlayerState* state = obj->extra;
    PlayerState* inner = obj->extra;
    short type;

    if (obj->anim.parent == parentObj)
    {
        Obj_SetParent(obj, NULL, 1);
        type = state->baddie.controlMode;
        if (type == 0xa || type == 0xc)
        {
            state->baddie.flags4 &= ~0x100000;
            playerRefreshCollisionState(obj, (int)inner, 5);
            inner->flags3F0.b80 = 0;
            inner->flags3F0.b10 = 0;
            inner->flags3F0.b08 = 0;
            Shield_setMode(gPlayerStaffObject, 2);
            inner->flags3F0.b02 = 0;
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ObjHits_SyncObjectPositionIfDirty(obj);
            inner->flags3F0.b40 = 0;
            inner->flags3F0.b04 = 1;
            inner->flags3F4.b10 = 1;
            inner->isHoldingObject = 0;
            if (inner->heldObj != NULL)
            {
                short id = ((GameObject*)inner->heldObj)->anim.romDefNo;
                if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                {
                    SmallBasket_throw((GameObject*)(inner->heldObj));
                }
                else
                {
                    Carryable_putDownAndSavePos((GameObject*)inner->heldObj);
                }
                *(s16*)((char*)inner->heldObj + 6) &= ~0x4000;
                inner->heldObj->userData2 = 0;
                inner->heldObj = 0;
            }
            (*gPlayerInterface)->setState(obj, (void*)state, 2);
            state->baddie.stateExitFn = (BaddieStateExitFn)playerStagedRestoreDefaultControl;
        }
    }
}

void playerReparentPreservingWorldTransform(GameObject* obj, GameObject* newParent)
{
    GameObject* oldParent = obj->anim.parent;
    int rotX;
    int targetYaw;
    int yaw;
    int prevTargetYaw;
    int prevYaw;
    int lastInputHeading;
    PlayerState* inner = obj->extra;
    struct {
        f32 wp0[3];
        f32 wv[3];
        f32 wp2[3];
        f32 wp[3];
    } s;

    if (oldParent == newParent) {
        return;
    }
    if (oldParent != NULL) {
        Obj_TransformLocalPointToWorld(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &s.wp[0],
                                       &s.wp[1], &s.wp[2], oldParent);
        Obj_TransformLocalPointToWorld(obj->anim.previousLocalPosX, obj->anim.previousLocalPosY,
                                       obj->anim.previousLocalPosZ, &s.wp2[0], &s.wp2[1], &s.wp2[2], oldParent);
        Obj_TransformLocalVectorToWorld(obj->anim.velocityX, 0.0f, obj->anim.velocityZ, &s.wv[0], &s.wv[1], &s.wv[2],
                                        oldParent);
        rotX = Angle_AddWrappedS16(obj->anim.rotX, &oldParent->anim.rotX);
        targetYaw = Angle_AddWrappedS16(inner->targetYaw, &oldParent->anim.rotX);
        yaw = Angle_AddWrappedS16(inner->yaw, &oldParent->anim.rotX);
        prevTargetYaw = Angle_AddWrappedS16(inner->prevTargetYaw, &oldParent->anim.rotX);
        prevYaw = Angle_AddWrappedS16(inner->prevYaw, &oldParent->anim.rotX);
        lastInputHeading = Angle_AddWrappedS16(inner->lastInputHeading, &oldParent->anim.rotX);
        Obj_TransformLocalPointToWorld(inner->baddie.unk118, inner->baddie.unk11C, inner->baddie.unk120, &s.wp0[0],
                                       &s.wp0[1], &s.wp0[2], oldParent);
    } else {
        s.wp[0] = obj->anim.localPosX;
        s.wp[1] = obj->anim.localPosY;
        s.wp[2] = obj->anim.localPosZ;
        s.wp2[0] = obj->anim.previousLocalPosX;
        s.wp2[1] = obj->anim.previousLocalPosY;
        s.wp2[2] = obj->anim.previousLocalPosZ;
        s.wv[0] = obj->anim.velocityX;
        s.wv[2] = obj->anim.velocityZ;
        rotX = obj->anim.rotX;
        targetYaw = inner->targetYaw;
        yaw = inner->yaw;
        prevTargetYaw = inner->prevTargetYaw;
        prevYaw = inner->prevYaw;
        lastInputHeading = inner->lastInputHeading;
        s.wp0[0] = inner->baddie.unk118;
        s.wp0[1] = inner->baddie.unk11C;
        s.wp0[2] = inner->baddie.unk120;
    }

    if (newParent != NULL) {
        Obj_TransformWorldPointToLocal(s.wp[0], s.wp[1], s.wp[2], &obj->anim.localPosX, &obj->anim.localPosY,
                                       &obj->anim.localPosZ, newParent);
        Obj_TransformWorldPointToLocal(s.wp2[0], s.wp2[1], s.wp2[2], &obj->anim.previousLocalPosX,
                                       &obj->anim.previousLocalPosY, &obj->anim.previousLocalPosZ, newParent);
        Obj_TransformWorldVectorToLocal(s.wv[0], 0.0f, s.wv[2], &obj->anim.velocityX, &s.wv[1], &obj->anim.velocityZ,
                                        newParent);
        obj->anim.rotX = Angle_SubWrappedS16(rotX, &newParent->anim.rotX);
        inner->targetYaw = Angle_SubWrappedS16(targetYaw, &newParent->anim.rotX);
        inner->yaw = Angle_SubWrappedS16(yaw, &newParent->anim.rotX);
        inner->prevTargetYaw = Angle_SubWrappedS16(prevTargetYaw, &newParent->anim.rotX);
        inner->prevYaw = Angle_SubWrappedS16(prevYaw, &newParent->anim.rotX);
        inner->lastInputHeading = Angle_SubWrappedS16(lastInputHeading, &newParent->anim.rotX);
        Obj_TransformWorldPointToLocal(s.wp0[0], s.wp0[1], s.wp0[2], &inner->baddie.unk118, &inner->baddie.unk11C,
                                       &inner->baddie.unk120, newParent);
    } else {
        obj->anim.localPosX = s.wp[0];
        obj->anim.localPosY = s.wp[1];
        obj->anim.localPosZ = s.wp[2];
        obj->anim.previousLocalPosX = s.wp2[0];
        obj->anim.previousLocalPosY = s.wp2[1];
        obj->anim.previousLocalPosZ = s.wp2[2];
        obj->anim.velocityX = s.wv[0];
        obj->anim.velocityZ = s.wv[2];
        obj->anim.rotX = rotX;
        inner->targetYaw = targetYaw;
        inner->yaw = yaw;
        inner->prevTargetYaw = prevTargetYaw;
        inner->prevYaw = prevYaw;
        inner->lastInputHeading = lastInputHeading;
        inner->baddie.unk118 = s.wp0[0];
        inner->baddie.unk11C = s.wp0[1];
        inner->baddie.unk120 = s.wp0[2];
    }
    obj->anim.worldPosX = s.wp[0];
    obj->anim.worldPosY = s.wp[1];
    obj->anim.worldPosZ = s.wp[2];
    obj->anim.previousWorldPosX = s.wp2[0];
    obj->anim.previousWorldPosY = s.wp2[1];
    obj->anim.previousWorldPosZ = s.wp2[2];
    Player_GetObjHitsState(obj)->localPosX = obj->anim.localPosX;
    Player_GetObjHitsState(obj)->localPosY = obj->anim.localPosY;
    Player_GetObjHitsState(obj)->localPosZ = obj->anim.localPosZ;
    Player_GetObjHitsState(obj)->worldPosX = obj->anim.worldPosX;
    Player_GetObjHitsState(obj)->worldPosY = obj->anim.worldPosY;
    Player_GetObjHitsState(obj)->worldPosZ = obj->anim.worldPosZ;
    obj->anim.parent = newParent;
}

void playerSetInCutscene(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->flags3F2.b20 = 1;
}

void playerSetCutsceneCameraFlag(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->flags3F2.b40 = 1;
}

void playerSetOverrideParentSlack(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->flags3F2.b80 = 1;
}

u32 playerGetStateFlag310(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->baddie.queuedBitMask;
}

GameObject* playerGetFocusObject(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    return inner->focusObject;
}

void playerGetAttackHitProperties(GameObject* obj, u32* outEffects, f32* outReaction, f32* outKnockbackSpeed,
                                  f32* outDrag, u16* outHitStunFrames)
{
    PlayerState* inner = obj->extra;
    s8 idx;
    u8 mode;
    f32 zero;

    *outEffects = 0;
    zero = 0.0f;
    *outReaction = zero;
    *outKnockbackSpeed = zero;
    *outDrag = zero;
    if (inner->baddie.controlMode == 0x26)
    {
        *outEffects |= 1;
        idx = inner->hitWindowIndex;
        if (idx != -1)
        {
            *outEffects |= *(int*)((inner->moveSlots + 8) + (u32)inner->moveSlotIndex * 0xb0 + idx * 4);
            *outKnockbackSpeed =
                *(f32*)((inner->moveSlots + 0x70) + (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
            *outDrag =
                *(f32*)((inner->moveSlots + 0x7c) + (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
            *outReaction =
                *(f32*)((inner->moveSlots + 0x94) + (u32)inner->moveSlotIndex * 0xb0 + inner->hitWindowIndex * 4);
        }
        if (*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) & 2)
        {
            if (inner->hitCount < inner->hitCountMax)
            {
                *outDrag = *outKnockbackSpeed = 0.0f;
            }
        }
        if ((*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) & 1) &&
            inner->cutsceneTimer >= 6.0f)
        {
            *outEffects |= 0x80;
        }
    }
    mode = inner->attackVariantMode;
    if (mode == 0)
    {
        *outEffects |= 0x100;
    }
    else if (mode == 1)
    {
        *outEffects |= 0x200;
    }
    else if (mode == 2)
    {
        *outEffects |= 0x400;
    }
    if (inner->baddie.controlMode == 0x2e || inner->baddie.controlMode == 0x2f)
    {
        *outEffects &= 0x7dLL;
        *outEffects |= 2;
    }
    *outHitStunFrames = 0x78;
}

int playerStateNoOp(void)
{
    return 0x0;
}

int playerState41(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    inner->probeHitDist = 10.0f;
    inner->flags360 |= 0x2000000LL;
    ((PlayerState*)state)->baddie.flags0 |= 0x200000;
    if (0.0f == inner->verticalVel)
    {
        GameObject* sub;
        inner->flags3F0.b80 = 0;
        inner->flags3F0.b10 = 0;
        inner->flags3F0.b08 = 0;
        Shield_setMode(gPlayerStaffObject, 2);
        inner->flags3F0.b02 = 0;
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirty(obj);
        inner->flags3F0.b40 = 0;
        inner->flags3F0.b04 = 1;
        inner->flags3F4.b10 = 0;
        inner->isHoldingObject = 0;
        sub = inner->heldObj;
        if (sub != NULL)
        {
            s16 id = sub->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
            {
                SmallBasket_throw((GameObject*)sub);
            }
            else
            {
                Carryable_putDownAndSavePos((GameObject*)sub);
            }
            inner->heldObj->anim.flags &= ~0x4000;
            inner->heldObj->userData2 = 0;
            inner->heldObj = 0;
        }
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 3;
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x12, 0.0f, 1);
    }
    {
        f32 one = 1.0f;
        f32 v = one + inner->verticalVel;
        f32 w;
        f32 clamped;
        ObjAnimComponent* o;
        w = v / 2.0f;
        o = &obj->anim;
        clamped = (w < 0.0f) ? 0.0f : ((w > one) ? one : w);
        ObjAnim_SetMoveProgress(o, one - clamped);
    }
    (*(void (*)(int, int, f32, f32, int))(*(int*)((char*)*gPlayerInterface + 0x44)))((int)obj, (int)state, fv, 1.0f,
                                                                              inner->inputHeading);
    ((PlayerState*)state)->baddie.velSmoothTime = 16.0f;
    ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
    obj->anim.velocityY = inner->verticalVel * fv;
    if (((PlayerState*)state)->baddie.inputMagnitude > 0.1f)
    {
        f32 ryaw = (f32)inner->targetYawRate * fv;
        inner->targetYaw = (s16)((f32)inner->targetYaw + 182.044f * (ryaw / 32.0f));
        inner->yaw = inner->targetYaw;
    }
    playerUpdateLookAndLean(obj, (BaddieState*)state, inner, 0.0f);
    return 0;
}

int playerState40(GameObject* p1, PlayerState* obj)
{
    if (*(s8*)((char*)obj + 0x27a) != 0)
    {
        *(u8*)((char*)obj + 0x357) = 0;
    }
    *(u8*)((char*)obj + 0x357) += 1;
    if (*(s8*)((char*)obj + 0x346) != 0 && *(s8*)((char*)obj + 0x357) > 0x1e)
    {
        *(int*)((char*)obj + 0x308) = (int)playerStagedRestoreDefaultControl;
        return 2;
    }
    return 0;
}

int playerState3F(GameObject* obj, PlayerState* state) {
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.009f;
    if (state->baddie.moveDone != 0) {
        state->baddie.nextStateExitFn = NULL;
        return 0x41;
    }
    return 0;
}

int playerStateNop3E(void)
{
    return 0x0;
}

void playerStagedEndGuardAndMarkTeleported(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
    inner->flags3F6.b20 = 0;
}

int playerState3D(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r;
    s16 hdr;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[gPlayerMoveSlotData[7].moveTableIndex], 0.0f, 0);
        state->baddie.moveSpeed = 0.018f;
        state->baddie.animSpeedC = 0.0f;
        state->baddie.animSpeedB = 0.0f;
        state->baddie.animSpeedA = 0.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    }
    r = playerState28((GameObject*)obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*gPlayerInterface)->rotateTowardTarget((void*)obj, (void*)state, fv, 0x10);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*gPlayerInterface)->updateAnimRootMotion((void*)obj, (void*)state, fv, 1);
    if (((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(5.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > 0.2f)
    {
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_sp_sa_def01);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
        ((GameObject*)obj)->anim.currentMoveProgress > 0.7f)
    {
        Sfx_PlayFromObject((GameObject*)obj, surfaceSfxSelectTrigger(inner->surfaceType, inner->footstepSoundId));
        ((PlayerState*)state)->baddie.moveEventFlags |= 2;
    }
    if (((PlayerState*)state)->baddie.moveDone != 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x25;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > 0.85f)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 0;
                inner->flags3F4.b08 = 0;
            }
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return -1;
        }
        r = playerState30((GameObject*)obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState3C(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    s16 hdr;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[gPlayerMoveSlotData[6].moveTableIndex], 0.0f, 0);
        state->baddie.moveSpeed = 0.025f;
        state->baddie.animSpeedC = 0.0f;
        state->baddie.animSpeedB = 0.0f;
        state->baddie.animSpeedA = 0.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 0x10);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        obj->anim.currentMoveProgress > 0.2f)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_sp_sa_def01);
        state->baddie.moveEventFlags |= 1;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
        obj->anim.currentMoveProgress > 0.7f)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_fox_fightbreath2);
        ((PlayerState*)state)->baddie.moveEventFlags |= 2;
    }
    if (*&((PlayerState*)state)->baddie.moveDone != 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > 0.85f)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 0;
                inner->flags3F4.b08 = 0;
            }
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState3B(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    s16 hdr;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[gPlayerMoveSlotData[9].moveTableIndex], 0.0f, 0);
        state->baddie.moveSpeed = 0.021f;
        state->baddie.moveEventFlags = 0;
        state->baddie.animSpeedC = 0.0f;
        state->baddie.animSpeedB = 0.0f;
        state->baddie.animSpeedA = 0.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 2);
    if (((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(5.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        obj->anim.currentMoveProgress > 0.2f)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_fox_fightbreath2);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if (((PlayerState*)state)->baddie.moveDone != 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > 0.85f)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 0;
                inner->flags3F4.b08 = 0;
            }
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState3A(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    s16 hdr;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[gPlayerMoveSlotData[8].moveTableIndex], 0.0f, 0);
        state->baddie.moveSpeed = 0.021f;
        state->baddie.moveEventFlags = 0;
        state->baddie.animSpeedC = 0.0f;
        state->baddie.animSpeedB = 0.0f;
        state->baddie.animSpeedA = 0.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 2);
    if (((PlayerState*)state)->baddie.eventFlags & 0x200)
    {
        doRumble(5.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
        inner->pendingFxFlags |= 4;
    }
    if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
        obj->anim.currentMoveProgress > 0.2f)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_fox_fightbreath2);
        ((PlayerState*)state)->baddie.moveEventFlags |= 1;
    }
    if (((PlayerState*)state)->baddie.moveDone != 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > 0.85f)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != 0 && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 0;
                inner->flags3F4.b08 = 0;
            }
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState39(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;
    f32 k;
    s16 hdr;

    inner->flags360 |= PLAYER_FLAG_GUARDING;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
        k = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedC = k;
        ((PlayerState*)state)->baddie.animSpeedB = k;
        ((PlayerState*)state)->baddie.animSpeedA = k;
        obj->anim.velocityX = k;
        obj->anim.velocityY = k;
        obj->anim.velocityZ = k;
    }
    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 1);
    hdr = *(s16*)obj;
    inner->yaw = hdr;
    inner->targetYaw = hdr;
    if ((padGetTriggers(0) & 0x20) == 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x25;
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        inner->flags3F6.b10 = 0;
    }
    if (inner->flags3F6.b10)
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.03f;
        if (obj->anim.currentMove != 0x455)
        {
            doRumble(10.0f);
            ObjAnim_SetCurrentMove(obj, 0x455, 0.0f, 0);
            state->baddie.animSpeedA = -inner->animSpeedStart;
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            inner->flags3F6.b10 = 0;
        }
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
        if (obj->anim.currentMove != 0x458 &&
            ObjAnim_GetCurrentEventCountdown(&obj->anim) == 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x458, obj->anim.currentMoveProgress, 0);
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 8);
        }
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA * powfBitEstimate(inner->animSpeedDecay, timeDelta);
    return 0;
}

int playerState38(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int r;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0xfb, 0.0f, 0);
        state->baddie.moveSpeed = 0.017f;
        state->baddie.animSpeedC = 0.0f;
        state->baddie.animSpeedB = 0.0f;
        state->baddie.animSpeedA = 0.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
    }

    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }

    (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 1);
    inner->targetYaw = inner->yaw = *(s16*)((char*)obj);
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 2);

    if (((PlayerState*)state)->baddie.moveDone != 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x25;
    }
    if (obj->anim.currentMoveProgress > 0.8f)
    {
        if (((PlayerState*)state)->baddie.hasTarget != 1)
        {
            if (gPlayerPathObject != NULL && inner->flags3F4.b40)
            {
                inner->staffActionRequest = 0;
                inner->flags3F4.b08 = 0;
            }
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return -1;
        }
        r = playerState30(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
    }
    return 0;
}

int playerState37(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    u8 v;
    inner->flags3F6.b20 = 1;
    v = ((PlayerState*)state)->baddie.inputSector;
    if (v == 3)
    {
        ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedEndGuardAndMarkTeleported;
        return 0x3c;
    }
    if (v == 4)
    {
        ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedEndGuardAndMarkTeleported;
        return 0x3e;
    }
    if (v == 1)
    {
        ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedEndGuardAndMarkTeleported;
        return 0x3b;
    }
    ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedEndGuardAndMarkTeleported;
    return 0x39;
}

void playerStagedResetAnimState(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->flags3F4.b20 = 0;
    inner->buttonHoldTimer = 0.0f;
    inner->flags3F3.b10 = 0;
    inner->animState = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int playerStateSuperQuake(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;

    state->baddie.flags0 |= 0x200000;

    if (state->baddie.moveJustStartedA != 0) {
        inner->flags3F3.b10 = 0;
        if (inner->animState == 0xc55) {
            inner->chargeCapacity = 0x14;
        } else {
            inner->chargeCapacity = 0xa;
        }
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }
    if (inner->flags3F0.b20 == 0 && 0.0f != inner->verticalVel) {
        state->baddie.nextStateExitFn = NULL;
        return 0x42;
    }
    switch (obj->anim.currentMove) {
    case 0x84:
        if (state->baddie.moveDone != 0) {
            ObjAnim_SetCurrentMove(obj, 0x85, 0.0f, 0);
            state->baddie.moveSpeed = 0.1f;
        }
        break;
    case 0x85:
        inner->chargeLevel = inner->chargeLevel + 2.0f * fv / 6.0f;
        inner->chargeLevel = 0.5f * fv + inner->chargeLevel;
        if (inner->chargeLevel >= (f32)(u32) inner->chargeCapacity)
        {
            int amt;
            PlayerStatus* r35c;
            int v;
            int hi;
            Sfx_PlayFromObject(obj, SFXTRIG_fox_roll2);
            amt = -inner->chargeCapacity;
            r35c = ((PlayerState*)obj->extra)->playerStatus;
            v = r35c->magic + amt;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > (hi = r35c->maxMagic))
            {
                v = hi;
            }
            r35c->magic = v;
            if (amt > 0)
            {
                Sfx_PlayFromObject(0, SFXTRIG_id_21c);
            }
            ObjAnim_SetCurrentMove(obj, 0x86, 0.0f, 0);
            state->baddie.moveSpeed = 0.01f;
        }
        break;
    case 0x86:
        if (inner->flags3F3.b10 == 0 &&
            obj->anim.currentMoveProgress > 0.1f)
        {
            void* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                trickyImpress(tricky);
            }
            Sfx_PlayFromObject(obj, SFXTRIG_staff_boulder_move1);
            staffStartQuakeSpell(&obj->anim.localPosX);
            inner->flags3F3.b10 = 1;
            doRumble(30.0f);
        }
        if (state->baddie.moveDone != 0) {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, SFXTRIG_staff_boulder_drops);
        state->baddie.animSpeedC = 0.0f;
        state->baddie.animSpeedB = 0.0f;
        state->baddie.animSpeedA = 0.0f;
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityY = 0.0f;
        obj->anim.velocityZ = 0.0f;
        ObjAnim_SetCurrentMove(obj, 0x84, 0.0f, 0);
        state->baddie.moveSpeed = 0.015f;
        inner->chargeLevel = 0.0f;
        inner->flags3F3.b10 = 0;
        if (gPlayerPathObject != NULL && inner->flags3F4.b40) {
            inner->staffActionRequest = 4;
            inner->flags3F4.b08 = 1;
        }
        break;
    }
    return 0;
}

void playerStagedSyncHitPosition(GameObject* obj) {
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int playerState35(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;

    if (state->baddie.moveJustStartedA != 0) {
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }

    state->baddie.animSpeedC = 0.0f;
    state->baddie.animSpeedB = 0.0f;
    state->baddie.animSpeedA = 0.0f;
    obj->anim.velocityX = 0.0f;
    obj->anim.velocityY = 0.0f;
    obj->anim.velocityZ = 0.0f;
    setAButtonIcon(0xe);
    setBButtonIcon(0xa);
    switch (obj->anim.currentMove)
    {
    case 0xe0:
        if (obj->anim.currentMoveProgress > 0.5f &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            Sfx_PlayFromObject(obj, SFXTRIG_recrate_hit);
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xdf, 0.0f, 0);
            state->baddie.moveSpeed = 0.02857f;
            state->baddie.moveEventFlags = 0;
        }
        break;
    case 0xde:
        if (obj->anim.currentMoveProgress > 0.4f &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            doRumble(5.0f);
            Sfx_PlayFromObject(obj, SFXTRIG_staff_rapidfire);
            staffactivated_setGameBitMirror(gPlayerInteractTarget, 0);
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe4, 0.0f, 0);
            state->baddie.moveSpeed = 0.02857f;
            Sfx_PlayFromObject(obj, SFXTRIG_staff_lever);
        }
        break;
    case 0xe1:
        if (obj->anim.currentMoveProgress > 0.5f &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            Sfx_PlayFromObject(obj, SFXTRIG_recrate_hit);
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xde, 0.0f, 0);
            state->baddie.moveSpeed = 0.02857f;
            state->baddie.moveEventFlags = 0;
        }
        break;
    case 0xdf:
        if (obj->anim.currentMoveProgress > 0.4f &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
            doRumble(5.0f);
            Sfx_PlayFromObject(obj, SFXTRIG_staff_rapidfire);
            staffactivated_setGameBitMirror(gPlayerInteractTarget, 1);
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xe5, 0.0f, 0);
            state->baddie.moveSpeed = 0.02857f;
            Sfx_PlayFromObject(obj, SFXTRIG_staff_lever);
        }
        break;
    case 0xe4:
    case 0xe5:
        if (state->baddie.moveDone != 0) {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    default:
        if (staffactivated_isGameBitMirrorSet(gPlayerInteractTarget) != 0) {
            ObjAnim_SetCurrentMove(obj, 0xe1, 0.0f, 0);
        } else {
            ObjAnim_SetCurrentMove(obj, 0xe0, 0.0f, 0);
        }
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &obj->anim.localPosX, &obj->anim.localPosZ);
        state->baddie.moveSpeed = 0.02857f;
        state->baddie.moveEventFlags = 0;
        inner->targetYaw = gPlayerInteractTarget->anim.rotX;
        inner->yaw = inner->targetYaw;
        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
        {
            inner->staffActionRequest = 4;
            inner->flags3F4.b08 = 1;
        }
        break;
    }
    return 0;
}

int playerState34(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 k;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }
    k = 0.0f;
    ((PlayerState*)state)->baddie.animSpeedC = k;
    ((PlayerState*)state)->baddie.animSpeedB = k;
    ((PlayerState*)state)->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;

    switch (obj->anim.currentMove)
    {
    case 0xdd:
        if (obj->anim.currentMoveProgress > 0.25f)
        {
            staffactivated_setLiftHeight(gPlayerInteractTarget, 0);
        }
        if (obj->anim.currentMoveProgress > 0.6f &&
            (((PlayerState*)state)->baddie.moveEventFlags & 1) == 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_recrate_smash);
            ((PlayerState*)state)->baddie.moveEventFlags |= 1;
        }
        if (*&((PlayerState*)state)->baddie.moveDone != 0)
        {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xdd, k, 0);
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &obj->anim.localPosX,
                                               &obj->anim.localPosZ);
        ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        inner->targetYaw = gPlayerInteractTarget->anim.rotX;
        inner->yaw = inner->targetYaw;
        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
        {
            inner->staffActionRequest = 4;
            inner->flags3F4.b08 = 1;
        }
        break;
    }
    return 0;
}

int playerStateStaffLiftRock(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    setBButtonIcon(0xa);
    {
        f32 zero = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedC = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((GameObject*)obj)->anim.velocityX = zero;
        ((GameObject*)obj)->anim.velocityY = zero;
        ((GameObject*)obj)->anim.velocityZ = zero;
    }
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0xab:
        setAButtonIcon(2);
        if (gPlayerRocketBoostSfxPlayed == 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress > 0.4f)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_staff_rocket_boost);
                gPlayerRocketBoostSfxPlayed = 1;
            }
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0xb1, 0.0f, 0);
            state->baddie.moveSpeed = 0.01f;
        }
        break;
    case 0xb1:
    {
        int flags;
        setAButtonIcon(2);
        staffactivated_setLiftHeight(gPlayerInteractTarget, 0);
        flags = inner->buttonsJustPressed;
        if ((flags & 0x100) != 0)
        {
            buttonDisable(0, PAD_BUTTON_A);
            gPlayerLiftRockPullAccum = 10.0f;
            ObjAnim_SetCurrentMove(obj, 0xac, 0.0f, 0);
            ((PlayerState*)state)->baddie.moveSpeed = 0.0f;
        }
        else if ((flags & 0x200) != 0)
        {
            buttonDisable(0, PAD_BUTTON_B);
            Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_boost);
            ObjAnim_SetCurrentMove(obj, 0xd1, 0.0f, 0);
            state->baddie.moveSpeed = 0.0333f;
        }
        break;
    }
    case 0xd1:
        if (state->baddie.moveDone != 0) {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    case 0xac: {
        int count;
        f32 prog;
        setAButtonIcon(2);
        gPlayerLiftRockPullAccum -= 1.0f;
        if ((inner->buttonsJustPressedIfNotBusy & PAD_BUTTON_A) != 0 || getCurSeqNo() != 0) {
            buttonDisable(0, PAD_BUTTON_A);
            gPlayerStaffSfxTimer = gPlayerStaffSfxTimer - fv;
            if (gPlayerStaffSfxTimer < 0.0f) {
                Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_impact3 : SFXTRIG_literun116));
                gPlayerStaffSfxTimer = (f32)randomGetRange(0xa, 0x12);
            }
            switch (staffactivated_getPullRateMode(gPlayerInteractTarget)) {
            case 2:
                gPlayerLiftRockPullAccum += 11.0f;
                break;
            default:
                gPlayerLiftRockPullAccum += 13.0f;
                break;
            case 0:
                gPlayerLiftRockPullAccum += 15.0f;
                break;
            }
        }
        if (gPlayerLiftRockPullAccum > 100.0f) {
            gPlayerLiftRockPullAccum = 100.0f;
        } else if (gPlayerLiftRockPullAccum < -400.0f) {
            gPlayerLiftRockPullAccum = -400.0f;
        }
        {
            f32 lh = (f32)(int)staffactivated_getLiftHeight(gPlayerInteractTarget);
            count = (int)(lh + gPlayerLiftRockPullAccum);
        }
        if (count <= 0) {
            gPlayerLiftRockPullAccum = 0.0f;
            count = 0;
            ObjAnim_SetCurrentMove(obj, 0xb1, 0.0f, 0);
            state->baddie.moveSpeed = 0.01f;
        } else if (count > 0x800) {
            count = 0x800;
        }
        prog = (f32)count / 2048.0f;
        if (prog >= 0.99f) {
            staffactivated_spawnMapEventDebris(gPlayerInteractTarget);
            Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_impact3 : SFXTRIG_literun116));
            ObjAnim_SetCurrentMove(obj, 0xd0, 0.0f, 0);
            state->baddie.moveSpeed = 0.05f;
        } else {
            ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, prog + (f32)randomGetRange(-0x64, 0x64) / 20000.0f);
        }
        staffactivated_setLiftHeight(gPlayerInteractTarget, count);
        break;
    }
    case 0xd0:
        staffactivated_setLiftHeight(gPlayerInteractTarget, 0x800);
        if (state->baddie.moveDone != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_menuups16k);
            ObjAnim_SetCurrentMove(obj, 0xb2, 0.0f, 0);
            state->baddie.moveSpeed = 0.01f;
        }
        break;
    case 0xb2:
        staffactivated_setLiftHeight(gPlayerInteractTarget, 0x800);
        if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0) {
            buttonDisable(0, PAD_BUTTON_B);
            Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_boost);
            ObjAnim_SetCurrentMove(obj, 0xad, 0.0f, 0);
            state->baddie.moveSpeed = 0.0333f;
        }
        break;
    case 0xad:
        if (state->baddie.moveDone != 0) {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xab, 0.0f, 0);
        state->baddie.moveSpeed = 0.02857f;
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &obj->anim.localPosX, &obj->anim.localPosZ);
        inner->targetYaw = gPlayerInteractTarget->anim.rotX + 0x8000;
        inner->yaw = inner->targetYaw;
        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
        {
            inner->staffActionRequest = 4;
            inner->flags3F4.b08 = 1;
        }
        gPlayerLiftRockPullAccum = 0.0f;
        gPlayerRocketBoostSfxPlayed = 0;
        gPlayerStaffSfxTimer = 0.0f;
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            CameraModeStaffAnimSettings cameraSettings;
            cameraSettings.approachThresholdDegrees = 0;
            cameraSettings.turnGate = 0;
            cameraSettings.snapToTarget = 1;
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_STAFF_ANIM_RESOURCE_ID, 1, 0, sizeof(CameraModeStaffAnimSettings),
                          &cameraSettings, 0, 0xff);
        }
        break;
    }
    return 0;
}

void playerStagedResetAnimStateAndSyncPosition(GameObject* obj) {
    ((PlayerState*)obj->extra)->animState = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int playerStateStaffBoost(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    u32 mask;
    s16 item;
    if (state->baddie.moveJustStartedA != 0) {
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }
    if ((s16)getYButtonItem(&item) == 1 && item == GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER) {
        mask = 0x900;
    } else {
        mask = 0x100;
    }
    state->baddie.flags0 |= 0x200000;
    switch (obj->anim.currentMove) {
    case 0x4:
        if (gPlayerQuakeChargeSfxPlayed == 0) {
            if (obj->anim.currentMoveProgress > 0.35f) {
                Sfx_PlayFromObject(obj, SFXTRIG_staff_quake_powerup);
                gPlayerQuakeChargeSfxPlayed = 1;
            }
        }
        if (state->baddie.moveDone != 0) {
            if ((inner->buttonsHeld & mask) != 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_staff_quake_strike);
                ObjAnim_SetCurrentMove(obj, 0x87, 0.0f, 0);
                state->baddie.moveSpeed = 0.01f;
            } else {
                ObjAnim_SetCurrentMove(obj, 0x43, 0.0f, 0);
                state->baddie.moveSpeed = 0.005f;
            }
        }
        break;
    case 0x87:
        if ((inner->buttonsHeld & mask) != 0 &&
            inner->chargeLevel <=
                (f32) * (s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 0x4))
        {
            ((PlayerState*)state)->baddie.moveSpeed = 0.025f * fv + ((PlayerState*)state)->baddie.moveSpeed;
            if (((PlayerState*)state)->baddie.moveSpeed > 0.05f)
            {
                ((PlayerState*)state)->baddie.moveSpeed = 0.05f;
            }
            inner->chargeLevel = 0.33333334f * fv + inner->chargeLevel;
            inner->chargeLevel = 0.5f * fv + inner->chargeLevel;
            if (inner->chargeLevel >= 10.0f)
            {
                PlayerStatus* sub;
                int v;
                inner->chargeLevel = 0.0f;
                sub = ((PlayerState*)obj->extra)->playerStatus;
                v = sub->magic - 0xa;
                if (v < 0)
                {
                    v = 0;
                }
                else if (v > sub->maxMagic)
                {
                    v = sub->maxMagic;
                }
                sub->magic = v;
                Sfx_PlayFromObject(obj, SFXTRIG_staff_boulder_move2);
                ObjAnim_SetCurrentMove(obj, 0x88, 0.0f, 0);
                state->baddie.moveSpeed = 0.05f;
            }
        } else {
            ObjAnim_SetCurrentMove(obj, 0x43, 0.0f, 0);
            state->baddie.moveSpeed = 0.005f;
        }
        break;
    case 0x43:
        if ((inner->buttonsHeld & mask) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_staff_quake_strike);
            ObjAnim_SetCurrentMove(obj, 0x87, 0.0f, 0);
            state->baddie.moveSpeed = 0.01f;
        } else if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0) {
            buttonDisable(0, PAD_BUTTON_B);
            ObjAnim_SetCurrentMove(obj, 0x44, 0.0f, 0);
            state->baddie.moveSpeed = 0.024f;
        }
        break;
    case 0x44:
        if (state->baddie.moveDone != 0) {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            obj->anim.velocityY = 0.0f;
            inner->animState = -1;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    case 0x88:
        obj->anim.velocityY = 0.05f * fv + obj->anim.velocityY;
        if (state->baddie.moveDone != 0) {
            void* t = getTrickyObject();
            if (t != NULL) {
                trickyImpress((GameObject*)t);
            }
            ObjAnim_SetCurrentMove(obj, 0x7f, 0.0f, 0);
            state->baddie.moveSpeed = 0.15f;
        }
        break;
    case 0x7f:
        obj->anim.velocityY = 0.1f * fv + obj->anim.velocityY;
        if (obj->anim.velocityY > 5.0f)
        {
            obj->anim.velocityY = 5.0f;
        }
        if (obj->anim.localPosY > gPlayerStaffBoostTargetY)
        {
            ObjAnim_SetCurrentMove(obj, 0x80, 0.0f, 0);
            state->baddie.moveSpeed = 0.012f;
        }
        break;
    case 0x80:
    {
        f32 p;
        obj->anim.velocityY = obj->anim.velocityY - 0.1 * fv;
        p = powfBitEstimate(0.98f, fv);
        obj->anim.velocityY = obj->anim.velocityY * p;
        (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            obj->anim.velocityY = 0.0f;
            inner->animState = -1;
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    }
    default:
    {
        f32 fromVec[3];
        f32 toVec[3];
        u8 hitBuf[0x58];
        f32 zero = 0.0f;
        state->baddie.animSpeedC = zero;
        state->baddie.animSpeedB = zero;
        state->baddie.animSpeedA = zero;
        obj->anim.velocityX = zero;
        obj->anim.velocityY = zero;
        obj->anim.velocityZ = zero;
        ObjAnim_SetCurrentMove(obj, 0x4, zero, 0);
        state->baddie.moveSpeed = 0.012f;
        gPlayerStaffBoostStartY = obj->anim.localPosY;
        inner->targetYaw = gPlayerInteractTarget->anim.rotX;
        inner->yaw = inner->targetYaw;
        staffactivated_calcInteractionTargetXZ(gPlayerInteractTarget, &obj->anim.localPosX,
                                               &obj->anim.localPosZ);
        playerRefreshCollisionState(obj, (int)inner, 7);
        ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
        fromVec[0] = obj->anim.localPosX;
        fromVec[1] = 10.0f + obj->anim.localPosY;
        fromVec[2] = obj->anim.localPosZ;
        toVec[0] = fromVec[0] - 100.0f * mathSinf(3.1415927f * (f32)(int)inner->targetYaw / 32768.0f);
        toVec[1] = fromVec[1];
        toVec[2] = fromVec[2] - 100.0f * mathCosf(3.1415927f * (f32)(int)inner->targetYaw / 32768.0f);
        if (trackGetLineIntersect(fromVec, toVec, 0.0f, 3, (TrackLineIntersectResult*)hitBuf, obj, 1, 1, 0xff, 0) != 0)
        {
            gPlayerStaffBoostTargetY = *(f32*)(hitBuf + 0x3c) - 30.0f;
        }
        else
        {
            gPlayerStaffBoostTargetY = 100.0f + obj->anim.localPosY;
        }
        gPlayerQuakeChargeSfxPlayed = 0;
        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
        {
            inner->staffActionRequest = 4;
            inner->flags3F4.b08 = 1;
        }
        inner->chargeLevel = 0.0f;
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            CameraModeStaffAnimSettings cameraSettings;
            cameraSettings.approachThresholdDegrees = 0;
            cameraSettings.turnGate = 0;
            cameraSettings.snapToTarget = 1;
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_STAFF_ANIM_RESOURCE_ID, 1, 0, sizeof(CameraModeStaffAnimSettings),
                          &cameraSettings, 0, 0xff);
        }
        break;
    }
    }
    return 0;
}

int playerState31(GameObject* obj, PlayerState* p2) {
    PlayerState* inner = obj->extra;
    u8 state30 = 0x1a;
    u8 state29 = 0x1a;
    GameObject* near;
    f32 dir[3];
    f32 cosv;
    f32 sinv;
    f32 dist = 100.0f;
    near = objGetNearestTypeTo(MAGICPLANT_OBJGROUP_B, obj, &dist);
    inner->flags3F4.b20 = 1;
    inner->buttonHoldTimer = 0.0f;
    if (near != 0) {
        dir[0] = near->anim.localPosX - obj->anim.localPosX;
        dir[1] = near->anim.localPosY - obj->anim.localPosY;
        dir[2] = near->anim.localPosZ - obj->anim.localPosZ;
        dir[1] = 0.0f;
        Vec3_Normalize(dir);
        cosv = mathSinf(3.1415927f * (f32)inner->targetYaw / 32768.0f);
        sinv = mathCosf(3.1415927f * (f32)inner->targetYaw / 32768.0f);
        switch (near->anim.modelInstance->pad75) {
        case 3:
            if (dir[2] * cosv - dir[0] * sinv > 0.0f) {
                state29 = 0x1a;
            }
            state30 = state29;
            break;
        case 2:
            state29 = 0x1a;
            break;
        case 1:
            state30 ^= state29;
            state29 ^= state30;
            state30 ^= state29;
            break;
        case 0:
        default:
            inner->altMoveToggle = (u8)(inner->altMoveToggle ^ 1);
            if (inner->altMoveToggle != 0)
            {
                state29 = 0x1a;
            }
            break;
        }
    }
    else
    {
        inner->altMoveToggle = (u8)(inner->altMoveToggle ^ 1);
        if (inner->altMoveToggle != 0)
        {
            state29 = 0x1a;
        }
    }
    if (((PlayerState*)p2)->baddie.inputSector == 2 && ((PlayerState*)p2)->baddie.inputMagnitude > 0.3f)
    {
        ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[((s16*)((char*)inner->moveSlots + 2))[state30 * 88]],
                               0.0f, 0);
        inner->moveSlotIndex = state30;
        ((PlayerState*)p2)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
        return 0x27;
    }
    ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[((s16*)((char*)inner->moveSlots + 2))[state29 * 88]],
                           0.0f, 0);
    inner->moveSlotIndex = state29;
    ((PlayerState*)p2)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
    return 0x27;
}

int playerState30(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    PartfxFlags spawnFlags;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 timer;

    if (gPlayerIceSpellSustaining != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_whit3_c);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= 0.0f) {
            PlayerStatus* sub = ((PlayerState*)obj->extra)->playerStatus;
            int v = sub->magic - 1;
            if (v < 0) {
                v = 0;
            } else if (v > sub->maxMagic) {
                v = sub->maxMagic;
            }
            sub->magic = v;
            inner->stateTimer = 15.0f;
        }
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = 2.5f;
        spawnFlags = PARTFXFLAG_200000;
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            (((PlayerState*)obj->extra)->playerStatus)->magic == 0 || getCurSeqNo() != 0)
        {
            int z[2];
            GameObject** p[1];
            z[0] = 0;
            gPlayerIceSpellSustaining = z[0];
            z[1] = gPlayerIceSpellSustaining;
            p[0] = gPlayerSpawnedObjects;
            do
            {
                if (*p[0] != NULL)
                {
                    Obj_FreeObject((GameObject*)*p[0]);
                    *p[0] = NULL;
                }
                p[0]++;
                z[1]++;
            } while (z[1] < 7);
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    if (inner->deferredItemCommand != -1 || (((PlayerState*)state)->baddie.pressedButtons & 0x800) != 0)
    {
        int r = playerStateTryCastSpell(obj, state, fv);
        if (r != 0)
        {
            return r;
        }
        inner->deferredItemCommand = -1;
    }
    if ((((PlayerState*)state)->baddie.pressedButtons & 0x400) != 0)
    {
        u8 sel = ((PlayerState*)state)->baddie.inputSector;
        if (sel == 1)
        {
            inner->moveSlotIndex = 8;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        if (sel == 3)
        {
            inner->moveSlotIndex = 9;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        if (sel == 4)
        {
            inner->moveSlotIndex = 7;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        if (sel == 2)
        {
            inner->moveSlotIndex = 6;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        inner->moveSlotIndex = 5;
        ObjAnim_SetCurrentMove(obj,
                               gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                               0.0f, 0);
        ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
        return 0x27;
    }
    if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0)
    {
        u8 sel = ((PlayerState*)state)->baddie.inputSector;
        if (sel == 2 && ((PlayerState*)state)->baddie.inputMagnitude > 0.3f)
        {
            inner->moveSlotIndex = 1;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        if (sel == 3 && ((PlayerState*)state)->baddie.inputMagnitude > 0.3f)
        {
            inner->moveSlotIndex = 4;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        if (sel == 1 && ((PlayerState*)state)->baddie.inputMagnitude > 0.3f)
        {
            inner->moveSlotIndex = 3;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        if (sel == 4 && ((PlayerState*)state)->baddie.inputMagnitude > 0.3f)
        {
            inner->moveSlotIndex = 2;
            ObjAnim_SetCurrentMove(obj, gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                0.0f, 0);
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
            return 0x27;
        }
        inner->moveSlotIndex = 0;
        ObjAnim_SetCurrentMove(obj,
                               gPlayerMoveSlotTable[*(s16*)((inner->moveSlots + 2) + (u32)inner->moveSlotIndex * 0xb0)],
                               0.0f, 0);
        ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedResetMoveHitState;
        return 0x27;
    }
    return 0;
}

void playerStagedRestoreCameraAndAnimState(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    if (inner->curAnimId != 0x42 && getCurSeqNo() == 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
    }
    inner->flags3F6.b40 = 0;
    inner->animState = -1;
}

void playerStagedEndIceSpellAndRestoreCamera(GameObject* obj, BaddieState* p2)
{
    int z[2];
    PlayerState* inner = obj->extra;
    int sel = ((PlayerState*)p2)->baddie.controlMode;

    if (sel == 0x2a)
        return;
    if (sel == 0x2e)
        return;
    if (sel == 0x2f)
        return;
    if (sel == 0x2c)
        return;

    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
    inner->animState = -1;
    inner->flags360 &= ~0x2000400LL;

    if (((PlayerState*)p2)->baddie.controlMode != 0x2b)
    {
        if (inner->curAnimId != 0x42 && getCurSeqNo() == 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
        }
        inner->flags3F6.b40 = 0;
    }

    z[0] = 0;
    gPlayerIceSpellSustaining = z[0];
    for (z[1] = z[0]; z[1] < 7; z[1]++)
    {
        if (gPlayerSpawnedObjects[z[1]] != NULL)
        {
            Obj_FreeObject(gPlayerSpawnedObjects[z[1]]);
            gPlayerSpawnedObjects[z[1]] = NULL;
        }
    }
    if (gPlayerResource != NULL)
    {
        Resource_Release(gPlayerResource);
        gPlayerResource = NULL;
    }
}

int playerStateFireLaser(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    int r = playerCheckCommonTransitions(obj, state, inner, fv);
    if (r != 0)
    {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        PlayerStatus* p = *(PlayerStatus**)((char*)(int)((GameObject*)obj)->extra + 0x35c);
        int val = p->magic;
        if (val < 0)
        {
            val = 0;
        }
        else
        {
            int hi = p->maxMagic;
            if (val > hi)
            {
                val = hi;
            }
        }
        p->magic = (s16)val;
        gPlayerFireLaserCountdown = 30.0f;
    }
    if (30.0f == gPlayerFireLaserCountdown || 25.0f == gPlayerFireLaserCountdown || 20.0f == gPlayerFireLaserCountdown)
    {
        playerSpawnRapidFireLaser(obj, state, inner->aimInputZ, (f32)randomGetRange(-0xc8, 0xc8) / 100.0f);
    }
    gPlayerFireLaserCountdown -= 1.0f;
    if (gPlayerFireLaserCountdown < 0.0f)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
        return 0x2d;
    }
    if (((PlayerState*)state)->baddie.targetObj == NULL)
    {
        if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52)
        {
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreCameraAndAnimState;
            return 0x2c;
        }
    }
    return 0;
}

int playerStateShootFireball(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    PartfxFlags spawnFlags;
    int r;
    f32 timer;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx2;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    if (((PlayerState*)state)->baddie.targetObj == NULL)
    {
        f32 z = 0.0f;
        state->baddie.animSpeedC = z;
        state->baddie.animSpeedB = z;
        state->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
    }
    r = playerCheckCommonTransitions(obj, state, inner, fv);
    if (r != 0) {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (gPlayerIceSpellSustaining != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_whit3_c);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= 0.0f) {
            PlayerStatus* sub = ((PlayerState*)obj->extra)->playerStatus;
            int v = sub->magic - 1;
            if (v < 0) {
                v = 0;
            } else if (v > sub->maxMagic) {
                v = sub->maxMagic;
            }
            sub->magic = v;
            inner->stateTimer = 15.0f;
        }
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = 2.5f;
        spawnFlags = PARTFXFLAG_200000;
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            (((PlayerState*)obj->extra)->playerStatus)->magic == 0 || getCurSeqNo() != 0)
        {
            gPlayerIceSpellSustaining = 0;
            playerFreeSpawnedObjects(gPlayerSpawnedObjects, 0, 0);
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    }
    switch (obj->anim.currentMove)
    {
    case 0x43f:
        if (((PlayerState*)state)->baddie.targetObj == NULL)
        {
            int res;
            int half;
            int low;
            f32 b;
            f32 a;
            f32 k;
            inner->flags360 &= ~PLAYER_FLAG_AIM_READY;
            a = inner->aimInputZ;
            b = inner->aimInputX;
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            k = 0.5f;
            inner->aimScreenX = k * (b * (f32)low) + (f32)low;
            if (a < 0.0f) {
                inner->aimScreenY = k * (a * (f32)half) + (f32)half;
            } else {
                inner->aimScreenY = 0.25f * (a * (f32)half) + (f32)half;
            }
            inner->flags360 |= PLAYER_FLAG_AIM_READY;
            if (state->baddie.moveDone != 0) {
                state->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
                return 0x2d;
            }
        }
        break;
    default: {
        int i;
        PlayerStatus* sub;
        int v;
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, &pfx2.x, &pfx2.y, &pfx2.z, 0);
        for (i = 0; i < 0x28; i++) {
            (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x3ed, &pfx2, 0x200001, -1, NULL);
        }
        sub = ((PlayerState*)obj->extra)->playerStatus;
        v = sub->magic - 2;
        if (v < 0) {
            v = 0;
        } else if (v > sub->maxMagic) {
            v = sub->maxMagic;
        }
        sub->magic = v;
        staffShootFireball(obj, state, inner->aimInputZ);
        if (state->baddie.targetObj == NULL) {
            state->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
            return 0x2d;
        } else {
            gPlayerStaffSfxTimer = 0.0f;
            lbl_803DE464 = 0.0f;
        }
    } break;
    }
    if (state->baddie.targetObj == NULL) {
        if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52) {
            state->baddie.nextStateExitFn = (BaddieStateExitFn)playerStagedRestoreCameraAndAnimState;
            return 0x2c;
        }
    }
    return 0;
}

int playerStateTryCastSpell(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    PartfxFlags spawnFlags;
    s16 deferredCmd;
    f32 timer;
    struct {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;

    if (gPlayerIceSpellSustaining != 0) {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_whit3_c);
        timer = inner->stateTimer - timeDelta;
        inner->stateTimer = timer;
        if (timer <= 0.0f) {
            PlayerStatus* sub = ((PlayerState*)obj->extra)->playerStatus;
            int v = sub->magic - 1;
            if (v < 0) {
                v = 0;
            } else if (v > sub->maxMagic) {
                v = sub->maxMagic;
            }
            sub->magic = v;
            inner->stateTimer = 15.0f;
        }
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.x, &pfx.y, &pfx.z, 0);
        pfx.scale = 2.5f;
        spawnFlags = PARTFXFLAG_200000;
        pfx.mode = 0;
        (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
        pfx.mode = 1;
        (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
        if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
            (((PlayerState*)obj->extra)->playerStatus)->magic == 0 || getCurSeqNo() != 0) {
            int cleanupCounters[2];
            GameObject** spawnedObjectCursors[1];
            inner->animState = -1;
            cleanupCounters[1] = 0;
            gPlayerIceSpellSustaining = 0;
            cleanupCounters[0] = 0;
            spawnedObjectCursors[0] = gPlayerSpawnedObjects;
            do {
                if (*spawnedObjectCursors[0] != NULL) {
                    Obj_FreeObject((*spawnedObjectCursors[0]));
                    *spawnedObjectCursors[0] = NULL;
                }
                spawnedObjectCursors[0]++;
                cleanupCounters[0]++;
            } while (cleanupCounters[0] < 7);
            if (gPlayerResource != NULL) {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
    } else {
        deferredCmd = inner->deferredItemCommand;
        if (deferredCmd != -1 || (inner->buttonsJustPressed & PAD_BUTTON_Y) != 0) {
            int hasYButtonItem;
            u16 buttonMask;
            s16 itemId;
            if (inner->buttonsJustPressed & PAD_BUTTON_Y) {
                hasYButtonItem = getYButtonItem(&itemId);
                buttonMask = 0x800;
            } else {
                hasYButtonItem = 0;
                itemId = deferredCmd;
                buttonMask = 0x100;
            }
            if (inner->deferredItemCommand != -1 ||
                (hasYButtonItem == 1 &&
                 (itemId == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER || itemId == GAMEBIT_STAFF_ABILITY_FREEZE_BLAST))) {
                buttonDisable(0, 0x900);
                inner->buttonsJustPressed = inner->buttonsJustPressed & ~0x900;
                gPlayerSelectedItem = itemId;
                if (itemId != inner->animState) {
                    playerCastSpell(obj, inner, itemId);
                }
                switch (gPlayerSelectedItem) {
                case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER: {
                    PlayerStatus* status = ((PlayerState*)obj->extra)->playerStatus;
                    if (status->magic >= 2) {
                        int nextState = playerStateShootFireball(obj, state, fv);
                        if (nextState != 0) {
                            return nextState;
                        }
                    } else {
                        Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                    }
                    break;
                }
                case GAMEBIT_ITEM_LaserSpell_Got: {
                    PlayerStatus* status = ((PlayerState*)obj->extra)->playerStatus;
                    if (status->magic >= 0) {
                        int nextState = playerStateFireLaser(obj, state, fv);
                        if (nextState != 0) {
                            return nextState;
                        }
                    } else {
                        Sfx_PlayFromObject(0, SFXTRIG_id_10a);
                    }
                    break;
                }
                case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST: {
                    PlayerStatus* status = ((PlayerState*)obj->extra)->playerStatus;
                    if (status->magic >= 1) {
                        PlayerStatus* statusAfterCast;
                        int magic;
                        playerCastIceSpell(obj);
                        gPlayerHeldButtonMask = buttonMask;
                        gPlayerIceSpellSustaining = 1;
                        lbl_803DE430 = 0.0f;
                        inner->stateTimer = 15.0f;
                        statusAfterCast = ((PlayerState*)obj->extra)->playerStatus;
                        magic = statusAfterCast->magic - 1;
                        if (magic < 0) {
                            magic = 0;
                        } else if (magic > statusAfterCast->maxMagic) {
                            magic = statusAfterCast->maxMagic;
                        }
                        statusAfterCast->magic = magic;
                    }
                    break;
                }
                }
            }
        }
    }
    inner->animState = -1;
    return 0;
}

int playerStateAimStaff(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    PartfxFlags spawnFlags;
    int r;
    f32 spin;
    PartFxSpawnParams pfx;

    r = playerCheckCommonTransitions(obj, state, inner, fv);
    if (r != 0) {
        return r;
    }
    {
        f32 z = 0.0f;
        state->baddie.animSpeedC = z;
        state->baddie.animSpeedB = z;
        state->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
    }
    inner->flags360 |= 0x2000000LL;
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (obj->anim.currentMove) {
    case 0x43e: {
        f32 t;
        f32 c;
        f32 a;
        t = state->baddie.moveInputZ / 56.0f;
        c = (t < -1.0f) ? -1.0f : ((t > 1.0f) ? 1.0f : t);
        inner->aimInputZ = inner->aimInputZ + interpolate(c - inner->aimInputZ, 0.1f, timeDelta);
        t = state->baddie.moveInputX / 56.0f;
        c = (t < -1.0f) ? -1.0f : ((t > 1.0f) ? 1.0f : t);
        inner->aimInputX = inner->aimInputX + interpolate(c - inner->aimInputX, 0.1f, timeDelta);
        t = inner->aimInputX;
        if (t > 0.0f) {
            spin = t - 0.75f;
            if (spin < 0.0f) {
                spin = 0.0f;
            }
        } else {
            spin = 0.75f + t;
            if (spin > 0.0f) {
                spin = 0.0f;
            }
        }
        a = inner->aimInputZ;
        if (a > 0.0f) {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x441, (int)(16384.0f * a));
        } else {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, 0x440, (int)(16384.0f * -a));
        }
        inner->bodyLeanHalf = -10240.0f * inner->aimInputX;
        objFindJointPoseVector(obj, 9);
        inner->flags360 &= ~PLAYER_FLAG_AIM_READY;
        if (gPlayerSelectedItem == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER) {
            f32 bv;
            f32 av;
            int res;
            int half;
            int low;
            f32 k;
            av = inner->aimInputZ;
            bv = inner->aimInputX;
            res = getScreenResolution();
            half = res >> 17;
            low = (res & 0xffff) >> 1;
            k = 0.5f;
            inner->aimScreenX = k * (bv * (f32)low) + (f32)low;
            if (av < 0.0f) {
                inner->aimScreenY = k * (av * (f32)half) + (f32)half;
            } else {
                inner->aimScreenY = 0.25f * (av * (f32)half) + (f32)half;
            }
            inner->flags360 |= PLAYER_FLAG_AIM_READY;
        }
        if (gPlayerIceSpellSustaining != 0) {
            f32 x;
            Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_whit3_c);
            x = inner->stateTimer - timeDelta;
            inner->stateTimer = x;
            if (x <= 0.0f) {
                PlayerStatus* sub = ((PlayerState*)obj->extra)->playerStatus;
                int v = sub->magic - 1;
                if (v < 0) {
                    v = 0;
                } else if (v > sub->maxMagic) {
                    v = sub->maxMagic;
                }
                sub->magic = v;
                inner->stateTimer = 15.0f;
            }
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 5, &pfx.posX, &pfx.posY, &pfx.posZ, 0);
            pfx.scale = 2.5f;
            spawnFlags = PARTFXFLAG_200000;
            pfx.arg3 = 0;
            (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
            pfx.arg3 = 1;
            (*gPartfxInterface)->spawnObject(gPlayerPathObject, 0x7f5, &pfx, spawnFlags + PARTFXFLAG_1, -1, NULL);
            if ((inner->buttonsHeld & gPlayerHeldButtonMask) == 0 ||
                *(s16*)((char*)*(int*)((char*)(int)((GameObject*)obj)->extra + 0x35c) + 0x4) == 0 ||
                getCurSeqNo() != 0)
            {
                int z[2];
                GameObject** p[1];
                z[1] = gPlayerIceSpellSustaining = z[0] = 0;
                p[0] = gPlayerSpawnedObjects;
                do
                {
                    if (*p[0] != NULL)
                    {
                        Obj_FreeObject((GameObject*)*p[0]);
                        *p[0] = NULL;
                    }
                    p[0]++;
                    z[1]++;
                } while (z[1] < 7);
                if (gPlayerResource != NULL)
                {
                    Resource_Release(gPlayerResource);
                    gPlayerResource = NULL;
                }
            }
        }
        else if ((inner->buttonsJustPressed & 0x900) != 0)
        {
            int yitem;
            u16 b28;
            s16 item;
            if (inner->buttonsJustPressed & PAD_BUTTON_Y)
            {
            yitem = getYButtonItem(&item);
                b28 = 0x800;
            }
            else
            {
                yitem = 0;
                item = gPlayerSelectedItem;
                b28 = 0x100;
            }
            if ((inner->buttonsJustPressed & PAD_BUTTON_A) != 0 ||
                (yitem == 1 &&
                 (item == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER || item == GAMEBIT_STAFF_ABILITY_FREEZE_BLAST)))
            {
                buttonDisable(0, 0x900);
                inner->buttonsJustPressed = inner->buttonsJustPressed & ~0x900;
                gPlayerSelectedItem = item;
                if (item != inner->animState)
                {
                    playerCastSpell(obj, inner, item);
                }
                switch (gPlayerSelectedItem)
                {
                case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
                {
                    PlayerStatus* sub = *(PlayerStatus**)((char*)(int)((GameObject*)obj)->extra + 0x35c);
                    if (sub->magic >= 2)
                    {
                        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
                        return 0x2f;
                    }
                    Sfx_PlayFromObject(0, SFXTRIG_staff_swipes_long);
                    break;
                }
                case 0x958:
                {
                    PlayerStatus* sub = *(PlayerStatus**)((char*)(int)((GameObject*)obj)->extra + 0x35c);
                    if (sub->magic >= 0)
                    {
                        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
                        return 0x30;
                    }
                    Sfx_PlayFromObject(0, SFXTRIG_staff_swipes_long);
                    break;
                }
                case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
                {
                    PlayerStatus* sub = *(PlayerStatus**)((char*)(int)((GameObject*)obj)->extra + 0x35c);
                    if (sub->magic >= 1)
                    {
                        PlayerStatus* sub2;
                        int v;
                        playerCastIceSpell((GameObject*)obj);
                        gPlayerHeldButtonMask = b28;
                        gPlayerIceSpellSustaining = 1;
                        lbl_803DE430 = 0.0f;
                        inner->stateTimer = 15.0f;
                        sub2 = *(PlayerStatus**)((char*)(int)((GameObject*)obj)->extra + 0x35c);
                        v = sub2->magic - 1;
                        if (v < 0)
                        {
                            v = 0;
                        }
                        else if (v > sub2->maxMagic)
                        {
                            v = sub2->maxMagic;
                        }
                        sub2->magic = v;
                        break;
                    }
                    Sfx_PlayFromObject(0, SFXTRIG_staff_swipes_long);
                    break;
                }
                }
            }
        }
        inner->targetYaw = -1000.0f * spin + (f32)(int)inner->targetYaw;
        {
            s16 targetYaw = inner->targetYaw;
            inner->yaw = targetYaw;
            obj->anim.rotX = targetYaw;
        }
        break;
    }
    default:
        ObjAnim_SetCurrentMove(obj, 0x43e, 0.0f, 0);
        state->baddie.moveSpeed = 0.015f;
        gPlayerIceSpellSustaining = 0;
        lbl_803DE430 = 0.0f;
        break;
    }
    if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52) {
        inner->flags360 &= ~0x2000000LL;
        state->baddie.nextStateExitFn = (BaddieStateExitFn)playerStagedRestoreCameraAndAnimState;
        return 0x2c;
    }
    return 0;
}

int playerStateStopAimStaff(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    int r = playerCheckCommonTransitions(obj, state, inner, fv);
    if (r != 0) {
        return r;
    }
    if (obj->anim.currentMove != 0x449) {
        u8 c;
        ObjAnim_SetCurrentMove(obj, 0x449, 0.0f, 0);
        state->baddie.moveSpeed = 0.0333f;
        Sfx_PlayFromObject(obj, SFXTRIG_staff_swipes_short);
        c = inner->curAnimId;
        if (c != 0x42 && c != 0x4c) {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
        }
    }
    if (state->baddie.moveDone != 0) {
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return -1;
    }
    return 0;
}

int playerStateStartAimStaff(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    int r = playerCheckCommonTransitions(obj, state, inner, fv);
    u32 b;
    if (r != 0) {
        return r;
    }
    {
        f32 z = 0.0f;
        state->baddie.animSpeedC = z;
        state->baddie.animSpeedB = z;
        state->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (obj->anim.currentMove) {
    case 0x43d:
        if (state->baddie.moveDone != 0) {
            state->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
            return 0x2d;
        }
        break;
    case 0x448:
        if (obj->anim.currentMoveProgress > 0.4f) {
            if (inner->staffGrown == 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_swddirt16);
                if (gPlayerPathObject != NULL) {
                    b = inner->flags3F4.b40;
                    if (b != 0) {
                        inner->staffActionRequest = 2;
                        inner->flags3F4.b08 = 0;
                    }
                }
            }
        }
        if (state->baddie.moveDone != 0) {
            state->baddie.nextStateExitFn = playerStagedEndIceSpellAndRestoreCamera;
            return 0x2d;
        }
        break;
    default: {
        f32 z;
        ObjAnim_SetCurrentMove(obj, 0x43d, 0.0f, 0);
        state->baddie.moveSpeed = 0.0333f;
        if (gPlayerPathObject != NULL) {
            b = inner->flags3F4.b40;
            if (b != 0) {
                inner->staffActionRequest = 4;
                inner->flags3F4.b08 = 1;
            }
        }
        z = 0.0f;
        gPlayerStaffSfxTimer = z;
        lbl_803DE464 = z;
        inner->aimInputZ = z;
        inner->aimInputX = z;
        break;
    }
    }
    if ((inner->buttonsJustPressed & PAD_BUTTON_B) != 0 || inner->curAnimId != 0x52) {
        buttonDisable(0, PAD_BUTTON_B);
        state->baddie.nextStateExitFn = (BaddieStateExitFn)playerStagedRestoreCameraAndAnimState;
        return 0x2c;
    }
    return 0;
}

int playerState29(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    u32 b;
    if ((state->baddie.pressedButtons & 0x100) != 0) {
        b = inner->flags3F4.b40;
        if (b != 0) {
            if (gPlayerPathObject != NULL && b != 0) {
                inner->staffActionRequest = 4;
                inner->flags3F4.b08 = 1;
            }
            state->baddie.nextStateExitFn = NULL;
            return 0x32;
        }
    }
    return 0;
}

int playerState28(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    int v;

    if (((PlayerState*)state)->baddie.hasTarget != 1 && ((PlayerState*)state)->baddie.controlMode != 0x26)
    {
        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
        {
            inner->staffActionRequest = 0;
            inner->flags3F4.b08 = 0;
        }
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    v = playerCheckCommonTransitions(obj, state, inner, fv);
    if (v != 0)
    {
        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
        {
            inner->staffActionRequest = 1;
            inner->flags3F4.b08 = 1;
        }
        ((PlayerState*)state)->baddie.targetObj = 0;
        ((PlayerState*)state)->baddie.hasTarget = 0;
        (*gCameraInterface)->setTarget(0);
        return v;
    }
    if (((PlayerState*)state)->baddie.controlMode == 0x26 || inner->flags3F6.b20)
    {
        return 0;
    }
    if (((PlayerState*)state)->baddie.controlMode != 0x39)
    {
        if ((padGetTriggers(0) & 0x20) != 0)
        {
            inner->flags3F6.b20 = 1;
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedEndGuardAndMarkTeleported;
            return 0x3a;
        }
    }
    if (((PlayerState*)state)->baddie.controlMode == 0x39)
    {
        return 0;
    }
    if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) && gPlayerPathObject != NULL &&
        inner->flags3F4.b40)
    {
        inner->staffActionRequest = 4;
        inner->flags3F4.b08 = 1;
    }
    v = playerState30(obj, state, fv);
    if (v != 0)
        return v;
    return 0;
}

void playerStagedResetMoveHitState(GameObject* obj) {
    Player_GetObjHitsState(obj)->objectHitMask = 0;
    if (gPlayerPathObject->anim.classId == 0x2d) {
        objSetAnimField48to0(gPlayerPathObject);
    }
    gPlayerModelChainStyle = 1;
}

int playerState27(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;

    if (state->baddie.moveJustStartedA != 0) {
        if (gPlayerHitReactionVariant == 0) {
            gPlayerHitReactionVariant = 1;
        } else if (gPlayerHitReactionVariant > 2) {
            gPlayerHitReactionVariant = 2;
        }
        state->baddie.moveSpeed = lbl_803DC690[gPlayerHitReactionVariant - 1];
        ObjAnim_SetCurrentMove(obj, lbl_803DC688[gPlayerHitReactionVariant - 1], 0.0f, 0);
        gPlayerHitReactionVariant = 0;
    }
    if (state->baddie.moveDone != 0) {
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        if (state->baddie.targetObj != NULL) {
            state->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
            return 0x25;
        }
        inner->flags3F1.b80 = 1;
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    return 0;
}

int playerStateAttack(GameObject* obj, struct PlayerState* state, f32 fv)
{
    int r;
    u8 changed;
    void* path;
    PlayerState* inner = obj->extra;
    f32 amt;

    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }
    path = gPlayerPathObject;
    state->baddie.stateTag = 1;
    gPlayerModelChainStyle = 5;
    if (((PlayerState*)state)->baddie.moveJustStartedA == 0)
    {
        if (gPlayerHitReactionVariant != 0)
        {
            doRumble(10.0f);
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0x28;
        }
        changed = 0;
        if (((PlayerState*)state)->baddie.moveSpeed > 0.0f)
        {
            if ((((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
            {
                doRumble(5.0f);
                Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
                inner->pendingFxFlags = inner->pendingFxFlags | 4;
            }
            if ((((PlayerState*)state)->baddie.eventFlags & 0x400) != 0)
            {
                doRumble(5.0f);
                Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
                inner->pendingFxFlags = inner->pendingFxFlags | 4;
            }
            if ((((PlayerState*)state)->baddie.moveEventFlags & 1) == 0 &&
                obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x50) + (u32)inner->moveSlotIndex * 0xb0))
            {
                u16 sfx;
                if (inner->characterId == 0)
                {
                    sfx = 0x2de;
                }
                else
                {
                    sfx = 0x1c;
                }
                Sfx_PlayFromObject(obj, sfx);
                state->baddie.moveEventFlags = state->baddie.moveEventFlags | 1;
            }
            if ((((PlayerState*)state)->baddie.moveEventFlags & 2) == 0 &&
                obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x54) + (u32)inner->moveSlotIndex * 0xb0))
            {
                Sfx_PlayFromObject(obj, SFXTRIG_sswsh);
                state->baddie.moveEventFlags = state->baddie.moveEventFlags | 2;
            }
        }
        {
            int slot = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
            if (*(s8*)(slot + 0x15) >= 0)
            {
                if (obj->anim.currentMoveProgress > *(f32*)(slot + 0x28))
                {
                    ((PlayerState*)state)->baddie.moveChainFlags = ((PlayerState*)state)->baddie.moveChainFlags | 2;
                    if (*(u8*)((inner->moveSlots + 0x6c) + (u32)inner->moveSlotIndex * 0xb0) != 0u)
                    {
                        ((PlayerState*)state)->baddie.moveChainFlags = ((PlayerState*)state)->baddie.moveChainFlags | 4;
                        inner->moveChainIndex = 0;
                    }
                }
                if (obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x20) + (u32)inner->moveSlotIndex * 0xb0))
                {
                    ((PlayerState*)state)->baddie.moveChainFlags = ((PlayerState*)state)->baddie.moveChainFlags | 1;
                }
                if (obj->anim.currentMoveProgress >
                    *(f32*)((inner->moveSlots + 0x24) + (u32)inner->moveSlotIndex * 0xb0))
                {
                    ((PlayerState*)state)->baddie.moveChainFlags = ((PlayerState*)state)->baddie.moveChainFlags & ~1;
                }
                if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0 &&
                    (((PlayerState*)state)->baddie.moveChainFlags & 1) != 0)
                {
                    ((PlayerState*)state)->baddie.moveChainFlags = ((PlayerState*)state)->baddie.moveChainFlags | 4;
                    ((PlayerState*)state)->baddie.pressedButtons =
                        ((PlayerState*)state)->baddie.pressedButtons & ~0x100;
                    buttonDisable(0, PAD_BUTTON_A);
                    inner->moveChainIndex = state->baddie.inputSector;
                }
                if ((((PlayerState*)state)->baddie.moveChainFlags & 4) != 0 && (((PlayerState*)state)->baddie.moveChainFlags & 2) != 0)
                {
                    f32 v = (f32)(u8)enemy_getFreezeRecoverSeconds((GameObject*)((PlayerState*)state)->baddie.targetObj);
                    int slot2 = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
                    if (v >= *(f32*)(slot2 + 0x8c))
                    {
                        inner->moveSlotIndex = *(u8*)((slot2 + 0x15) + (u32)inner->moveChainIndex);
                    }
                    else
                    {
                        inner->moveSlotIndex = *(u8*)(slot2 + 0x90);
                    }
                    changed = 1;
                }
            }
        }
    }
    else
    {
        gPlayerHitReactionVariant = 0;
        changed = 1;
        inner->flags360 &= 0xFFFFFFFBF;
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        {
            f32 z = 0.0f;
            inner->hitTimer = z;
            inner->hitCount = 0;
            inner->lastHitObject = 0;
            inner->activeHitWindow = -1;
            state->baddie.animSpeedC = z;
            state->baddie.animSpeedB = z;
            state->baddie.animSpeedA = z;
            obj->anim.velocityX = z;
            obj->anim.velocityY = z;
            obj->anim.velocityZ = z;
        }
    }
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        if (inner->moveSlotIndex >= 5 && inner->moveSlotIndex <= 9)
        {
            amt = (f32)inner->targetObjectBearing;
        }
        else
        {
            amt = (f32)inner->targetObjectBearing / 12.0f;
        }
        inner->targetYaw = (f32)(int)inner->targetYaw + amt;
        inner->yaw = inner->targetYaw;
    }
    else if (((PlayerState*)state)->baddie.moveJustStartedA != 0 && inner->cameraTargetObject != NULL &&
             inner->targetObjModelType == 1)
    {
        if (inner->targetObjectBearingAbs < 0x4000)
        {
            amt = (f32)inner->targetObjectBearing;
        }
        inner->targetYaw = (f32)(int)inner->targetYaw + amt;
        inner->yaw = inner->targetYaw;
    }
    else if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        s16 inputHeading = inner->inputHeading;
        inner->targetYaw = inputHeading;
        inner->yaw = inputHeading;
    }
    if (changed != 0)
    {
        obj->anim.weaponDaTable = &((PlayerMoveSlot*)(inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0))->weaponDa;
        if (obj->anim.currentMove !=
            gPlayerMoveSlotTable[*(s16*)(inner->moveSlots + offsetof(PlayerMoveSlot, moveTableIndex) +
                                         (u32)inner->moveSlotIndex * sizeof(PlayerMoveSlot))]) {
            ObjAnim_SetCurrentMove(obj,
                gPlayerMoveSlotTable[*(s16*)(inner->moveSlots + offsetof(PlayerMoveSlot, moveTableIndex) +
                                             (u32)inner->moveSlotIndex * sizeof(PlayerMoveSlot))],
                *(f32*)(inner->moveSlots + offsetof(PlayerMoveSlot, animSpeed) +
                        (u32)inner->moveSlotIndex * sizeof(PlayerMoveSlot)),
                0);
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 2);
        }
        ((PlayerState*)state)->baddie.moveChainFlags = ((PlayerState*)state)->baddie.moveChainFlags & ~0xef;
        ((PlayerState*)state)->baddie.moveSpeed = *(f32*)((inner->moveSlots + 0x1c) + (u32)inner->moveSlotIndex * 0xb0);
        inner->unk824 = ((PlayerState*)state)->baddie.moveSpeed;
        inner->cutsceneEnded = 0;
        ((PlayerState*)state)->baddie.animSpeedB = 0.0f;
        ((PlayerState*)state)->baddie.moveEventFlags = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            if (inner->moveSlotIndex >= 5 && inner->moveSlotIndex <= 9)
            {
                (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 1);
            }
            else
            {
                (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 2);
            }
            {
                s16 v = obj->anim.rotX;
                inner->yaw = v;
                inner->targetYaw = v;
            }
        }
        if (obj->anim.hitReactState != NULL)
        {
            Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        }
        inner->activeHitWindow = -1;
        if (*(s16*)((char*)path + 0x44) == 0x2d)
        {
            objSetAnimField48to0((GameObject*)path);
            STAFF_INTERFACE(path)->func10((GameObject*)path,
                                          *(u8*)((inner->moveSlots + 0x5c) + (u32)inner->moveSlotIndex * 0xb0));
            (*(void (*)(int, f32, f32)) * (int*)(*(int*)(*(int*)((char*)path + 0x68)) + 0x4c))(
                (int)path, *(f32*)((inner->moveSlots + 0x48) + (u32)inner->moveSlotIndex * 0xb0),
                *(f32*)((inner->moveSlots + 0x4c) + (u32)inner->moveSlotIndex * 0xb0));
        }
        {
            f32 z = 0.0f;
            inner->boulderChargeLevel = z;
            inner->hitTimer = z;
            inner->hitCount = 0;
            inner->lastHitObject = 0;
        }
    }
    Player_GetObjHitsState(obj)->hitVolumePriority = 0xb;
    *(u8*)&Player_GetObjHitsState(obj)->hitVolumeId =
        *(u8*)((inner->moveSlots + 0x14) + (u32)inner->moveSlotIndex * 0xb0);
    {
        int slot = inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0;
        f32 t = *(f32*)(slot + 0xa0);
        if (t >= 0.0f)
        {
            if (obj->anim.currentMoveProgress > t &&
                obj->anim.currentMoveProgress < *(f32*)(slot + 0xa4))
            {
                if (0.0f == inner->boulderChargeLevel)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_staff_boulder_drops);
                }
                inner->boulderChargeLevel = 2.0f * timeDelta + inner->boulderChargeLevel;
                if (inner->boulderChargeLevel > 60.0f)
                {
                    inner->boulderChargeLevel = 60.0f;
                }
            }
            else
            {
                inner->boulderChargeLevel = 0.0f;
            }
        }
    }
    if ((*(u8*)((inner->moveSlots + 0x88) + (u32)inner->moveSlotIndex * 0xb0) & 2) != 0 &&
        (void*)inner->lastHitObject != NULL)
    {
        if (inner->hitCount < inner->hitCountMax)
        {
            f32 t = inner->hitTimer - 1.0f;
            inner->hitTimer = t;
            if (t <= 0.0f)
            {
                ObjHits_RecordObjectHit((GameObject*)inner->lastHitObject, obj, 0xb, 1, 0);
                (inner->hitCount)++;
                inner->hitTimer = (f32)inner->hitInterval;
            }
        }
        else
        {
            inner->lastHitObject = 0;
        }
    }
    {
        int i;
        Player_GetObjHitsState(obj)->objectHitMask = 0;
        for (i = 0; i != 3; i++)
        {
            if (obj->anim.currentMoveProgress >=
                    ((PlayerMoveSlot*)inner->moveSlots + (u32)inner->moveSlotIndex)->hitWindowStart[i] &&
                obj->anim.currentMoveProgress <=
                    ((PlayerMoveSlot*)inner->moveSlots + (u32)inner->moveSlotIndex)->hitWindowEnd[i])
            {
                if ((s8)Player_GetObjHitsState(obj)->suppressOutgoingHits == 0)
                {
                    int bits;
                    switch (((PlayerMoveSlot*)(inner->moveSlots + (u32)inner->moveSlotIndex * 0xb0))->hitWindowType[i])
                    {
                    case -1:
                        bits = 0;
                        break;
                    case 0:
                        bits = 0xc;
                        break;
                    case 1:
                        bits = 3;
                        break;
                    case 4:
                        bits = 0xf;
                        break;
                    case 2:
                        bits = 0x100000;
                        break;
                    case 3:
                        bits = 0x10000;
                        break;
                    default:
                        bits = 0;
                        break;
                    }
                    Player_GetObjHitsState(obj)->objectHitMask = bits;
                }
                if (i != inner->activeHitWindow)
                {
                    Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
                    inner->activeHitWindow = (s8)i;
                    inner->hitCount = 0;
                    inner->hitTimer = 0.0f;
                    inner->lastHitObject = 0;
                }
                break;
            }
        }
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 3);
    if (((PlayerState*)state)->baddie.moveDone != 0)
    {
        Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
            return 0x25;
        }
        inner->flags3F1.b80 = 1;
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    if (obj->anim.currentMoveProgress >=
        *(f32*)((inner->moveSlots + 0x2c) + (u32)inner->moveSlotIndex * 0xb0))
    {
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0)
            {
                Player_GetObjHitsState(obj)->suppressOutgoingHits = 0;
                inner->activeHitWindow = -1;
                (*gPlayerInterface)->rotateTowardTarget(obj, (void*)state, fv, 2);
                {
                    s16 v = obj->anim.rotX;
                    inner->yaw = v;
                    inner->targetYaw = v;
                }
                state->baddie.nextStateExitFn = NULL;
                return 0x31;
            }
        } else if ((state->baddie.pressedButtons & 0x100) != 0 && state->baddie.inputMagnitude > 0.3f) {
            inner->targetYaw = inner->targetYaw + inner->targetYawRate * 0xb6;
            inner->yaw = inner->targetYaw;
            inner->targetYawRateSigned = 0;
            inner->targetYawRate = 0;
            inner->yawRateSigned = 0;
            inner->yawRate = 0;
            state->baddie.nextStateExitFn = NULL;
            return 0x32;
        }
    }
    return 0;
}

void playerStagedEndIceSpellAndSettleHeading(GameObject* obj, BaddieState* p2) {
    PlayerState* inner = obj->extra;
    if (((PlayerState*)p2)->baddie.inputMagnitude < 0.05f) {
        s16 h = obj->anim.rotX;
        inner->yaw = h;
        inner->targetYaw = h;
        inner->lastInputHeading = h;
        ((PlayerState*)p2)->baddie.inputMagnitude = 0.0f;
    } else {
        int t = inner->inputHeading;
        inner->lastInputHeading = t;
        inner->yaw = (s16)t;
        inner->yawRate = 0;
        inner->yawRateSigned = 0;
    }
    gPlayerModelChainStyle = 1;
    if (((PlayerState*)p2)->baddie.controlMode != 0x24 && ((PlayerState*)p2)->baddie.controlMode != 0x25 &&
        gPlayerIceSpellSustaining != 0)
    {
        int z[2];
        inner->animState = -1;
        z[0] = 0;
        gPlayerIceSpellSustaining = z[0];
        for (z[1] = z[0]; z[1] < 7; z[1]++)
        {
            if (gPlayerSpawnedObjects[z[1]] != NULL)
            {
                Obj_FreeObject(gPlayerSpawnedObjects[z[1]]);
                gPlayerSpawnedObjects[z[1]] = NULL;
            }
        }
        if (gPlayerResource != NULL)
        {
            Resource_Release(gPlayerResource);
            gPlayerResource = NULL;
        }
    }
}

int playerState25(GameObject* obj, PlayerState* state, f32 updateRate)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 inputScale, sinYaw, cosYaw, targetVelX, moveProgress, moveSpeed;
    f32 targetVelZ;
    int result;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        gPlayerModelChainStyle = 5;
    }
    result = playerState28((GameObject*)obj, state, updateRate);
    if (result != 0)
    {
        return result;
    }
    {
        f32 normalizedInput = (((PlayerState*)state)->baddie.inputMagnitude - 0.2f) / 0.8f;
        inputScale = (normalizedInput < 0.0f) ? 0.0f : ((normalizedInput > 1.0f) ? 1.0f : normalizedInput);
    }
    {
        f32 ang = 3.1415927f * (f32)inner->inputHeading / 32768.0f;
        targetVelX = inputScale * -mathSinf(ang);
        targetVelX = inner->maxSpeed * targetVelX;
    }
    {
        f32 ang = 3.1415927f * (f32)inner->inputHeading / 32768.0f;
        targetVelZ = inner->maxSpeed * (inputScale * -mathCosf(ang));
    }
    {
        f32 deltaX = interpolate(targetVelX - inner->smoothVelX, 0.25f, timeDelta);
        f32 deltaZ = interpolate(targetVelZ - inner->smoothVelZ, 0.25f, timeDelta);
        inner->smoothVelX += deltaX;
        inner->smoothVelZ += deltaZ;
    }
    state->baddie.animSpeedC = sqrtf(inner->smoothVelX * inner->smoothVelX + inner->smoothVelZ * inner->smoothVelZ);
    {
        f32 animSpeed = state->baddie.animSpeedC;
        f32 minSpeed = inner->moveParamValues[0];
        state->baddie.animSpeedC = (state->baddie.animSpeedC < minSpeed)
                                       ? minSpeed
                                       : ((animSpeed > inner->maxSpeed) ? inner->maxSpeed : state->baddie.animSpeedC);
    }
    {
        f32 ang = 3.1415927f * (f32)inner->targetYaw / 32768.0f;
        sinYaw = mathSinf(ang);
    }
    {
        f32 ang = 3.1415927f * (f32)inner->targetYaw / 32768.0f;
        cosYaw = mathCosf(ang);
    }
    {
        f32 smoothVelZ = inner->smoothVelZ;
        f32 smoothVelX;
        ((PlayerState*)state)->baddie.animSpeedA +=
            interpolate(-smoothVelZ * cosYaw - (smoothVelX = inner->smoothVelX) * sinYaw -
                            ((PlayerState*)state)->baddie.animSpeedA,
                        inner->targetAnimSpeed, timeDelta);
        ((PlayerState*)state)->baddie.animSpeedB +=
            interpolate(smoothVelX * cosYaw - smoothVelZ * sinYaw - ((PlayerState*)state)->baddie.animSpeedB,
                        inner->targetAnimSpeed, timeDelta);
    }
    moveProgress = obj->anim.currentMoveProgress;
    {
        u8 phase = *(u8*)&((PlayerState*)inner)->gaitLevel;
        int idx = (u8)((s8)phase >> 1);
        if (((PlayerState*)state)->baddie.animSpeedC < gPlayerAnimSpeedThresholds.gaitSpeedThresholds[idx])
        {
            if ((s8)phase == 4)
            {
                if (((PlayerState*)state)->baddie.inputMagnitude < 0.2f)
                {
                    ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
                    return 0x25;
                }
            }
            else
            {
                *(u8*)&((PlayerState*)inner)->gaitLevel -= 4;
            }
        }
        else
        {
            if (((PlayerState*)state)->baddie.animSpeedC >= gPlayerAnimSpeedThresholds.gaitSpeedThresholds[idx + 1] && (s8)phase < 8)
            {
                if ((s8)phase == 0)
                {
                    moveProgress = 0.0f;
                }
                if (((PlayerState*)state)->baddie.animSpeedC < inner->maxSpeed)
                {
                    *(u8*)&((PlayerState*)inner)->gaitLevel += 4;
                }
            }
        }
    }
    {
        f32 absAnimSpeedX;
        f32 absAnimSpeedZ = ((PlayerState*)state)->baddie.animSpeedB;
        if (absAnimSpeedZ < 0.0f)
        {
            absAnimSpeedZ = -absAnimSpeedZ;
        }
        absAnimSpeedX = ((PlayerState*)state)->baddie.animSpeedA;
        if (absAnimSpeedX < 0.0f)
        {
            absAnimSpeedX = -absAnimSpeedX;
        }
        if (ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, ((PlayerState*)state)->baddie.animSpeedC,
                                         &moveSpeed) != 0)
        {
            ((PlayerState*)state)->baddie.moveSpeed = moveSpeed;
        }
        if (absAnimSpeedX > absAnimSpeedZ)
        {
            if (((PlayerState*)state)->baddie.animSpeedA < 0.0f)
            {
                ((PlayerState*)state)->baddie.moveSpeed = -((PlayerState*)state)->baddie.moveSpeed;
            }
            if (((GameObject*)obj)->anim.currentMove != gPlayerMoveTableB[inner->gaitLevel])
            {
                if (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
                {
                    ObjAnim_SetCurrentMove(obj, gPlayerMoveTableB[inner->gaitLevel], moveProgress, 0);
                    if (((PlayerState*)state)->baddie.moveJustStartedA == 0)
                    {
                        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
                    }
                }
            }
        }
        else
        {
            if (((PlayerState*)state)->baddie.animSpeedB >= 0.0f)
            {
                ((PlayerState*)state)->baddie.moveSpeed = -((PlayerState*)state)->baddie.moveSpeed;
            }
            if (((GameObject*)obj)->anim.currentMove != (gPlayerMoveTableB + 2)[inner->gaitLevel])
            {
                if (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
                {
                    ObjAnim_SetCurrentMove(obj, (gPlayerMoveTableB + 2)[inner->gaitLevel], moveProgress, 0);
                    if (((PlayerState*)state)->baddie.moveJustStartedA == 0)
                    {
                        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
                    }
                }
            }
        }
    }
    inner->targetYaw = (s16)(inner->targetYaw + (int)((f32)inner->targetObjectBearing / 24.0f));
    inner->yaw = inner->targetYaw;
    inner->flags360 |= 0x2000000LL;
    playerUpdateCameraTargetLookAngles(obj, state, inner);
    return 0;
}

int playerState24(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    f32 t, ang, vx, vy, dx, dy;
    f32 zero = 0.0f;
    int r;

    state->baddie.animSpeedA = zero;
    state->baddie.animSpeedB = zero;
    if (state->baddie.moveJustStartedA != 0) {
        inner->maxSpeed = 1.5f;
        inner->gaitLevel = 0;
        inner->smoothVelX = zero;
        inner->smoothVelZ = zero;
        state->baddie.moveSpeed = 0.012f;
        state->baddie.animSpeedC = zero;
        gPlayerModelChainStyle = 5;
    }

    r = playerState28(obj, state, fv);
    if (r != 0)
    {
        return r;
    }

    t = (((PlayerState*)state)->baddie.inputMagnitude - 0.2f) / 0.8f;
    ang = (t < 0.0f) ? 0.0f : ((t > 1.0f) ? 1.0f : t);
    vx = inner->maxSpeed * (ang * -mathSinf(3.1415927f * (f32)inner->inputHeading / 32768.0f));
    vy = inner->maxSpeed * (ang * -mathCosf(3.1415927f * (f32)inner->inputHeading / 32768.0f));
    dx = interpolate(vx - inner->smoothVelX, 0.25f, timeDelta);
    dy = interpolate(vy - inner->smoothVelZ, 0.25f, timeDelta);
    inner->smoothVelX += dx;
    inner->smoothVelZ += dy;
    ((PlayerState*)state)->baddie.animSpeedC =
        sqrtf(inner->smoothVelX * inner->smoothVelX + inner->smoothVelZ * inner->smoothVelZ);
    ((PlayerState*)state)->baddie.animSpeedC =
        (((PlayerState*)state)->baddie.animSpeedC < 0.0f)
            ? 0.0f
            : ((state->baddie.animSpeedC > inner->maxSpeed) ? inner->maxSpeed : state->baddie.animSpeedC);

    if (*(f32*)&((PlayerState*)state)->baddie.trackedObj >= 0.22f &&
        ((PlayerState*)state)->baddie.inputMagnitude >= 0.22f &&
        ((PlayerState*)state)->baddie.animSpeedC >= gPlayerAnimSpeedThresholds.gaitSpeedThresholds[1])
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
        return 0x26;
    }

    if (obj->anim.currentMove != 0x8c)
    {
        ObjAnim_SetCurrentMove(obj, 0x8c, 0.0f, 0);
        if (((PlayerState*)state)->baddie.prevControlMode == 0x39)
        {
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 8);
        }
        state->baddie.moveSpeed = 0.012f;
    }

    inner->targetYaw += (int)((f32)inner->targetObjectBearing / 24.0f);
    inner->yaw = inner->targetYaw;
    inner->flags360 |= 0x2000000LL;
    playerUpdateCameraTargetLookAngles(obj, state, inner);
    return 0;
}

int playerState23(GameObject* obj, PlayerState* state, f32 fv)
{
    MoveTable* mt = (MoveTable*)lbl_80332EC0;
    PlayerState* inner = obj->extra;
    u32 flags;
    int idx;

    ((PlayerState*)state)->baddie.stateTag = 3;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (((PlayerState*)state)->baddie.targetObj != NULL && (inner->flags884 & 1))
        {
            doRumble(10.0f);
            flags = inner->flags884;
            if (flags & 2)
            {
                idx = 3;
            }
            else if (flags & 4)
            {
                idx = 1;
            }
            else if (flags & 8)
            {
                idx = 2;
            }
            else
            {
                idx = 3;
            }
            ObjAnim_SetCurrentMove(obj, mt->moves[idx], mt->blend[idx], 0);
            ((PlayerState*)state)->baddie.moveSpeed = mt->angles[idx];
            ((PlayerState*)state)->baddie.animSpeedA = -inner->animSpeedStart;
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, mt->moves[inner->moveVariantIndex], 0.0f, 0);
            ((PlayerState*)state)->baddie.moveSpeed = mt->angles[inner->moveVariantIndex];
        }
    }
    if (((PlayerState*)state)->baddie.targetObj != NULL)
    {
        inner->targetYaw = inner->targetYaw + (int)((f32)inner->targetObjectBearing / 24.0f);
        inner->yaw = inner->targetYaw;
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA * powfBitEstimate(inner->animSpeedDecay, fv);
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 2);
    if (((PlayerState*)state)->baddie.moveDone != 0)
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    return 0;
}

int playerState22(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    state->baddie.stateTag = 3;
    if ((inner->playerStatus)->health > 0) {
        ObjAnim_SetCurrentMove(obj, 0xc8, 0.0f, 0);
        state->baddie.nextStateExitFn = NULL;
        return -0x21;
    }
    return 0;
}

int playerState21(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    u16 sfxId;
    int d;

    switch (obj->anim.currentMove) {
    case 0x450:
        state->baddie.moveSpeed = 0.02f;
        if (obj->anim.velocityY < 1.0f && inner->flags3F1.b01) {
            if (inner->characterId == 0) {
                sfxId = 0x2d2;
            } else {
                sfxId = 0x214;
            }
            Sfx_PlayFromObject(obj, sfxId);
            ObjAnim_SetCurrentMove(obj, 0xc6, 0.0f, 0);
        }
        if (obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ > 1.0f) {
            d = getAngle(obj->anim.velocityX, obj->anim.velocityZ) & 0xffff;
            d -= (u16)inner->targetYaw;
            if (d > 0x8000) {
                d -= 0xffff;
            }
            if (d < -0x8000) {
                d += 0xffff;
            }
            inner->targetYaw += (d * (int)fv >> 3);
            inner->yaw = inner->targetYaw;
        }
        break;
    case 0xc4:
        state->baddie.moveSpeed = 0.05f;
        if (obj->anim.velocityY < 1.0f && inner->flags3F1.b01) {
            if (inner->characterId == 0) {
                sfxId = 0x2d2;
            } else {
                sfxId = 0x214;
            }
            Sfx_PlayFromObject(obj, sfxId);
            ObjAnim_SetCurrentMove(obj, 0xc6, 0.0f, 0);
        }
        if (obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ > 1.0f) {
            d = getAngle(obj->anim.velocityX, obj->anim.velocityZ) & 0xffff;
            d -= (u16)inner->targetYaw;
            if (d > 0x8000) {
                d -= 0xffff;
            }
            if (d < -0x8000) {
                d += 0xffff;
            }
            inner->targetYaw += (d * (int)fv >> 3);
            inner->yaw = inner->targetYaw;
        }
        break;
    case 0xc6:
        state->baddie.moveSpeed = 0.05f;
        if (state->baddie.moveDone != 0) {
            ObjAnim_SetCurrentMove(obj, 0xc8, 0.0f, 0);
        }
        obj->anim.velocityX = 0.0f;
        obj->anim.velocityZ = 0.0f;
        break;
    case 0xc8:
        state->baddie.moveSpeed = 0.01f;
        if (state->baddie.moveDone != 0) {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return -1;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0xc4, 0.0f, 0);
        break;
    }
    ((PlayerState*)state)->baddie.movementFlags |= 2;
    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * powfBitEstimate(0.96f, fv);
    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(0.96f, fv);
    return 0;
}

int playerState20(GameObject* obj, PlayerState* state, f32 fv) {
    state->baddie.stateTag = 3;
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0x44c, 0.0f, 0);
        state->baddie.moveSpeed = 0.013f;
    }
    switch (obj->anim.currentMove) {
    case 0x44c:
        if (state->baddie.moveDone != 0) {
            ObjAnim_SetCurrentMove(obj, 0x44d, 0.0f, 0);
            state->baddie.moveSpeed = 0.02f;
        }
        break;
    case 0x44d:
        if (state->baddie.moveDone != 0) {
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    return 0;
}

int playerState1F(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    GameObject* hit;

    state->baddie.stateTag = 3;
    if (state->baddie.moveJustStartedA != 0) {
        if (ObjHits_GetPriorityHit(obj, &hit, 0, 0)) {
            inner->targetYaw = (s16)getAngle(-hit->anim.velocityX, -hit->anim.velocityZ);
            inner->yaw = inner->targetYaw;
        }
        ObjAnim_SetCurrentMove(obj, 0x407, 0.0f, 0);
        state->baddie.moveSpeed = 0.015f;
    }
    switch (obj->anim.currentMove) {
    case 0x407:
        if (state->baddie.moveDone != 0) {
            ObjAnim_SetCurrentMove(obj, 0x408, 0.0f, 0);
            state->baddie.moveSpeed = 0.02f;
        }
        break;
    case 0x408:
        if (state->baddie.moveDone != 0) {
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    }
    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
    return 0;
}

int playerState1E(GameObject* obj, PlayerState* state, f32 fv) {
    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.022f;
    state->baddie.animSpeedA = 0.0f;
    (*gPlayerInterface)->updateAnimRootMotion((void*)obj, (void*)state, fv, 2);
    if (state->baddie.moveDone != 0) {
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    return 0;
}

void playerStagedRestoreCameraAndSyncPosition(GameObject* obj, BaddieState* state)
{
    PlayerState* inner = obj->extra;
    u8 c;
    state->flags0 &= ~0x4000;
    c = inner->curAnimId;
    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xfe);
    }
    ObjHits_SyncObjectPositionIfDirty(obj);
}

s16 playerSetMoveBlendFromPlane(GameObject* obj, int baseMoveId, int blendMoveId, int* blendAnchor, int* blendPlane,
                                f32 samplePhase, f32 moveStepScale, int axis, int flags);

PlayerModelChainEntry gPlayerModelChainDefault = {lbl_80332EC0, 5};
PlayerModelChainEntry* gPlayerModelChainConfig = &gPlayerModelChainDefault;
u8 gPlayerModelChainStyle = 1;
f32 gPlayerModelChainOriginX = 0.12f;
f32 gPlayerModelChainOriginY = 0.675f;
f32 gPlayerModelChainOriginZ = 0.15f;
f32 lbl_803DC67C = 0.1f;
f32 lbl_803DC680 = 2.3f;
f32 lbl_803DC684 = 1.0f;
int lbl_803DC688[2] = {210, 212};
f32 lbl_803DC690[2] = {0.030000001f, 0.030000001f};
s16 lbl_803DC698 = 102;
s16 lbl_803DC69A = 103;
s16 lbl_803DC69C[2] = {240, 241};
s16 gPlayerCurrentMoveId = -1;
s16 gPlayerPrevMoveId = -1;
u8 lbl_803DC6A4[4] = {10, 8, 5, 0};
u8 lbl_803DC6A8[8] = {200, 170, 160, 120, 100, 0, 0, 0};
u8 lbl_803DC6B0[8] = {10, 0, 0, 0, 0, 0, 0, 0};
f32 lbl_803DC6B8[2] = {0.05f, 8.5f};
f32 lbl_803DC6C0 = 8.5f;
int lbl_803DC6C4[2] = {24, 26};
s16 gPlayerStopMoves[4] = {27, 28, 29, 33};
f32 lbl_803DC6D4 = 0.03f;
f32 lbl_803DC6D8 = 0.03f;
f32 lbl_803DC6DC = 0.03f;
f32 lbl_803DC6E0 = -0.3f;
f32 lbl_803DC6E4 = 0.05f;

int lbl_803DE4BC;
void* gPlayerDefaultStateHandler;
u16 gPlayerHeldButtonMask;
s16 gPlayerSelectedItem;
s16 lbl_803DE4B0;
u64 gPlayerFrameCounter;
u64 gPlayerLastSfxFrame;
f32 gPlayerLadderSlideVel;
f32 gPlayerStaffBoostStartY;
f32 gPlayerStaffBoostTargetY;
u8 gPlayerQuakeChargeSfxPlayed;
u8 gPlayerRocketBoostSfxPlayed;
f32 gPlayerLiftRockPullAccum;
int gPlayerSfxTimerD;
int gPlayerSfxTimerC;
int gPlayerSfxTimerB;
f32 gPlayerTeleportAnimRearm;
int gPlayerStepSfxTimer;
int gPlayerSfxTimerA;
s8 gPlayerSeqWalkStallFrames;
f32 gPlayerSeqWalkPrevDist;
f32 lbl_803DE464;
f32 gPlayerStaffSfxTimer;
f32 gPlayerFireLaserCountdown;
u8 gPlayerHitReactionVariant;
u8 lbl_803DE458;
StaffCollisionInterface** gPlayerResource;
GameObject* gPlayerStaffObject;
GameObject* gPlayerPathObject;
int gPlayerEggObject;
void* gPlayerChildObject;
f32 gPlayerSinkSfxTimer;
f32 gPlayerClimbEndY;
f32 gPlayerClimbStartY;
GameObject* gPlayerInteractTarget;
f32 lbl_803DE430;
u8 gPlayerIceSpellSustaining;
int gPlayerHeldObject;
int gPlayerPendingHealth;
int gPlayerModelChain;

PartFxSpawnParams gPlayerPartFxParams;

int playerState1D(int obj, PlayerState* state, f32 fv)
{
    HeadMoveTable* tbl = (HeadMoveTable*)lbl_80332EC0;
    u8 prev;
    int* tblB;
    GameObject* self = (GameObject*)obj;
    PlayerState* inner = self->extra;
    GameObject* sub;
    int nextMove = -1;
    int doXform = 1;
    int camCall = 0;
    f32 t;
    f32 t2;
    f32 xc;
    f32 yc;
    f32 yOut;
    CameraModeForceBehindInitParams col = sPlayerColRange;

    setAButtonIcon(0xf);
    if (state->baddie.moveJustStartedA != 0)
    {
        inner->flags3F3.b01 = inner->flags3F3.b08;
        state->baddie.stateId = 0x1d;
        inner->stateHandler = playerStagedRestoreCameraAndSyncPosition;
    }
    if (state->baddie.moveJustStartedA != 0)
    {
        if (gPlayerPathObject != 0 && inner->flags3F4.b40 != 0)
        {
            inner->staffActionRequest = 1;
            inner->flags3F4.b08 = 1;
        }
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            Camera_setBlendCurveMode(2);
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_FORCE_BEHIND_RESOURCE_ID, 1, 0, sizeof(col), &col, 0x1e, 0xff);
        }
        inner->stickDirection = 0;
        inner->latchedStickDir = 0;
        inner->targetYaw = getAngle(inner->surfaceNormalX, inner->surfaceNormalZ);
        {
            s16 ang = inner->targetYaw;
            inner->yaw = ang;
            self->anim.rotX = ang;
        }
        inner->flags3F2.b01 = 1;
        ObjAnim_SetCurrentMove((void*)obj, 0x5f, 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
        state->baddie.moveSpeed = 0.01f;
        {
            f32 z = 0.0f;
            inner->stickTargetX = z;
            inner->stickTargetY = z;
        }
        inner->flags3F3.b80 = 0;
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
    }
    inner->aimInputZ = 0.8f;
    {
        f32 z = 0.0f;
        inner->aimInputX = z;
        state->baddie.animSpeedA = z;
        state->baddie.animSpeedB = z;
    }
    sub = (GameObject*)inner->contactObject;
    switch (self->anim.currentMove)
    {
    case 0x5f:
        if ((*(int*)&state->baddie.heldButtons & 0x100) == 0)
        {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    case 0x4d:
    case 0x4e:
    case 0x5a:
    case 0x65:
        if (state->baddie.moveDone != 0)
        {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        camCall = 1;
        doXform = 0;
        break;
    }
    prev = inner->stickDirection;
    t = (f32)padGetStickX(0) / 56.0f;
    xc = (t < -1.0f) ? -1.0f : ((t > 1.0f) ? 1.0f : t);
    t2 = (f32)padGetStickY(0) / 56.0f;
    yc = (t2 < -1.0f) ? -1.0f : ((t2 > 1.0f) ? 1.0f : t2);
    if (inner->flags3F3.b80 == 0) {
        f32 component;
        f32 k;
        f32 yT;
        f32 xT;

        if (yc > 0.2f) {
            xT = -0.05f - 0.6f * yc;
            yT = 0.0f;
            inner->stickTargetY = 0.0f;
            inner->stickDirection = 1;
        } else if (yc < -0.2f) {
            xT = 0.05f - 0.6f * yc;
            yT = 0.0f;
            inner->stickTargetY = 0.0f;
            inner->stickDirection = 2;
        } else if (xc > 0.2f) {
            xT = 0.0f;
            inner->stickTargetX = 0.0f;
            yT = 0.3f * xc + 0.05f;
            inner->stickDirection = 3;
        } else if (xc < -0.2f) {
            xT = 0.0f;
            inner->stickTargetX = 0.0f;
            yT = 0.3f * xc + (-0.05f);
            inner->stickDirection = 4;
        } else {
            component = inner->stickTargetX;
            if (component <= 0.05f && component >= -0.05f) {
                component = inner->stickTargetY;
                if (component <= 0.05f && component >= -0.05f) {
                    inner->stickDirection = 0;
                    nextMove = 0x5f;
                    state->baddie.moveSpeed = 0.01f;
                }
            }
            xT = 0.0f;
            yT = 0.0f;
        }
        k = 0.1f;
        inner->stickTargetX += k * (xT - inner->stickTargetX);
        inner->stickTargetY += k * (yT - inner->stickTargetY);
    }
    if (inner->flags3F3.b80 == 0 &&
        ((*(int*)&state->baddie.heldButtons & 0x100) == 0 || inner->stickEdgeLatch != 0 ||
         (inner->flags3F1.b01 == 0 && state->baddie.unk1B0 >= 15.0f)))
    {
        if (inner->stickDirection != 0)
        {
            ObjAnim_SetCurrentMove((void*)obj, tbl->moveA[inner->stickDirection], 0.5f, 0);
            state->baddie.moveSpeed = 0.025f;
        }
        else
        {
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        inner->stickDirection = 0;
        inner->flags3F3.b80 = 1;
    }
    if (inner->flags3F3.b80 == 0)
    {
        if (inner->stickDirection != 0)
        {
            gPlayerSfxTimerD = gPlayerSfxTimerD - framesThisStep;
            if (gPlayerSfxTimerD <= 0)
            {
                gPlayerSfxTimerD = randomGetRange(0xb4, 0xf0);
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_literun116);
            }
            inner->flags360 |= 0x200LL;
            if (inner->stickDirection != prev || *(s8*)&inner->latchedStickDir == 0)
            {
                inner->flags3F2.b01 = 1;
                inner->latchedStickDir = 0;
            }
            else if (inner->stickDirection == *(s8*)&inner->latchedStickDir)
            {
                if (inner->flags3F3.b08 != 0 && inner->flags3F3.b01 == 0)
                {
                    inner->flags3F2.b01 = 1;
                    inner->latchedStickDir = 0;
                }
                else
                {
                    inner->flags3F2.b01 = 0;
                }
            }
            if (inner->flags3F2.b01 != 0)
            {
                state->baddie.moveSpeed =
                    0.01f * state->baddie.inputMagnitude + tbl->spdD[inner->stickDirection];
                nextMove = tbl->moveC[inner->stickDirection];
            }
            else
            {
                if (self->anim.currentMove != (tblB = tbl->moveB)[inner->stickDirection] ||
                    self->anim.currentMoveProgress >= 0.985f)
                {
                    state->baddie.moveSpeed =
                        0.005f * ((f32)randomGetRange(0, 100) / 100.0f) + tbl->spdE[inner->stickDirection];
                }
                nextMove = tblB[inner->stickDirection];
            }
        }
        {
            u8 res;
            s8 direction = inner->stickDirection;
            f32 a;
            f32 b;
            if (direction == 0)
            {
                a = 0.0f;
                b = 0.0f;
            }
            else
            {
                a = inner->stickTargetX;
                b = inner->stickTargetY;
            }
            res = PUSHABLE_INTERFACE(sub)->push(sub, (GameObject*)obj, direction, a, b);
            if (res == 1)
            {
                inner->latchedStickDir = 1;
            }
            else if (res == 2)
            {
                inner->latchedStickDir = 2;
            }
            else if (res == 3)
            {
                inner->latchedStickDir = 4;
            }
            else if (res == 4)
            {
                inner->latchedStickDir = 3;
            }
            else if (res == 5)
            {
                inner->stickEdgeLatch = 1;
            }
            else
            {
                inner->latchedStickDir = 0;
            }
        }
    }
    if (nextMove != -1 && self->anim.currentMove != nextMove &&
        ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
    {
        ObjAnim_SetCurrentMove((void*)obj, nextMove, 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xa);
    }
    if (camCall != 0)
    {
        (*gPlayerInterface)->updateAnimRootMotion((void*)obj, state, fv, 3);
    }
    if (doXform != 0)
    {
        Obj_TransformLocalPointToWorld(inner->contactPointX, inner->contactPointY, inner->contactPointZ,
                                       (f32*)(obj + 0xc), &yOut, (f32*)(obj + 0x14), (GameObject*)sub);
        {
            f32 k = 12.0f;
            self->anim.localPosX = k * inner->surfaceNormalX + self->anim.localPosX;
            self->anim.localPosZ = k * inner->surfaceNormalZ + self->anim.localPosZ;
        }
    }
    inner->flags3F3.b01 = inner->flags3F3.b08;
    return 0;
}

int playerState1C(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 k;
    f32 a, b;
    u8 s1, s2;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.stateId = 0x1c;
        inner->stateHandler = 0;
    }
    k = 0.0f;
    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        s1 = 0;
        a = inner->surfaceNormalX;
        if (a < k)
        {
            s1 = 1;
            a = -a;
        }
        s2 = 0;
        b = inner->surfaceNormalZ;
        if (b < 0.0f)
        {
            s2 = 1;
            b = -b;
        }
        if (a > b)
        {
            if (s1)
            {
                inner->surfaceDir = 0;
            }
            else
            {
                inner->surfaceDir = 1;
            }
        }
        else
        {
            if (s2)
            {
                inner->surfaceDir = 2;
            }
            else
            {
                inner->surfaceDir = 3;
            }
        }
        ObjAnim_SetCurrentMove(obj, 0x57, 0.0f, 0);
        state->baddie.moveSpeed = 0.016f;
        Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_impact3 : SFXTRIG_literun116));
    }
    if (state->baddie.moveDone != 0) {
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return -1;
    }
    return 0;
}

int playerState1B(GameObject* obj, PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    int curveId;
    int camArg = 0;
    f32 vec[3];
    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.stateId = 0x1b;
        inner->stateHandler = (BaddieStateExitFn)objUpdateHitboxPos;
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }
    {
        PlayerState* in2 = obj->extra;
        in2->flags360 = in2->flags360 & ~2LL;
        in2->flags360 |= 0x2000LL;
    }
    state->baddie.flags4 |= 0x100000;
    {
        f32 zero = 0.0f;
        state->baddie.animSpeedA = zero;
        state->baddie.animSpeedB = zero;
        state->baddie.flags0 |= 0x200000;
        obj->anim.velocityX = zero;
        obj->anim.velocityZ = zero;
        state->baddie.physicsActive = 0;
        obj->anim.velocityY = zero;
    }
    switch (obj->anim.currentMove) {
    case 0x76:
    case 0x40d: {
        int active;
        int atDest;
        f32 amt = state->baddie.moveInputZ / 56.0f;
        f32 clamped;
        f32 sp;
        f32 spd;
        if (amt < 0.0f) {
            amt = -amt;
        }
        clamped = (amt < 0.1f) ? 0.1f : ((amt > 1.0f) ? 1.0f : amt);
        sp = state->baddie.moveInputZ;
        if (sp > 1.0f) {
            spd = 0.25f * clamped;
            active = 1;
        } else if (sp < -1.0f) {
            spd = 0.25f * -clamped;
            active = 1;
        } else {
            spd = 0.0f;
            active = 0;
        }
        if (active != 0) {
            gPlayerSfxTimerC = gPlayerSfxTimerC - framesThisStep;
            if (gPlayerSfxTimerC <= 0) {
                gPlayerSfxTimerC = randomGetRange(0x1e, 0x2d);
                Sfx_PlayFromObject(0, SFXTRIG_foot_ladder3);
            }
        }
        state->baddie.animSpeedC =
            state->baddie.animSpeedC + interpolate(spd - state->baddie.animSpeedC, 0.1f, timeDelta);
        inner->traveledDistance = state->baddie.animSpeedC * timeDelta + inner->traveledDistance;
        {
            f32 ph = ((PlayerState*)state)->baddie.animSpeedC;
            if (ph < 0.01f && ph > -0.01f)
            {
                f32 zeroPh = 0.0f;
                ((PlayerState*)state)->baddie.animSpeedC = zeroPh;
                if (obj->anim.currentMove != 0x76)
                {
                    ObjAnim_SetCurrentMove(obj, 0x76, zeroPh, 0);
                }
                ((PlayerState*)state)->baddie.moveSpeed = 0.005f;
            }
            else
            {
                if (obj->anim.currentMove != 0x40d)
                {
                    ObjAnim_SetCurrentMove(obj, 0x40d, 0.0f, 0);
                }
                ObjAnim_SampleRootCurvePhase(&obj->anim, ((PlayerState*)state)->baddie.animSpeedC,
                                             (f32*)((char*)state + 0x2a0));
            }
        }
        atDest = inner->traveledDistance > inner->travelTargetDistance || inner->traveledDistance < 0.0f;
        if (atDest)
        {
            u8 anim;
            ObjAnim_SetCurrentMove(obj, 0x40f, 0.0f, 0);
            anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47)
            {
                camArg = inner->traveledDistance < 0.0f ? 0 : 1;
                (*gCameraInterface)->releaseAction(&camArg, camArg);
            }
        }
        else
        {
            inner->targetYaw = (s16)getAngle(-inner->travelDirX, -inner->travelDirZ);
            inner->yaw = inner->targetYaw;
            obj->anim.rotY = 0;
        }
        break;
    }
    case 0x40f:
        state->baddie.moveSpeed = 0.015f;
        (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
        if (state->baddie.moveDone != 0) {
            u8 anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47) {
                (*gCameraInterface)->setMode(0x42, 1, 1, 0, NULL, 0, 0xff);
            }
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    case 0x40e:
        state->baddie.moveSpeed = 0.015f;
        (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, fv, 1);
        inner->targetYaw = (s16)getAngle(inner->hitNormalX, inner->hitNormalZ);
        inner->yaw = inner->targetYaw;
        sqrtf(inner->hitNormalX * inner->hitNormalX + inner->hitNormalZ * inner->hitNormalZ);
        obj->anim.rotY = 0;
        if (state->baddie.moveDone != 0) {
            ObjAnim_SetCurrentMove(obj, 0x40d, 0.0f, 0);
        }
        break;
    default: {
        int found;
        curveId = 0x1f;
        found =
            (*gRomCurveInterface)->find(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, &curveId, 1, 0);
        if (found != -1) {
            RomCurveDef* pt = (*gRomCurveInterface)->getById(found);
            RomCurveDef* pt2;
            inner->curveStartX = pt->x;
            inner->curveStartY = pt->y;
            inner->curveStartZ = pt->z;
            obj->anim.localPosX = pt->x;
            obj->anim.localPosY = pt->y;
            obj->anim.localPosZ = pt->z;
            inner->targetYaw = (s16)getAngle(inner->hitNormalX, inner->hitNormalZ);
            inner->yaw = inner->targetYaw;
            sqrtf(inner->hitNormalX * inner->hitNormalX + inner->hitNormalZ * inner->hitNormalZ);
            obj->anim.rotY = 0;
            found = (*gRomCurveInterface)->getRandomForwardLink(pt, -1);
            if (found == -1) {
                found = (*gRomCurveInterface)->getRandomBackwardLink(pt, -1);
            }
            pt2 = (*gRomCurveInterface)->getById(found);
            inner->curveEndX = pt2->x;
            inner->curveEndY = pt2->y;
            inner->curveEndZ = pt2->z;
            inner->traveledDistance = 0.0f;
            PSVECSubtract((Vec*)&inner->curveEndX, (Vec*)&inner->curveStartX, (Vec*)vec);
            inner->travelTargetDistance = PSVECMag((Vec*)vec);
            PSVECNormalize((Vec*)vec, (Vec*)&inner->travelDirX);
        }
        ObjAnim_SetCurrentMove(obj, 0x40e, 0.0f, 0);
        {
            u8 anim = inner->curAnimId;
            if (anim != 0x48 && anim != 0x47)
            {
                (*gCameraInterface)->setMode(0x50, 1, 0, 0, NULL, 0x28, 0xff);
            }
        }
        state->baddie.animSpeedC = 0.0f;
        break;
    }
    }
    PSVECScale((Vec*)((char*)inner + 0x634), (Vec*)vec, inner->traveledDistance);
    PSVECAdd((Vec*)((char*)inner + 0x61c), (Vec*)vec, &obj->anim.localPos);
    playerRefreshCollisionState(obj, (int)inner, 7);
    return 0;
}

int playerStateOnCloudRunner(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    GameObject* sub;
    f32 aimInputX, aimInputZ;
    f32 k;
    int res, halfH, halfW;

    inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    ObjHits_EnableObject(obj);
    sub = inner->focusObject;
    if (sub == NULL) {
        f32 z = 0.0f;
        state->baddie.animSpeedC = z;
        state->baddie.animSpeedB = z;
        state->baddie.animSpeedA = z;
        obj->anim.velocityX = z;
        obj->anim.velocityY = z;
        obj->anim.velocityZ = z;
        ObjHits_EnableObject(obj);
    } else {
        if (sub->anim.romDefNo != 0x714) {
            ObjHits_DisableObject(obj);
        }
    }
    if (state->baddie.moveJustStartedA != 0) {
        f32 z = 0.0f;
        inner->aimInputX = z;
        inner->aimInputZ = z;
        (*gCameraInterface)->setMode(CAMERA_MODE_CLOUDRUNNER_RESOURCE_ID, 1, sub != NULL ? 0x12 : -2, 0, NULL, 0, 0xff);
        ObjAnim_SetCurrentMove(obj, 0x43e, 0.0f, 0);
        state->baddie.moveSpeed = 0.015f;
        inner->actionCooldown = 0.0f;
        if (gPlayerPathObject != NULL) {
            if (inner->flags3F4.b40 != 0) {
                inner->staffActionRequest = 4;
                inner->flags3F4.b08 = 1;
            }
        }
    }
    if (obj->anim.alpha > 1) {
        obj->anim.alpha = 1;
    }
    inner->actionCooldown = inner->actionCooldown - timeDelta;
    if (inner->actionCooldown < 0.0f) {
        inner->actionCooldown = 0.0f;
    }
    if ((inner->buttonsJustPressed & PAD_BUTTON_A) != 0) {
        if (inner->actionCooldown <= 0.0f) {
            buttonDisable(0, PAD_BUTTON_A);
            playerFireCloudRunnerProjectile(obj, state, inner->aimInputZ, 0.0f);
            inner->actionCooldown = 5.0f;
        }
    }
    {
        f32 c;
        GameObject* hit;
        c = (state->baddie.moveInputZ / 56.0f) < -1.5f  ? -1.5f
            : (state->baddie.moveInputZ / 56.0f) > 1.5f ? 1.5f
                                                        : state->baddie.moveInputZ / 56.0f;
        hit = inner->focusObject;
        if (hit != NULL && hit->anim.romDefNo == 0x484) {
            c = c + lbl_803DC6E0;
        }
        if (hit == NULL) {
            c = c + lbl_803DC6E4;
        }
        inner->aimInputZ += interpolate(c - inner->aimInputZ, lbl_803DC6D4, timeDelta);
    }
    {
        f32 x = state->baddie.moveInputX / 56.0f;
        f32 c;
        c = (x < -1.0f) ? -1.0f : ((x > 1.0f) ? 1.0f : x);
        inner->aimInputX += interpolate(c - inner->aimInputX, lbl_803DC6D8, timeDelta);
    }
    {
        f32 d = inner->aimInputX;
        if (d > 0.0f) {
            d -= 0.75f;
            if (d < 0.0f) {
                d = 0.0f;
            }
        } else {
            d = 0.75f + d;
            if (d > 0.0f) {
                d = 0.0f;
            }
        }
        {
            f32 p = -1000.0f * d;
            inner->targetYaw = (s16)(p * lbl_803DC6DC + (f32)inner->targetYaw);
        }
        inner->yaw = inner->targetYaw;
    }
    if (inner->aimInputZ > 0.0f) {
        Object_ObjAnimSetSecondaryBlendMove(&obj->anim, 0x441, (int)(16384.0f * inner->aimInputZ));
    } else {
        Object_ObjAnimSetSecondaryBlendMove(&obj->anim, 0x440, (int)(16384.0f * -inner->aimInputZ));
    }
    inner->headPitch = (f32)inner->headPitch * powfBitEstimate(0.9f, timeDelta);
    inner->headYaw = (f32)inner->headYaw * powfBitEstimate(0.85f, timeDelta);
    inner->bodyLeanHalf = -10240.0f * inner->aimInputX;
    inner->bodyLeanAngle = (s16)(inner->bodyLeanHalf >> 1);
    inner->flags360 &= ~PLAYER_FLAG_AIM_READY;
    aimInputZ = inner->aimInputZ;
    aimInputX = inner->aimInputX;
    res = getScreenResolution();
    halfH = res >> 17;
    halfW = (int)(u16)res >> 1;
    k = 0.5f;
    inner->aimScreenX = k * (aimInputX * (f32)halfW) + (f32)halfW;
    if (aimInputZ < 0.0f) {
        inner->aimScreenY = k * (aimInputZ * (f32)halfH) + (f32)halfH;
    } else {
        inner->aimScreenY = 0.25f * (aimInputZ * (f32)halfH) + (f32)halfH;
    }
    inner->flags360 |= PLAYER_FLAG_AIM_READY;
    return 0;
}

int playerState19(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    GameObject* sub = inner->focusObject;
    s16* vec;
    int kind;
    ObjModel* joint;
    int n;
    f32 t;
    f32 pos1[3];
    f32 pos2[3];
    s16 ang[3];
    f32 localPt;
    f32 cam[3];

    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.stateId = 0x19;
        inner->stateHandler = NULL;
    }
    {
        PlayerState* inner2 = obj->extra;
        inner2->flags360 = inner2->flags360 & ~2LL;
        inner2->flags360 |= 0x2000;
    }
    state->baddie.flags4 |= 0x100000;
    {
        f32 z = 0.0f;
        state->baddie.animSpeedA = z;
        state->baddie.animSpeedB = z;
        state->baddie.flags0 |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    state->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
    obj->anim.velocityY = 0.0f;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        VEHICLE_INTERFACE(sub)->getRiderPosition((GameObject*)sub, (f32*)((char*)obj + 0xc),
                                                 (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14));
        switch (sub->anim.romDefNo)
        {
        case 0x38c:
        case 0x72:
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x64, 0xff);
            break;
        default:
            (*gCameraInterface)->loadTriggeredCamAction(0, 1, 0);
            break;
        }
        kind = VEHICLE_INTERFACE(sub)->getDismountSide(sub);
        VEHICLE_INTERFACE(sub)->setMountState(sub, VEHICLE_Dismounting);
        switch (kind) {
        case 1:
            n = 8;
            break;
        case 2:
        default:
            n = 9;
            break;
        }
        inner->targetYaw = sub->anim.rotX;
        inner->yaw = inner->targetYaw;
        obj->anim.rotY = 0;
        obj->anim.rotZ = 0;
        ObjAnim_SetCurrentMove(obj, inner->moveSequence[n], 0.0f, 1);
        joint = Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(joint, 0, 0, 0.0f, obj->anim.rootMotionScale, pos1, ang);
        ObjModel_SampleJointTransform(joint, 0, 0, 1.0f, obj->anim.rootMotionScale, pos2, ang);
        ang[0] = inner->targetYaw;
        ang[1] = 0;
        ang[2] = 0;
        vecRotateZXY(ang, pos2);
        pos2[0] = pos2[0] + obj->anim.localPosX;
        pos2[2] = pos2[2] + obj->anim.localPosZ;
        obj->anim.localPosY -= pos1[1];
        t = (*gPathControlInterface)
                ->sampleHeight((void*)obj, pos2[0], obj->anim.localPosY, pos2[2], 20.0f);
        inner->warpStartX = pos2[0];
        inner->warpStartY = t;
        inner->warpStartZ = pos2[2];
        inner->warpDeltaY = obj->anim.localPosY - t;
        inner->warpKind = (u8)kind;
        obj->anim.flags &= ~0x8;
        obj->anim.activeMove = -1;
        state->baddie.moveSpeed = 0.016f;
    }
    t = 1.0f - obj->anim.currentMoveProgress;
    obj->anim.localPosY = inner->warpDeltaY * t + inner->warpStartY;
    vec = objFindJointPoseVector(obj, 5);
    if (vec != NULL) {
        vec[0] = (f32)sub->anim.rotY * t;
        vec[2] = (f32)sub->anim.rotZ * t;
    }
    VEHICLE_INTERFACE(sub)->getCameraPosition(sub, &cam[0], &cam[1], &cam[2]);
    {
        f32 w = obj->anim.currentMoveProgress;
        f32 cx = w * (inner->warpStartX - cam[0]) + cam[0];
        f32 cy = w * (inner->warpStartY - cam[1]) + cam[1];
        f32 cz = w * (inner->warpStartZ - cam[2]) + cam[2];
        (*gCameraInterface)->overridePos(cx, cy, cz);
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA == 0 &&
        ((PlayerState*)state)->baddie.moveDone != 0)
    {
        if (vec != NULL)
        {
            *(s16*)vec = 0;
            *(s16*)((char*)vec + 0x4) = 0;
        }
        obj->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        obj->anim.worldPosX = inner->savedPosX;
        obj->anim.worldPosZ = inner->savedPosZ;
        if (obj->anim.parent != NULL)
        {
            obj->anim.worldPosX += playerMapOffsetX;
            obj->anim.worldPosZ += playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, 0.0f,
                                       obj->anim.worldPosZ, &obj->anim.localPosX,
                                       &localPt, &obj->anim.localPosZ,
                                       obj->anim.parent);
        if (inner->warpKind == 1)
        {
            inner->targetYaw += 0x4000;
            inner->yaw = inner->targetYaw;
        }
        else
        {
            inner->targetYaw -= 0x4000;
            inner->yaw = inner->targetYaw;
        }
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 1);
        ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_CURRENT,
                               OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
        VEHICLE_INTERFACE(sub)->setMountState((GameObject*)sub, VEHICLE_NoRider);
        playerRefreshCollisionState(obj, (int)inner, 7);
        ObjHits_EnableObject(obj);
        inner->focusObject = NULL;
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    return 0;
}

void playerStagedClearActiveMove(GameObject* obj)
{
    ObjModelState* modelState = obj->anim.modelState;
    s16* v;
    modelState->flags &= 0xFFFFEFFFLL;
    obj->anim.flags &= ~0x8;
    obj->anim.activeMove = -1;
    v = objFindJointPoseVector(obj, 9);
    if (v != NULL)
    {
        v[0] = 0;
        v[1] = 0;
        v[2] = 0;
    }
}

int playerStateOnBike(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    GameObject* sub;
    f32 out;
    f32 a;
    int b;
    f32 c;
    int d;
    f32 ret;
    int blend;
    (*gCameraInterface)->func1C(2);
    state->baddie.physicsActive = 0;
    state->baddie.flags4 |= 0x100000;
    inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    ObjHits_DisableObject(obj);
    sub = inner->focusObject;
    if (sub == NULL) {
        obj->anim.activeMove = -1;
        return 0;
    }
    if (state->baddie.moveJustStartedA != 0) {
        if (inner->moveSequence == NULL) {
            inner->moveSequence = gPlayerMotionTuning.moveSequences[0];
        }
        ObjAnim_SetCurrentMove(obj, inner->moveSequence[1], 0.0f, 0);
        ObjAnim_AdvanceCurrentMove(obj, 0.0f, 0.0f, NULL);
    }
    if ((inner->moveSequenceFlags & 0x4) != 0) {
        ObjAnim_SetMoveProgress(&obj->anim, sub->anim.currentMoveProgress);
        state->baddie.moveSpeed = 0.0f;
    } else {
        ret = VEHICLE_INTERFACE(sub)->getNormalizedSpeed(sub, &out);
        if (out <= 1.0f) {
            state->baddie.moveSpeed = out;
        } else {
            state->baddie.moveSpeed = 0.05f * ret + 0.01f;
        }
    }
    if ((inner->moveSequenceFlags & 0x1) != 0) {
        VEHICLE_INTERFACE(sub)->getPlayerAnim(sub, &a, &b);
        blend = (int)(16384.0f * a);
        if (blend < 0) {
            blend = -blend;
        }
        if (b != 0) {
            Object_ObjAnimSetSecondaryBlendMove(&obj->anim, inner->moveSequence[5], blend);
        } else {
            Object_ObjAnimSetSecondaryBlendMove(&obj->anim, inner->moveSequence[4], blend);
        }
    } else if ((inner->moveSequenceFlags & 0x8) != 0) {
        VEHICLE_INTERFACE(sub)->getPlayerAnim(sub, &c, &d);
        inner->flags360 |= 0x2000000LL;
        inner->headYaw = (s16)d;
        inner->bodyLeanAngle = (s16)c;
        inner->bodyLeanHalf = inner->bodyLeanAngle / 2;
        inner->headPitch = inner->bodyLeanAngle / 2;
    }
    if ((inner->moveSequenceFlags & 0x1) != 0) {
        ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
        ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_ACTIVE, OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    }
    if (VEHICLE_INTERFACE(sub)->canDismount(sub, obj) != 0) {
        state->baddie.nextStateExitFn = NULL;
        return 0x1a;
    }
    return 0;
}

int playerState17(GameObject* p1, PlayerState* state) {
    if (mainGetBit(GAMEBIT_LV_EscapedFromPole)) {
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return -1;
    }
    return 0;
}

int playerStateMountBike(GameObject* obj, PlayerState* state, f32 fv)
{
    char* base = (char*)lbl_80332EC0;
    PlayerState* inner = obj->extra;
    GameObject* sub = inner->focusObject;
    ObjModel* joint;
    f32 j0[3];
    f32 j1[3];
    f32 wpos[3];

    inner->flags360 = inner->flags360 & ~2LL;
    inner->flags360 |= 0x2000;
    state->baddie.flags4 |= 0x100000;
    {
        f32 z = 0.0f;
        state->baddie.animSpeedA = z;
        state->baddie.animSpeedB = z;
        state->baddie.flags0 |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    ((PlayerState*)state)->baddie.physicsActive = 0;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.stateId = 0x16;
        inner->stateHandler = 0;
    }
    ObjHits_DisableObject(obj);
    obj->anim.velocityY = 0.0f;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        int sel;
        s16 scratch[3];

        if (gPlayerPathObject != NULL && inner->flags3F4.b40 != 0)
        {
            inner->staffActionRequest = 1;
            inner->flags3F4.b08 = 1;
        }
        switch (sub->anim.romDefNo)
        {
        case 0x72:
            inner->moveSequence = (s16*)(base + 0x3f0);
            inner->moveSequenceFlags = 3;
            if (coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ) == 0x13)
            {
                mainSetBits(0xf0a, 1);
            }
            (*gCameraInterface)->setMode(0x45, 1, 0, 0, NULL, 0, 0xff);
            break;
        case 0x38c:
            inner->moveSequence = (s16*)(base + 0x3f0);
            inner->moveSequenceFlags = 3;
            (*gCameraInterface)->setFocus((void*)sub, 0);
            (*gCameraInterface)->setMode(0x45, 1, 0, 0, NULL, 0, 0xff);
            break;
        case 0x419:
            inner->moveSequence = (s16*)(base + 0x420);
            (*gCameraInterface)->setMode(CAMERA_MODE_CLOUDRUNNER_RESOURCE_ID, 1, 0, 0, NULL, 0x2d, 0xff);
            break;
        case 0x416:
            inner->moveSequence = (s16*)(base + 0x438);
            inner->moveSequenceFlags = 8;
            (*gCameraInterface)->setFocus((void*)sub, 0);
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x69, 0);
            break;
        case 0x8c:
            inner->moveSequence = (s16*)(base + 0x408);
            inner->moveSequenceFlags = 4;
            break;
        default:
            inner->moveSequence = (s16*)(base + 0x420);
            inner->moveSequenceFlags = 4;
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x1d, 0);
            break;
        }
        {
            int t = VEHICLE_INTERFACE(sub)->getMountSide((GameObject*)sub);
            VEHICLE_INTERFACE(sub)->setMountState((GameObject*)sub, VEHICLE_Mounting);
            switch (t)
            {
            case 1:
                sel = 6;
                break;
            case 2:
            default:
                sel = 7;
                break;
            }
        }
        inner->targetYaw = sub->anim.rotX;
        inner->yaw = inner->targetYaw;
        ObjAnim_SetCurrentMove(obj, inner->moveSequence[sel], 0.0f, 4);
        joint = Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(joint, 0, 0, 0.0f, obj->anim.rootMotionScale, j0, scratch);
        ObjModel_SampleJointTransform(joint, 0, 0, 1.0f, obj->anim.rootMotionScale, j1, scratch);
        VEHICLE_INTERFACE(sub)->getRiderPosition(sub, &wpos[0], &wpos[1], &wpos[2]);
        wpos[0] = wpos[0] - obj->anim.localPosX;
        wpos[1] = wpos[1] - obj->anim.localPosY;
        wpos[2] = wpos[2] - obj->anim.localPosZ;
        inner->warpStartX = obj->anim.localPosX;
        inner->warpStartY = obj->anim.localPosY;
        inner->warpStartZ = obj->anim.localPosZ;
        inner->warpDeltaX = wpos[0];
        inner->warpDeltaY = wpos[1] - j1[1];
        inner->warpDeltaZ = wpos[2];
        obj->anim.flags |= 8;
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        obj->anim.modelState->shadowAlphaStep = 0;
        state->baddie.moveSpeed = 0.022f;
    }
    {
        obj->anim.localPosX = obj->anim.currentMoveProgress * inner->warpDeltaX + inner->warpStartX;
        obj->anim.localPosY = obj->anim.currentMoveProgress * inner->warpDeltaY + inner->warpStartY;
        obj->anim.localPosZ = obj->anim.currentMoveProgress * inner->warpDeltaZ + inner->warpStartZ;
        VEHICLE_INTERFACE(sub)->getCameraPosition(sub, &wpos[0], &wpos[1], &wpos[2]);
        (*gCameraInterface)
            ->overridePos(
                obj->anim.currentMoveProgress * (wpos[0] - inner->warpStartX) + inner->warpStartX,
                obj->anim.currentMoveProgress * (wpos[1] - inner->warpStartY) + inner->warpStartY,
                obj->anim.currentMoveProgress * (wpos[2] - inner->warpStartZ) + inner->warpStartZ);
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA == 0 &&
        ((PlayerState*)state)->baddie.moveDone != 0) {
        ObjAnim_SetCurrentMove(obj, *inner->moveSequence, 0.0f, 1);
        VEHICLE_INTERFACE(sub)->setMountState((GameObject*)sub, VEHICLE_Mounted);
        if (arrayIndexOf((int*)(base + 0x160), 4, sub->anim.romDefNo) != -1)
        {
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedClearActiveMove;
            return 0x1b;
        }
        ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedClearActiveMove;
        return 0x19;
    }
    return 0;
}

void playerStagedRestoreCameraUnlessClimbing(GameObject* obj, BaddieState* p2)
{
    PlayerState* inner = obj->extra;
    s16 v = ((PlayerState*)p2)->baddie.controlMode;
    if (v != 0x15 && v != 0x14 && v != 0x12 && v != 0x13 && v != 0xe && v != 0xf && v != 0x10)
    {
        u8 curAnimId = inner->curAnimId;
        if (curAnimId != 0x48 && curAnimId != 0x47 && curAnimId != 0x42 && getCurSeqNo() == 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
            inner->curAnimId = 0x42;
        }
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    obj->anim.activeMove = -1;
}

void objUpdateHitboxPos(GameObject* obj) {
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int playerStateClimbDownFromWall(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    playerPlayClimbingSound(obj, state);
    if (state->baddie.moveJustStartedA != 0) {
        u8 ic;
        ObjModel* model;
        s16 buf2[3];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty(&obj->anim);
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47) {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[0x13], 0.0f, 1);
        Object_ObjAnimSetSecondaryBlendMove(&obj->anim, lbl_80332F48[0x14], 0);
        state->baddie.moveSpeed = 0.015f;
        model = Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(model, 0, 0, 1.0f, obj->anim.rootMotionScale, buf1, buf2);
        inner->moveOffsetX = inner->groundNormalX * buf1[2];
        inner->moveOffsetZ = inner->groundNormalZ * buf1[2];
        obj->anim.localPosY = inner->spanBottomY;
        state->baddie.stateId = 0x15;
        inner->stateHandler = playerStagedRestoreCameraUnlessClimbing;
    }
    {
        PlayerState* ex = obj->extra;
        ex->flags360 &= ~2LL;
        ex->flags360 |= 0x2000LL;
    }
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    fz = 0.0f;
    state->baddie.animSpeedA = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = fz;
    ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_STATE,
                           inner->animEventState);
    if ((((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
    {
        doRumble(5.0f);
    }
    obj98 = obj->anim.currentMoveProgress;
    if (obj98 > 0.99f)
    {
        obj->anim.worldPosX = inner->savedPosX;
        obj->anim.worldPosZ = inner->savedPosZ;
        if ((void*)obj->anim.parent != NULL)
        {
            obj->anim.worldPosX = obj->anim.worldPosX + playerMapOffsetX;
            obj->anim.worldPosZ = obj->anim.worldPosZ + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, 0.0f,
                                       obj->anim.worldPosZ, &obj->anim.localPosX, &outY,
                                       &obj->anim.localPosZ, obj->anim.parent);
        playerRefreshCollisionState(obj, (int)inner, 5);
        ObjAnim_SetCurrentMove(obj, *inner->moveAnimIds, 0.0f, 1);
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return -1;
    }
    t1 = inner->moveOffsetX * obj98 + obj->anim.localPosX;
    t2 = obj->anim.localPosY - inner->moveOffsetY * (1.0f - obj98);
    t3 = inner->moveOffsetZ * obj98 + obj->anim.localPosZ;
    (*gCameraInterface)->overridePos(t1, t2, t3);
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

int playerStateClimbUpFromWall(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    f32 obj98;
    f32 t1, t2, t3;
    f32 outY;
    playerPlayClimbingSound(obj, state);
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        u8 ic;
        ObjModel* model;
        s16 buf2[3];
        f32 buf1[3];
        ObjHits_MarkObjectPositionDirty(&obj->anim);
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x3c, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[0x11], 0.0f, 1);
        Object_ObjAnimSetSecondaryBlendMove(&obj->anim, lbl_80332F48[0x12], 0);
        state->baddie.moveSpeed = 0.012f;
        model = Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(model, 0, 0, 1.0f, obj->anim.rootMotionScale, buf1, buf2);
        inner->moveOffsetX = inner->groundNormalX * buf1[2];
        inner->moveOffsetZ = inner->groundNormalZ * buf1[2];
        obj->anim.localPosY = inner->spanTopY;
        state->baddie.stateId = 0x14;
        inner->stateHandler = playerStagedRestoreCameraUnlessClimbing;
    }
    {
        PlayerState* ex = obj->extra;
        ex->flags360 &= ~2LL;
        ex->flags360 |= 0x2000LL;
    }
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    fz = 0.0f;
    state->baddie.animSpeedA = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = fz;
    ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_STATE,
                           inner->animEventState);
    obj98 = obj->anim.currentMoveProgress;
    if (obj98 > 0.99f)
    {
        obj->anim.worldPosX = inner->savedPosX;
        obj->anim.worldPosZ = inner->savedPosZ;
        if ((void*)obj->anim.parent != NULL)
        {
            obj->anim.worldPosX = obj->anim.worldPosX + playerMapOffsetX;
            obj->anim.worldPosZ = obj->anim.worldPosZ + playerMapOffsetZ;
        }
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, 0.0f,
                                       obj->anim.worldPosZ, &obj->anim.localPosX, &outY,
                                       &obj->anim.localPosZ, obj->anim.parent);
        playerRefreshCollisionState(obj, (int)inner, 5);
        ObjAnim_SetCurrentMove(obj, *inner->moveAnimIds, 0.0f, 1);
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return -1;
    }
    t1 = inner->moveOffsetX * obj98 + obj->anim.localPosX;
    t2 = obj->anim.localPosY - inner->moveOffsetY * (1.0f - obj98);
    t3 = inner->moveOffsetZ * obj98 + obj->anim.localPosZ;
    (*gCameraInterface)->overridePos(t1, t2, t3);
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

int playerStateClimbWall(GameObject* obj, struct PlayerState* stateArg)
{
    int mask;
    int movingUp;
    int movingDown;
    int movingRight;
    int movingLeft;
    int dir;
    PlayerState* state = stateArg;
    ObjModel* model;
    PlayerState* inner = obj->extra;
    s16 i;
    f32 oldSpd;
    f32 dx;
    f32 dy;
    f32 ph;
    WallHit hit;
    f32 out1[3];
    f32 pnt[3];
    f32 dst[3];
    s16 tmp[3];

    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        gPlayerCurrentMoveId = 0x10;
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }
    {
        PlayerState* player = obj->extra;
        player->flags360 = player->flags360 & ~2LL;
        player->flags360 |= 0x2000;
    }
    state->baddie.flags4 |= 0x100000;
    {
        f32 z = 0.0f;
        state->baddie.animSpeedA = z;
        state->baddie.animSpeedB = z;
        state->baddie.flags0 |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
        state->baddie.flags4 |= 0x8000000;
        obj->anim.velocityY = z;
    }
    model = Player_GetActiveModel(obj);
    ph = state->baddie.moveSpeed;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    switch ((s16)gPlayerCurrentMoveId)
    {
    case 0x10:
        if (obj->anim.currentMove == 0x66)
        {
            inner->moveAltToggle = 0;
            gPlayerCurrentMoveId = 0x16;
        }
        else
        {
            inner->moveAltToggle = 1;
            gPlayerCurrentMoveId = 0x15;
        }
        obj->anim.localPosY = inner->savedPosY;
        ph = 0.006f;
    case 0x15:
    case 0x16:
    {
        f32 z = 0.0f;
        inner->moveOffsetX = z;
        inner->moveOffsetY = z;
        inner->moveOffsetZ = z;
    }
        playerPlayClimbingSound(obj, stateArg);
        if (state->baddie.inputMagnitude <= 0.1f)
        {
            break;
        }
        oldSpd = obj->anim.currentMoveProgress;
        obj->anim.currentMoveProgress = 1.0f;
    default:
        if (1.0f == obj->anim.currentMoveProgress)
        {
            pnt[0] = -(30.0f * inner->groundNormalX - inner->savedPosX);
            pnt[1] = inner->savedPosY;
            pnt[2] = -(30.0f * inner->groundNormalZ - inner->savedPosZ);
            {
                int r = trackGetLineIntersect(&inner->savedPosX, pnt, 0.0f, 3,
                                           (TrackLineIntersectResult*)&hit, obj, 1, 3, 0xff, 0);
                if (r != 0)
                {
                    obj->anim.localPosX = pnt[0];
                    obj->anim.localPosZ = pnt[2];
                    {
                        f32 ga = hit.ga;
                        inner->spanTopY = hit.gt * (hit.gb - ga) + ga;
                    }
                    {
                        f32 fz0 = hit.fz0;
                        inner->spanBottomY = hit.gt * (hit.fz1 - fz0) + fz0;
                    }
                    inner->groundNormalX = hit.nx;
                    inner->groundNormalY = hit.ny;
                    inner->groundNormalZ = hit.nz;
                    inner->groundNormalW = hit.nw;
                    inner->slopeTangentX = -hit.nz;
                    inner->slopeTangentY = 0.0f;
                    inner->slopeTangentZ = hit.nx;
                    inner->slopePlaneD = -(pnt[2] * inner->slopeTangentZ +
                                           (pnt[0] * inner->slopeTangentX + pnt[1] * inner->slopeTangentY));
                    inner->targetYaw = (s16)getAngle(inner->groundNormalX, inner->groundNormalZ);
                    inner->yaw = inner->targetYaw;
                    {
                        int hf = hit.flags;
                        if ((hf & 4) != 0)
                        {
                            dir = 0;
                        }
                        else if ((hf & 8) != 0)
                        {
                            dir = 1;
                        }
                        else if ((hf & 2) != 0)
                        {
                            dir = 2;
                        }
                        else
                        {
                            dir = 3;
                        }
                    }
                }
                else
                {
                    dir = 2;
                }
            }
            if (gPlayerCurrentMoveId != 0x15 && gPlayerCurrentMoveId != 0x16)
            {
                obj->anim.localPosY = inner->savedPosY;
            }
            if (state->baddie.inputMagnitude > 0.1f)
            {
                gPlayerCurrentMoveId =
                    (((getAngle(state->baddie.moveInputX, -state->baddie.moveInputZ) & 0xffff) + 0x1000) >> 13) & 7;
                gPlayerPrevMoveId = -1;
                if ((s16)gPlayerCurrentMoveId == 4 || (s16)gPlayerCurrentMoveId == 0)
                {
                    inner->moveAltToggle ^= 1;
                }
                movingUp = 0;
                movingDown = 0;
                movingRight = 0;
                movingLeft = 0;
                switch (gPlayerCurrentMoveId)
                {
                case 4:
                    movingUp = 1;
                    break;
                case 0:
                    movingDown = 1;
                    break;
                case 6:
                    movingRight = 1;
                    break;
                case 2:
                    movingLeft = 1;
                    break;
                case 3:
                    movingUp = 1;
                    movingLeft = 1;
                    break;
                case 5:
                    movingUp = 1;
                    movingRight = 1;
                    break;
                case 1:
                    movingDown = 1;
                    movingLeft = 1;
                    break;
                case 7:
                    movingDown = 1;
                    movingRight = 1;
                    break;
                }
                if (inner->moveAltToggle != 0)
                {
                    gPlayerCurrentMoveId += 8;
                }
                if (movingUp != 0)
                {
                    f32 fv = inner->spanTopY - inner->savedPosY;
                    f32 lo = gPlayerMoveRootHeights[12];
                    f32 hi;
                    if (lo < 0.0f)
                    {
                        lo = -lo;
                    }
                    hi = gPlayerMoveRootHeights[13];
                    if (hi < 0.0f)
                    {
                        hi = -hi;
                    }
                    if (fv < hi && (dir == 0 || dir == 3))
                    {
                        f32 frac = (fv - lo) / (hi - lo);
                        f32 m = (frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac);
                        inner->animEventState = (s16)(16384.0f * m);
                        inner->moveOffsetY = m;
                        state->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
                        return 0x15;
                    }
                }
                else if (movingDown != 0)
                {
                    f32 fv = inner->savedPosY - inner->spanBottomY;
                    f32 lo = gPlayerMoveRootHeights[14];
                    f32 hi;
                    if (lo < 0.0f)
                    {
                        lo = -lo;
                    }
                    hi = gPlayerMoveRootHeights[15];
                    if (hi < 0.0f)
                    {
                        hi = -hi;
                    }
                    if (fv < hi && (dir == 1 || dir == 3))
                    {
                        f32 frac = (fv - lo) / (hi - lo);
                        f32 m = (frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac);
                        inner->animEventState = (s16)(16384.0f * m);
                        inner->moveOffsetY = m;
                        state->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
                        return 0x16;
                    }
                }
                Object_ObjAnimSetMove(obj, lbl_80332F48[gPlayerCurrentMoveId], 0.0f, 1);
                ObjModel_SampleJointTransform(model, 1, 0, 1.0f, obj->anim.rootMotionScale, out1, tmp);
                obj->anim.activeMove = -1;
                inner->moveOffsetX = inner->slopeTangentX * -out1[0];
                inner->moveOffsetY = out1[1];
                inner->moveOffsetZ = inner->slopeTangentZ * -out1[0];
                if (movingUp == 0 && movingDown == 0) {
                    inner->moveOffsetY = 0.0f;
                }
                if (movingRight == 0 && movingLeft == 0) {
                    f32 z = 0.0f;
                    inner->moveOffsetX = z;
                    inner->moveOffsetZ = z;
                }
                mask = 0;
                if (out1[0] < 0.0f) {
                    dx = 7.0f * inner->slopeTangentX;
                    dy = 7.0f * inner->slopeTangentZ;
                } else {
                    dx = 7.0f * -inner->slopeTangentX;
                    dy = 7.0f * -inner->slopeTangentZ;
                }
                if (movingUp != 0 || movingDown != 0) {
                    pnt[1] = inner->savedPosY + out1[1];
                    if (out1[1] < 0.0f) {
                        pnt[1] -= 11.0f;
                    } else {
                        pnt[1] += 11.0f;
                    }
                    i = 0;
                    ph = 30.0f;
                    for (; i < 2; i++) {
                        if (i != 0) {
                            pnt[0] = inner->savedPosX + dx;
                            pnt[2] = inner->savedPosZ + dy;
                        } else {
                            pnt[0] = inner->savedPosX - dx;
                            pnt[2] = inner->savedPosZ - dy;
                        }
                        dst[0] = -(ph * inner->groundNormalX - pnt[0]);
                        dst[1] = pnt[1];
                        dst[2] = -(ph * inner->groundNormalZ - pnt[2]);
                        if (trackGetLineIntersect(pnt, dst, 0.0f, 3, NULL, obj, 1, 3, 0xff, 0) != 0) {
                            mask = mask | 1 << i;
                        }
                    }
                } else {
                    mask |= 3;
                }
                if (movingRight != 0 || movingLeft != 0) {
                    pnt[0] = dx + (inner->savedPosX + inner->moveOffsetX);
                    pnt[2] = dy + (inner->savedPosZ + inner->moveOffsetZ);
                    i = 0;
                    dy = 30.0f;
                    for (; i < 2; i++) {
                        if (i != 0) {
                            pnt[1] = 11.0f + inner->savedPosY;
                        } else {
                            pnt[1] = inner->savedPosY - 11.0f;
                        }
                        dst[0] = -(dy * inner->groundNormalX - pnt[0]);
                        dst[1] = pnt[1];
                        dst[2] = -(dy * inner->groundNormalZ - pnt[2]);
                        if (trackGetLineIntersect(pnt, dst, 0.0f, 3, NULL, obj, 1, 3, 0xff, 0) != 0) {
                            mask = mask | 1 << (i + 2);
                        }
                    }
                } else {
                    mask |= 0xc;
                }
                ph = 0.02f;
                if (mask != 0xf) {
                    {
                        f32 z = 0.0f;
                        inner->moveOffsetX = z;
                        inner->moveOffsetY = z;
                        inner->moveOffsetZ = z;
                    }
                    {
                        int st2 = (s16)gPlayerCurrentMoveId;
                        if (st2 == 4 || st2 == 0 || ((st2 == 0xc) | (st2 == 8)) != 0)
                        {
                            inner->moveAltToggle ^= 1;
                        }
                    }
                    {
                        s16 ns;
                        if (inner->moveAltToggle != 0)
                        {
                            ns = 0x15;
                        }
                        else
                        {
                            ns = 0x16;
                        }
                        gPlayerCurrentMoveId = ns;
                    }
                    if (obj->anim.currentMove == lbl_80332F48[21] ||
                        obj->anim.currentMove == lbl_80332F48[22])
                    {
                        gPlayerPrevMoveId = *(s16*)&gPlayerCurrentMoveId;
                        obj->anim.currentMoveProgress = oldSpd;
                    }
                    ph = 0.006f;
                }
            }
            else
            {
                obj->anim.localPosY = inner->savedPosY;
                {
                    s16 ns;
                    if (inner->moveAltToggle != 0)
                    {
                        ns = 0x15;
                    }
                    else
                    {
                        ns = 0x16;
                    }
                    gPlayerCurrentMoveId = ns;
                }
                ph = 0.006f;
            }
        }
        if (gPlayerCurrentMoveId != 0x15 && gPlayerCurrentMoveId != 0x16)
        {
            f32 v = state->baddie.inputMagnitude;
            if (ph < 0.0f)
            {
                ph = -(0.003999997f * v + 0.034f);
            }
            else if (ph > 0.0f)
            {
                ph = 0.003999997f * v + 0.034f;
            }
        }
        playerPlayClimbingSound(obj, stateArg);
        break;
    }
    state->baddie.moveSpeed = ph;
    {
        s16 cur;
        if (gPlayerPrevMoveId != (cur = gPlayerCurrentMoveId))
        {
            ObjAnim_SetCurrentMove(obj, lbl_80332F48[cur], 0.0f, 1);
        }
    }
    {
        f32 sp = obj->anim.currentMoveProgress;
        (*gCameraInterface)
            ->overridePos(inner->moveOffsetX * sp + obj->anim.localPosX,
                          inner->moveOffsetY * sp + obj->anim.localPosY,
                          inner->moveOffsetZ * sp + obj->anim.localPosZ);
    }
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

int playerStateClimbOntoWall(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    PlayerState* in0 = obj->extra;
    int flag549;
    f32 fz;
    s16* tbl;
    int flags;
    ObjModel* model;
    u8 ic;
    f32 buf1[3];
    s16 buf2[3];
    f32 pos[2];
    in0->flags360 &= ~PLAYER_FLAG_HITDETECT;
    in0->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    fz = 0.0f;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    ((PlayerState*)state)->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = fz;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.stateId = 0x12;
        inner->stateHandler = playerStagedRestoreCameraUnlessClimbing;
        if (gPlayerPathObject != NULL)
        {
            if (inner->flags3F4.b40)
            {
                inner->staffActionRequest = 1;
                inner->flags3F4.b08 = 1;
            }
        }
        ObjHits_MarkObjectPositionDirty(&obj->anim);
    }
    flag549 = inner->climbMoveVariant;
    if (flag549 != 0)
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.0145f;
    }
    playerPlayClimbingSound(obj, state);
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        f32 zero = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedA = zero;
        ((PlayerState*)state)->baddie.animSpeedB = zero;
        inner->targetYaw = (s16)getAngle(inner->groundNormalX, inner->groundNormalZ);
        inner->yaw = inner->targetYaw;
        obj->anim.localPosX = inner->climbStartPosX;
        obj->anim.localPosZ = inner->climbStartPosZ;
        if (flag549 != 0)
        {
            tbl = lbl_803DC69C;
        }
        else
        {
            tbl = &lbl_803DC698;
        }
        flags = 0x25;
        if (flag549 != 0)
        {
            flags |= 0x40;
        }
        {
            inner->animEventState =
                playerSetMoveBlendFromPlane(obj, tbl[0], tbl[1], (int*)((char*)inner + 0x598),
                            (int*)&inner->groundNormalX, 0.0f, 0.0f, 2, (u8)flags);
        }
        model = Player_GetActiveModel(obj);
        ObjModel_SampleJointTransform(model, 0, 0, 1.0f, obj->anim.rootMotionScale, buf1, buf2);
        fz = 0.0f;
        inner->moveOffsetX = fz;
        inner->moveOffsetY = buf1[1];
        inner->moveOffsetZ = fz;
        pos[0] = inner->spanTopY;
        pos[1] = inner->spanBottomY;
        ic = inner->curAnimId;
        if (ic != 0x48 && ic != 0x47)
        {
            (*gCameraInterface)->setMode(0x4b, 1, 1, 8, pos, 0, 0);
        }
    }
    else
    {
        if (obj->anim.currentMoveProgress >= 1.0f)
        {
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
            return 0x14;
        }
    }
    ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_STATE,
                           inner->animEventState);
    (*gCameraInterface)
        ->overridePos(obj->anim.localPosX,
                      inner->moveOffsetY * obj->anim.currentMoveProgress +
                          obj->anim.localPosY,
                      obj->anim.localPosZ);
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

void playerPlayClimbingSound(GameObject* obj, PlayerState* p2)
{
    PlayerState* inner = obj->extra;
    int cell;
    int t;
    int sfx;

    if (((PlayerState*)p2)->baddie.eventFlags & 1)
    {
        cell = coordsToMapCell(obj->anim.localPosX, obj->anim.localPosZ);
        if (cell == 0x12)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_mv_ropecreak22);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_foot);
        }
    }
    if (gPlayerSfxTimerB > 0)
    {
        t = gPlayerSfxTimerB - framesThisStep;
        gPlayerSfxTimerB = t;
        if (t < 0)
            gPlayerSfxTimerB = 0;
    }
    if (((PlayerState*)p2)->baddie.eventFlags & 0x80)
    {
        if (gPlayerSfxTimerB == 0)
        {
            if (randomGetRange(1, 0x64) < 0x46)
            {
                if (inner->characterId == 0)
                {
                    sfx = 0x398;
                }
                else
                {
                    sfx = 0x25;
                }
                Sfx_PlayFromObject(obj, (u16)sfx);
                gPlayerSfxTimerB = 0x3c;
            }
        }
    }
}

int playerState11(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 k;
    f32 pos[2];

    inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    inner->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    k = 0.0f;
    state->baddie.animSpeedA = k;
    state->baddie.animSpeedB = k;
    state->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = k;
    obj->anim.velocityZ = k;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = k;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0 && gPlayerPathObject != 0 &&
        inner->flags3F4.b40)
    {
        inner->staffActionRequest = 1;
        inner->flags3F4.b08 = 1;
    }
    switch (obj->anim.currentMove)
    {
    case 0x41a:
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            playerRefreshCollisionState(obj, (int)inner + 4, 5);
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
            return -0x13;
        }
        break;
    default:
    {
        pos[0] = inner->spanTopY;
        pos[1] = inner->spanBottomY;
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
        {
            (*gCameraInterface)->setMode(0x4b, 1, 1, 8, pos, 0, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, 0x41a, 0.0f, 1);
        inner->targetYaw =
            getAngle(inner->groundNormalX, inner->groundNormalZ);
        inner->yaw = inner->targetYaw;
        obj->anim.localPosX = inner->climbStartPosX;
        obj->anim.localPosY = inner->savedPosY;
        obj->anim.localPosZ = inner->climbStartPosZ;
        state->baddie.moveSpeed = 0.035f;
        break;
    }
    }
    playerRefreshCollisionState(obj, (int)inner + 4, 5);
    return 0;
}

int playerStateSlideDownLadder(GameObject* obj, PlayerState* state, f32 fv)
{
    PlayerState* inner = obj->extra;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty(&obj->anim);
        gPlayerLadderSlideVel = 0.0f;
        ObjAnim_SetCurrentMove(obj, 0x35, 0.0f, 1);
        state->baddie.moveSpeed = 0.025f;
        inner->moveStartPosY = obj->anim.localPosY;
        obj->anim.localPosY = inner->savedPosY;
        playerRefreshCollisionState(obj, (int)inner, 5);
    }
    if (inner->waterDepth > 25.0f)
    {
        playerRefreshCollisionState(obj, (int)inner, 5);
        playerEnterDeepWater(obj, inner, state);
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    ((PlayerState*)state)->baddie.flags0 |= 0x200000;
    switch (obj->anim.currentMove)
    {
    case 0x35:
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0x36, 0.0f, 0);
            state->baddie.moveSpeed = 0.025f;
        }
    case 0x36:
    {
        f32 f30 = 10.0f * -gPlayerLadderSlideVel;
        f32 f3;
        if ((((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_mv_dive4_c);
        }
        f3 = obj->anim.localPosY - (32.0f + inner->climbBaseY);
        if (f3 < 0.0f)
        {
            f3 = 0.0f;
        }
        if (f3 < f30)
        {
            f32 ed4 = 2.0f;
            f32 base = ed4 * (gPlayerLadderSlideVel * gPlayerLadderSlideVel / (ed4 * f30));
            obj->anim.velocityY = -sqrtf(base * f3);
            if (obj->anim.velocityY >= -0.01f)
            {
                u8 anim = inner->curAnimId;
                f32 climbBaseY;
                if (anim != 0x48 && anim != 0x47 && anim != 0x42)
                {
                    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
                    inner->curAnimId = 0x42;
                }
                inner->moveStartPosY = obj->anim.localPosY;
                climbBaseY = inner->climbBaseY;
                obj->anim.worldPosY = climbBaseY;
                obj->anim.localPosY = climbBaseY;
                if (inner->flags547.b80)
                {
                    ObjAnim_SetCurrentMove(obj, 0x37, 0.0f, 1);
                    state->baddie.moveSpeed = 0.02f;
                    obj->anim.velocityY = 0.0f;
                }
                else
                {
                    f32 zero = 0.0f;
                    GameObject* sub;
                    state->baddie.animSpeedC = zero;
                    state->baddie.animSpeedB = zero;
                    state->baddie.animSpeedA = zero;
                    obj->anim.velocityX = zero;
                    obj->anim.velocityY = zero;
                    obj->anim.velocityZ = zero;
                    playerRefreshCollisionState(obj, (int)inner, 5);
                    inner->flags3F0.b80 = 0;
                    inner->flags3F0.b10 = 0;
                    inner->flags3F0.b08 = 0;
                    Shield_setMode(gPlayerStaffObject, 2);
                    inner->flags3F0.b02 = 0;
                    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
                    ObjHits_SyncObjectPositionIfDirty(obj);
                    inner->flags3F0.b40 = 0;
                    inner->flags3F0.b04 = 1;
                    inner->flags3F4.b10 = 1;
                    inner->isHoldingObject = 0;
                    sub = inner->heldObj;
                    if (sub != NULL)
                    {
                        s16 id = sub->anim.romDefNo;
                        if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                        {
                            SmallBasket_throw((GameObject*)sub);
                        }
                        else
                        {
                            Carryable_putDownAndSavePos((GameObject*)sub);
                        }
                        inner->heldObj->anim.flags &= ~0x4000;
                        inner->heldObj->userData2 = 0;
                        inner->heldObj = 0;
                    }
                    ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
                    return 3;
                }
            }
        }
        else
        {
            if (obj->anim.velocityY > -3.0f)
            {
                obj->anim.velocityY = obj->anim.velocityY - 0.05f * fv;
            }
            if (obj->anim.velocityY < -3.0f)
            {
                obj->anim.velocityY = -3.0f;
            }
            if (obj->anim.velocityY < gPlayerLadderSlideVel)
            {
                gPlayerLadderSlideVel = obj->anim.velocityY;
            }
        }
    }
    break;
    case 0x37:
        if ((((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            int snd = surfaceSfxSelectTrigger(inner->surfaceType, inner->footstepSoundId);
            Sfx_PlayFromObject(obj, snd);
            doRumble(5.0f);
            if (inner->waterDepth > 0.0f)
            {
                (*gWaterfxInterface)
                    ->spawnSplashBurst((void*)obj, obj->anim.localPosX,
                                       obj->anim.localPosY, obj->anim.localPosZ,
                                       8.0f);
            }
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            f32 local;
            obj->anim.worldPosX = inner->savedPosX;
            obj->anim.worldPosZ = inner->savedPosZ;
            if (obj->anim.parent != NULL)
            {
                obj->anim.worldPosX += playerMapOffsetX;
                obj->anim.worldPosZ += playerMapOffsetZ;
            }
            Obj_TransformWorldPointToLocal(obj->anim.worldPosX, 0.0f,
                                           obj->anim.worldPosZ, &obj->anim.localPosX,
                                           &local, &obj->anim.localPosZ,
                                           obj->anim.parent);
            playerRefreshCollisionState(obj, (int)inner, 5);
            ObjAnim_SetCurrentMove(obj, *inner->moveAnimIds, 0.0f, 1);
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    }
    {
        f32 w;
        f32 py;
        f32 cx = obj->anim.localPosX;
        f32 cy;
        f32 cz = obj->anim.localPosZ;
        f32 czOut = cz;
        switch (obj->anim.currentMove)
        {
        case 0x35:
            cy = obj->anim.currentMoveProgress *
                     (obj->anim.localPosY - inner->moveStartPosY) +
                 inner->moveStartPosY;
            break;
        case 0x37:
        {
            w = obj->anim.currentMoveProgress;
            cx = w * (inner->savedPosX - cx) + cx;
            py = obj->anim.localPosY;
            cy = (1.0f - w) * (inner->moveStartPosY - py) + py;
            czOut = w * (inner->savedPosZ - cz) + cz;
        }
        break;
        default:
            cy = obj->anim.localPosY;
            break;
        }
        (*gCameraInterface)->overridePos(cx, cy, czOut);
    }
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

int playerStateOnLadder(GameObject* obj, struct PlayerState* state)
{
    ObjModel* jt;
    PlayerState* inner;
    f32 t;
    f32 spd;
    f32 ph;
    f32 buf1[3];
    f32 buf2[3];
    s16 tmp[3];
    f32 outY;

    inner = ((GameObject*)obj)->extra;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
        if (gPlayerPathObject != 0 && (inner->flags3F4.b40) != 0)
        {
            inner->staffActionRequest = 1;
            inner->flags3F4.b08 = 1;
        }
        if (((GameObject*)obj)->anim.currentMove == lbl_80332F2C[8] ||
            ((GameObject*)obj)->anim.currentMove == lbl_80332F2C[12])
        {
            gPlayerCurrentMoveId = 8;
        }
        else
        {
            gPlayerCurrentMoveId = 9;
        }
    }
    if (inner->climbStep > 3)
    {
        setAButtonIcon(0x1a);
    }
    else
    {
        setAButtonIcon(0x1c);
    }
    {
        PlayerState* base = ((GameObject*)obj)->extra;
        base->flags360 &= ~0x2LL;
        base->flags360 |= 0x2000LL;
    }
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    {
        f32 z = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        *(int*)state |= 0x200000;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
        if (inner->waterDepth > 25.0f)
        {
            playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
            playerEnterDeepWater(obj, inner, state);
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        ((GameObject*)obj)->anim.velocityY = z;
        {
            f32 mag = ((PlayerState*)state)->baddie.moveInputZ / 56.0f;
            if (mag < z)
            {
                mag = -mag;
            }
            t = (mag < 0.1f) ? 0.1f : ((mag > 1.0f) ? 1.0f : mag);
        }
    }
    jt = Player_GetActiveModel(obj);
    spd = 0.0f;
    ph = ((PlayerState*)state)->baddie.moveSpeed;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    if ((((PlayerState*)state)->baddie.eventFlags & 1) != 0)
    {
        switch (inner->footstepSurface)
        {
        case 4:
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_foot_33a);
            break;
        default:
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_foot_var);
            break;
        }
    }
    switch ((s16)gPlayerCurrentMoveId)
    {
    case 8:
    case 9:
    case 12:
    case 13:
        ((GameObject*)obj)->anim.localPosY = inner->climbTargetY;
        ((GameObject*)obj)->anim.activeMove = -1;
        inner->climbingUp = 0;
        inner->climbStartY = inner->climbTargetY;
        ph = spd = 0.0f;
        if ((gPlayerCurrentMoveId & 1) != 0)
        {
            gPlayerCurrentMoveId = 1;
        }
        else
        {
            gPlayerCurrentMoveId = 0;
        }
        break;
    case 6:
    case 7:
        if ((((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
        {
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_foot);
            if (inner->characterId == 0)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_jump3);
            }
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((GameObject*)obj)->anim.localPosY = inner->climbEndLocalY;
        }
        else
        {
            ObjModel_SampleJointTransform(jt, 0, 0, 0.0f, ((GameObject*)obj)->anim.rootMotionScale, buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, 1.0f, ((GameObject*)obj)->anim.rootMotionScale, buf2, tmp);
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.currentMoveProgress *
                                                     ((gPlayerClimbEndY - (buf2[1] - buf1[1])) - (gPlayerClimbStartY + buf1[1])) +
                                                 gPlayerClimbStartY;
        }
    case 10:
    case 11:
        if ((((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            doRumble(5.0f);
            if (inner->waterDepth > 0.0f)
            {
                (*gWaterfxInterface)
                    ->spawnSplashBurst((void*)obj, ((GameObject*)obj)->anim.localPosX,
                                       ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                       8.0f);
            }
        }
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((GameObject*)obj)->anim.worldPosX = inner->savedPosX;
            ((GameObject*)obj)->anim.worldPosZ = inner->savedPosZ;
            if (((GameObject*)obj)->anim.parent != NULL)
            {
                ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.worldPosX + playerMapOffsetX;
                ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.worldPosZ + playerMapOffsetZ;
            }
            Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, 0.0f,
                                           ((GameObject*)obj)->anim.worldPosZ, &((GameObject*)obj)->anim.localPosX,
                                           &outY, &((GameObject*)obj)->anim.localPosZ,
                                           ((GameObject*)obj)->anim.parent);
            if (gPlayerCurrentMoveId == 6 || gPlayerCurrentMoveId == 7)
            {
                playerRefreshCollisionState((GameObject*)obj, (int)inner, 7);
            }
            else
            {
                playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
            }
            ObjAnim_SetCurrentMove(obj, *inner->moveAnimIds, 0.0f, 1);
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    case 4:
    case 5:
        if (((PlayerState*)state)->baddie.moveInputZ > 5.0f)
        {
            ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, 0.0f);
        }
        else if (((PlayerState*)state)->baddie.moveInputZ < -5.0f)
        {
            ObjAnim_SetMoveProgress((ObjAnimComponent*)obj, 0.0f);
        }
        else
        {
            if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0 && inner->climbStep > 3)
            {
                ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
                return -0x10;
            }
            break;
        }
    default:
        if ((((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
        {
            Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_foot_var);
        }
        if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0 && inner->climbStep > 3)
        {
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
            return -0x10;
        }
        if (1.0f == ((GameObject*)obj)->anim.currentMoveProgress)
        {
            if (((PlayerState*)state)->baddie.moveInputZ < -5.0f)
            {
                inner->climbingUp = 0;
                ph = -(0.01f * t + 0.025f);
                if ((s16)gPlayerCurrentMoveId <= 1)
                {
                    gPlayerCurrentMoveId += 2;
                    spd = 0.99f;
                }
            }
            else
            {
                *(u8*)&inner->climbStep += 1;
                inner->climbingUp = 1;
                ph = 0.0f;
                if ((s16)gPlayerCurrentMoveId <= 1)
                {
                    gPlayerCurrentMoveId ^= 1;
                    spd = ph;
                }
                inner->climbStartY =
                    ((GameObject*)obj)->anim.localPosY + inner->moveStartPosY;
                inner->climbTargetY =
                    (f32) inner->climbStep * inner->climbStepHeight +
                    inner->climbBaseY;
                ((GameObject*)obj)->anim.localPosY = inner->climbStartY;
            }
        }
        {
            f32 z2 = 0.0f;
            if (z2 == ((GameObject*)obj)->anim.currentMoveProgress)
            {
                if (((PlayerState*)state)->baddie.moveInputZ > 5.0f)
                {
                    inner->climbingUp = 1;
                    if ((int)inner->climbStep >= inner->climbStepCount - 3)
                    {
                        spd = z2;
                        ph = 0.011f;
                        {
                            s16 ns;
                            if ((gPlayerCurrentMoveId & 1) != 0)
                            {
                                ns = 7;
                            }
                            else
                            {
                                ns = 6;
                            }
                            gPlayerCurrentMoveId = ns;
                        }
                        gPlayerClimbStartY = ((GameObject*)obj)->anim.localPosY;
                        gPlayerClimbEndY = inner->climbEndLocalY + gPlayerMoveRootHeights[0];
                        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
                        {
                            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        }
                        break;
                    }
                    spd = z2;
                    ph = 0.012f * t + 0.025f;
                    if ((s16)gPlayerCurrentMoveId > 1)
                    {
                        if ((gPlayerCurrentMoveId & 1) != 0)
                        {
                            gPlayerCurrentMoveId = 1;
                        }
                        else
                        {
                            gPlayerCurrentMoveId = 0;
                        }
                    }
                }
                else if (((PlayerState*)state)->baddie.moveInputZ < -5.0f)
                {
                    *(u8*)&inner->climbStep -= 1;
                    inner->climbingUp = 0;
                    if (inner->climbStep < 1)
                    {
                        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47 &&
                            inner->curAnimId != 0x42)
                        {
                            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                            inner->curAnimId = 0x42;
                        }
                        if (inner->flags547.b80 != 0)
                        {
                            spd = 0.0f;
                            ph = 0.016f;
                            {
                                s16 ns;
                                if ((gPlayerCurrentMoveId & 1) != 0)
                                {
                                    ns = 0xb;
                                }
                                else
                                {
                                    ns = 0xa;
                                }
                                gPlayerCurrentMoveId = ns;
                            }
                            ((GameObject*)obj)->anim.localPosY = inner->climbBaseY;
                            break;
                        }
                        else
                        {
                            {
                                f32 z3 = 0.0f;
                                ((PlayerState*)state)->baddie.animSpeedC = z3;
                                ((PlayerState*)state)->baddie.animSpeedB = z3;
                                ((PlayerState*)state)->baddie.animSpeedA = z3;
                                ((GameObject*)obj)->anim.velocityX = z3;
                                ((GameObject*)obj)->anim.velocityY = z3;
                                ((GameObject*)obj)->anim.velocityZ = z3;
                            }
                            inner->flags3F0.b80 = 0;
                            inner->flags3F0.b10 = 0;
                            inner->flags3F0.b08 = 0;
                            Shield_setMode(gPlayerStaffObject, 2);
                            inner->flags3F0.b02 = 0;
                            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
                            ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
                            inner->flags3F0.b40 = 0;
                            inner->flags3F0.b04 = 1;
                            inner->flags3F4.b10 = 1;
                            inner->isHoldingObject = 0;
                            if (inner->heldObj != NULL)
                            {
                                if (((GameObject*)inner->heldObj)->anim.romDefNo ==
                                        SMALLBASKET_SEQUENCE_VARIANT_A ||
                                    ((GameObject*)inner->heldObj)->anim.romDefNo ==
                                        SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                                {
                                    SmallBasket_throw((GameObject*)(inner->heldObj));
                                }
                                else
                                {
                                    Carryable_putDownAndSavePos((GameObject*)inner->heldObj);
                                }
                                *(s16*)((char*)inner->heldObj + 6) =
                                    *(s16*)((char*)inner->heldObj + 6) & ~0x4000;
                                inner->heldObj->userData2 = 0;
                                inner->heldObj = 0;
                            }
                            playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
                            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
                            return 3;
                        }
                    }
                    else
                    {
                        spd = 0.99f;
                        ph = -(0.01f * t + 0.025f);
                        {
                            s16 ns;
                            if ((gPlayerCurrentMoveId & 1) != 0)
                            {
                                ns = 2;
                            }
                            else
                            {
                                ns = 3;
                            }
                            gPlayerCurrentMoveId = ns;
                        }
                        inner->climbTargetY =
                            (f32) inner->climbStep * inner->climbStepHeight +
                            inner->climbBaseY;
                        {
                            f32 y2 = ((GameObject*)obj)->anim.localPosY - inner->moveStartPosY;
                            inner->climbStartY = y2;
                            ((GameObject*)obj)->anim.localPosY = y2;
                        }
                    }
                }
                else
                {
                    if (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
                    {
                        spd = 0.0f;
                        ph = 0.01f;
                        if ((gPlayerCurrentMoveId & 1) != 0 && gPlayerCurrentMoveId != 5)
                        {
                            gPlayerCurrentMoveId = 5;
                        }
                        else if ((gPlayerCurrentMoveId & 1) == 0 && gPlayerCurrentMoveId != 4)
                        {
                            gPlayerCurrentMoveId = 4;
                        }
                        break;
                    }
                }
            }
        }
        if (ph < 0.0f)
        {
            ph = -(0.01f * t + 0.025f);
        }
        else if (ph > 0.0f)
        {
            ph = 0.012f * t + 0.025f;
        }
        if (inner->climbingUp != 0)
        {
            ((GameObject*)obj)->anim.localPosY =
                ((GameObject*)obj)->anim.currentMoveProgress *
                    (inner->climbTargetY - inner->climbStartY) +
                inner->climbStartY;
        }
        else
        {
            ((GameObject*)obj)->anim.localPosY =
                (1.0f - ((GameObject*)obj)->anim.currentMoveProgress) *
                    (inner->climbTargetY - inner->climbStartY) +
                inner->climbStartY;
        }
        break;
    }
    ((PlayerState*)state)->baddie.moveSpeed = ph;
    if (gPlayerPrevMoveId != gPlayerCurrentMoveId)
    {
        ObjAnim_SetCurrentMove(obj, lbl_80332F2C[gPlayerCurrentMoveId], spd, 1);
        if ((s16)gPlayerCurrentMoveId <= 1 && inner->climbSampleDone == 0)
        {
            ObjModel_SampleJointTransform(jt, 0, 0, 0.0f, ((GameObject*)obj)->anim.rootMotionScale, buf1, tmp);
            ObjModel_SampleJointTransform(jt, 0, 0, 1.0f, ((GameObject*)obj)->anim.rootMotionScale, buf2, tmp);
            inner->moveStartPosY = buf2[1] - buf1[1];
            *(u8*)&inner->climbSampleDone = 1;
        }
    }
    {
        f32 w;
        f32 py;
        f32 x = ((GameObject*)obj)->anim.localPosX;
        f32 y;
        f32 zz = ((GameObject*)obj)->anim.localPosZ;
        f32 zzOut = zz;
        switch ((s16)gPlayerCurrentMoveId)
        {
        case 0:
        case 1:
        case 2:
        case 3:
            y = ((GameObject*)obj)->anim.currentMoveProgress *
                    (((f32)(inner->climbStep + 1) * inner->climbStepHeight +
                      inner->climbBaseY) -
                     ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            break;
        case 10:
        case 11:
            w = ((GameObject*)obj)->anim.currentMoveProgress;
            x = w * (inner->savedPosX - x) + x;
            py = ((GameObject*)obj)->anim.localPosY;
            y = (1.0f - w) * (inner->climbTargetY - py) + py;
            zzOut = w * (inner->savedPosZ - zz) + zz;
            break;
        case 6:
        case 7:
            w = ((GameObject*)obj)->anim.currentMoveProgress;
            x = w * (inner->savedPosX - x) + x;
            y = w * (inner->climbEndLocalY - ((GameObject*)obj)->anim.localPosY) +
                ((GameObject*)obj)->anim.localPosY;
            zzOut = w * (inner->savedPosZ - zz) + zz;
            break;
        default:
            y = ((GameObject*)obj)->anim.localPosY;
            break;
        }
        (*gCameraInterface)->overridePos(x, y, zzOut);
    }
    playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
    return 0;
}

int playerStateClimbOntoLadder(GameObject* obj, PlayerState* state, f32 fv)
{
    int flag;
    PlayerState* innerV = obj->extra;
    PlayerState* inner = obj->extra;

    innerV->flags360 &= ~PLAYER_FLAG_HITDETECT;
    innerV->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    {
        f32 z = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedA = z;
        ((PlayerState*)state)->baddie.animSpeedB = z;
        ((PlayerState*)state)->baddie.flags0 |= 0x200000;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
        ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
        obj->anim.velocityY = z;
    }
    flag = innerV->climbStep != 1;
    if (flag)
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
    }
    else
    {
        ((PlayerState*)state)->baddie.moveSpeed = 0.014f;
    }
    if ((((PlayerState*)state)->baddie.eventFlags & 0x80) != 0)
    {
        GameObject* o = obj;
        u16 sfxId = inner->characterId == 0 ? 0x398 : 0x1d;
        Sfx_PlayFromObject((GameObject*)o, sfxId); // what?
    }
    if ((((PlayerState*)state)->baddie.eventFlags & 1) != 0)
    {
        switch (inner->footstepSurface)
        {
        case 4:
            Sfx_PlayFromObject(obj, SFXTRIG_foot_33a);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_foot_var);
            break;
        }
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        s16* tbl;
        int sel;
        f32 jp[3];
        struct
        {
            f32 vx;
            f32 sp1c;
            f32 vy;
            f32 vz;
        } vb;
        ObjHits_MarkObjectPositionDirty(&obj->anim);
        if (gPlayerPathObject != NULL && inner->flags3F4.b40 != 0)
        {
            inner->staffActionRequest = 1;
            inner->flags3F4.b08 = 1;
        }
        {
            f32 z = 0.0f;
            ((PlayerState*)state)->baddie.animSpeedA = z;
            ((PlayerState*)state)->baddie.animSpeedB = z;
            ((PlayerState*)state)->baddie.stateId = 0xe;
            inner->stateHandler = playerStagedRestoreCameraUnlessClimbing;
            vb.sp1c = z;
        }
        if (flag)
        {
            vb.vx = -inner->moveDirX;
            vb.vy = -inner->moveDirY;
            vb.vz = -inner->moveDirZ;
        }
        else
        {
            vb.vx = inner->moveDirX;
            vb.vy = inner->moveDirY;
            vb.vz = inner->moveDirZ;
        }
        {
            int delta = (u16)getAngle(vb.vx, vb.vy) - inner->targetYaw;
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            inner->targetYaw += delta;
            inner->yaw = inner->targetYaw;
        }
        inner->savedLocalPosX = obj->anim.localPosX;
        inner->savedLocalPosZ = obj->anim.localPosZ;
        obj->anim.localPosX = inner->moveStartPosX;
        obj->anim.localPosZ = inner->moveStartPosZ;
        sel = inner->unk4FC >= 0.0f ? 0 : 4;
        if (flag)
        {
            tbl = lbl_80332F88;
        }
        else
        {
            tbl = lbl_80332F78;
        }
        inner->eventCountdown =
            playerSetMoveBlendFromPlane(obj, tbl[sel], tbl[sel + 2], (int*)inner->blendAnchor, (int*)&vb.vx,
                        0.0f, ((PlayerState*)state)->baddie.moveSpeed, 2, 9);
        {
            int f9 = 0x34;
            if (flag)
            {
                f9 |= 0x40;
            }
            playerSetMoveBlendFromPlane(obj, tbl[sel], tbl[sel + 1], (int*)inner->blendAnchor,
                                        (int*)inner->blendPlane,
                        0.0f, ((PlayerState*)state)->baddie.moveSpeed, 0, (u8)f9);
        }
        playerSetMoveBlendFromPlane(obj, tbl[sel + 2], tbl[sel + 3], (int*)inner->blendAnchor,
                                    (int*)inner->blendPlane, 0.0f, ((PlayerState*)state)->baddie.moveSpeed, 0, 0x1a);
        inner->climbTargetY = inner->climbStepHeight * (f32)(int)inner->climbStep + inner->climbBaseY;
        inner->climbStartY = obj->anim.localPosY;
        {
            ObjModel* joint = Player_GetActiveModel(obj);
            s16 scratch[3];
            f32 camBuf[2];
            ObjModel_SampleJointTransform(joint, 0, 0, 1.0f, obj->anim.rootMotionScale, jp,
                                          scratch);
            gPlayerClimbStartY = obj->anim.localPosY + jp[1];
            gPlayerClimbEndY = inner->climbTargetY + gPlayerMoveRootHeights[1];
            camBuf[0] = inner->climbEndLocalY;
            camBuf[1] = inner->climbBaseY;
            if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47)
            {
                (*gCameraInterface)->setMode(0x4b, 1, 1, 8, camBuf, 0, 0);
            }
        }
    }
    else
    {
        if (obj->anim.currentMoveProgress > 0.9f)
        {
            Object_ObjAnimAdvanceMove(obj, ((PlayerState*)state)->baddie.moveSpeed, fv, NULL);
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
            return 0x10;
        }
    }
    {
        f32 mp = obj->anim.currentMoveProgress;
        if (mp >= 0.7f)
        {
            f32 g = 3.333f * (1.052f * mp - 0.7f);
            f32 c;
            c = (g < 0.0f) ? 0.0f : ((g > 1.0f) ? 1.0f : g);
            obj->anim.localPosY = c * (gPlayerClimbEndY - gPlayerClimbStartY) + inner->climbStartY;
        }
    }
    ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_CURRENT,
                           OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_ACTIVE,
                           OBJANIM_STATE_WORD_PREV_EVENT_STATE, 0);
    ObjAnim_WriteStateWord(&obj->anim, OBJANIM_STATE_INDEX_ACTIVE,
                           OBJANIM_STATE_WORD_EVENT_COUNTDOWN, inner->eventCountdown);
    Object_ObjAnimAdvanceMove(obj, ((PlayerState*)state)->baddie.moveSpeed, fv, NULL);
    (*gCameraInterface)
        ->overridePos(obj->anim.localPosX,
                      obj->anim.currentMoveProgress *
                              (inner->climbTargetY - obj->anim.localPosY) +
                          obj->anim.localPosY,
                      obj->anim.localPosZ);
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

int playerState0D(GameObject* obj, PlayerState* targetState)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    inner->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    targetState->baddie.flags4 |= 0x100000;
    fz = 0.0f;
    targetState->baddie.animSpeedA = fz;
    targetState->baddie.animSpeedB = fz;
    targetState->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    return 0;
}

int playerStateClimbLedge(int obj, int state, f32 fv)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 diff = inner->leapTargetY - inner->characterHeightOffset;
    f32 blend;
    f32 z;
    f32 t;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.stateId = 0xc;
        inner->stateHandler = 0;
        ((GameObject*)obj)->anim.velocityY = 0.0f;
    }
    z = 0.0f;
    inner->probeHitDist = z;
    {
        PlayerState* in2 = ((GameObject*)obj)->extra;
        in2->flags360 &= ~2LL;
        in2->flags360 |= 0x2000LL;
    }
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    ((PlayerState*)state)->baddie.animSpeedA = z;
    ((PlayerState*)state)->baddie.animSpeedB = z;
    *(int*)state |= 0x200000;
    ((GameObject*)obj)->anim.velocityX = z;
    ((GameObject*)obj)->anim.velocityZ = z;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    gPlayerPrevMoveId = gPlayerCurrentMoveId;
    switch (gPlayerCurrentMoveId)
    {
    case 0:
        t = (((GameObject*)obj)->anim.localPosY - inner->moveStartY) /
            (diff - inner->moveStartY);
        ((GameObject*)obj)->anim.localPosX =
            t * (inner->moveEnd2X - inner->moveStartX) +
            inner->moveStartX;
        ((GameObject*)obj)->anim.localPosZ =
            t * (inner->moveEnd2Z - inner->moveStartZ) +
            inner->moveStartZ;
        (*gPlayerInterface)->updateAnimRootMotion((void*)obj, (void*)state, fv, 0x14);
        ((GameObject*)obj)->anim.localPosY =
            ((PlayerState*)state)->baddie.rootMotionDelta * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            f32 v;
            gPlayerCurrentMoveId = 2;
            blend = 0.01f;
            v = (5.0f + diff) - ((GameObject*)obj)->anim.localPosY;
            v = -0.3f * -v;
            if (v >= 0.0f)
            {
                ((GameObject*)obj)->anim.velocityY = sqrtf(v);
            }
            else
            {
                ((GameObject*)obj)->anim.velocityY = 0.0f;
            }
            Sfx_PlayFromObject((GameObject*)obj,
                               (u16)(inner->characterId == 0 ? SFXTRIG_foxcom_var : SFXTRIG_sa_def));
        }
        break;
    case 2:
        if (((GameObject*)obj)->anim.localPosY >= diff)
        {
            gPlayerCurrentMoveId = 3;
            blend = 0.035f;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.localPosX = inner->moveEnd2X;
            ((GameObject*)obj)->anim.localPosY = diff;
            ((GameObject*)obj)->anim.localPosZ = inner->moveEnd2Z;
        }
        else
        {
            ((GameObject*)obj)->anim.velocityY = -0.15f * fv + ((GameObject*)obj)->anim.velocityY;
            t = (((GameObject*)obj)->anim.localPosY - inner->moveStartY) /
                (diff - inner->moveStartY);
            ((GameObject*)obj)->anim.localPosX =
                t * (inner->moveEnd2X - inner->moveStartX) +
                inner->moveStartX;
            ((GameObject*)obj)->anim.localPosZ =
                t * (inner->moveEnd2Z - inner->moveStartZ) +
                inner->moveStartZ;
        }
        break;
    case 3:
        inner->moveStartX = ((GameObject*)obj)->anim.localPosX;
        inner->moveStartY = ((GameObject*)obj)->anim.localPosY;
        inner->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        if (((GameObject*)obj)->anim.currentMoveProgress > 0.6f)
        {
            if (((PlayerState*)state)->baddie.moveInputZ > 5.0f)
            {
                gPlayerCurrentMoveId = 5;
                blend = 0.014f;
                Sfx_PlayFromObject((GameObject*)obj,
                                   (u16)(inner->characterId == 0 ? SFXTRIG_jump3 : SFXTRIG_sabrepush));
                if (inner->unk608 == 5)
                {
                    Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_fox_swimstroke222);
                }
            }
            else if (((PlayerState*)state)->baddie.moveInputZ < -5.0f)
            {
                inner->launchYaw = *(s16*)obj;
                gPlayerCurrentMoveId = 7;
                blend = 0.08f;
                ((GameObject*)obj)->anim.velocityY = z;
            }
            else if (((PlayerState*)state)->baddie.moveDone != 0)
            {
                gPlayerCurrentMoveId = 6;
                blend = 0.008f;
            }
        }
        break;
    case 6:
        inner->moveStartX = ((GameObject*)obj)->anim.localPosX;
        inner->moveStartY = ((GameObject*)obj)->anim.localPosY;
        inner->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        if (((PlayerState*)state)->baddie.moveInputZ > 5.0f)
        {
            gPlayerCurrentMoveId = 5;
            blend = 0.014f;
            Sfx_PlayFromObject((GameObject*)obj, (u16)(inner->characterId == 0 ? SFXTRIG_jump3 : SFXTRIG_sabrepush));
            if (inner->unk608 == 5)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_fox_swimstroke222);
            }
        }
        else if (((PlayerState*)state)->baddie.moveInputZ < -5.0f)
        {
            inner->launchYaw = *(s16*)obj;
            gPlayerCurrentMoveId = 7;
            blend = 0.08f;
            ((GameObject*)obj)->anim.velocityY = z;
        }
        break;
    case 7:
    {
        f32 y2 =
            inner->launchDirZ * (0.5f + lbl_803DC6C0) + inner->launchAnchorZ;
        s16 ang;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.currentMoveProgress *
                                                 ((inner->launchDirX * (0.5f + lbl_803DC6C0) +
                                                   inner->launchAnchorX) -
                                                  inner->moveStartX) +
                                             inner->moveStartX;
        ((GameObject*)obj)->anim.localPosZ =
            ((GameObject*)obj)->anim.currentMoveProgress * (y2 - inner->moveStartZ) +
            inner->moveStartZ;
        ((GameObject*)obj)->anim.velocityY = -(0.05f * timeDelta - ((GameObject*)obj)->anim.velocityY);
        ang = -(32768.0f * ((GameObject*)obj)->anim.currentMoveProgress - (f32)inner->launchYaw);
        inner->yaw = ang;
        inner->targetYaw = ang;
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((PlayerState*)state)->baddie.animSpeedC = z;
            ((PlayerState*)state)->baddie.animSpeedA = z;
            ((PlayerState*)state)->baddie.animSpeedB = z;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityZ = z;
            ((PlayerState*)state)->baddie.flags4 &= ~0x100000;
            playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
            inner->flags3F0.b80 = 0;
            inner->flags3F0.b10 = 0;
            inner->flags3F0.b08 = 0;
            Shield_setMode(gPlayerStaffObject, 2);
            inner->flags3F0.b02 = 0;
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
            inner->flags3F0.b40 = 0;
            inner->flags3F0.b04 = 1;
            inner->flags3F4.b10 = 1;
            inner->isHoldingObject = 0;
            if (inner->heldObj != NULL)
            {
                s16 typ = ((GameObject*)inner->heldObj)->anim.romDefNo;
                if (typ == SMALLBASKET_SEQUENCE_VARIANT_A || typ == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                {
                    SmallBasket_throw((GameObject*)(inner->heldObj));
                }
                else
                {
                    Carryable_putDownAndSavePos((GameObject*)inner->heldObj);
                }
                inner->heldObj->anim.flags =
                    inner->heldObj->anim.flags & ~0x4000;
                inner->heldObj->userData2 = 0;
                inner->heldObj = 0;
            }
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreDefaultControl;
            return 3;
        }
        break;
    }
    case 5:
        t = ((GameObject*)obj)->anim.currentMoveProgress / 0.99f;
        z = (t < z) ? z : ((t > 1.0f) ? 1.0f : t);
        ((GameObject*)obj)->anim.localPosX = z * (inner->moveEndX - inner->moveStartX) +
                                             inner->moveStartX;
        ((GameObject*)obj)->anim.localPosY = z * (inner->moveEndY - inner->moveStartY) +
                                             inner->moveStartY;
        ((GameObject*)obj)->anim.localPosZ = z * (inner->moveEndZ - inner->moveStartZ) +
                                             inner->moveStartZ;
        if (((GameObject*)obj)->anim.currentMoveProgress > 0.99f)
        {
            ((PlayerState*)state)->baddie.flags4 &= ~0x100000;
            playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    default:
        gPlayerCurrentMoveId = 0;
        gPlayerPrevMoveId = 0;
        ((PlayerState*)state)->baddie.moveSpeed = 0.029f;
        ObjAnim_SetCurrentMove((void*)obj, lbl_80332EF0[gPlayerCurrentMoveId], 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 10);
        {
            s16 ang = getAngle(inner->launchDirX, inner->launchDirZ);
            inner->yaw = ang;
            inner->targetYaw = ang;
        }
        ((GameObject*)obj)->anim.velocityY = 0.0f;
        Obj_TransformWorldPointToLocal(((GameObject*)obj)->anim.worldPosX, ((GameObject*)obj)->anim.worldPosY,
                                       ((GameObject*)obj)->anim.worldPosZ, (f32*)(obj + 0xc), (f32*)(obj + 0x10),
                                       (f32*)(obj + 0x14), ((GameObject*)obj)->anim.parent);
        Obj_SetParent((GameObject*)obj, inner->groundObject, 1);
        inner->moveStartX = ((GameObject*)obj)->anim.localPosX;
        inner->moveStartY = ((GameObject*)obj)->anim.localPosY;
        inner->moveStartZ = ((GameObject*)obj)->anim.localPosZ;
        {
            char* xf = *(char**)((char*)inner + 0x4c4);
            if (xf != NULL)
            {
                Obj_TransformWorldPointToLocal(inner->launchAnchorX,
                                               inner->launchAnchorY,
                                               inner->launchAnchorZ, (f32*)((char*)inner + 0x5d4),
                                               (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc), (GameObject*)xf);
                Obj_TransformWorldPointToLocal(inner->moveEndX,
                                               inner->moveEndY,
                                               inner->moveEndZ, (f32*)((char*)inner + 0x5ec),
                                               (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                               inner->groundObject);
                Obj_TransformWorldPointToLocal(inner->moveEnd2X,
                                               inner->moveEnd2Y,
                                               inner->moveEnd2Z, (f32*)((char*)inner + 0x5f8),
                                               (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                               inner->groundObject);
                inner->leapTargetY =
                    inner->leapTargetY - inner->groundObject->anim.localPosY;
                inner->leapBaseY =
                    inner->leapBaseY - inner->groundObject->anim.localPosY;
                inner->unk609 = 0;
            }
        }
        break;
    }
    if (gPlayerPrevMoveId != gPlayerCurrentMoveId)
    {
        ObjAnim_SetCurrentMove((void*)obj, lbl_80332EF0[gPlayerCurrentMoveId], 0.0f, 0);
        ((PlayerState*)state)->baddie.moveSpeed = blend;
    }
    playerRefreshCollisionState((GameObject*)obj, (int)inner, 5);
    return 0;
}

int playerState0B(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    inner->flags360 &= ~PLAYER_FLAG_HITDETECT;
    inner->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
    state->baddie.flags4 |= 0x100000;
    fz = 0.0f;
    state->baddie.animSpeedA = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = fz;
    ((PlayerState*)state)->baddie.flags0 |= 0x200000;
    switch (gPlayerCurrentMoveId)
    {
    case 0x12:
    case 0x1a:
        if (((PlayerState*)state)->baddie.eventFlags & 1)
        {
            Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_jump3 : SFXTRIG_sabrepush));
        }
        if ((inner->flags3F0.b20) || gPlayerCurrentMoveId == 0x1a)
        {
            if (((PlayerState*)state)->baddie.eventFlags & 0x80)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_fox_swimstroke222);
            }
        }
    case 0xe:
    case 0x16:
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ((PlayerState*)state)->baddie.flags4 &= ~0x100000;
            playerRefreshCollisionState(obj, (int)inner, 5);
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    default:
    {
        f32 lo;
        f32 hi;
        f32 t;
        f32 r;
        f32 v;
        if (inner->unk606 == 0x10)
        {
            gPlayerCurrentMoveId = 0x1a;
            lo = 23.0f;
            hi = 34.0f;
            ((PlayerState*)state)->baddie.moveSpeed = 0.017f;
        }
        else if ((v = inner->leapSpeed) >= 23.0f)
        {
            gPlayerCurrentMoveId = 0xe;
            lo = 23.0f;
            hi = 30.0f;
            ((PlayerState*)state)->baddie.moveSpeed = 0.018f;
        }
        else if (v >= 12.1f)
        {
            gPlayerCurrentMoveId = 0x16;
            lo = 12.1f;
            hi = 23.0f;
            ((PlayerState*)state)->baddie.moveSpeed = 0.019f;
        }
        else
        {
            gPlayerCurrentMoveId = 0x12;
            lo = 8.0f;
            hi = 12.1f;
            ((PlayerState*)state)->baddie.moveSpeed = 0.019f;
        }
        t = (inner->leapSpeed - lo) / (hi - lo);
        t *= 16384.0f;
        r = (t < 0.0f) ? 0.0f : ((t > 16384.0f) ? 16384.0f : t);
        inner->secondaryBlendAmount = (s16)r;
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[gPlayerCurrentMoveId], 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0xa);
        inner->targetYaw = inner->yaw = (s16)getAngle(inner->launchDirX, inner->launchDirZ);
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY,
                                       obj->anim.worldPosZ, (f32*)((char*)obj + 0xc),
                                       (f32*)((char*)obj + 0x10), (f32*)((char*)obj + 0x14),
                                       obj->anim.parent);
        Obj_SetParent(obj, inner->groundObject, 1);
        inner->moveStartX = obj->anim.localPosX;
        inner->moveStartY = obj->anim.localPosY;
        inner->moveStartZ = obj->anim.localPosZ;
        if (inner->groundObject != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           inner->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           inner->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           inner->groundObject);
            inner->leapTargetY = inner->leapTargetY - inner->groundObject->anim.localPosY;
            inner->leapBaseY = inner->leapBaseY - inner->groundObject->anim.localPosY;
            inner->unk609 = 0;
        }
        break;
    }
    }
    obj->anim.localPosX =
        obj->anim.currentMoveProgress * (inner->moveEndX - inner->moveStartX) +
        inner->moveStartX;
    obj->anim.localPosY =
        obj->anim.currentMoveProgress * (inner->moveEndY - inner->moveStartY) +
        inner->moveStartY;
    obj->anim.localPosZ =
        obj->anim.currentMoveProgress * (inner->moveEndZ - inner->moveStartZ) +
        inner->moveStartZ;
    Object_ObjAnimSetSecondaryBlendMove(&obj->anim, lbl_80332EF0[gPlayerCurrentMoveId + 2],
                                        inner->secondaryBlendAmount);
    playerRefreshCollisionState(obj, (int)inner, 5);
    return 0;
}

int playerStateGrabLedge(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        GameObject* sub;
        Sfx_PlayFromObject(obj,
                           (u16)(inner->characterId == 0 ? SFXTRIG_foxcom_heel : SFXTRIG_sa_def01));
        ((PlayerState*)state)->baddie.stateId = 0xa;
        inner->stateHandler = 0;
        inner->isHoldingObject = 0;
        sub = inner->heldObj;
        if (sub != NULL)
        {
            s16 id = sub->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
            {
                SmallBasket_throw((GameObject*)sub);
            }
            else
            {
                Carryable_putDownAndSavePos((GameObject*)sub);
            }
            inner->heldObj->anim.flags &= ~0x4000;
            inner->heldObj->userData2 = 0;
            inner->heldObj = 0;
        }
    }
    fz = 0.0f;
    inner->probeHitDist = fz;
    {
        PlayerState* e = obj->extra;
        e->flags360 &= ~2LL;
        e->flags360 |= 0x2000LL;
    }
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    ((PlayerState*)state)->baddie.animSpeedA = fz;
    ((PlayerState*)state)->baddie.animSpeedB = fz;
    ((PlayerState*)state)->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = fz;
    switch (obj->anim.currentMove)
    {
    case 0xd:
    case 0x22:
    {
        f32 c;
        f32 d = obj->anim.currentMoveProgress / 0.25f;
        c = (d < 0.0f) ? 0.0f : ((d > 1.0f) ? 1.0f : d);
        obj->anim.localPosX =
            c * (inner->moveEnd2X - inner->moveStartX) +
            inner->moveStartX;
        obj->anim.localPosY =
            inner->moveStartY -
            obj->anim.currentMoveProgress *
                (inner->moveStartY -
                 (inner->leapTargetY - inner->characterHeightOffset));
        obj->anim.localPosZ =
            c * (inner->moveEnd2Z - inner->moveStartZ) +
            inner->moveStartZ;
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[6], 0.0f, 0);
            state->baddie.moveSpeed = 0.008f;
            gPlayerCurrentMoveId = 6;
            playerRefreshCollisionState(obj, (int)inner + 4, 5);
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0xd;
        }
        break;
    }
    default:
    {
        int m;
        int d = (u16)getAngle(inner->launchDirX, inner->launchDirZ) -
                inner->targetYaw;
        if (d > 0x8000)
        {
            d -= 0xffff;
        }
        if (d < -0x8000)
        {
            d += 0xffff;
        }
        m = inner->unk607 == 1 ? 0xb : 0xa;
        inner->targetYaw += d;
        inner->yaw = inner->targetYaw;
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ,
                                       &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ,
                                       obj->anim.parent);
        Obj_SetParent(obj, inner->groundObject, 1);
        inner->moveStartX = obj->anim.localPosX;
        inner->moveStartY = obj->anim.localPosY;
        inner->moveStartZ = obj->anim.localPosZ;
        ObjAnim_SetCurrentMove(obj, lbl_80332EF0[m], 0.0f, 4);
        state->baddie.moveSpeed = 0.015f;
        if (inner->curAnimId != 0x48 && inner->curAnimId != 0x47) {
            CameraModeStaffAnimSettings cameraSettings;
            cameraSettings.approachThresholdDegrees = 0;
            cameraSettings.turnGate = 0;
            cameraSettings.snapToTarget = 1;
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_STAFF_ANIM_RESOURCE_ID, 1, 0, sizeof(CameraModeStaffAnimSettings),
                          &cameraSettings, 0, 0xff);
        }
        if (inner->groundObject != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           inner->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5ec), *(f32*)((int)inner + 0x5f0),
                                           *(f32*)((int)inner + 0x5f4), (f32*)((char*)inner + 0x5ec),
                                           (f32*)((char*)inner + 0x5f0), (f32*)((char*)inner + 0x5f4),
                                           inner->groundObject);
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5f8), *(f32*)((int)inner + 0x5fc),
                                           *(f32*)((int)inner + 0x600), (f32*)((char*)inner + 0x5f8),
                                           (f32*)((char*)inner + 0x5fc), (f32*)((char*)inner + 0x600),
                                           inner->groundObject);
            inner->leapTargetY =
                inner->leapTargetY - inner->groundObject->anim.localPosY;
            inner->leapBaseY =
                inner->leapBaseY - inner->groundObject->anim.localPosY;
            inner->unk609 = 0;
        }
        break;
    }
    }
    inner->cameraFlags |= 4;
    playerRefreshCollisionState(obj, (int)inner + 4, 5);
    return 0;
}

int playerState09(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    f32 fz;
    PlayerState* flagsBase;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ((PlayerState*)state)->baddie.stateId = 9;
        inner->stateHandler = 0;
    }
    flagsBase = obj->extra;
    flagsBase->flags360 &= ~2LL;
    flagsBase->flags360 |= 0x2000LL;
    ((PlayerState*)state)->baddie.flags4 |= 0x100000;
    fz = 0.0f;
    state->baddie.animSpeedA = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.flags0 |= 0x200000;
    obj->anim.velocityX = fz;
    obj->anim.velocityZ = fz;
    ((PlayerState*)state)->baddie.flags4 |= 0x8000000;
    obj->anim.velocityY = fz;
    switch (obj->anim.currentMove)
    {
    case 0x419:
        if (((PlayerState*)state)->baddie.moveDone != 0)
        {
            ObjAnim_SetCurrentMove(obj, lbl_80332EF0[6], fz, 0);
            gPlayerCurrentMoveId = 6;
            ((PlayerState*)state)->baddie.moveSpeed = 0.008f;
            playerRefreshCollisionState(obj, (int)inner + 4, 5);
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0xd;
        }
        break;
    default:
    {
        f32 k;
        ObjAnim_SetCurrentMove(obj, 0x419, fz, 1);
        state->baddie.moveSpeed = 0.04f;
        inner->targetYaw = (s16)getAngle(inner->launchDirX, inner->launchDirZ);
        inner->yaw = inner->targetYaw;
        k = 5.0f;
        obj->anim.worldPosX = k * inner->launchDirX + *(f32*)((int)inner + 0x5d4);
        obj->anim.worldPosY =
            inner->leapTargetY - inner->characterHeightOffset;
        obj->anim.worldPosZ = k * inner->launchDirZ + *(f32*)((int)inner + 0x5dc);
        Obj_TransformWorldPointToLocal(obj->anim.worldPosX, obj->anim.worldPosY,
                                       obj->anim.worldPosZ, &obj->anim.localPosX,
                                       &obj->anim.localPosY, &obj->anim.localPosZ,
                                       obj->anim.parent);
        Obj_SetParent(obj, inner->groundObject, 1);
        if (inner->groundObject != NULL)
        {
            Obj_TransformWorldPointToLocal(*(f32*)((int)inner + 0x5d4), *(f32*)((int)inner + 0x5d8),
                                           *(f32*)((int)inner + 0x5dc), (f32*)((char*)inner + 0x5d4),
                                           (f32*)((char*)inner + 0x5d8), (f32*)((char*)inner + 0x5dc),
                                           inner->groundObject);
            Obj_TransformWorldPointToLocal(inner->moveEndX, inner->moveEndY, inner->moveEndZ, &inner->moveEndX,
                                           &inner->moveEndY, &inner->moveEndZ, inner->groundObject);
            Obj_TransformWorldPointToLocal(inner->moveEnd2X, inner->moveEnd2Y, inner->moveEnd2Z, &inner->moveEnd2X,
                                           &inner->moveEnd2Y, &inner->moveEnd2Z, inner->groundObject);
            inner->leapTargetY = inner->leapTargetY - inner->groundObject->anim.localPosY;
            inner->leapBaseY = inner->leapBaseY - inner->groundObject->anim.localPosY;
            inner->unk609 = 0;
        }
        break;
    }
    }
    playerRefreshCollisionState(obj, (int)inner + 4, 5);
    return 0;
}

int playerState08(GameObject* obj, struct PlayerState* state, f32 fv) {
    PlayerState* inner = obj->extra;
    s8 c;
    GameObject** list;
    int i;
    u8 buf[64];
    f32 dist;
    int cnt41;
    int cnt20;
    int cnt30;

    dist = 200.0f;
    if (inner->curAnimId != 0x44) {
        if (inner->heldObj != NULL) {
            c = playerCheckIfClimbingOntoWall((int)obj, (int)inner, (int)state, buf, fv, 0x22);
        } else {
            c = playerCheckIfClimbingOntoWall((int)obj, (int)inner, (int)state, buf, fv, (u32)-0x141);
        }
        if (c == -1) {
            inner->climbProbeResult = -1;
            inner->climbProbeStableCount = 0;
        } else if (c == inner->climbProbeResult) {
            if (++inner->climbProbeStableCount > 200) {
                inner->climbProbeStableCount = 200;
            }
        } else {
            inner->climbProbeResult = c;
            inner->climbProbeStableCount = 0;
        }
        switch (inner->climbProbeResult)
        {
        case 0:
            if (inner->flags3F1.b01)
            {
                ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
                return 0xf;
            }
            break;
        case 9:
            if (inner->flags3F1.b01)
            {
                ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
                return 0x13;
            }
            break;
        case 4:
            gPlayerCurrentMoveId = -1;
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0xd;
        case 5:
            if (inner->heldObj == NULL)
            {
                gPlayerCurrentMoveId = -1;
                ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
                return 0xc;
            }
            break;
        case 6:
            ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraAndSyncPosition;
            return -0x1d;
        case 0xd:
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0x1d;
        case 7:
            playerStartWallTransition(obj, inner, state);
            return 0;
        case 8:
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0xb;
        case 0xb:
            ((PlayerState*)state)->baddie.stateHandler = (int)objUpdateHitboxPos;
            return 0x1c;
        case 10:
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0x17;
        default:
            break;
        }
        if (inner->heldObj == NULL && inner->flags3F4.b40)
        {
            GameObject** objects;
            objects = (GameObject**)objGetAllOfType(STAFF_ACTIVATED_OBJECT_GROUP, &cnt41);
            for (i = 0, list = objects; i < cnt41; i++)
            {
                GameObject* o = *list;
                gPlayerInteractTarget = o;
                if ((*(u8*)((char*)o + 0xaf) & 4) != 0 && (*(u8*)((char*)o + 0xaf) & 0x10) == 0)
                {
                    switch ((u8)staffactivated_getMode(gPlayerInteractTarget))
                    {
                    case 2:
                        setAButtonIcon(2);
                        if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0)
                        {
                            buttonDisable(0, PAD_BUTTON_A);
                            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedSyncHitPosition;
                            return 0x34;
                        }
                        break;
                    case 4:
                    case 5:
                        setAButtonIcon(0xe);
                        if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0)
                        {
                            buttonDisable(0, PAD_BUTTON_A);
                            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedSyncHitPosition;
                            return 0x36;
                        }
                        break;
                    case 3:
                        setAButtonIcon(2);
                        if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0)
                        {
                            buttonDisable(0, PAD_BUTTON_A);
                            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedSyncHitPosition;
                            return 0x35;
                        }
                        break;
                    case 0:
                        break;
                    }
                }
                list++;
            }
        }
    }
    objGetAllOfType(BABYCLOUDRUNNER_OBJGROUP, &cnt20);
    mainSetBits(GAMEBIT_ITEM_Flute_Disabled, !cnt20);
    if ((*gGameUIInterface)->isAnyItemBeingUsed() != 0) {
        if ((*gGameUIInterface)->isItemBeingUsed(0x1ee) != 0) {
            GameObject* found;
            ObjPlacement* def = NULL;
            buttonDisable(0, PAD_BUTTON_A);
            found = objGetNearestTypeTo(0xf, obj, &dist);
            if (found != NULL) {
                def = (ObjPlacement*)found->anim.placementData;
            }
            if (def != NULL && def->objectId == 0x860 && (found->anim.resetHitboxFlags & 4) != 0) {
                mainSetBits(GAMEBIT_ITEM_DinoHorn_3F1, 1);
                mainSetBits(GAMEBIT_ITEM_DinoHorn_3D8, 1);
                mainSetBits(GAMEBIT_ITEM_DinoHorn_651, 1);
            }
            return 0;
        }
        if ((*gGameUIInterface)->isItemBeingUsed(0x953) != 0 && gPlayerChildObject == NULL) {
            GameObject* player;
            void* att;
            buttonDisable(0, PAD_BUTTON_A);
            if (gPlayerPathObject != NULL && inner->flags3F4.b40) {
                inner->staffActionRequest = 1;
                inner->flags3F4.b08 = 1;
            }
            player = Obj_GetPlayerObject();
            if ((u8)Obj_CanSetupObject() == 0) {
                att = NULL;
            } else {
                ObjPlacement* setup = Obj_AllocObjectSetup(0x24, 0x62d);
                setup->objectId = 0x62d;
                setup->color[0] = 2;
                setup->color[2] = 0xff;
                setup->color[1] = 1;
                setup->color[3] = 0xff;
                setup->posX = player->anim.localPosX;
                setup->posY = player->anim.localPosY;
                setup->posZ = player->anim.localPosZ;
                att = objSetupObject(setup, 4, player->anim.mapEventSlot, -1, player->anim.parent);
            }
            gPlayerChildObject = att;
            ObjLink_AttachChild(obj, (GameObject*)att, 1);
            (*gObjectTriggerInterface)->runSequence(0xd, (void*)obj, -1);
        }
    }
    if (inner->curAnimId != 0x44 && (*gGameUIInterface)->isAnyItemBeingUsed() != 0 &&
        (*gGameUIInterface)->isItemBeingUsed(0x13e) != 0 &&
        (objGetAllOfType(LANTERNFIREFLY_OBJGROUP, &cnt30), cnt30 == 0))
    {
        gameBitDecrement(0x13d);
        if ((u8)Obj_CanSetupObject() != 0)
        {
            ObjPlacement* setup = Obj_AllocObjectSetup(0x24, 0x43b);
            setup->objectId = 0x43b;
            setup->size = 9;
            setup->color[0] = 2;
            setup->color[2] = 0xff;
            setup->color[1] = 1;
            setup->color[3] = 0xff;
            setup->posX = obj->anim.localPosX;
            setup->posY = 15.0f + obj->anim.localPosY;
            setup->posZ = obj->anim.localPosZ;
            *(u8*)((char*)setup + 0x19) = 1;
            objSetupObject(setup, 5, -1, -1, obj->anim.parent);
        }
        (*(void (*)(void))(*(int*)((char*)*gGameUIInterface + 0x10)))();
        return 0;
    }
    {
        if (inner->staffGrown != 0)
        {
            int r2;
            if ((((PlayerState*)state)->baddie.pressedButtons & 0x200) != 0 && gPlayerPathObject != NULL &&
                inner->flags3F4.b40)
            {
                inner->staffActionRequest = 0;
                inner->flags3F4.b08 = 0;
            }
            {
                PlayerState* in2 = obj->extra;
                u8 b;
                if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0 &&
                    (b = in2->flags3F4.b40, b != 0))
                {
                    if (gPlayerPathObject != NULL && b != 0)
                    {
                        in2->staffActionRequest = 4;
                        in2->flags3F4.b08 = 1;
                    }
                    ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
                    r2 = 0x32;
                }
                else
                {
                    r2 = 0;
                }
                if (r2 != 0)
                {
                    return r2;
                }
            }
        }
        else
        {
            if ((((PlayerState*)state)->baddie.pressedButtons & 0x100) != 0)
            {
                int ok2;
                if (inner->heldObj != NULL || !inner->flags3F4.b40 ||
                    inner->flags3F0.b20 || inner->flags3F0.b10)
                {
                    ok2 = 0;
                }
                else
                {
                    ok2 = 1;
                }
                if (ok2 != 0)
                {
                    if (inner->staffActionRequest == 2 ||
                        (inner->cameraTargetObject != NULL && inner->targetObjectDist < 70.0f &&
                         inner->targetObjectBearingAbs < 0x4000 && inner->targetObjModelType == 1))
                    {
                        if (gPlayerPathObject != NULL && inner->flags3F4.b40)
                        {
                            inner->staffActionRequest = 4;
                            inner->flags3F4.b08 = 1;
                        }
                        ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
                        return 0x32;
                    }
                    if (gPlayerPathObject != NULL && inner->flags3F4.b40)
                    {
                        inner->staffActionRequest = 2;
                        inner->flags3F4.b08 = 0;
                    }
                }
            }
        }
        return 0;
    }
}

void playerResetMoveTables(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    inner->moveParamValues = gPlayerDefaultMoveParams;
    inner->moveAnimIds = gPlayerMoveTableA;
}

int playerStateThrowing(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    f32 k;

    if (state->baddie.moveJustStartedA != 0) {
        if (inner->heldObj != NULL) {
            ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)inner->heldObj);
        }
        ObjAnim_SetCurrentMove(obj, 0x443, 0.3f, 0);
        state->baddie.stateId = 1;
        inner->stateHandler = playerStagedRestoreDefaultControl;
    }
    k = 0.0f;
    state->baddie.animSpeedC = k;
    state->baddie.animSpeedB = k;
    state->baddie.animSpeedA = k;
    obj->anim.velocityX = k;
    obj->anim.velocityY = k;
    obj->anim.velocityZ = k;
    state->baddie.moveSpeed = 0.0165f;

    if (state->baddie.eventFlags & 1) {
        Sfx_PlayFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_foxcom_decoy : SFXTRIG_sa_jump02));
    }

    if (inner->heldObj == NULL && state->baddie.moveDone != 0) {
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    if (inner->heldObj != NULL && obj->anim.currentMoveProgress > 0.4f) {
        inner->isHoldingObject = 0;
        if (inner->heldObj != NULL) {
            GameObject* s2 = inner->heldObj;
            s16 id = s2->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED) {
                SmallBasket_throw(s2);
            } else {
                Carryable_putDownAndSavePos(s2);
            }
            inner->heldObj->anim.flags &= ~0x4000;
            inner->heldObj->userData2 = 0;
            inner->heldObj = 0;
        }
    }
    return 0;
}

void playerStagedMarkTeleported(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    GameObject* p = inner->heldObj;
    if (p != NULL)
    {
        p->userData2 = 1;
    }
    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
}

int playerState06(GameObject* obj, PlayerState* state)
{
    PlayerState* inner = obj->extra;
    GameObject* sub;

    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x447, 0.0f, 0);
        ((PlayerState*)state)->baddie.stateId = 1;
        inner->stateHandler = playerStagedRestoreDefaultControl;
    }
    if ((((PlayerState*)state)->baddie.eventFlags & 1) && (sub = inner->heldObj) != NULL)
    {
        switch (sub->anim.romDefNo)
        {
        case 0x6d:
        case 0x754:
            Sfx_PlayFromObject(obj, SFXTRIG_barrel_putdown_31f);
            break;
        case 0x1f4:
        case 0x1f5:
        case 0x1f6:
        case 0x1f7:
        case 0x1f8:
        case 0x1f9:
        case 0x519:
            Sfx_PlayFromObject(obj, SFXTRIG_weetinkoneshot);
            break;
        default:
            Sfx_PlayFromObject(obj, SFXTRIG_vineclimb116);
            break;
        }
    }
    state->baddie.animSpeedA = 0.0f;
    state->baddie.moveSpeed = 0.02857f;

    sub = inner->heldObj;
    if (sub == NULL && ((PlayerState*)state)->baddie.moveDone != 0)
    {
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    if (sub != NULL && obj->anim.currentMoveProgress > 0.6f)
    {
        inner->isHoldingObject = 0;
        if (inner->heldObj != NULL)
        {
            GameObject* s2 = inner->heldObj;
            s16 id = s2->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
            {
                SmallBasket_throw(s2);
            }
            else
            {
                Carryable_putDownAndSavePos(s2);
            }
            inner->heldObj->anim.flags &= ~0x4000;
            inner->heldObj->userData2 = 0;
            inner->heldObj = 0;
        }
    }
    return 0;
}

int playerState05(GameObject* obj, PlayerState* state) {
    PlayerState* inner = obj->extra;
    state->baddie.animSpeedB = 0.0f;
    if (state->baddie.moveJustStartedA != 0) {
        if (gPlayerPathObject != NULL) {
            if (inner->flags3F4.b40) {
                inner->staffActionRequest = 1;
                inner->flags3F4.b08 = 1;
            }
        }
        state->baddie.stateId = 1;
        inner->stateHandler = playerStagedRestoreDefaultControl;
    }
    switch (obj->anim.currentMove) {
    case 5: {
        GameObject* sub;
        state->baddie.moveSpeed = 0.02857f;
        state->baddie.animSpeedA = 0.0f;
        sub = inner->heldObj;
        if (sub != NULL) {
            f32 amt;
            if (obj->anim.currentMoveProgress > 0.5f) {
                sub->userData2 = 1;
            }
            amt = interpolate((f32)inner->targetObjectBearing, 0.083333336f, timeDelta);
            inner->targetYaw = (f32)inner->targetYaw + amt;
            inner->yaw = inner->targetYaw;
        }
        if (obj->anim.currentMoveProgress > 0.8f) {
            inner->moveAnimIds = lbl_80333110;
            ObjAnim_SetCurrentMove(obj, inner->moveAnimIds[0], 0.0f, 0);
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        }
        break;
    }
    default: {
        GameObject* sub = inner->heldObj;
        if (sub != NULL && sub->anim.romDefNo == 0x112) {
            inner->moveAnimIds = lbl_80333110;
            inner->heldObj->userData2 = 1;
            ObjAnim_SetCurrentMove(obj, inner->moveAnimIds[0], 0.0f, 0);
            inner->flags360 |= PLAYER_FLAG_TELEPORTED;
            state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
            return 2;
        } else {
            ObjAnim_SetCurrentMove(obj, 5, 0.0f, 0);
        }
        break;
    }
    }
    if (state->baddie.eventFlags & 1) {
        u16 snd;
        if (inner->characterId == 0) {
            snd = 0x320;
        } else {
            snd = 0x3c1;
        }
        Sfx_PlayFromObject(obj, snd);
    }
    return 0;
}

int playerState04(GameObject* obj, PlayerState* state, f32 fv) {
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0x92, 0.0f, 0);
        state->baddie.moveSpeed = 0.007f;
    }
    (*gPlayerInterface)->updateAnimRootMotion((void*)obj, (void*)state, fv, 3);
    if (state->baddie.moveDone != 0) {
        state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 2;
    }
    return 0;
}

int playerStateIceSpell(GameObject* obj, PlayerState* state, f32 fv) {
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0x8e, 0.0f, 0);
        state->baddie.moveSpeed = 0.007f;
    }
    (*gPlayerInterface)->updateAnimRootMotion((void*)obj, (void*)state, fv, 3);
    if (state->baddie.moveDone != 0) {
        GameObject** p;
        int z[2];
        z[0] = 0;
        gPlayerIceSpellSustaining = z[0];
        z[1] = z[0];
        p = gPlayerSpawnedObjects;
        for (; z[1] < 7; z[1]++) {
            if (p[z[1]] != NULL) {
                Obj_FreeObject(p[z[1]]);
                p[z[1]] = NULL;
            }
        }
        if (gPlayerResource != NULL) {
            Resource_Release(gPlayerResource);
            gPlayerResource = NULL;
        }
        showDeathMenu();
    }
    return 0;
}

void playerStagedRestoreDefaultControl(GameObject* obj, BaddieState* state) {
    PlayerState* inner = obj->extra;
    inner->flags3F1.b80 = 0;
    {
        s16 mode = ((PlayerState*)state)->baddie.controlMode;
        if (mode != 2 && mode != 1 && mode != 5 && mode != 7 && mode != 6) {
            GameObject* sub;
            inner->isHoldingObject = 0;
            sub = inner->heldObj;
            if (sub != NULL) {
                s16 id = sub->anim.romDefNo;
                if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED) {
                    SmallBasket_throw(sub);
                } else {
                    Carryable_putDownAndSavePos(sub);
                }
                inner->heldObj->anim.flags &= ~0x4000;
                inner->heldObj->userData2 = 0;
                inner->heldObj = 0;
            }
        }
    }
    {
        s16 mode = ((PlayerState*)state)->baddie.controlMode;
        if (mode != 2 && mode != 1) {
            inner->flags3F0.b10 = 0;
            inner->flags3F0.b80 = 0;
            inner->flags3F0.b40 = 0;
            inner->flags3F0.b08 = 0;
            inner->flags3F0.b04 = 0;
            inner->staffHoldFrames = 0;
            inner->flags3F0.b20 = 0;
            if (inner->flags3F1.b20) {
                s16 t = obj->anim.rotX;
                inner->yaw = t;
                inner->targetYaw = t;
                inner->lastInputHeading = t;
                inner->baddie.animSpeedB = 0.0f;
            }
            inner->flags3F1.b20 = 0;
            if (inner->flags3F1.b10) {
                u8 anim = inner->curAnimId;
                if (anim != 0x48 && anim != 0x47 && getCurSeqNo() == 0) {
                    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                    inner->flags3F1.b10 = 0;
                }
            }
            inner->flags360 &= ~0x2000000LL;
        }
    }
    if (((PlayerState*)state)->baddie.controlMode != 2) {
        Shield_setMode(gPlayerStaffObject, 2);
        inner->flags3F0.b02 = 0;
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    gPlayerModelChainStyle = 1;
}

int playerStateMoving(int obj, int state, f32 fv)
{
    PlayerState* inner;
    int dir;
    f32 t;
    f32 spd;
    f32 ya;

    inner = ((GameObject*)obj)->extra;
    inner->flags3F1.b02 = 0;
    inner->flags3F1.b04 = 0;
    inner->flags3F1.b08 = 0;
    inner->flags3F2.b10 = 0;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        inner->flags360 |= 0x2000000LL;
        inner->flags3F0.b80 = 0;
        inner->flags3F0.b40 = 0;
        inner->flags3F3.b40 = 0;
        inner->gaitLevel = 0;
        inner->unk81E = 0;
        inner->flags3F2.b10 = 1;
    }
    {
        int r = playerCheckCommonTransitions((GameObject*)obj, (PlayerState*)state, inner, fv);
        if (r != 0)
        {
            return r;
        }
    }
    playerSetMovingAnims((GameObject*)obj, inner);
    {
        u32 fl = inner->flagByte3F0;
        if ((fl >> 5 & 1) != 0)
        {
            *(int*)state |= 0x200000;
            inner->flags360 |= PLAYER_FLAG_NO_POS_VELOCITY;
            inner->flags360 |= 0x2000000LL;
            ((PlayerState*)state)->baddie.stateId = 2;
            inner->stateHandler = playerStagedRestoreDefaultControl;
            if ((inner->flags3F1.b20) != 0)
            {
                inner->maxSpeed = 0.8f;
            }
            else
            {
                inner->maxSpeed = 1.1996999f;
            }
        }
        else if ((inner->flags3F1.b20) != 0)
        {
            inner->flags360 |= 0x2000000LL;
            *(int*)state |= 0x800000;
            ((PlayerState*)state)->baddie.stateId = 0;
            inner->maxSpeed = 2.0f;
        }
        else if ((fl >> 3 & 1) != 0 || (fl >> 2 & 1) != 0)
        {
            *(int*)state |= 0x200000;
            inner->flags360 |= 0x2000000LL;
            inner->maxSpeed = 1.9f;
        }
        else
        {
            inner->flags360 |= 0x2000000LL;
            *(int*)state |= 0x800000;
            ((PlayerState*)state)->baddie.stateId = 0;
            inner->maxSpeed = 2.3993998f;
        }
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if ((inner->flags3F1.b20) == 0 && (inner->flags3F0.b04) == 0)
        {
            inner->yaw = inner->yaw + inner->yawRate * 0xb6;
        }
        inner->yawRateSigned = 0;
        inner->yawRate = 0;
    }
    {
        t = ((((PlayerState*)state)->baddie.inputMagnitude - 0.2f) / 0.8f < 0.0f)
                ? 0.0f
                : (((((PlayerState*)state)->baddie.inputMagnitude - 0.2f) / 0.8f > 1.0f)
                       ? 1.0f
                       : (((PlayerState*)state)->baddie.inputMagnitude - 0.2f) / 0.8f);
    }
    inner->currentSpeed =
        (inner->maxSpeed - 0.05f) * (t * inner->speedScale);
    {
        u32 fl = inner->flagByte3F0;
        if ((fl >> 6 & 1) != 0)
        {
            inner->flags360 |= PLAYER_FLAG_HEADING_LOCK;
            ((PlayerState*)state)->baddie.moveSpeed = 0.033f;
            {
                s16 cd = (s16)(32768.0f * ((GameObject*)obj)->anim.currentMoveProgress +
                               (f32) * (int*)((char*)inner + 0x858));
                inner->targetYaw = cd;
                inner->lastInputHeading = cd;
            }
            if (((PlayerState*)state)->baddie.moveDone != 0)
            {
                inner->flags3F0.b40 = 0;
                {
                    int a = inner->yaw;
                    inner->targetYaw = a;
                    inner->lastInputHeading = a;
                }
                inner->gaitLevel = 0xc;
                inner->flags3F1.b04 = 1;
                inner->flags3F1.b08 = 1;
            }
            ((PlayerState*)state)->baddie.animSpeedC =
                inner->animSpeedRate * timeDelta + ((PlayerState*)state)->baddie.animSpeedC;
            inner->currentSpeed = 0.0f;
            if (((GameObject*)obj)->anim.currentMoveProgress > 0.1f &&
                ((GameObject*)obj)->anim.currentMoveProgress < 0.55f)
            {
                inner->pendingFxFlags |= 8;
            }
        }
        else if ((fl >> 4 & 1) != 0)
        {
            playerUpdateStaffAttack((GameObject*)obj, inner, (PlayerState*)state);
        }
        else if ((fl >> 7 & 1) != 0)
        {
            int r = playerUpdateQuickTurn((GameObject*)obj, inner, (PlayerState*)state);
            if (r != 0)
            {
                ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreDefaultControl;
                return 2;
            }
        }
        else if ((fl >> 1 & 1) != 0)
        {
            int leave;
            inner->flags360 |= PLAYER_FLAG_GUARDING;
            {
                f32 z = 0.0f;
                ((PlayerState*)state)->baddie.animSpeedC = z;
                ((PlayerState*)state)->baddie.animSpeedC = z;
                ((PlayerState*)state)->baddie.animSpeedB = z;
                ((PlayerState*)state)->baddie.animSpeedA = z;
                ((GameObject*)obj)->anim.velocityX = z;
                ((GameObject*)obj)->anim.velocityY = z;
                ((GameObject*)obj)->anim.velocityZ = z;
                {
                    f32 w = 20.0f;
                    inner->targetYawSmoothRate = w;
                    inner->targetYawRateLimit = z;
                    inner->yawSmoothRate = w;
                    inner->yawRateLimit = z;
                    inner->currentSpeed = z;
                }
            }
            {
                u32 fl2;
                int stay;
                if ((padGetTriggers(0) & 0x20) != 0 &&
                    (inner->flags3F4.b40) != 0 &&
                    ((fl2 = inner->flagByte3F0) >> 5 & 1) == 0 && (fl2 >> 3 & 1) == 0 &&
                    (fl2 >> 2 & 1) == 0 && inner->curAnimId != 0x44 &&
                    inner->heldObj == NULL && inner->baddie.targetObj == NULL &&
                    (inner->flags3F6.b40) == 0 &&
                    inner->baddie.controlMode != 0x26 &&
                    (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0 &&
                    !inner->idleDelayTimer)
                {
                    stay = 1;
                }
                else
                {
                    stay = 0;
                }
                if (!stay)
                {
                    if (gPlayerPathObject != 0 && (inner->flags3F4.b40) != 0)
                    {
                        inner->staffActionRequest = 1;
                        inner->flags3F4.b08 = 1;
                    }
                    Shield_setMode(gPlayerStaffObject, 2);
                    inner->flags3F0.b02 = 0;
                    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
                    ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
                    leave = 1;
                }
                else
                {
                    leave = 0;
                }
            }
            if (leave)
            {
                ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreDefaultControl;
                return 2;
            }
        }
        else if ((fl >> 5 & 1) != 0)
        {
            playerUpdateWaterMotion((GameObject*)obj, inner, (PlayerState*)state);
        }
        else if ((fl >> 3 & 1) != 0)
        {
            playerUpdateFallingMotion((GameObject*)obj, inner, (PlayerState*)state);
        }
        else if ((fl >> 2 & 1) != 0)
        {
            int r = playerUpdateAirborneMotion((GameObject*)obj, inner, (PlayerState*)state);
            if (r != 0)
            {
                ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreDefaultControl;
                return 2;
            }
        }
    }
    {
        int calm;
        {
            u32 fl = inner->flagByte3F0;
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
                (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 && inner->heldObj == NULL &&
                inner->curAnimId != 0x44)
            {
                calm = 1;
            }
            else
            {
                calm = 0;
            }
        }
        if (calm && (inner->buttonsJustPressed & PAD_BUTTON_X) != 0)
        {
            playerStartStaffAttack((GameObject*)obj, inner, (PlayerState*)state);
        }
    }
    {
        int ok;
        {
            u32 fl = inner->flagByte3F0;
            if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 7 & 1) == 0 && (fl >> 4 & 1) == 0 &&
                (fl >> 2 & 1) == 0 && (fl >> 3 & 1) == 0 && (inner->flags3F1.b20) == 0)
            {
                ok = 1;
            }
            else
            {
                ok = 0;
            }
        }
        if (ok && ((PlayerState*)state)->baddie.animSpeedC > 0.3f + inner->moveParamValues[5] &&
            (inner->inputMagnitude < -0.3f || inner->yawRateSigned >= 0x96))
        {
            inner->pendingFxFlags |= 8;
            inner->flags3F0.b80 = 1;
            inner->animSoundId = inner->altAnimSoundId;
            inner->flags360 |= PLAYER_FLAG_HEADING_LOCK;
            inner->animSpeedRate = ((PlayerState*)state)->baddie.animSpeedA;
            ObjAnim_SetCurrentMove((void*)obj, inner->moveAnimIds[30], 0.0f, 0);
        }
    }
    {
        u32 fl = inner->flagByte3F0;
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (inner->flags3F1.b20) == 0)
        {
            if (inner->yawRateSigned < 0x96)
            {
                f32 d = interpolate((f32) inner->targetYawRateSigned,
                                    1.0f / inner->targetYawSmoothRate, timeDelta);
                {
                    f32 m =
                        timeDelta * (inner->targetYawRateLimit * inner->leanCurveScale);
                    d = (d > m) ? m : d;
                }
                if (inner->targetYawRate < 0)
                {
                    d = -d;
                }
                inner->targetYaw =
                    (s16)(182.044f * d + (f32) inner->targetYaw);
            }
            if (inner->yawRateSigned < 0x96)
            {
                f32 d = interpolate((f32) inner->yawRateSigned, 1.0f / inner->yawSmoothRate,
                                    timeDelta);
                {
                    f32 m = inner->yawRateLimit * timeDelta;
                    d = (d > m) ? m : d;
                }
                if (inner->yawRate < 0)
                {
                    d = -d;
                }
                inner->yaw = (s16)(182.044f * d + (f32) inner->yaw);
            }
            else
            {
                u32 fl3 = inner->flagByte3F0;
                if ((fl3 >> 3 & 1) == 0 && (fl3 >> 2 & 1) == 0 && (fl3 >> 4 & 1) == 0 &&
                    ((PlayerState*)state)->baddie.animSpeedC <= inner->moveParamValues[1] &&
                    ((PlayerState*)state)->baddie.animSpeedA <= inner->moveParamValues[3])
                {
                    inner->yaw = inner->yaw + inner->yawRate * 0xb6;
                }
            }
        }
    }
    {
        u32 fl;
        u32 fl1 = inner->flagByte3F1;
        if ((fl1 >> 5 & 1) != 0)
        {
            spd = inner->maxSpeed *
                  (t * -mathSinf((3.1415927f * (f32) inner->inputHeading) / 32768.0f));
            ya = inner->maxSpeed *
                 (t * -mathCosf((3.1415927f * (f32) inner->inputHeading) / 32768.0f));
            t = interpolate(spd - inner->smoothVelX, inner->velSmoothRate, timeDelta);
            {
                f32 dy = interpolate(ya - inner->smoothVelZ, inner->velSmoothRate,
                                     timeDelta);
                inner->smoothVelX = inner->smoothVelX + t;
                inner->smoothVelZ = inner->smoothVelZ + dy;
            }
            ((PlayerState*)state)->baddie.animSpeedC =
                sqrtf(inner->smoothVelX * inner->smoothVelX +
                      inner->smoothVelZ * inner->smoothVelZ);
            {
                ((PlayerState*)state)->baddie.animSpeedC =
                    (((PlayerState*)state)->baddie.animSpeedC < **(f32**)((char*)inner + 0x400))
                        ? **(f32**)((char*)inner + 0x400)
                        : ((((PlayerState*)state)->baddie.animSpeedC > inner->maxSpeed)
                               ? inner->maxSpeed
                               : ((PlayerState*)state)->baddie.animSpeedC);
            }
            t = mathSinf((3.1415927f * (f32) inner->targetYaw) / 32768.0f);
            {
                f32 cs = mathCosf((3.1415927f * (f32) inner->targetYaw) / 32768.0f);
                ya = inner->smoothVelZ;
                spd = -ya * cs - inner->smoothVelX * t;
                ya = inner->smoothVelX * cs - ya * t;
                ((PlayerState*)state)->baddie.animSpeedA =
                    ((PlayerState*)state)->baddie.animSpeedA +
                    interpolate(spd - ((PlayerState*)state)->baddie.animSpeedA, inner->targetAnimSpeed,
                                timeDelta);
                ((PlayerState*)state)->baddie.animSpeedB =
                    ((PlayerState*)state)->baddie.animSpeedB +
                    interpolate(ya - ((PlayerState*)state)->baddie.animSpeedB, inner->targetAnimSpeed,
                                timeDelta);
            }
            spd = ((PlayerState*)state)->baddie.animSpeedB;
            spd = (spd < 0.0f) ? -spd : spd;
            t = ((PlayerState*)state)->baddie.animSpeedA;
            t = (t < 0.0f) ? -t : t;
            {
                int r = ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj,
                                                     ((PlayerState*)state)->baddie.animSpeedC,
                                                     (f32*)(state + 0x2a0));
                if (r == 0)
                {
                    ((PlayerState*)state)->baddie.moveSpeed = 0.005f;
                }
            }
            if ((inner->flags3F0.b20) != 0)
            {
                ((PlayerState*)state)->baddie.moveSpeed *= 0.5f;
            }
            if (t > spd)
            {
                if (((PlayerState*)state)->baddie.animSpeedA < 0.0f)
                {
                    dir = 1;
                }
                else
                {
                    dir = 0;
                }
            }
            else if (((PlayerState*)state)->baddie.animSpeedB >= 0.0f)
            {
                dir = 3;
            }
            else
            {
                dir = 2;
            }
        }
        else
        {
            fl = inner->flagByte3F0;
            if ((fl >> 6 & 1) == 0 && (fl1 >> 2 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl1 >> 1 & 1) == 0 &&
                (fl >> 3 & 1) == 0 && (fl >> 2 & 1) == 0 && (fl >> 1 & 1) == 0)
            {
                f32 d = interpolate(inner->currentSpeed - ((PlayerState*)state)->baddie.animSpeedC,
                                    inner->velSmoothRate, timeDelta);
                d = (d < -0.1f * timeDelta) ? -0.1f * timeDelta : ((d > 0.1f * timeDelta) ? 0.1f * timeDelta : d);
                if (inner->yawRateSigned >= 0x96 && d > 0.0f)
                {
                    d = 2.0f * -d;
                }
                ((PlayerState*)state)->baddie.animSpeedC = ((PlayerState*)state)->baddie.animSpeedC + d;
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        (((PlayerState*)state)->baddie.animSpeedC < **(f32**)((char*)inner + 0x400))
                            ? **(f32**)((char*)inner + 0x400)
                            : ((((PlayerState*)state)->baddie.animSpeedC > inner->maxSpeed)
                                   ? inner->maxSpeed
                                   : ((PlayerState*)state)->baddie.animSpeedC);
                }
                ((PlayerState*)state)->baddie.animSpeedB = 0.0f;
            }
            else if (inner->flags3F0.b08 != 0 ||
                     inner->flags3F0.b04 != 0)
            {
                f32 vz;

                t = inner->currentSpeed *
                    -mathSinf((3.1415927f * (182.044f * (f32) inner->yawRate)) / 32768.0f);
                vz = inner->currentSpeed *
                     mathCosf((3.1415927f * (182.044f * (f32) inner->yawRate)) / 32768.0f);
                if ((inner->flags3F0.b04) != 0)
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        ((PlayerState*)state)->baddie.animSpeedC * powfBitEstimate(0.98f, timeDelta);
                }
                else
                {
                    ((PlayerState*)state)->baddie.animSpeedC =
                        -(0.025f * timeDelta - ((PlayerState*)state)->baddie.animSpeedC);
                }
                {
                    f32 v2 = 0.03f * vz;
                    f32 m = (v2 < -0.075f) ? -0.075f : ((v2 > 0.075f) ? 0.075f : v2);
                    ((PlayerState*)state)->baddie.animSpeedC = m * timeDelta + ((PlayerState*)state)->baddie.animSpeedC;
                }
                {
                    f32 v = ((PlayerState*)state)->baddie.animSpeedC;
                    ((PlayerState*)state)->baddie.animSpeedC =
                        (v < 0.65f)
                            ? 0.65f
                            : ((v > 0.1f + inner->maxSpeed) ? 0.1f + inner->maxSpeed
                                                                            : v);
                }
                t *= 0.35f;
                ((PlayerState*)state)->baddie.animSpeedB =
                    ((PlayerState*)state)->baddie.animSpeedB +
                    interpolate(t - ((PlayerState*)state)->baddie.animSpeedB, 0.075f, timeDelta);
            }
            else
            {
                f32 lim;
                f32 v;
                v = ((PlayerState*)state)->baddie.animSpeedC;
                lim = inner->maxSpeed;
                ((PlayerState*)state)->baddie.animSpeedC = (v < -lim) ? -lim : ((v > lim) ? lim : v);
            }
            {
                if ((inner->flags3F0.b10) == 0 &&
                    (inner->flags3F1.b02) == 0 &&
                    (inner->flags3F0.b02) == 0)
                {
                    ((PlayerState*)state)->baddie.animSpeedA =
                        ((PlayerState*)state)->baddie.animSpeedA +
                        interpolate(((PlayerState*)state)->baddie.animSpeedC - ((PlayerState*)state)->baddie.animSpeedA,
                                    inner->targetAnimSpeed, timeDelta);
                }
            }
            dir = 0;
        }
    }
    {
        u32 fl = inner->flagByte3F0;
        if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
            (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0)
        {
            int step;
            int locked;
            locked = 0;
            if ((inner->flags3F1.b08) != 0)
            {
                locked = 1;
                spd = 0.0f;
            }
            else
            {
                spd = ((GameObject*)obj)->anim.currentMoveProgress;
            }
            step = inner->gaitLevel / 4 * 2;
            inner->gaitStepLevel = (step >> 1) + 1;
            if (inner->gaitStepLevel > 4)
            {
                inner->gaitStepLevel = 4;
            }
            {
                u8 c;
                if (inner->gaitStepLevel > 3)
                {
                    c = inner->runAnimSoundId;
                }
                else
                {
                    c = inner->walkAnimSoundId;
                }
                inner->animSoundId = c;
            }
            {
                f32 v = ((PlayerState*)state)->baddie.animSpeedC;
                f32* tb = inner->moveParamValues;
                if (v < tb[step])
                {
                    if (inner->gaitLevel == 4)
                    {
                        if (((PlayerState*)state)->baddie.animSpeedA < tb[4] &&
                            ((PlayerState*)state)->baddie.inputMagnitude < 0.2f)
                        {
                            ((PlayerState*)state)->baddie.stateHandler = (int)playerStagedRestoreDefaultControl;
                            return 2;
                        }
                    }
                    else
                    {
                        *(u8*)&inner->gaitLevel -= 4;
                    }
                }
                else if (v >= tb[step + 1])
                {
                    int cc = inner->gaitLevel;
                    if (cc < 0x14)
                    {
                        if (cc == 0)
                        {
                            spd = 0.0f;
                        }
                        if (v < inner->maxSpeed)
                        {
                            *(u8*)&inner->gaitLevel += 4;
                        }
                    }
                }
            }
            if (locked != 0 || inner->prevMoveAnimIds != inner->moveAnimIds ||
                ((GameObject*)obj)->anim.currentMove !=
                    inner->moveAnimIds[inner->gaitLevel + dir])
            {
                if (ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0 ||
                    inner->flags3F2.b10 != 0)
                {
                    ObjAnim_SetCurrentMove(
                        (void*)obj,
                        inner->moveAnimIds[inner->gaitLevel + dir],
                        spd, 0);
                    if ((inner->flags3F1.b20) != 0 &&
                        ((PlayerState*)state)->baddie.moveJustStartedA == 0)
                    {
                        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
                    }
                }
            }
        }
    }
    {
        f32 v = (f32)((PlayerState*)state)->baddie.spawnRotY / 8192.0f;
        t = (v < (t = -1.0f)) ? t : ((v > (t = 1.0f)) ? t : v);
    }
    {
        f32 ad = t;
        int pos;
        if (t > 0.0f)
        {
            pos = 1;
        }
        else
        {
            pos = 0;
        }
        if (t < 0.0f)
        {
            ad = -t;
        }
        if ((inner->flags3F1.b20) == 0)
        {
            u32 fl = inner->flagByte3F0;
            if ((fl >> 7 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
                (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0)
            {
                if ((fl >> 5 & 1) == 0)
                {
                    Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj,
                                                        inner->moveAnimIds[inner->gaitLevel + pos + 1],
                                                        (int)(16384.0f * ad));
                }
                {
                    int r = ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj,
                                                         ((PlayerState*)state)->baddie.animSpeedC,
                                                         (f32*)(state + 0x2a0));
                    if (r == 0)
                    {
                        ((PlayerState*)state)->baddie.moveSpeed = 0.005f;
                    }
                }
            }
        }
    }
    playerUpdateLookAndLean((GameObject*)obj, (BaddieState*)state, inner, t);
    return 0;
}

int playerStateIdle(GameObject* obj, struct PlayerState* state, f32 fv)
{
    char* tbl;
    PlayerState* inner;
    int move;
    f32 t;
    f32 v;
    int calm;

    tbl = (char*)lbl_80332EC0;
    inner = ((GameObject*)obj)->extra;
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        if (((PlayerState*)state)->baddie.prevControlMode != 0x24 &&
            ((PlayerState*)state)->baddie.prevControlMode != 0x25)
        {
            ((PlayerState*)state)->baddie.animSpeedC = 0.0f;
        }
        else if (inner->flags3F1.b20 == 0)
        {
            int a = inner->inputHeading;
            inner->lastInputHeading = a;
            inner->yaw = a;
            inner->yawRate = 0;
            inner->yawRateSigned = 0;
        }
        else
        {
            f32 z = 0.0f;
            inner->smoothVelX = z;
            inner->smoothVelZ = z;
        }
        inner->idleHoldTimer = 0.0f;
        inner->idleWaitTimer = randomGetRange(800, 0x44c);
    }
    ((PlayerState*)state)->baddie.animSpeedA =
        ((PlayerState*)state)->baddie.animSpeedA -
        interpolate(((PlayerState*)state)->baddie.animSpeedA, inner->targetAnimSpeed, timeDelta);
    if (((PlayerState*)state)->baddie.animSpeedA <= *(f32*)(tbl + 0x398))
    {
        ((PlayerState*)state)->baddie.animSpeedA = 0.0f;
    }
    {
        f32 z = 0.0f;
        state->baddie.animSpeedB = z;
        obj->anim.velocityX = z;
        obj->anim.velocityZ = z;
    }
    {
        int r = playerCheckCommonTransitions((GameObject*)obj, (PlayerState*)state, inner, fv);
        if (r != 0)
        {
            return r;
        }
    }
    if (*(f32*)&((PlayerState*)state)->baddie.trackedObj >= 0.22f &&
        ((PlayerState*)state)->baddie.inputMagnitude >= 0.22f &&
        ((PlayerState*)state)->baddie.animSpeedC >= inner->moveParamValues[1])
    {
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 3;
    }
    playerSetMovingAnims(obj, inner);
    if (inner->moveAnimIds == (s16*)(tbl + 0x190))
    {
        if (inner->idleHoldTimer >= 60.0f && (inner->playerStatus)->health <= 4)
        {
            move = 0x5d;
            fv = 0.005f;
            if (RandomTimer_UpdateRangeTrigger(&inner->randomTimer3EC, 2.0f, 5.0f) != 0)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_fox_452);
            }
        }
        else
        {
            move = *inner->moveAnimIds;
            fv = 0.005f;
            if (inner->idleWaitTimer <= 0)
            {
                if (inner->curAnimId != 0x44)
                {
                    u32 i = inner->stopMoveIndex;
                    move = gPlayerStopMoves[i];
                    if (inner->characterId == 0)
                    {
                        fv = ((f32*)(tbl + 0x170))[i];
                    }
                    else
                    {
                        fv = ((f32*)(tbl + 0x180))[i];
                    }
                    inner->stopMoveIndex += 1;
                    inner->stopMoveIndex = (u8)(inner->stopMoveIndex % 3);
                }
                inner->idleWaitTimer = randomGetRange(800, 0x44c);
            }
        }
        if (obj->anim.currentMove == *inner->moveAnimIds) {
            inner->idleHoldTimer = inner->idleHoldTimer + timeDelta;
            v = inner->idleHoldTimer;
            inner->idleHoldTimer = (v < 0.0f) ? 0.0f : ((v > 60.0f) ? 60.0f : v);
            inner->idleWaitTimer = (f32)inner->idleWaitTimer - timeDelta;
            {
                int cd = inner->idleWaitTimer;
                if (cd < 0) {
                    cd = 0;
                } else if (cd > 0x44c) {
                    cd = 0x44c;
                }
                inner->idleWaitTimer = (s16)cd;
            }
        } else {
            if (obj->anim.currentMove != 0x5d) {
                inner->idleHoldTimer = 0.0f;
            }
            inner->idleWaitTimer = randomGetRange(800, 0x44c);
        }
    } else {
        move = *inner->moveAnimIds;
        fv = 0.005f;
    }
    if (inner->flags3F0.b20 != 0) {
        state->baddie.flags0 |= 0x200000;
        inner->flags360 &= ~0x2000000LL;
        state->baddie.stateId = 1;
        inner->stateHandler = playerStagedRestoreDefaultControl;
        if (inner->flags3F1.b20 != 0) {
            inner->maxSpeed = 0.8f;
        } else {
            inner->maxSpeed = 1.1996999f;
        }
    } else {
        if (inner->flags3F1.b20 != 0) {
            inner->flags360 |= 0x2000000LL;
            state->baddie.stateId = 0;
            inner->maxSpeed = 2.0f;
        } else {
            inner->flags360 |= 0x2000000LL;
            state->baddie.stateId = 0;
            inner->maxSpeed = 2.3993998f;
        }
    }
    {
        f32 frac = (state->baddie.inputMagnitude - 0.2f) / 0.8f;
        t = (frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac);
    }
    inner->currentSpeed =
        (inner->maxSpeed - 0.05f) * (t * inner->speedScale);
    if (inner->flags3F0.b20 != 0)
    {
        playerUpdateWaterMotion((GameObject*)obj, inner, state);
    }
    {
        u32 fl = inner->flagByte3F0;
        if ((fl >> 5 & 1) == 0 && (fl >> 6 & 1) == 0 && (fl >> 4 & 1) == 0 && (fl >> 2 & 1) == 0 &&
            (fl >> 3 & 1) == 0 && (fl >> 1 & 1) == 0 && inner->heldObj == NULL &&
            inner->curAnimId != 0x44)
        {
            calm = 1;
        }
        else
        {
            calm = 0;
        }
    }
    if (calm && (inner->buttonsJustPressed & PAD_BUTTON_X) != 0)
    {
        playerStartStaffAttack((GameObject*)obj, inner, state);
        ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
        return 3;
    }
    if (inner->flags3F1.b20 == 0)
    {
        ((PlayerState*)state)->baddie.animSpeedC =
            ((PlayerState*)state)->baddie.animSpeedC +
            interpolate(inner->currentSpeed - ((PlayerState*)state)->baddie.animSpeedC,
                        inner->velSmoothRate, timeDelta);
    }
    if (((PlayerState*)state)->baddie.moveJustStartedA != 0)
    {
        inner->targetYawRateSigned = 0;
        inner->targetYawRate = 0;
        inner->yawRateSigned = 0;
        inner->yawRate = 0;
        inner->animSoundId = inner->walkAnimSoundId;
        inner->gaitStepLevel = 0;
        ((PlayerState*)state)->baddie.velSmoothTime = 8.0f;
        ((PlayerState*)state)->baddie.moveSpeed = 0.0066649998f;
        if (inner->flags3F0.b20 == 0 && inner->flags3F1.b20 == 0)
        {
            if (((PlayerState*)state)->baddie.prevControlMode == 2)
            {
                int mA;
                int mB;
                if (((GameObject*)obj)->anim.currentMove !=
                        (mA = inner->moveAnimIds[24]) &&
                    (mB = inner->moveAnimIds[25],
                     ((GameObject*)obj)->anim.currentMove != mB) &&
                    inner->flags3F3.b40 == 0)
                {
                    if (((GameObject*)obj)->anim.currentMoveProgress <= 0.5f)
                    {
                        ObjAnim_SetCurrentMove(obj, mA, 0.0f, 0);
                    }
                    else
                    {
                        ObjAnim_SetCurrentMove(obj, mB, 0.0f, 0);
                    }
                }
                ((PlayerState*)state)->baddie.moveSpeed = 0.030000001f;
            }
            else if (((GameObject*)obj)->anim.currentMove != move)
            {
                ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
                ((PlayerState*)state)->baddie.moveSpeed = fv;
            }
        }
        else if (((GameObject*)obj)->anim.currentMove != move)
        {
            ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
            state->baddie.moveSpeed = fv;
        }
    }
    if (((GameObject*)obj)->anim.currentMove == inner->moveAnimIds[24] ||
        ((GameObject*)obj)->anim.currentMove == inner->moveAnimIds[25])
    {
        if (((PlayerState*)state)->baddie.moveDone != 0 &&
            ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
        {
            ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
            state->baddie.moveSpeed = fv;
        }
    }
    else if (inner->flags3F0.b20 == 0 && inner->flags3F1.b20 == 0 &&
             inner->targetYawRateSigned > 5)
    {
        if (((GameObject*)obj)->anim.currentMove != inner->moveAnimIds[31] &&
            ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
        {
            ObjAnim_SetCurrentMove(obj, inner->moveAnimIds[31], 0.0f, 0);
            ((PlayerState*)state)->baddie.moveSpeed = 0.04f;
        }
    }
    else if (((GameObject*)obj)->anim.currentMove != move &&
             ObjAnim_GetCurrentEventCountdown((ObjAnimComponent*)obj) == 0)
    {
        s16 cur = ((GameObject*)obj)->anim.currentMove;
        if (cur == gPlayerStopMoves[0] || cur == gPlayerStopMoves[1] || cur == gPlayerStopMoves[2] ||
            cur == gPlayerStopMoves[3])
        {
            if (((PlayerState*)state)->baddie.moveDone != 0)
            {
                ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
                state->baddie.moveSpeed = fv;
            }
        }
        else
        {
            ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
            ((PlayerState*)state)->baddie.moveSpeed = fv;
            if (move == 0x5d)
            {
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0x1e);
            }
        }
    }
    if (inner->flags3F1.b20 == 0)
    {
        f32 step;
        f32 lim;
        step = interpolate((f32) inner->targetYawRateSigned,
                           1.0f / inner->targetYawSmoothRate, timeDelta);
        lim = timeDelta * (inner->targetYawRateLimit * inner->leanCurveScale);
        step = (step < lim) ? step : lim;
        if (inner->targetYawRate < 0)
        {
            step = -step;
        }
        *(u16*)&inner->targetYaw = 182.044f * step + (f32) inner->targetYaw;
        step = interpolate((f32) inner->yawRateSigned, 1.0f / inner->yawSmoothRate,
                           timeDelta);
        lim = inner->yawRateLimit * timeDelta;
        step = (step < lim) ? step : lim;
        if (inner->yawRate < 0)
        {
            step = -step;
        }
        inner->yaw = 182.044f * step + (f32) inner->yaw;
    }
    else
    {
        f32 vx;
        f32 vz;
        f32 trig;
        trig = mathSinf((3.1415927f * (f32) inner->inputHeading) / 32768.0f);
        vx = t * -trig;
        vx = inner->maxSpeed * vx;
        trig = mathCosf((3.1415927f * (f32) inner->inputHeading) / 32768.0f);
        vz = t * -trig;
        vz = inner->maxSpeed * vz;
        vx = interpolate(vx - inner->smoothVelX, inner->velSmoothRate, timeDelta);
        vz = interpolate(vz - inner->smoothVelZ, inner->velSmoothRate, timeDelta);
        inner->smoothVelX = inner->smoothVelX + vx;
        inner->smoothVelZ = inner->smoothVelZ + vz;
        ((PlayerState*)state)->baddie.animSpeedC =
            sqrtf(inner->smoothVelX * inner->smoothVelX +
                  inner->smoothVelZ * inner->smoothVelZ);
        ((PlayerState*)state)->baddie.animSpeedC =
            (((PlayerState*)state)->baddie.animSpeedC < 0.0f)
                ? 0.0f
                : ((state->baddie.animSpeedC > inner->maxSpeed) ? inner->maxSpeed : state->baddie.animSpeedC);
    }
    if (inner->flags3F0.b20 == 0)
    {
        playerUpdateLookAtTarget(obj, state, inner);
    }
    return 0;
}

int playerState00(GameObject* obj, PlayerState* state) {
    if (mainGetBit(GAMEBIT_CF_DoStandUpAnim)) {
        mainSetBits(GAMEBIT_CF_DoStandUpAnim, 0);
        (*gObjectTriggerInterface)->runSequence(0x10, (void*)obj, -1);
    }
    state->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
    return 2;
}

s16 playerSetMoveBlendFromPlane(GameObject* obj, int baseMoveId, int blendMoveId, int* blendAnchor, int* blendPlane,
                                f32 samplePhase, f32 moveStepScale, int axis, int flags) {
    ObjModel* model;
    int controlFlags;
    u8 moveFlags;
    int axisOffset;
    int blendWeight;
    f32 baseDistance, blendDistance, blendFactor;
    f32 jointPosition[3];
    s16 jointRotation[3];
    model = Player_GetActiveModel(obj);
    moveFlags = 0;
    controlFlags = (u8)flags;
    if (controlFlags & 0x2) {
        moveFlags |= 0x2;
    }
    if (controlFlags & 0x40) {
        moveFlags |= 0x4;
    }
    if (controlFlags & 0x10) {
        moveFlags |= 0x8;
    }
    if (controlFlags & 0x20) {
        moveFlags |= 0x1;
    }
    if (controlFlags & 0x4) {
        ObjAnim_SetCurrentMove(obj, baseMoveId, 0.0f, moveFlags);
        ObjAnim_AdvanceCurrentMove(obj, moveStepScale, 0.0f, NULL);
        ObjModel_SampleJointTransform(model, 0, 0, samplePhase, obj->anim.rootMotionScale, jointPosition,
                                      jointRotation);
    } else {
        Object_ObjAnimSetMove(obj, baseMoveId, 0.0f, moveFlags);
        Object_ObjAnimAdvanceMove(obj, moveStepScale, 0.0f, NULL);
        ObjModel_SampleJointTransform(model, 1, 0, samplePhase, obj->anim.rootMotionScale, jointPosition,
                                      jointRotation);
    }
    axisOffset = (u8)axis << 2;
    baseDistance = *(f32*)((char*)jointPosition + axisOffset);
    if (baseDistance < 0.0f) {
        baseDistance = -baseDistance;
    }
    if (controlFlags & 0x4) {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, blendMoveId, 0);
        ObjModel_SampleJointTransform(model, 0, 2, samplePhase, obj->anim.rootMotionScale, jointPosition,
                                      jointRotation);
    } else {
        Object_ObjAnimSetPrimaryBlendMove((ObjAnimComponent*)obj, blendMoveId, 0);
        ObjModel_SampleJointTransform(model, 1, 2, samplePhase, obj->anim.rootMotionScale, jointPosition,
                                      jointRotation);
    }
    blendDistance = *(f32*)((char*)jointPosition + axisOffset);
    if (blendDistance < 0.0f) {
        blendDistance = -blendDistance;
    }
    blendFactor =
        *(f32*)((char*)blendPlane + 0xc) + (*(f32*)((char*)blendAnchor + 0x0) * *(f32*)((char*)blendPlane + 0x0) +
                                            *(f32*)((char*)blendAnchor + 0x8) * *(f32*)((char*)blendPlane + 0x8));
    if (blendFactor < 0.0f) {
        blendFactor = -blendFactor;
    }
    blendFactor = (blendFactor - baseDistance) / (blendDistance - baseDistance);
    if (controlFlags & 0x1) {
        if (blendFactor < 0.0f) {
            blendFactor = 0.0f;
        }
    } else {
        if (blendFactor < 0.0f) {
            blendFactor = -blendFactor;
        }
    }
    if (blendFactor > 1.0f) {
        blendFactor = 1.0f;
    }
    blendWeight = (int)(16384.0f * blendFactor);
    if (controlFlags & 0x4) {
        Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent*)obj, blendMoveId, (s16)blendWeight);
    } else {
        Object_ObjAnimSetPrimaryBlendMove((ObjAnimComponent*)obj, blendMoveId, (s16)blendWeight);
    }
    return blendWeight;
}

char sNotOnGroundFailureMessage[] = "FAIL ON NOT ON GROUND\n";

int playerCheckIfClimbingOntoWall(int obj, int state, int state2, void* out, f32 fv, u32 probeMask)
{
    f32* dir;
    int focusCandidateCount;
    f32 nearDist;
    f32 rot[3];
    f32 vec[3];
    f32 start[3];
    f32 end[3];
    f32 sc1[3];
    f32* sc1p = sc1;
    f32 sc0[3];
    f32* sc0p = sc0;
    u8 dirs[13] = {0xb, 4, 6, 0xa, 0xa, 3, 3, 2, 0xe, 0x10, 0x12, 0x13, 5};
    u16 dirMasks[13] = {1, 2, 4, 8, 8, 0x10, 0x10, 0x40, 0x80, 0x100, 1, 0x20, 0xffff};
    struct
    {
        u8 pad[2];
        u16 mode;
        u8 pad2[4];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    TrackLineIntersectResult buf;
    u8 useAlt;
    f32 hd;
    f32 dp;
    int i;
    s8 ok;
    f32 lo;
    int k;
    s8 flagB;
    s8 flagA;
    u8 hit;
    int ai;

    ai = (u16)getAngle(((PlayerState*)state2)->baddie.moveInputX, -((PlayerState*)state2)->baddie.moveInputZ) -
         ((PlayerState*)state2)->baddie.cameraYaw;
    rot[0] = -mathSinf((3.1415927f * (f32)ai) / 32768.0f);
    rot[1] = 0.0f;
    rot[2] = -mathCosf((3.1415927f * (f32)ai) / 32768.0f);
    playerGetMovementOrFacingDirection((GameObject*)(obj), state, vec);
    sc1p[0] = 50.0f * rot[0];
    sc1p[1] = 50.0f * rot[1];
    sc1p[2] = 50.0f * rot[2];
    sc0p[0] = 50.0f * vec[0];
    sc0p[1] = 50.0f * vec[1];
    sc0p[2] = 50.0f * vec[2];
    ((PlayerState*)state)->flags360 = ((PlayerState*)state)->flags360 & ~PLAYER_FLAG_LEDGE_DETECTED;
    for (i = 0; i < 13; i++) {
        if ((probeMask & dirMasks[i]) == 0)
        {
            continue;
        }
        ok = 0;
        useAlt = 0;
        flagB = 1;
        flagA = 0;
        switch (i)
        {
        case 1:
        case 7:
        case 12:
        {
            u8 b;
            s16 v = ((PlayerState*)state2)->baddie.controlMode;
            if (v == 0xc)
            {
                continue;
            }
            if ((u16)(v - 9) <= 2)
            {
                continue;
            }
            b = ((PlayerState*)state)->flagByte3F0;
            if ((u32)b >> 3 & 1)
            {
                continue;
            }
            if ((u32)b >> 2 & 1)
            {
                continue;
            }
            flagB = 0;
            flagA = 1;
            ok = 1;
            break;
        }
        case 0:
        case 10:
            if ((((PlayerState*)state)->flags3F1.b01) == 0)
            {
                logPrintf(sNotOnGroundFailureMessage);
                continue;
            }
            ok = 1;
            break;
        case 3:
        case 5:
        {
            u8 b = ((PlayerState*)state)->flagByte3F0;
            if ((u32)b >> 3 & 1 || (u32)b >> 2 & 1)
            {
                ok = 1;
            }
            useAlt = 1;
            break;
        }
        case 2:
        {
            u8 b2;
            if ((((PlayerState*)state)->flags3F1.b01) == 0)
            {
                u8 b = ((PlayerState*)state)->flagByte3F0;
                if (((u32)b >> 3 & 1) == 0 && ((u32)b >> 2 & 1) == 0)
                {
                    continue;
                }
            }
            b2 = ((PlayerState*)state)->flagByte3F0;
            if ((u32)b2 >> 3 & 1 || (u32)b2 >> 2 & 1)
            {
                ok = 1;
            }
            break;
        }
        case 4:
        case 6:
        {
            u8 b2;
            if ((((PlayerState*)state)->flags3F1.b01) == 0)
            {
                u8 b = ((PlayerState*)state)->flagByte3F0;
                if (((u32)b >> 3 & 1) == 0 && ((u32)b >> 2 & 1) == 0)
                {
                    continue;
                }
            }
            b2 = ((PlayerState*)state)->flagByte3F0;
            if ((u32)b2 >> 3 & 1 || (u32)b2 >> 2 & 1)
            {
                ok = 1;
            }
            break;
        }
        case 11:
            flagB = 0;
            ok = 1;
            break;
        }
        if (ok == 0)
        {
            if (((PlayerState*)state2)->baddie.inputMagnitude < 0.1f)
            {
                continue;
            }
        }
        if (useAlt == 0)
        {
            if (ok == 0)
            {
                end[0] = ((GameObject*)obj)->anim.localPosX + sc1p[0];
                end[1] = ((GameObject*)obj)->anim.localPosY + sc1p[1];
                end[2] = ((GameObject*)obj)->anim.localPosZ + sc1p[2];
                dir = rot;
            }
            else
            {
                end[0] = ((GameObject*)obj)->anim.localPosX + sc0p[0];
                end[1] = ((GameObject*)obj)->anim.localPosY + sc0p[1];
                end[2] = ((GameObject*)obj)->anim.localPosZ + sc0p[2];
                dir = vec;
            }
            start[0] = ((GameObject*)obj)->anim.localPosX;
            start[1] = ((GameObject*)obj)->anim.localPosY;
            start[2] = ((GameObject*)obj)->anim.localPosZ;
        }
        else
        {
            if (ok == 0)
            {
                start[0] = ((GameObject*)obj)->anim.localPosX + sc1p[0];
                start[1] = ((GameObject*)obj)->anim.localPosY + sc1p[1];
                start[2] = ((GameObject*)obj)->anim.localPosZ + sc1p[2];
                dir = rot;
            }
            else
            {
                start[0] = ((GameObject*)obj)->anim.localPosX + sc0p[0];
                start[1] = ((GameObject*)obj)->anim.localPosY + sc0p[1];
                start[2] = ((GameObject*)obj)->anim.localPosZ + sc0p[2];
                dir = vec;
            }
            end[0] = ((GameObject*)obj)->anim.localPosX;
            end[1] = ((GameObject*)obj)->anim.localPosY;
            end[2] = ((GameObject*)obj)->anim.localPosZ;
        }
        hit = trackGetLineIntersect(start, end, 0.0f, 3, &buf, (GameObject*)obj, 1, dirs[i],
                                0xff, 10);
        if (flagA != 0 && hit != 0)
        {
            ((PlayerState*)state)->probeHitDist = buf.distance;
        }
        if (flagB != 0 && hit != 0)
        {
            dp = buf.normalX * dir[0] + buf.normalY * dir[1] + buf.normalZ * dir[2];
            switch (i)
            {
            case 3:
            case 5:
                if (((GameObject*)obj)->anim.localPosY < 5.0f + buf.lineStartY &&
                    ((GameObject*)obj)->anim.localPosY < 5.0f + buf.lineEndY)
                {
                    hit = 0;
                }
                break;
            case 2:
            case 4:
            case 6:
                if ((((PlayerState*)state)->flags3F1.b01) != 0)
                {
                    if (dp > -0.8f || (((GameObject*)obj)->anim.localPosY > buf.upperY0 - 10.0f &&
                                              ((GameObject*)obj)->anim.localPosY > buf.upperY1 - 10.0f))
                    {
                        hit = 0;
                    }
                }
                else
                {
                    if (dp > -0.5f)
                    {
                        hit = 0;
                    }
                }
                break;
            case 0:
            case 10:
                break;
            default:
                if (dp > -0.8f)
                {
                    hit = 0;
                }
            }
        }
        if (flagB != 0 && hit != 0)
        {
            if (useAlt == 0)
            {
                start[0] = ((GameObject*)obj)->anim.localPosX;
                start[1] = ((GameObject*)obj)->anim.localPosY;
                start[2] = ((GameObject*)obj)->anim.localPosZ;
                end[0] = -(50.0f * buf.normalX - ((GameObject*)obj)->anim.localPosX);
                end[1] = ((GameObject*)obj)->anim.localPosY;
                end[2] = -(50.0f * buf.normalZ - ((GameObject*)obj)->anim.localPosZ);
            }
            else
            {
                start[0] = 50.0f * buf.normalX + ((GameObject*)obj)->anim.localPosX;
                start[1] = ((GameObject*)obj)->anim.localPosY;
                start[2] = 50.0f * buf.normalZ + ((GameObject*)obj)->anim.localPosZ;
                end[0] = ((GameObject*)obj)->anim.localPosX;
                end[1] = ((GameObject*)obj)->anim.localPosY;
                end[2] = ((GameObject*)obj)->anim.localPosZ;
            }
            hit = trackGetLineIntersect(start, end, 0.0f, 3, &buf, (GameObject*)obj, 1,
                                    dirs[i], 0xff, 10);
        }
        if (hit == 0)
        {
            continue;
        }
        hd = buf.distance;
        if (useAlt != 0)
        {
            hd = 50.0f - hd;
        }
        switch (i)
        {
        case 0:
        {
            GameObject* target = buf.object;
            if (target == NULL)
            {
                continue;
            }
            if (PUSHABLE_INTERFACE(target)->isRestored(target) != 0 &&
                ((PlayerState*)state2)->baddie.inputMagnitude > 0.1f && hd <= 2.0f + lbl_803DC6C0)
            {
                switch (playerBuildLedgeClimbProbe(obj, state, &buf, state + 0x5a8, end, hd))
                {
                case 2:
                    return 4;
                case 3:
                    return 5;
                }
            }
            if (!(hd < 20.0f))
            {
                continue;
            }
            if (target->anim.resetHitboxFlags & 8)
            {
                continue;
            }
            ((PlayerState*)state)->flags360 |= (u32)PLAYER_FLAG_LEDGE_DETECTED;
            if ((((PlayerState*)state2)->baddie.pressedButtons & 0x100) == 0)
            {
                continue;
            }
            ((PlayerState*)state)->surfaceNormalX = buf.normalX;
            ((PlayerState*)state)->surfaceNormalY = buf.normalY;
            ((PlayerState*)state)->surfaceNormalZ = buf.normalZ;
            ((PlayerState*)state)->surfaceNormalW = buf.sourceNormalW;
            *(u8*)&((PlayerState*)state)->stickEdgeLatch = 0;
            if (buf.object != NULL)
            {
                Obj_TransformWorldPointToLocal(end[0], end[1], end[2], &((PlayerState*)state)->contactPointX,
                                               &((PlayerState*)state)->contactPointY,
                                               &((PlayerState*)state)->contactPointZ, buf.object);
                ((PlayerState*)state)->contactObject = (GameObject*)buf.object;
            }
            else
            {
                ((PlayerState*)state)->contactPointX = end[0];
                ((PlayerState*)state)->contactPointY = end[1];
                ((PlayerState*)state)->contactPointZ = end[2];
                ((PlayerState*)state)->contactObject = 0;
            }
            return 6;
        }
        case 10:
            if (!(hd < 18.0f))
            {
                continue;
            }
            if ((((PlayerState*)state2)->baddie.pressedButtons & 0x100) == 0)
            {
                continue;
            }
            ((PlayerState*)state)->surfaceNormalX = buf.normalX;
            ((PlayerState*)state)->surfaceNormalY = buf.normalY;
            ((PlayerState*)state)->surfaceNormalZ = buf.normalZ;
            ((PlayerState*)state)->surfaceNormalW = buf.sourceNormalW;
            *(u8*)&((PlayerState*)state)->stickEdgeLatch = 0;
            if (buf.object != NULL)
            {
                Obj_TransformWorldPointToLocal(end[0], end[1], end[2], &((PlayerState*)state)->contactPointX,
                                               &((PlayerState*)state)->contactPointY,
                                               &((PlayerState*)state)->contactPointZ, buf.object);
                ((PlayerState*)state)->contactObject = (GameObject*)buf.object;
            }
            else
            {
                ((PlayerState*)state)->contactPointX = end[0];
                ((PlayerState*)state)->contactPointY = end[1];
                ((PlayerState*)state)->contactPointZ = end[2];
                ((PlayerState*)state)->contactObject = 0;
            }
            return 0xd;
        case 3:
        case 4:
            if (!(hd <= 15.0f))
            {
                continue;
            }
            if (player_probeClimbable((GameObject*)obj, state, &buf, state + 0x4e4, i == 3) == 0)
            {
                continue;
            }
            return 0;
        case 5:
        case 6:
            if (!(hd <= 1.0f + lbl_803DC6C0))
            {
                continue;
            }
            if (playerBuildWallPlaneProbe(obj, state, &buf, end, state + 0x548, i == 5) == 0)
            {
                continue;
            }
            return 9;
        case 1:
        case 7:
        case 12:
            if (!(hd < 15.0f))
            {
                continue;
            }
            switch (playerBuildWallTransitionProbe((GameObject*)obj, (char*)&buf, (f32*)(state + 0x5a8), end, hd, fv))
            {
            case 4:
                return 8;
            case 5:
                return 7;
            }
            break;
        case 2:
        case 9:
            if (!(hd <= 1.0f + lbl_803DC6C0))
            {
                continue;
            }
            switch (playerBuildLedgeClimbProbe(obj, state, &buf, state + 0x5a8, end, hd))
            {
            case 2:
                return 4;
            case 3:
                return 5;
            case 6:
                return 0xc;
            }
            break;
        case 8:
        {
            s8 ok2;
            int t8;
            if (!(hd <= 1.0f + lbl_803DC6C0))
            {
                continue;
            }
            nearDist = 50.0f;
            t8 = (int)objGetNearestTypeTo(WALL_ANIMATOR_GROUP_CLIMBABLE, (GameObject*)obj, &nearDist);
            ok2 = 1;
            if ((u32)t8 != 0)
            {
                if (WALL_ANIMATOR_INTERFACE(t8)->isComplete((GameObject*)t8) == 0)
                {
                    ok2 = 0;
                }
            }
            if (ok2 == 0)
            {
                continue;
            }
            ((PlayerState*)state)->hitNormalX = buf.normalX;
            ((PlayerState*)state)->hitNormalY = buf.normalY;
            ((PlayerState*)state)->hitNormalZ = buf.normalZ;
            ((PlayerState*)state)->hitNormalW = buf.normalW;
            return 0xb;
        }
        case 11:
            if (!(hd < 14.0f))
            {
                continue;
            }
            if (buf.kind == 0xd)
            {
                if (!(((PlayerState*)state2)->baddie.animSpeedA > 1.2530199f))
                {
                    continue;
                }
                if (((PlayerState*)state)->particleBurstCooldown <= 0.0f)
                {
                    for (k = 0; k < 0x4b; k++)
                    {
                        lo = buf.lineStartX;
                        pfx.x = lo + (buf.lineEndX - lo) * (f32)randomGetRange(0, 100) / 100.0f;
                        lo = buf.lineStartY;
                        pfx.y = lo + (buf.upperY0 - lo) * (f32)randomGetRange(0, 100) / 100.0f;
                        lo = buf.lineStartZ;
                        pfx.z = lo + (buf.lineEndZ - lo) * (f32)randomGetRange(0, 100) / 100.0f;
                        pfx.scale = 1.0f;
                        pfx.mode = 0x3c;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x804, &pfx, 0x200001, -1, NULL);
                    }
                    ((PlayerState*)state)->particleBurstCooldown = 30.0f;
                }
            }
            else
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, &pfx.x, &pfx.y, &pfx.z, 0);
                ObjHits_RecordPositionHit((GameObject*)obj, NULL, 8, 1, -1, pfx.x, pfx.y, pfx.z);
            }
            break;
        }
    }
    if ((((PlayerState*)state2)->baddie.pressedButtons & 0x100) != 0 && (probeMask & 0x200) != 0)
    {
        int* focusCandidates;
        int* focusCandidateList;
        int candidateIndex;

        focusCandidateList = (int*)objGetAllOfType(10, &focusCandidateCount);
        candidateIndex = 0;
        focusCandidates = focusCandidateList;
        for (; candidateIndex < focusCandidateCount; candidateIndex++)
        {
            int candidate = *focusCandidates;
            if (VEHICLE_INTERFACE(candidate)->canMount((GameObject*)candidate, (GameObject*)obj) != 0)
            {
                ((PlayerState*)state)->focusObject = (GameObject*)candidate;
                return 0xa;
            }
            focusCandidates++;
        }
    }
    return -1;
}

void playerGetMovementOrFacingDirection(GameObject* obj, int state, f32* out)
{
    f32 mag;
    u32 flag = ((PlayerState*)state)->flags3F1.b20;

    if (flag != 0 || ((PlayerState*)state)->baddie.targetObj != NULL)
    {
        out[0] = obj->anim.velocityX;
        out[1] = 0.0f;
        out[2] = obj->anim.velocityZ;
        mag = PSVECMag((Vec*)out);
        if (mag > 0.0f)
        {
            mag = 1.0f / mag;
            PSVECScale((Vec*)out, (Vec*)out, mag);
        }
        else
        {
            out[0] = -mathSinf(3.1415927f * (f32)((PlayerState*)state)->targetYaw / 32768.0f);
            out[1] = 0.0f;
            out[2] = -mathCosf(3.1415927f * (f32)((PlayerState*)state)->targetYaw / 32768.0f);
        }
    }
    else
    {
        out[0] = -mathSinf(3.1415927f * (f32)((PlayerState*)state)->targetYaw / 32768.0f);
        out[1] = 0.0f;
        out[2] = -mathCosf(3.1415927f * (f32)((PlayerState*)state)->targetYaw / 32768.0f);
    }
}

/*
 * Probe for a climbable map surface (a HITQUERY_CLIMB_SURFACE collision hit) and,
 * if one is found near the player, seed the climb state at `dst` (PlayerState's
 * climb block: climbStepCount = surface height / step size, climbStepHeight,
 * climbStep) and return 1; return 0 when no ladder is in range. Called per
 * candidate direction from the player move handler.
 */
int player_probeClimbable(GameObject* obj, int p4, TrackLineIntersectResult* src, int dst, int flag)
{
    TrackGroundHit** hits;
    f32 pos[3];
    f32 y;
    f32 minDist;
    int best;
    int i;
    int count;
    TrackGroundHit* chosen;
    f32 zero;

    *(u8*)((char*)dst + 3) = 0;
    ((ByteFlags*)((char*)dst + 0x63))->b80 = 1;
    if ((*(s8*)((char*)src + 0x52) & 0x08) == 0)
    {
        ((ByteFlags*)((char*)dst + 0x63))->b80 = 0;
    }

    {
        f32 s4 = src->lineStartX;
        f32 t = 0.5f;
        *(f32*)((char*)dst + 0x48) = s4 + t * (src->lineEndX - s4);
        *(f32*)((char*)dst + 0x4c) = src->lineStartY;
        *(f32*)((char*)dst + 0x50) = src->lineStartZ + t * (src->lineEndZ - src->lineStartZ);
    }

    if (flag != 0)
    {
        *(f32*)((char*)dst + 0x28) = -src->normalX;
        *(f32*)((char*)dst + 0x2c) = -src->normalY;
        *(f32*)((char*)dst + 0x30) = -src->normalZ;
        *(f32*)((char*)dst + 0x34) = -src->normalW;
    }
    else
    {
        *(f32*)((char*)dst + 0x28) = src->normalX;
        *(f32*)((char*)dst + 0x2c) = src->normalY;
        *(f32*)((char*)dst + 0x30) = src->normalZ;
        *(f32*)((char*)dst + 0x34) = src->normalW;
    }

    *(f32*)((char*)dst + 0x38) = -src->normalZ;
    *(f32*)((char*)dst + 0x3c) = zero = 0.0f;
    *(f32*)((char*)dst + 0x40) = src->normalX;
    *(f32*)((char*)dst + 0x44) = -(*(f32*)((char*)dst + 0x48) * *(f32*)((char*)dst + 0x38) +
                                   *(f32*)((char*)dst + 0x4c) * *(f32*)((char*)dst + 0x3c) +
                                   *(f32*)((char*)dst + 0x50) * *(f32*)((char*)dst + 0x40));

    *(f32*)((char*)dst + 0x54) = ((PlayerState*)p4)->savedPosX;
    *(f32*)((char*)dst + 0x58) = zero;
    *(f32*)((char*)dst + 0x5c) = ((PlayerState*)p4)->savedPosZ;
    *(f32*)((char*)dst + 0x18) = *(f32*)((char*)dst + 0x54) * *(f32*)((char*)dst + 0x38) +
                                 *(f32*)((char*)dst + 0x58) * *(f32*)((char*)dst + 0x3c) +
                                 *(f32*)((char*)dst + 0x5c) * *(f32*)((char*)dst + 0x40) + *(f32*)((char*)dst + 0x44);

    *(s8*)((char*)dst + 0x62) = (s8)(int)*(s8*)((char*)src + 0x53);

    if (*(f32*)((char*)dst + 0x18) > -9.0f && *(f32*)((char*)dst + 0x18) < 9.0f)
    {
        *(f32*)((char*)dst + 0x8) = src->lineStartY;
        PSVECScale((Vec*)&src->normalX, (Vec*)pos, -lbl_803DC6B8[1]);
        PSVECAdd((Vec*)(dst + 0x48), (Vec*)pos, (Vec*)pos);
        y = src->upperY0;
        pos[1] = y;
        count = trackGetHeight(obj, pos[0], y, pos[2], &hits, 0, HITQUERY_CLIMB_SURFACE);

        minDist = 10000.0f;
        best = -1;
        for (i = 0; i < count; i++)
        {
            TrackGroundHit* entry = hits[i];
            if (entry->normalY > 0.707f)
            {
                f32 d = pos[1] - entry->height;
                if (d < 0.0f)
                {
                    d = -d;
                }
                if (d < minDist)
                {
                    minDist = d;
                    best = i;
                }
            }
        }

        chosen = hits[best];
        *(f32*)((char*)dst + 0x4) = chosen->height;
        *(s8*)((char*)dst + 0x1) = (s8)(s32)((2.2f + (src->upperY0 - *(f32*)((char*)dst + 0x8))) / 8.8f);
        *(f32*)((char*)dst + 0xc) = (src->upperY0 - *(f32*)((char*)dst + 0x8)) / (f32) * (s8*)((char*)dst + 0x1);

        if (obj->anim.localPosY > *(f32*)((char*)dst + 0x4) - 10.0f)
        {
            *(s8*)((char*)dst + 0x0) = *(u8*)((char*)dst + 0x1) - 3;
        }
        else
        {
            *(s8*)((char*)dst + 0x0) = 1;
        }
        return 1;
    }
    return 0;
}

int playerBuildWallPlaneProbe(int p1, int p2, TrackLineIntersectResult* src, f32* vec, int out, int flag)
{
    f32 p48;
    f32 m44;
    f32 d1;
    f32 m4c;
    f32 nx;
    f32 ny;
    f32 d2;
    f32 c38;
    *(f32*)((char*)out + 0x44) = *(f32*)((char*)vec + 0x0);
    *(f32*)((char*)out + 0x48) = src->lineStartY;
    *(f32*)((char*)out + 0x4c) = *(f32*)((char*)vec + 0x8);
    *(f32*)((char*)out + 0x50) = ((PlayerState*)p2)->savedPosX;
    *(f32*)((char*)out + 0x54) = 0.0f;
    *(f32*)((char*)out + 0x58) = ((PlayerState*)p2)->savedPosZ;
    if (flag != 0)
    {
        *(u8*)((char*)out + 0x1) = 1;
    }
    else
    {
        *(u8*)((char*)out + 0x1) = 0;
    }
    *(f32*)((char*)out + 0x24) = src->normalX;
    *(f32*)((char*)out + 0x28) = src->normalY;
    *(f32*)((char*)out + 0x2c) = src->normalZ;
    *(f32*)((char*)out + 0x30) = src->normalW;
    *(f32*)((char*)out + 0x34) = -src->normalZ;
    c38 = 0.0f;
    *(f32*)((char*)out + 0x38) = c38;
    *(f32*)((char*)out + 0x3c) = src->normalX;
    *(f32*)((char*)out + 0x40) = -(*(f32*)((char*)out + 0x44) * *(f32*)((char*)out + 0x34) +
                                   *(f32*)((char*)out + 0x48) * *(f32*)((char*)out + 0x38) +
                                   *(f32*)((char*)out + 0x4c) * *(f32*)((char*)out + 0x3c));
    nx = -*(f32*)((char*)out + 0x2c);
    ny = *(f32*)((char*)out + 0x24);
    d1 = -(nx * src->lineStartX + ny * src->lineStartZ) +
         (ny * (m4c = *(f32*)((char*)out + 0x4c)) +
          (nx * (m44 = *(f32*)((char*)out + 0x44)) + (p48 = c38 * *(f32*)((char*)out + 0x48))));
    nx = -nx;
    ny = -ny;
    d2 = -(nx * src->lineEndX + ny * src->lineEndZ) + (ny * m4c + (nx * m44 + p48));
    if (d1 > 7.5f && d2 > 7.5f)
    {
        *(f32*)((char*)out + 0x8) = src->lineStartY;
        *(f32*)((char*)out + 0x4) = src->upperY0;
        *(s8*)((char*)out + 0x2) = (int)*(s8*)((char*)src + 0x53);
        return 1;
    }
    return 0;
}

int playerBuildWallTransitionProbe(GameObject* obj, char* cam, f32* out, f32* vec, f32 fa, f32 fb)
{
    f32* dp;
    char* cp;
    f32* px2;
    f32* py2;
    f32* pz2;
    PlayerState* inner;
    f32* b6b8;
    s8 mode;
    int wallHit;
    int tris;
    int verts;
    ObjAnimComponent* parent;
    f32* pl;

    f32 x2;
    f32 x1;
    f32 z2;
    f32 z1;
    f32 y2;
    f32 y1;
    TrackGroundHit** list;
    f32 planes[8];
    struct
    {
        f32 x;
        f32 y;
        f32 z;
    } probe;
    f32 dists[2];

    mode = 0;
    inner = obj->extra;
    if (fa <= inner->baddie.animSpeedA * fb || fa <= 3.5f)
    {
        s8 st = *(s8*)(cam + 0x50);
        if (st == 2 || st == 0x11)
        {
            mode = 4;
        }
        else if (inner->baddie.animSpeedA >= 1.2530199f)
        {
            mode = 5;
        }
        else if (st != 4)
        {
            mode = 4;
        }
    }
    out[7] = ((GameObject*)cam)->anim.worldPosY;
    out[8] = ((GameObject*)cam)->anim.worldPosZ;
    out[9] = ((GameObject*)cam)->anim.velocityX;
    out[7] = -out[7];
    out[8] = -out[8];
    out[9] = -out[9];
    out[10] = -((GameObject*)cam)->anim.velocityY;
    out[0xb] = vec[0];
    out[0xc] = vec[1];
    out[0xd] = vec[2];
    parent = *(void**)cam;
    if (mode == 4)
    {
        f32 thresh;
        int i;
        int j;
        wallHit = 0;
        if (parent != NULL)
        {
            tris = (int)parent->modelInstance->intersectionLines;
            verts = (int)parent->modelInstance->intersectionPoints;
        }
        else
        {
            tris = gIntersectLinePool;
            verts = (int)gIntersectPoints;
        }
        planes[0] = out[9];
        planes[1] = 0.0f;
        planes[2] = -out[7];
        planes[3] = -(planes[0] * *(f32*)(cam + 0x4) + planes[2] * ((GameObject*)cam)->anim.localPosZ);
        planes[4] = -planes[0];
        planes[5] = 0.0f;
        planes[6] = -planes[2];
        planes[7] =
            -(planes[4] * ((GameObject*)cam)->anim.rootMotionScale + planes[6] * ((GameObject*)cam)->anim.worldPosX);
        i = 0;
        pl = planes;
        dp = dists;
        cp = cam;
        b6b8 = lbl_803DC6B8;
        px2 = &x2;
        py2 = &y2;
        pz2 = &z2;
        thresh = 0.5f;
        do
        {
            f32 dot = PSVECDotProduct((Vec*)pl, (Vec*)vec);
            *dp = pl[3] + dot;
            if (*dp < thresh + b6b8[1])
            {
                int tri;
                if (*(s16*)(cp + 0x4c) > -1)
                {
                    tri = tris + *(s16*)(cp + 0x4c) * 0x10;
                }
                else
                {
                    tri = 0;
                }
                if ((void*)tri != NULL && ((*(s8*)(tri + 3) & 0x3f) == 5 || (*(s8*)(tri + 3) & 0x3f) == 2))
                {
                    j = *(s16*)(tri + 4);
                    x1 = *(f32*)(verts + j * 12);
                    y1 = 0.0f;
                    z1 = ((f32*)verts)[j * 3 + 2];
                    j = *(s16*)(tri + 6);
                    x2 = *(f32*)(verts + j * 12);
                    y2 = 0.0f;
                    z2 = ((f32*)verts)[j * 3 + 2];
                    if (parent != NULL)
                    {
                        Obj_TransformLocalPointToWorld(x1, y1, z1, &x1, &y1, &z1, (void*)parent);
                        Obj_TransformLocalPointToWorld(x2, y2, z2, px2, py2, pz2, (void*)parent);
                    }
                    {
                        f32 dz = z2 - z1;
                        f32 dx = x1 - x2;
                        f32 inv = 1.0f / sqrtf(dz * dz + dx * dx);
                        dz = dz * inv;
                        dx = dx * inv;
                        if (dz * out[7] + dx * out[9] < 0.5f)
                        {
                            wallHit = 1;
                        }
                    }
                }
                else
                {
                    wallHit = 1;
                }
            }
            pl += 4;
            dp++;
            cp += 2;
            i++;
        } while (i < 2);
        if (dists[0] < dists[1])
        {
            *(u8*)((char*)out + 0x5f) = 0;
        }
        else
        {
            *(u8*)((char*)out + 0x5f) = 1;
        }
        if (wallHit != 0)
        {
            out[0xb] = out[0xb] + ((0.5f + b6b8[1]) - dists[*(u8*)((char*)out + 0x5f)]) *
                                      planes[(u32) * (u8*)((char*)out + 0x5f) * 4];
            out[0xd] = out[0xd] + ((0.5f + b6b8[1]) - dists[*(u8*)((char*)out + 0x5f)]) *
                                      planes[(u32) * (u8*)((char*)out + 0x5f) * 4 + 2];
        }
        out[0x11] = -(out[7] * (0.5f + lbl_803DC6C0) - out[0xb]);
        out[0x13] = -(out[9] * (0.5f + lbl_803DC6C0) - out[0xd]);
        {
            f32 f = 5.0f;
            out[0x14] = f * out[7] + out[0xb];
            out[0x16] = f * out[9] + out[0xd];
        }
        out[1] = ((GameObject*)cam)->anim.localPosX +
                 *(f32*)(cam + 0x48) * (((GameObject*)cam)->anim.localPosY - ((GameObject*)cam)->anim.localPosX);
        probe.x = out[0x14];
        probe.y = out[1];
        probe.z = out[0x16];
        Obj_TransformLocalPointToWorld(probe.x, probe.y, probe.z, &probe.x, &probe.y, &probe.z,
                                       obj->anim.parent);
        {
            int cnt = trackGetHeight(obj, probe.x, probe.y, probe.z, &list, 0, 0x201);
            if (cnt != 0)
            {
                TrackGroundHit** pp;
                f32 best = 10000.0f;
                f32 dy;
                f32 best2 = best;
                int bi = -1;
                int i2 = 0;
                pp = list;
                for (; cnt > 0; cnt--)
                {
                    dy = probe.y - (*pp)->height;
                    if (dy >= 0.0f && (best < 0.0f || dy < best))
                    {
                        best = dy;
                        bi = i2;
                    }
                    if ((*pp)->normalY > 0.707f && dy >= 0.0f && (best2 < 0.0f || dy < best2))
                    {
                        best2 = dy;
                    }
                    pp++;
                    i2++;
                }
                if (best < 40.0f && bi != -1 && list[bi]->normalY <= 0.707f && list[bi]->normalY > 0.175f)
                {
                    return 0;
                }
                if (best2 < 40.0f)
                {
                    return 0;
                }
            }
        }
        probe.x = out[0x11];
        probe.y = out[1];
        probe.z = out[0x13];
        Obj_TransformLocalPointToWorld(probe.x, probe.y, probe.z, &probe.x, &probe.y, &probe.z,
                                       obj->anim.parent);
        if (trackGetNearestGroundOffset(obj, probe.x, probe.y, probe.z, out + 0x12, 0x205) == 0)
        {
            out[0x12] = out[1] - out[0x12];
        }
        else
        {
            out[0x12] = out[1];
        }
        out[2] = ((GameObject*)cam)->anim.localPosX;
        out[0] = out[1] - out[2];
        *(u8*)((char*)out + 0x5e) = *(u8*)(cam + 0x50);
        *(u8*)((char*)out + 0x60) = *(u8*)(cam + 0x53);
        if (obj->anim.parent != NULL)
        {
            Obj_TransformLocalPointToWorld(out[0xb], out[0xc], out[0xd], out + 0xb, out + 0xc, out + 0xd,
                                           obj->anim.parent);
            Obj_TransformLocalPointToWorld(out[0x11], out[0x12], out[0x13], out + 0x11, out + 0x12,
                                           out + 0x13, obj->anim.parent);
            Obj_TransformLocalPointToWorld(out[0x14], out[0x15], out[0x16], out + 0x14, out + 0x15,
                                           out + 0x16, obj->anim.parent);
            inner->leapTargetY =
                inner->leapTargetY + *(f32*)((char*)obj->anim.parent + 0x10);
            inner->leapBaseY =
                inner->leapBaseY + *(f32*)((char*)obj->anim.parent + 0x10);
        }
        *(u8*)((char*)out + 0x61) = 1;
        if (parent != NULL && (parent->modelInstance->flags & 0x8000) == 0)
        {
            inner->groundObject = (void*)parent;
        }
        else
        {
            inner->groundObject = NULL;
        }
    }
    else
    {
        inner->groundObject = NULL;
    }
    return mode;
}

int playerBuildLedgeClimbProbe(int a, int b, void* c, int d, f32* e, f32 distance)
{
    char* cp;
    f32* b6b8;
    f32* pbx;
    f32* pby;
    f32* pbz;
    int tbl1, tbl2;
    EmitPlane* pl;
    ObjAnimComponent* hit;
    int i;
    int j;
    f32 bx, ax, bz, az, by, ay;
    f32 threshold;
    EmitPlane planes[2];

    ((PlayerState*)b)->groundObject = NULL;
    *(f32*)((char*)d + 0x1c) = *(f32*)((char*)c + 0x1c);
    *(f32*)((char*)d + 0x20) = *(f32*)((char*)c + 0x20);
    *(f32*)((char*)d + 0x24) = *(f32*)((char*)c + 0x24);
    *(f32*)((char*)d + 0x28) = *(f32*)((char*)c + 0x28);
    *(u8*)((char*)d + 0x60) = *(u8*)((char*)c + 0x53);
    hit = *(void**)((char*)c + 0x0);
    if (hit != NULL)
    {
        tbl1 = (int)hit->modelInstance->intersectionLines;
        tbl2 = (int)hit->modelInstance->intersectionPoints;
    }
    else
    {
        tbl1 = gIntersectLinePool;
        tbl2 = (int)gIntersectPoints;
    }
    planes[0].nx = -*(f32*)((char*)d + 0x24);
    planes[0].ny = 0.0f;
    planes[0].nz = *(f32*)((char*)d + 0x1c);
    planes[0].d = -(planes[0].nx * *(f32*)((char*)c + 0x4) + planes[0].nz * *(f32*)((char*)c + 0x14));
    planes[1].nx = -planes[0].nx;
    planes[1].ny = 0.0f;
    planes[1].nz = -planes[0].nz;
    planes[1].d = -(planes[1].nx * *(f32*)((char*)c + 0x8) + planes[1].nz * *(f32*)((char*)c + 0x18));
    i = 0;
    pl = planes;
    cp = (char*)c;
    b6b8 = lbl_803DC6B8;
    pbx = &bx;
    pby = &by;
    pbz = &bz;
    threshold = 0.5f;
    do
    {
        f32 dot = PSVECDotProduct((Vec*)pl, (Vec*)e);
        if (pl->d + dot < threshold + b6b8[1])
        {
            void* face;
            if (*(s16*)(cp + 0x4c) > -1)
            {
                face = (void*)(tbl1 + *(s16*)(cp + 0x4c) * 0x10);
            }
            else
            {
                face = NULL;
            }
            if (face != NULL &&
                (((s8) * (s8*)((char*)face + 0x3) & 0x3f) == 6 || ((s8) * (s8*)((char*)face + 0x3) & 0x3f) == 0x10))
            {
                j = *(s16*)((char*)face + 0x4);
                ax = *(f32*)(tbl2 + j * 12);
                ay = 0.0f;
                az = ((f32*)tbl2)[j * 3 + 2];
                j = *(s16*)((char*)face + 0x6);
                bx = *(f32*)(tbl2 + j * 12);
                by = 0.0f;
                bz = ((f32*)tbl2)[j * 3 + 2];
                if (hit != NULL)
                {
                    Obj_TransformLocalPointToWorld(ax, ay, az, &ax, &ay, &az, (GameObject*)(int)hit);
                    Obj_TransformLocalPointToWorld(bx, by, bz, pbx, pby, pbz, (GameObject*)(int)hit);
                }
                {
                    f32 dz = bz - az;
                    f32 dx = ax - bx;
                    f32 scale = 1.0f / sqrtf(dz * dz + dx * dx);
                    dz = dz * scale;
                    dx = dx * scale;
                    if (dz * *(f32*)((char*)d + 0x1c) + dx * *(f32*)((char*)d + 0x24) < 0.5f)
                    {
                        return 0;
                    }
                }
            }
            else
            {
                return 0;
            }
        }
        pl++;
        cp += 2;
        i++;
    } while (i < 2);
    *(f32*)((char*)d + 0x2c) = *(f32*)((char*)e + 0x0);
    *(f32*)((char*)d + 0x30) = *(f32*)((char*)e + 0x4);
    *(f32*)((char*)d + 0x34) = *(f32*)((char*)e + 0x8);
    {
        f32 e2;
        f32 e3;
        *(f32*)((char*)d + 0x44) =
            -(*(f32*)((char*)d + 0x1c) * ((e2 = 0.5f) + (e3 = lbl_803DC6C0)) - *(f32*)((char*)d + 0x2c));
        *(f32*)((char*)d + 0x4c) = -(*(f32*)((char*)d + 0x24) * (e2 + lbl_803DC6C0) - *(f32*)((char*)d + 0x34));
    }
    {
        f32 f = 5.0f;
        *(f32*)((char*)d + 0x50) = f * *(f32*)((char*)d + 0x1c) + *(f32*)((char*)d + 0x2c);
        *(f32*)((char*)d + 0x58) = f * *(f32*)((char*)d + 0x24) + *(f32*)((char*)d + 0x34);
    }
    *(f32*)((char*)d + 0x38) = ((PlayerState*)b)->savedPosX;
    *(f32*)((char*)d + 0x3c) = 0.0f;
    *(f32*)((char*)d + 0x40) = ((PlayerState*)b)->savedPosZ;
    *(f32*)((char*)d + 0x4) =
        *(f32*)((char*)c + 0x48) * (*(f32*)((char*)c + 0x40) - *(f32*)((char*)c + 0x3c)) + *(f32*)((char*)c + 0x3c);
    *(u8*)((char*)d + 0x5e) = *(u8*)((char*)c + 0x50);
    *(u8*)((char*)d + 0x61) = 1;
    if (trackGetNearestGroundOffset((GameObject*)a, *(f32*)((char*)d + 0x44), *(f32*)((char*)d + 0x4),
                             *(f32*)((char*)d + 0x4c), (f32*)((char*)d + 0x48), 0x205) == 0)
    {
        *(f32*)(d + 0x48) = *(f32*)((char*)d + 0x4) - *(f32*)(d + 0x48);
    }
    else
    {
        return 0;
    }
    if ((s8) * (s8*)((char*)c + 0x50) != 0x10)
    {
        *(f32*)((char*)d + 0x8) = ((GameObject*)a)->anim.previousLocalPosY;
        *(f32*)((char*)d + 0x0) = *(f32*)((char*)d + 0x4) - *(f32*)((char*)d + 0x8);
        if ((((PlayerState*)b)->flags3F1.b01) != 0u)
        {
            if (hit != NULL && (hit->modelInstance->flags & 0x8000) == 0)
            {
                ((PlayerState*)b)->groundObject = (GameObject*)hit;
            }
            if (*(f32*)((char*)d + 0x0) <= 64.0f)
            {
                if (*(f32*)((char*)d + 0x0) > 40.0f)
                {
                    return 2;
                }
            }
            if (*(f32*)((char*)d + 0x0) <= 40.0f && *(f32*)((char*)d + 0x0) >= 8.0f)
            {
                return 3;
            }
        }
        else
        {
            f32 q;
            q = *(f32*)((char*)c + 0x48) * (*(f32*)((char*)c + 0x10) - *(f32*)((char*)c + 0xc)) +
                *(f32*)((char*)c + 0xc);
            q = *(f32*)((char*)d + 0x4) - q;
            if (*(f32*)((char*)d + 0x0) >= 10.0f && *(f32*)((char*)d + 0x0) <= 60.0f && q >= 40.0f)
            {
                if (hit != NULL && (hit->modelInstance->flags & 0x8000) == 0)
                {
                    ((PlayerState*)b)->groundObject = (GameObject*)hit;
                }
                return 6;
            }
        }
    }
    else
    {
        *(f32*)((char*)d + 0x8) = ((GameObject*)a)->anim.localPosY;
        *(f32*)((char*)d + 0x0) = *(f32*)((char*)d + 0x4) - *(f32*)((char*)d + 0x8);
        if (*(f32*)((char*)d + 0x0) >= 34.0f)
        {
            return 0;
        }
        if (hit != NULL && (hit->modelInstance->flags & 0x8000) == 0)
        {
            ((PlayerState*)b)->groundObject = (GameObject*)hit;
        }
        return 3;
    }
    return 0;
}

void playerRestoreAfterSequence(GameObject* obj, int p2, void* p3)
{
    PlayerState* inner = obj->extra;
    f32 dist;
    void* found;
    s16* vec;
    ObjTextureRuntimeSlot* tex;
    dist = 1000.0f;
    obj->anim.rootMotionScale = 1.0f;
    viewFinderSetZoom(Camera_GetFovY());
    obj->objectFlags &= ~OBJECT_OBJFLAG_PARENT_SLACK;
    obj->anim.alpha = 0xff;
    inner->flags3F2.b80 = 0;
    if (inner->flags3F2.b40)
    {
        inner->targetSuppressTimer = 60.0f;
    }
    inner->flags3F2.b40 = 0;
    inner->flags3F2.b20 = 0;
    inner->flags3F4.b80 = 0;
    ObjHits_EnableObject(obj);
    obj->anim.velocityY = 0.0f;
    if ((*(s16*)((char*)p3 + 0x6e) & 1) != 0)
    {
        playerRefreshCollisionState(obj, (int)inner, 7);
    }
    ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 1);
    inner->timeScaleMode = 2;
    if (gPlayerChildObject != NULL)
    {
        found = (void*)objGetNearestTypeTo(BABYCLOUDRUNNER_OBJGROUP, obj, &dist);
        if (found != NULL)
        {
            BABY_CLOUD_RUNNER_INTERFACE(found)->tryCapture(found);
        }
        ObjLink_DetachChild(obj, (GameObject*)gPlayerChildObject);
        Obj_FreeObject((GameObject*)gPlayerChildObject);
        gPlayerChildObject = NULL;
    }
    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
    inner->interactObject = NULL;
    inner->flags3F0.b10 = 0;
    inner->flags3F0.b08 = 0;
    inner->flags3F0.b04 = 0;
    inner->staffHoldFrames = 0;
    inner->flags3F0.b80 = 0;
    inner->flags3F0.b40 = 0;
    inner->flags3F0.b20 = 0;
    inner->animState = -1;
    inner->flags3F6.b40 = 0;
    Shield_setMode(gPlayerStaffObject, 2);
    inner->flags3F0.b02 = 0;
    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
    ObjHits_SyncObjectPositionIfDirty(obj);
    inner->waterDepth = 0.0f;
    inner->waterSurfaceY = -100000.0f;
    inner->idleDelayTimer = 20.0f;
    inner->baddie.physicsActive = 1;
    inner->baddie.flags4 &= ~0x100000;
    inner->baddie.flags4 |= 0x8000000;
    if (((PlayerState*)obj->extra)->playerStatus->health <= 0) {
        (*gPlayerInterface)->setState(obj, inner, 3);
        inner->baddie.stateExitFn = NULL;
    }
    vec = objFindJointPoseVector(obj, 1);
    if (vec != NULL) {
        vec[0] = 0;
        vec[1] = 0;
        vec[2] = 0;
    }
    ObjModel_ClearBlendChannels(Obj_GetActiveModel(obj));
    tex = objFindTexture(obj, 1, 0);
    tex->offsetS = 0;
    tex->offsetT = 0;
    tex = objFindTexture(obj, 0, 0);
    tex->offsetS = 0;
    tex->offsetT = 0;
}

void playerCastIceSpell(GameObject* unused) {
    ObjPlacement* setup;
    s8 i;

    if ((u8)Obj_CanSetupObject() == 0) {
        return;
    }
    for (i = 0; i < 7; i++) {
        if (gPlayerSpawnedObjects[i] == NULL) {
            setup = Obj_AllocObjectSetup(0x24, 0x4ec);
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, &setup->posX, &setup->posY, &setup->posZ, 0);
            setup->color[0] = 2;
            setup->color[1] = 1;
            setup->color[2] = 0xff;
            setup->color[3] = 0xff;
            ((IceblastPlacement*)setup)->initialLaunchTimer = (s16)(i * 3);
            ((IceblastPlacement*)setup)->unk1C = 0;
            gPlayerSpawnedObjects[i] = objSetupObject(setup, 5, -1, -1, NULL);
        }
    }
}

int playerCanUseStaffBooster(GameObject* obj, PlayerState* p2)
{
    PlayerState* inner = obj->extra;
    GameObject* slot;
    u8 af;
    u8 c;
    s16 sel = ((PlayerState*)p2)->baddie.controlMode;

    if (!((sel != 1 && sel != 2 && sel != 0x26) || !mainGetBit(GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER) ||
          (slot = inner->cameraTargetObject) == NULL || slot->anim.romDefNo != 0x64f ||
          ((af = slot->anim.resetHitboxFlags) & 4) == 0 || (af & 0x18) != 0 ||
          ((PlayerState*)p2)->baddie.targetObj != NULL || (c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
          inner->heldObj != NULL || inner->flags3F0.b20 ||
          inner->flags3F0.b04 || inner->flags3F0.b08 ||
          inner->flags3F4.b40 == 0 ||
          *(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 4) < 0xa))
    {
        return 1;
    }
    return 0;
}

int playerCanCastPortalOpenSpell(GameObject* obj, PlayerState* p2)
{
    PlayerState* inner = obj->extra;
    s16 sel = p2->baddie.controlMode;

    if (sel == 1 || sel == 2)
    {
        GameObject* slot = inner->cameraTargetObject;
        u8 af;
        u8 c;
        if (slot == NULL || slot->anim.romDefNo != 0x414 ||
            ((af = slot->anim.resetHitboxFlags) & 4) == 0 || (af & 0x18) != 0)
        {
            return 0;
        }
        if (((PlayerState*)p2)->baddie.targetObj != NULL || (c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 ||
            inner->heldObj != NULL || inner->flags3F0.b20 ||
            inner->flags3F0.b04 || inner->flags3F0.b08 ||
            inner->flags3F4.b40 == 0 || (inner->playerStatus)->magic < 0x14 ||
            !mainGetBit(GAMEBIT_STAFF_ABILITY_OPEN_PORTAL))
        {
            return 0;
        }
        return 1;
    }
    return 0;
}

int playerCanCastQuakeSpell(GameObject* obj, PlayerState* p2)
{
    PlayerState* inner = obj->extra;
    int threshold;
    if (mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE))
    {
        threshold = 0x14;
    }
    else
    {
        threshold = 0xa;
    }
    if (mainGetBit(GAMEBIT_STAFF_ABILITY_GROUND_QUAKE) == 0 ||
        *(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 4) < threshold || inner->curAnimId == 0x44 ||
        inner->heldObj != NULL || inner->flags3F0.b20 ||
        inner->flags3F0.b04 || inner->flags3F0.b08 ||
        inner->flags3F4.b40 == 0)
    {
        return 0;
    }
    {
        s16 v;
        if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || v == 0x25 || v == 0x24)
        {
            return 1;
        }
    }
    return 0;
}

int playerCanCastBlasterSpell(GameObject* obj, PlayerState* p2, int p3)
{
    PlayerState* inner = obj->extra;
    u8 c;
    int v;
    if ((c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 || inner->heldObj != NULL ||
        inner->flags3F0.b20 || inner->flags3F0.b04 ||
        inner->flags3F0.b08 || inner->flags3F4.b40 == 0)
    {
        return 0;
    }
    if (p3 == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER)
    {
        if ((inner->playerStatus)->magic < 2)
            return 0;
    }
    else
    {
        if ((inner->playerStatus)->magic < 1)
            return 0;
    }
    if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || v == 0x2a || v == 0x2c || (u16)(v - 0x2e) <= 1 ||
        v == 0x2d)
    {
        return 1;
    }
    return 0;
}

int playerIsBlasterSpellAvailable(GameObject* obj, PlayerState* p2, int p3)
{
    PlayerState* inner = obj->extra;
    u8 c;
    int v;
    if ((c = inner->curAnimId) == 0x48 || c == 0x47 || c == 0x44 || inner->heldObj != NULL ||
        inner->flags3F0.b20 || inner->flags3F0.b04 ||
        inner->flags3F0.b08 || inner->flags3F4.b40 == 0)
    {
        return 0;
    }
    if (p3 == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER)
    {
        if ((inner->playerStatus)->magic < 2)
            return 0;
    }
    else
    {
        if ((inner->playerStatus)->magic < 1)
            return 0;
    }
    if ((v = ((PlayerState*)p2)->baddie.controlMode) == 1 || v == 2 || (u16)(v - 0x24) <= 1 || (u16)(v - 0x2a) <= 2 ||
        (u16)(v - 0x2e) <= 1 || v == 0x2d)
    {
        return 1;
    }
    return 0;
}

void playerSyncTransformToFocusObject(GameObject* p1, PlayerState* p2, GameObject* p3, int p4, int p5, int p6, int p7, int p8)
{
    void* vec;
    s16 v;
    f32 a, b, c;
    int d, e, flag;
    s16 angle;
    int clamped;
    PlayerState* inner;
    if (p8 != 0)
    {
        vec = (void*)objFindJointPoseVector((GameObject*)(p1), 0);
        if (vec != NULL)
        {
            v = *(s16*)((char*)vec + 0x2);
            if (v > 0)
            {
                *(s16*)((char*)vec + 0x2) -= (s16)(200.0f * timeDelta);
                if (*(s16*)((char*)vec + 0x2) < 0)
                {
                    *(s16*)((char*)vec + 0x2) = 0;
                }
            }
            else
            {
                *(s16*)((char*)vec + 0x2) += (s16)(200.0f * timeDelta);
                if (*(s16*)((char*)vec + 0x2) > 0)
                {
                    *(s16*)((char*)vec + 0x2) = 0;
                }
            }
        }
        VEHICLE_INTERFACE(p3)->render(p3, p4, p5, p6, p7, -1);
        p1->anim.previousWorldPosX = p1->anim.worldPosX;
        p1->anim.previousWorldPosY = p1->anim.worldPosY;
        p1->anim.previousWorldPosZ = p1->anim.worldPosZ;
        p1->anim.previousLocalPosX = p1->anim.localPosX;
        p1->anim.previousLocalPosY = p1->anim.localPosY;
        p1->anim.previousLocalPosZ = p1->anim.localPosZ;
    }
    VEHICLE_INTERFACE(p3)->getRiderPosition((GameObject*)p3, &a, &b, &c);
    ((GameObject*)p1)->anim.localPosX = a;
    ((GameObject*)p1)->anim.localPosY = b;
    ((GameObject*)p1)->anim.localPosZ = c;
    inner = ((GameObject*)p1)->extra;
    if (inner->baddie.controlMode != 0x18 &&
        (((GameObject*)p1)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
    {
        flag = 1;
        VEHICLE_INTERFACE(p3)->getLookTargetYaw((GameObject*)p3, 2, &d);
        angle = (s16)(((PlayerState*)p2)->targetYaw - (u16)d);
        if (angle > 0x8000)
        {
            angle = angle - 0xFFFF;
        }
        if (angle < -0x8000)
        {
            angle = angle + 0xFFFF;
        }
        VEHICLE_INTERFACE(p3)->getLookTargetYaw((GameObject*)p3, 3, &e);
        clamped = (angle < (s16)-e) ? (s16)-e : ((angle > (s16)e) ? (s16)e : angle);
        ((PlayerState*)p2)->targetYaw = (s16)d + clamped;
        VEHICLE_INTERFACE(p3)->getLookTargetYaw((GameObject*)p3, 4, &flag);
        if (flag != 0)
        {
            ((GameObject*)p1)->anim.rotY = ((GameObject*)p3)->anim.rotY;
            ((GameObject*)p1)->anim.rotZ = ((GameObject*)p3)->anim.rotZ;
        }
    }
    else
    {
        ((GameObject*)p1)->anim.rotY = ((GameObject*)p3)->anim.rotY;
        ((GameObject*)p1)->anim.rotZ = ((GameObject*)p3)->anim.rotZ;
        ((PlayerState*)p2)->targetYaw = ((GameObject*)p3)->anim.rotX;
    }
    v = ((PlayerState*)p2)->targetYaw;
    ((PlayerState*)p2)->yaw = v;
    ((GameObject*)p1)->anim.rotX = v;
    ((GameObject*)p1)->anim.worldPosX = ((GameObject*)p1)->anim.localPosX;
    ((GameObject*)p1)->anim.worldPosY = ((GameObject*)p1)->anim.localPosY;
    ((GameObject*)p1)->anim.worldPosZ = ((GameObject*)p1)->anim.localPosZ;
    ((GameObject*)p1)->anim.velocityX = ((GameObject*)p3)->anim.velocityX;
    ((GameObject*)p1)->anim.velocityY = ((GameObject*)p3)->anim.velocityY;
    ((GameObject*)p1)->anim.velocityZ = ((GameObject*)p3)->anim.velocityZ;
    playerRefreshCollisionState((GameObject*)p1, (int)p2, 7);
}

void playerFireCloudRunnerProjectile(GameObject* obj, PlayerState* state, f32 aimInputZ, f32 zero)
{
    GameObject* o;
    Camera* slot;
    ObjPlacement* setup;
    f32 v[3];
    f32 fov, xcomp, cot, aspect, ycomp, len;
    f32 scale;
    f32 mix;
    f32 t;
    int res, halfW, halfH;
    PlayerState* inner;

    inner = obj->extra;
    slot = Camera_GetCurrent();
    if (Obj_CanSetupObject())
    {
        setup = Obj_AllocObjectSetup(0x24, 0x14b);
        setup->color[0] = 2;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        setup->posX = slot->x;
        setup->posY = slot->y;
        setup->posZ = slot->z;
        Sfx_PlayFromObject(obj, SFXTRIG_staff_rocket_hitdirt);
        o = objSetupObject(setup, 5, -1, -1, NULL);
        if (o != NULL)
        {
            o->anim.flags |= 0x2000;
            res = getScreenResolution();
            halfH = res >> 17;
            o->anim.rotX = slot->yaw;
            t = Camera_GetFovY();
            t *= 91.022f;
            fov = (3.1415927f * t) / 32768.0f;
            cot = mathSinf(fov);
            cot = 100.0f * (cot / mathCosf(fov));
            aspect = Camera_GetAspectRatio();
            halfW = (u16)res >> 1;
            t = (inner->aimScreenX - (f32)halfW) / (f32)halfW;
            t *= aspect;
            xcomp = cot * -t;
            ycomp = cot * ((inner->aimScreenY - (f32)halfH) / (f32)halfH);
            len = sqrtf(10000.0f + (xcomp * xcomp + ycomp * ycomp));
            v[0] = xcomp / len;
            v[1] = ycomp / len;
            v[2] = 100.0f / len;
            Matrix_TransformVector(Camera_GetWorldMatrix(), v, v);
            scale = -40.0f;
            o->anim.velocityX = v[0] * scale;
            o->anim.velocityY = v[1] * scale;
            o->anim.velocityZ = v[2] * scale;
            mix = 2.0f;
            o->anim.localPosX = o->anim.worldPosX =
                mix * o->anim.velocityX + slot->x;
            o->anim.localPosY = o->anim.worldPosY =
                mix * o->anim.velocityY + slot->y;
            o->anim.localPosZ = o->anim.worldPosZ =
                mix * o->anim.velocityZ + slot->z;
            o->anim.rotY = slot->pitch / 2;
            o->anim.rotX = -slot->yaw;
            o->userData1 = 0x64;
        }
    }
}

void playerSpawnRapidFireLaser(GameObject* unusedObj, PlayerState* unusedState, f32 unusedAimInput, f32 randomOffset) {
    ObjPlacement* setup;
    enum {
        PLAYER_LINK_EFFECT_DISABLED,
        PLAYER_LINK_EFFECT_ENABLED
    } linkEffect;
    f32 x1, y1, z1, x0, y0, z0;
    f32 dx, dy, dz, len;

    linkEffect = PLAYER_LINK_EFFECT_ENABLED;
    Camera_GetCurrent();
    if (Obj_CanSetupObject() != 0) {
        Sfx_PlayFromObject(0, SFXTRIG_staff_rocket_hitdirt);
        setup = Obj_AllocObjectSetup(0x24, ARW_SEQID_RAPIDFIRE_LASER);
        setup->color[0] = 2;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, &x0, &y0, &z0, 0);
        setup->posX = x0 + randomOffset;
        setup->posY = y0 + randomOffset;
        setup->posZ = z0 + randomOffset;
        setup = (ObjPlacement*)objSetupObject(setup, 5, -1, -1, NULL);
        if (setup != NULL) {
            ObjPath_GetPointWorldPosition((GameObject*)gPlayerPathObject, 0, &x0, &y0, &z0, 0);
            ObjPath_GetPointWorldPosition((GameObject*)gPlayerPathObject, 1, &x1, &y1, &z1, 0);
            dx = x0 - x1;
            dy = y0 - y1;
            dz = z0 - z1;
            len = sqrtf(dx * dx + dy * dy + dz * dz);
            dx = dx / len;
            dy = dy / len;
            dz = dz / len;
            *(s16*)setup = (s16)getAngle(dx, dz);
            setup->unk02 = (s16)(-getAngle(dy, sqrtf(dx * dx + dz * dz)));
            setup->posX *= 6.0f;
            arwprojectile_placeForward((GameObject*)setup, 10.0f);
            arwprojectile_setLifetime((GameObject*)setup, 0x32);
            if (linkEffect == PLAYER_LINK_EFFECT_ENABLED) {
                arwprojectile_createLinkedEffect((GameObject*)setup, 1);
            }
        }
    }
}

void staffShootFireball(GameObject* obj, PlayerState* state, f32 unused)
{
    int spawned = 0;
    PlayerState* inner = obj->extra;
    GameObject* fb;
    Camera* slot;
    ObjPlacement* setup;
    f32 vec[3];
    MatrixTransform v;
    f32 mtx[16];

    slot = Camera_GetCurrent();
    if (Obj_CanSetupObject())
    {
        Sfx_PlayFromObject(obj, SFXTRIG_wp_hitpos_6_20a);
        setup = Obj_AllocObjectSetup(0x24, 0x14b);
        setup->color[0] = 2;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            ObjPath_GetPointWorldPosition(gPlayerPathObject, 0, &setup->posX, &setup->posY,
                                          &setup->posZ, 0);
        }
        else
        {
            setup->posX = slot->x;
            setup->posY = slot->y;
            setup->posZ = slot->z;
        }
        *(s8*)((char*)setup + 0x19) =
            (s8)STAFF_INTERFACE(gPlayerPathObject)->getHitReactValue((GameObject*)gPlayerPathObject);
        if (((PlayerState*)state)->baddie.targetObj == NULL)
        {
            *(s16*)((char*)setup + 0x1a) = 1;
        }
        fb = objSetupObject(setup, 5, -1, -1, NULL);
        if (fb == NULL)
        {
            return;
        }
        fb->anim.flags = fb->anim.flags | OBJANIM_FLAG_OWNS_PLACEMENT_DATA;
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            ObjHitVolumeRuntimeTransform* pt;
            GameObject* target;
            GameObject* ppo;
            f32 dx;
            f32 dz;
            f32 dy;
            target = *(GameObject**)&((PlayerState*)state)->baddie.targetObj;
            spawned = (int)target;
            pt = &target->anim.hitVolumeTransforms[target->hitVolumeIndex];
            dx = pt->jointX - (ppo = (GameObject*)gPlayerPathObject)->anim.localPosX;
            dy = pt->jointY - ppo->anim.localPosY;
            dz = pt->jointZ - ppo->anim.localPosZ;
            v.x = 0.0f;
            v.y = 0.0f;
            v.z = 0.0f;
            v.scale = 1.0f;
            v.rotX = inner->targetYaw;
            v.rotY = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            v.rotZ = 0;
            if (obj->anim.parent != NULL)
            {
                v.rotX = v.rotX + *(s16*)((char*)obj->anim.parent);
            }
            setMatrixFromObjectPos(mtx, &v);
            Matrix_TransformPoint(mtx, 0.0f, 0.0f, -10.0f, &fb->anim.velocityX, &fb->anim.velocityY,
                                  &fb->anim.velocityZ);
            fb->anim.worldPosX = fb->anim.localPosX;
            fb->anim.worldPosY = fb->anim.localPosY;
            fb->anim.worldPosZ = fb->anim.localPosZ;
            fb->anim.rotX = inner->targetYaw;
            fb->anim.rotY = slot->pitch / 2;
        }
        else
        {
            int res = getScreenResolution();
            int half = res >> 17;
            f32 fov;
            f32 cot;
            f32 fx;
            f32 mag;
            fb->anim.rotX = slot->yaw;
            fov = Camera_GetFovY();
            fov *= 91.022f;
            fov = 3.1415927f * fov / 32768.0f;
            {
                f32 sn = mathSinf(fov);
                cot = 100.0f * (sn / mathCosf(fov));
            }
            fx = cot * -((inner->aimScreenX - (f32)(int)((res & 0xffff) >> 1)) / (f32)(int)((res & 0xffff) >> 1) *
                         Camera_GetAspectRatio());
            cot = cot * ((inner->aimScreenY - (f32)half) / (f32)half);
            mag = sqrtf(10000.0f + (fx * fx + cot * cot));
            vec[0] = fx / mag;
            vec[1] = cot / mag;
            vec[2] = 100.0f / mag;
            Matrix_TransformVector(Camera_GetWorldMatrix(), vec, vec);
            fb->anim.velocityX = -10.0f * vec[0];
            fb->anim.velocityY = -10.0f * vec[1];
            fb->anim.velocityZ = -10.0f * vec[2];
            fb->anim.localPosX = fb->anim.worldPosX = 2.0f * fb->anim.velocityX + slot->x;
            fb->anim.localPosY = fb->anim.worldPosY = 2.0f * fb->anim.velocityY + slot->y;
            fb->anim.localPosZ = fb->anim.worldPosZ = 2.0f * fb->anim.velocityZ + slot->z;
            fb->anim.rotY = slot->pitch / 2;
            fb->anim.rotX = -slot->yaw;
        }
        fb->userData1 = 0x5f;
        fb->userData2 = spawned;
    }
}

void objDoTeleportAnim(GameObject* obj) {
    PlayerState* inner = obj->extra;
    struct {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 base = 40.0f;
    int i;

    buf.y = base - inner->teleportAnimProgress;
    if (gPlayerTeleportAnimRearm < -40.0f) {
        inner->teleportAnimActive = 0;
        return;
    }
    if (buf.y <= 0.0f) {
        gPlayerTeleportAnimRearm = gPlayerTeleportAnimRearm - 0.2f * timeDelta;
        return;
    }
    gPlayerTeleportAnimRearm = base;
    buf.y += obj->anim.localPosY;
    {
        for (i = 0; i < 10; i++) {
            buf.x = obj->anim.localPosX + (f32)randomGetRange(-0x64, 0x64) / 10.0f;
            buf.z = obj->anim.localPosZ + (f32)randomGetRange(-0x64, 0x64) / 10.0f;
            (*gPartfxInterface)->spawnObject((void*)obj, randomGetRange(0, 2) + 0x3f4, &buf, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, randomGetRange(0, 2) + 0x3f7, &buf, 1, -1, NULL);
        }
    }
}

void playerDie(GameObject* obj)
{
    PlayerState* inner = obj->extra;
    ObjPlacement* setup;
    int variant;
    int z[2];
    cutsceneFadeInOut(1);
    setTimeStop(0xff);
    setPendingMapLoad(1);
    if (obj != NULL)
    {
        variant = (&obj->anim)->bankIndex != 0;
    }
    else
    {
        variant = 0;
    }
    if (variant != 0)
    {
        setup = Obj_AllocObjectSetup(0x20, 0x882);
    }
    else
    {
        setup = Obj_AllocObjectSetup(0x20, 0x887);
    }
    setup->posX = obj->anim.localPosX;
    setup->posY = obj->anim.localPosY;
    setup->posZ = obj->anim.localPosZ;
    inner->spawnedObject = objSetupObject(setup, 5, -1, -1, NULL);
    inner->flags3F3.b04 = 0;
    inner->flags3F3.b02 = 1;
    z[0] = 0;
    gPlayerIceSpellSustaining = z[0];
    for (z[1] = z[0]; z[1] < 7; z[1]++)
    {
        if (gPlayerSpawnedObjects[z[1]] != NULL)
        {
            Obj_FreeObject(gPlayerSpawnedObjects[z[1]]);
            gPlayerSpawnedObjects[z[1]] = NULL;
        }
    }
    if (gPlayerResource != NULL)
    {
        Resource_Release(gPlayerResource);
        gPlayerResource = NULL;
    }
    inner->flags360 &= ~PLAYER_FLAG_AIM_READY;
    AudioStream_StopCurrent();
    AudioStream_Play(0x51e0, AudioStream_StartPrepared);
}

void playerCacheMoveRootHeights(GameObject* obj)
{
    ObjModel* model;
    GameObject* object;
    PlayerState* player;
    s16* moveTable;
    s16 moveIndex;
    s16 moveTableIndex;
    s16 jointRotation[3];
    f32 jointPosition[3];

    object = obj;
    model = object->anim.modelBanks[object->anim.bankIndex];
    player = object->extra;
    moveTable = player->moveAnimIds;

    ObjAnim_SetCurrentMove(obj, moveTable[0], 0.0f, 0);
    ObjModel_SampleJointTransform(model, 0, 0, 0.0f, object->anim.rootMotionScale, jointPosition, jointRotation);
    gPlayerMoveRootHeights[0] = jointPosition[1];

    ObjAnim_SetCurrentMove(obj, lbl_80332F2C[0], 0.0f, 0);
    ObjModel_SampleJointTransform(model, 0, 0, 0.0f, object->anim.rootMotionScale, jointPosition, jointRotation);
    gPlayerMoveRootHeights[1] = jointPosition[1];

    moveIndex = 12;
    moveTableIndex = 17;
    while (moveIndex <= 15) {
        ObjAnim_SetCurrentMove(obj, lbl_80332F48[moveTableIndex], 0.0f, 0);
        ObjModel_SampleJointTransform(model, 0, 0, 0.0f, object->anim.rootMotionScale, jointPosition, jointRotation);
        gPlayerMoveRootHeights[moveIndex] = jointPosition[1];
        moveTableIndex++;
        moveIndex++;
    }
    ObjAnim_WriteStateWord(&object->anim, OBJANIM_STATE_INDEX_CURRENT, OBJANIM_STATE_WORD_EVENT_COUNTDOWN, 0);
}

void playerDrawTeleportAnim(GameObject* obj)
{
    PlayerState* state = obj->extra;
    LightmapVertex* vp = gPlayerHudVtxBuf;
    LightmapVertex* p = vp;
    int i;
    f32 height;
    f32 v;
    struct
    {
        s16 rx, ry, rz, pad;
        f32 scale;
        f32 px, py, pz;
    } xf;
    f32 mtx[16];

    height = state->teleportAnimProgress;
    setTextColor(0, 0xff, 0xff, 0xff, 0x80);
    gxTevResetStages();
    gxTevTextureTimesColor1Stage();
    gxTevCommitStages();
    gxSetOpaqueZWriteMode();
    GXSetColorUpdate(0);

    i = 0;
    for (; i < 8; i++)
    {
        v = 20.0f * (40.0f - height);
        if (i < 4)
        {
            p->y = 0x320;
        }
        else
        {
            p->y = v;
        }
        if (i < 4)
        {
            p->x = (20.0f * gPlayerTeleportBoxCorners[i * 3 + 0]);
            p->z = (20.0f * gPlayerTeleportBoxCorners[i * 3 + 2]);
        }
        else
        {
            p->x = (20.0f * gPlayerTeleportBoxCorners[i * 3 + 0]);
            p->z = (20.0f * gPlayerTeleportBoxCorners[i * 3 + 2]);
        }
        p->r = 0xff;
        p->g = 0;
        p->b = 0;
        p->a = 0x40;
        p++;
    }

    xf.px = obj->anim.localPosX - playerMapOffsetX;
    xf.py = obj->anim.localPosY;
    xf.pz = obj->anim.localPosZ - playerMapOffsetZ;
    xf.rx = state->targetYaw;
    xf.ry = 0;
    xf.rz = 0;
    xf.scale = 0.05f;
    setMatrixFromObjectTransposed(&xf, mtx);
    PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), (MtxPtr)mtx, (MtxPtr)mtx);
    GXLoadPosMtxImm((const f32(*)[4])mtx, 0);
    lightmapDrawTriangleList(vp, (u8*)lbl_802C2B30, 0xc);

    if (state->teleportAnimProgress >= 68.0f)
    {
        int t = obj->anim.alpha - (framesThisStep << 2);
        if (t < 0)
        {
            t = 0;
        }
        obj->anim.alpha = t;
    }
    GXSetColorUpdate(1);
}

void playerRenderPostEffects(GameObject* obj, PlayerState* inner, int a, int b, int c)
{
    int v;
    if (gPlayerPathObject != NULL && ((u32)((PlayerState*)inner)->flags3F4.b40) != 0)
    {
        (*gModgfxInterface)->renderEffects((void*)a, b, c, 1, gPlayerPathObject);
    }
    if (((PlayerState*)inner)->pendingBoneEffectId != 0)
    {
        (*gBoneParticleEffectInterface)
            ->spawnEffect((void*)obj, ((PlayerState*)inner)->pendingBoneEffectId, NULL, 0x64, NULL);
    }
    ((PlayerState*)inner)->pendingBoneEffectId = 0;
    if (((PlayerState*)inner)->teleportAnimActive == 1)
    {
        objDoTeleportAnim(obj);
    }
    if ((*gSkyInterface)->getVisibility(2) != 0)
    {
        playerUpdatePathEffectCountdown(obj, inner);
    }
    v = ((PlayerState*)inner)->flags360;
    if ((v & 0x60000u) != 0)
    {
        gPlayerPartFxParams.posX = obj->anim.localPosX;
        gPlayerPartFxParams.posY = obj->anim.localPosY;
        gPlayerPartFxParams.posZ = obj->anim.localPosZ;
        if ((v & 0x40000u) != 0)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x427, &gPlayerPartFxParams, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x427, &gPlayerPartFxParams, 0x200001, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x427, &gPlayerPartFxParams, 0x200001, -1, NULL);
        }
        if ((((PlayerState*)inner)->flags360 & 0x20000u) != 0)
        {
            (*gWaterfxInterface)
                ->spawnSplashBurst((void*)obj, obj->anim.localPosX,
                                   (obj->anim.localPosY + ((PlayerState*)inner)->waterDepth) -
                                       5.0f,
                                   obj->anim.localPosZ, 7.0f);
            (*gWaterfxInterface)->spawnRipple(
                obj->anim.localPosX,
                obj->anim.localPosY + ((PlayerState*)inner)->waterDepth,
                obj->anim.localPosZ, 0, 4.0f, 2);
            ((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_WATER_SPLASH_PENDING;
        }
    }
}

GameObject* playerFindNearestLookTarget(GameObject* obj) {
    GameObject* cur;
    GameObject** objs;
    GameObject* best;
    int count;
    int i;
    f32 dist;
    f32 bestDist;
    f32 scale;
    s16 yaw;
    void* held;

    if (obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) {
        return 0;
    }
    held = ((PlayerState*)obj->extra)->baddie.targetObj;
    if (held != NULL) {
        return held;
    }
    best = NULL;
    objs = (GameObject**)objGetAllOfType(8, &count);
    i = 0;
    bestDist = 0.0f;
    for (; i < count;) {
        cur = objs[i++];
        if ((cur->anim.classId == 0x1c || cur->anim.classId == 0x2a) && cur->anim.alpha == 0xff) {
            f32 dx = cur->anim.worldPosX - obj->anim.worldPosX;
            f32 dy = cur->anim.worldPosY - obj->anim.worldPosY;
            f32 dz = cur->anim.worldPosZ - obj->anim.worldPosZ;
            dist = dx * dx + dy * dy + dz * dz;
            if (dist < 40000.0f) {
                if (dist <= 0.0f) {
                    scale = (f32)cur->anim.modelInstance->group8RegistrationCount;
                    if (scale <= 0.0f) {
                        scale = 1.0f;
                    }
                    dist = sqrtf(dist) / scale;
                }
                yaw = Obj_GetYawDeltaToObject(obj, cur, 0);
                if (yaw < 0x5555 && yaw > -0x5555) {
                    if (dist < bestDist || 0.0f == bestDist) {
                        bestDist = dist;
                        best = cur;
                    }
                }
            }
        }
    }
    return best;
}

void playerCastSpell(GameObject* a, PlayerState* b, int c)
{
    switch (c)
    {
    case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
        gPlayerSelectedItem = GAMEBIT_STAFF_ABILITY_FIRE_BLASTER;
        break;
    case 0x958:
        gPlayerSelectedItem = 0x958;
        break;
    case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
        gPlayerSelectedItem = GAMEBIT_STAFF_ABILITY_FREEZE_BLAST;
        break;
    case GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER:
        gPlayerInteractTarget = b->cameraTargetObject;
        (*gPlayerInterface)->setState((void*)a, (void*)b, 0x32);
        b->baddie.stateExitFn = (BaddieStateExitFn)playerStagedResetAnimStateAndSyncPosition;
        break;
    case GAMEBIT_STAFF_ABILITY_GROUND_QUAKE:
    case GAMEBIT_STAFF_ABILITY_SUPER_QUAKE:
        (*gPlayerInterface)->setState((void*)a, (void*)b, 0x36);
        b->baddie.stateExitFn = (BaddieStateExitFn)playerStagedResetAnimState;
        break;
    case GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE:
        b->stateTimer = 300.0f;
        {
            PlayerStatus* sub = ((PlayerState*)a->extra)->playerStatus;
            int v = sub->magic - 0xa;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > sub->maxMagic)
            {
                v = sub->maxMagic;
            }
            sub->magic = v;
        }
        playerSetDisguised(a, 1);
        Sfx_PlayFromObject(a, SFXTRIG_dn_boar1_c_209);
        break;
    case GAMEBIT_STAFF_ABILITY_OPEN_PORTAL:
        c = -1;
        {
            PlayerStatus* sub = ((PlayerState*)a->extra)->playerStatus;
            int v = sub->magic - 0x14;
            if (v < 0)
            {
                v = 0;
            }
            else if (v > sub->maxMagic)
            {
                v = sub->maxMagic;
            }
            sub->magic = v;
        }
        {
            GameObject* cam = (GameObject*)(*gCameraInterface)->getTarget();
            if (cam != NULL)
            {
                s16 id = cam->anim.romDefNo;
                if (id == 0x414 || id == 0x4a9)
                {
                    c = GAMEBIT_STAFF_ABILITY_OPEN_PORTAL;
                    getAngle(cam->anim.hitVolumeTransforms->jointX - a->anim.localPosX,
                             cam->anim.hitVolumeTransforms->jointZ - a->anim.localPosZ);
                }
            }
        }
        break;
    }
    b->animState = c;
}

void playerRefreshCollisionState(GameObject* obj, int p2, int flags)
{
    u8 f = (u8)flags;
    CurvesCollisionState* q = (CurvesCollisionState*)(p2 + 4);
    if (f & 1)
    {
        curves_updateLocalPointTransforms((GameObject*)obj, (CurvesCollisionState*)q);
    }
    if (f & 2)
    {
        curves_preparePointCollisionFrame((GameObject*)obj, (CurvesCollisionState*)((char*)(int)p2 + 4));
        q->points[2][0] = obj->anim.worldPosX;
        q->points[2][1] = 35.0f + obj->anim.worldPosY;
        q->points[2][2] = obj->anim.worldPosZ;
    }
    if (f & 4)
    {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosX = obj->anim.localPosX;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosY = obj->anim.localPosY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->localPosZ = obj->anim.localPosZ;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosX = obj->anim.worldPosX;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosY = obj->anim.worldPosY;
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->worldPosZ = obj->anim.worldPosZ;
    }
}

void playerCalcWaterCurrent(f32* outX, f32* outZ, f32 p3, GameObject* player)
{
    int any;
    GameObject* object = player;
    PlayerState* inner = object->extra;
    int n;
    int i;
    GameObject* o;
    GameObject** objs;
    f32 sumS;
    f32 sumC;
    f32 ratio;

    sumC = 0.0f;
    sumS = 0.0f;
    objs = (GameObject**)objGetAllOfType(0x14, &n);
    any = 0;
    for (i = 0; i < n; i++)
    {
        o = objs[i];
        if (((FoliageCurrentSetup*)o->anim.placementData)->currentFlags & 2)
        {
            f32 dy;
            any = 1;
            dy = o->anim.localPosY - object->anim.localPosY;
            if (dy <= 200.0f && dy >= -200.0f)
            {
                f32 dx = o->anim.localPosX - object->anim.localPosX;
                f32 dz = o->anim.localPosZ - object->anim.localPosZ;
                f32 dist = sqrtf(dx * dx + dz * dz);
                f32 thresh = 1.5f * (f32)(u32)((FoliageCurrentSetup*)o->anim.placementData)->currentRadius;
                if (dist < thresh)
                {
                    ratio = 0.0f;
                    if (thresh > 0.0f)
                    {
                        ratio = (thresh - dist) / thresh;
                    }
                    ratio = ratio * (10.0f * o->anim.rootMotionScale);
                    sumS = ratio * mathSinf(3.1415927f * (f32)(int)o->anim.rotX / 32768.0f) + sumS;
                    sumC = ratio * mathCosf(3.1415927f * (f32)(int)o->anim.rotX / 32768.0f) + sumC;
                }
            }
        }
    }
    objs = (GameObject**)objGetAllOfType(0x50, &n);
    for (i = 0; i < n; i++)
    {
        f32 strength;
        s16 currentAngle;
        f32 dy;
        o = objs[i];
        strength = (f32)(u32)((ObjectCurrentSourceSetup*)o->anim.placementData)->strengthTenths / 10.0f;
        any = 1;
        dy = o->anim.localPosY - object->anim.localPosY;
        if (dy <= 200.0f && dy >= -200.0f)
        {
            f32 dx = o->anim.localPosX - object->anim.localPosX;
            f32 dz = o->anim.localPosZ - object->anim.localPosZ;
            f32 dist;
            f32 thresh;
            currentAngle = (s16)(getAngle(dx, dz) + 0x84d0);
            dist = sqrtf(dx * dx + dz * dz);
            thresh = (f32)(int)(((ObjectCurrentSourceSetup*)o->anim.placementData)->radiusCells << 3);
            if (dist < thresh)
            {
                ratio = 0.0f;
                if (thresh > 0.0f)
                {
                    ratio = (thresh - dist) / thresh;
                }
                ratio = ratio * strength;
                sumS = ratio * mathSinf(3.1415927f * (f32)(int)currentAngle / 32768.0f) + sumS;
                sumC = ratio * mathCosf(3.1415927f * (f32)(int)currentAngle / 32768.0f) + sumC;
            }
        }
    }
    if (any)
    {
        f32 mag;
        f32 k;
        sumS = sumS / (f32)any;
        sumC = sumC / (f32)any;
        k = 0.05f;
        inner->avoidVelX = inner->avoidVelX - k * sumS;
        inner->avoidVelZ = inner->avoidVelZ - k * sumC;
        {
            f32 k;
            k = 0.99f;
            inner->avoidVelX = inner->avoidVelX * k;
            inner->avoidVelZ = inner->avoidVelZ * k;
        }
        mag = sqrtf(inner->avoidVelX * inner->avoidVelX + inner->avoidVelZ * inner->avoidVelZ);
        if (mag > 0.85f)
        {
            f32 s = 0.85f / mag;
            inner->avoidVelX = inner->avoidVelX * s;
            inner->avoidVelZ = inner->avoidVelZ * s;
        }
        *outX = inner->avoidVelX * timeDelta;
        *outZ = inner->avoidVelZ * timeDelta;
    }
    else
    {
        *outX = 0.0f;
        *outZ = 0.0f;
    }
}

void playerUpdateLookAndLean(GameObject* obj, BaddieState* baddie, PlayerState* player, f32 turnInput) {
    int d = player->targetYaw - (u16)player->prevTargetYaw;
    GameObject* near;
    int g;
    if (d > 0x8000) {
        d -= 0xffff;
    }
    if (d < -0x8000) {
        d += 0xffff;
    }
    if (((u32)player->flags3F1.b20) || (player->flags3F0.b10)) {
        d = 0;
    }
    {
        f32 f2 = 0.5f * (baddie->animSpeedC - 0.4f) + 1.0f;
        if (f2 < 0.0f) {
            f2 = 0.0f;
        }
        d = (int)((f32)d * (1.5f * f2));
        d = (d < -0xccc) ? -0xccc : ((d > 0xccc) ? 0xccc : d);
    }
    d -= (u16)player->headPitch;
    if (d > 0x8000) {
        d = d - 0xffff;
    }
    if (d < -0x8000) {
        d = d + 0xffff;
    }
    player->headPitch = (f32)(int)player->headPitch + interpolate((f32)d, 0.15f, timeDelta);
    near = playerFindNearestLookTarget(obj);
    if (near != NULL && (player->flags3F0.b80) == 0 && (player->flags3F0.b40) == 0 && (player->flags3F0.b10) == 0 &&
        (player->flags3F0.b20) == 0) {
        f32 t;
        f32 f5;
        g = getAngle(-(near->anim.localPosX - obj->anim.localPosX), -(near->anim.localPosZ - obj->anim.localPosZ)) &
            0xffff;
        g -= (u16)player->targetYaw;
        if (g > 0x8000) {
            g -= 0xffff;
        }
        if (g < -0x8000) {
            g += 0xffff;
        }
        t = 1.0f - (baddie->animSpeedC - 0.4f) / (player->maxSpeed - 0.4f);
        f5 = 40.0f * ((t < 0.0f) ? 0.0f : ((t > 1.0f) ? 1.0f : t)) + 45.0f;
        g = CLAMP_EXPR((f32)g, 182.0f * -f5, 182.0f * f5);
    } else {
        g = 0;
    }
    {
        int turnRate;
        if (!(((u32)player->flags3F1.b20) || (player->flags3F0.b10))) {
            turnRate = player->targetYawRate;
        } else {
            turnRate = 0;
        }
        turnRate = CLAMP_EXPR(turnRate, -0x28, 0x28);
        g += turnRate * 0xb6;
        g = CLAMP_EXPR(g, -0x3ffc, 0x3ffc);
        g = g - (u16)player->bodyLeanAngle;
        if (g > 0x8000) {
            g -= 0xffff;
        }
        if (g < -0x8000) {
            g += 0xffff;
        }
        g *= 0.15f;
        g = CLAMP_EXPR(g, -0x16c, 0x16c);
        player->bodyLeanAngle =
            (f32)g * timeDelta + (f32)(int)*(s16*)((char*)player + offsetof(PlayerState, bodyLeanAngle));
        player->bodyLeanHalf = player->bodyLeanAngle / 2;
    }
    {
        int headYawDelta = (int)(182.0f * (10.0f * -turnInput));
        headYawDelta -= (u16)player->headYaw;
        if (headYawDelta > 0x8000) {
            headYawDelta -= 0xffff;
        }
        if (headYawDelta < -0x8000) {
            headYawDelta += 0xffff;
        }
        player->headYaw += headYawDelta;
    }
}

void playerUpdateCameraTargetLookAngles(GameObject* obj, PlayerState* state, PlayerState* inner)
{
    f32 x1, y1, z1;
    f32 pos[3];
    GameObject* sub;

    inner->headPitch *= powfBitEstimate(0.9f, timeDelta);
    sub = inner->cameraTargetObject;
    if (sub != NULL && sub->anim.modelInstance->attachPointCount != 0)
    {
        ObjPath_GetPointWorldPosition(obj, 5, &x1, &y1, &z1, 0);
        if (objFindJointPoseVector(sub, 0) != 0)
        {
            objGetJointWorldPosition(sub, 0, pos);
        }
        else
        {
            pos[0] = sub->anim.localPosX;
            pos[1] = sub->anim.localPosY;
            pos[2] = sub->anim.localPosZ;
        }

        {
            f32 dx = pos[0] - x1;
            f32 dy = pos[1] - y1;
            f32 dz = pos[2] - z1;

            int d = getAngle(-dy, sqrtf(dx * dx + dz * dz)) & 0xffff;
            d -= (u16)inner->headYaw;
            if (d > 0x8000)
                d = d - 0xffff;
            if (d < -0x8000)
                d = d + 0xffff;
            d *= 0.15f;
            inner->headYaw += d * timeDelta;

            d = getAngle(-dx, -dz) & 0xffff;
            d -= (u16)inner->targetYaw;

            if (d > 0x8000)
                d = d - 0xffff;
            if (d < -0x8000)
                d = d + 0xffff;

            d = (d < -0x1c70) ? -0x1c70 : ((d > 0x1c70) ? 0x1c70 : d);
            d -= (u16)inner->bodyLeanAngle;

            if (d > 0x8000)
                d = d - 0xffff;
            if (d < -0x8000)
                d = d + 0xffff;

            d *= 0.15f;
            inner->bodyLeanAngle += d * timeDelta;
            inner->bodyLeanHalf = inner->bodyLeanAngle / 2;
        }
    }
    else
    {
        inner->headYaw *= powfBitEstimate(0.85f, timeDelta);
    }
}

void playerUpdateLookAtTarget(GameObject* p1, PlayerState* p2, PlayerState* p3)
{
    void* near;
    int angle1;
    int angle2;

    near = playerFindNearestLookTarget((GameObject*)p1);
    if (near != NULL && ((PlayerState*)p3)->flags3F0.b80 == 0 && ((PlayerState*)p3)->flags3F0.b40 == 0)
    {
        f32 ratio;
        f32 clamped;
        f32 f5;

        if (--((PlayerState*)p3)->lookAtTimer <= 0)
        {
            ((PlayerState*)p3)->lookAtTimer = (s16)randomGetRange(0x78, 0xf0);
            ((PlayerState*)p3)->lookAtRandOffset = (s16)randomGetRange(0, 0x28);
        }
        angle1 = getAngle(-(*(f32*)((char*)near + 0xc) - ((GameObject*)p1)->anim.localPosX),
                          -(*(f32*)((char*)near + 0x14) - ((GameObject*)p1)->anim.localPosZ)) &
                 0xffff;
        angle1 -= (u16)((PlayerState*)p3)->targetYaw;
        if (angle1 > 0x8000)
        {
            angle1 = angle1 - 0xFFFF;
        }
        if (angle1 < -0x8000)
        {
            angle1 = angle1 + 0xFFFF;
        }
        ratio = 1.0f - (p2->baddie.animSpeedC - 0.4f) / (p3->maxSpeed - 0.4f);
        f5 = 40.0f;
        clamped = (ratio < 0.0f) ? 0.0f : ((ratio > 1.0f) ? 1.0f : ratio);
        f5 = f5 * clamped + 45.0f;
        angle1 = ((f32)angle1 < 182.0f * -f5)
                     ? 182.0f * -f5
                     : (((f32)angle1 > 182.0f * f5) ? 182.0f * f5 : (f32)angle1);
    }
    else
    {
        angle1 = 0;
        p3->lookAtTimer = angle1;
    }

    {
        int targetYawRate;
        if (((PlayerState*)p3)->flags3F1.b20)
        {
            targetYawRate = 0;
        }
        else
        {
            targetYawRate = ((PlayerState*)p3)->targetYawRate;
        }
        targetYawRate = (targetYawRate < -0x28) ? -0x28 : ((targetYawRate > 0x28) ? 0x28 : targetYawRate);
        angle1 += targetYawRate * 0xb6;
    }
    angle1 = (angle1 < -0x3ffc) ? -0x3ffc : ((angle1 > 0x3ffc) ? 0x3ffc : angle1);
    angle1 -= (u16)((PlayerState*)p3)->bodyLeanAngle;
    if (angle1 > 0x8000)
    {
        angle1 = angle1 - 0xFFFF;
    }
    if (angle1 < -0x8000)
    {
        angle1 = angle1 + 0xFFFF;
    }
    angle1 *= 0.15f;
    angle1 = (angle1 < -0x16c) ? -0x16c : ((angle1 > 0x16c) ? 0x16c : angle1);
    ((PlayerState*)p3)->bodyLeanAngle += angle1 * timeDelta;
    ((PlayerState*)p3)->bodyLeanHalf = (s16)(((PlayerState*)p3)->bodyLeanAngle / 2);

    angle2 = ((PlayerState*)p3)->targetYaw - (u16)((PlayerState*)p3)->prevTargetYaw;
    if (angle2 > 0x8000)
    {
        angle2 = angle2 - 0xFFFF;
    }
    if (angle2 < -0x8000)
    {
        angle2 = angle2 + 0xFFFF;
    }
    if (((PlayerState*)p3)->flags3F1.b20)
    {
        angle2 = 0;
    }
    {
        f32 f2 = 0.5f * (((PlayerState*)p2)->baddie.animSpeedC - 0.4f) + 1.0f;
        if (f2 < 0.0f)
        {
            f2 = 0.0f;
        }
        angle2 = (int)((f32)angle2 * (1.5f * f2));
    }
    angle2 = (angle2 < -0xccc) ? -0xccc : ((angle2 > 0xccc) ? 0xccc : angle2);
    angle2 -= (u16)((PlayerState*)p3)->headPitch;
    if (angle2 > 0x8000)
    {
        angle2 = angle2 - 0xFFFF;
    }
    if (angle2 < -0x8000)
    {
        angle2 = angle2 + 0xFFFF;
    }
    ((PlayerState*)p3)->headPitch =
        (f32)((PlayerState*)p3)->headPitch + interpolate((f32)angle2, 0.15f, timeDelta);
    ((PlayerState*)p3)->headYaw = (f32)((PlayerState*)p3)->headYaw * powfBitEstimate(0.85f, timeDelta);
}

int playerCheckCommonTransitions(GameObject* obj, struct PlayerState* state, struct PlayerState* inner, f32 fv)
{
    int r;
    int ok;
    CameraModeForceBehindInitParams camp = sPlayerCamRange;
    MatrixTransform pos;
    u8 buf[52];
    f32 mtx[16];
    f32 dummy;
    f32 idleZero = 0.0f;

    if (((PlayerState*)inner)->curAnimId != 0x48 && ((PlayerState*)inner)->curAnimId != 0x47 &&
        !((PlayerState*)inner)->flags3F0.b04 && !((PlayerState*)inner)->flags3F0.b08 &&
        ((PlayerState*)inner)->heldObj == NULL && !((PlayerState*)inner)->flags3F0.b02 &&
        ((PlayerState*)inner)->baddie.targetObj == NULL && !((PlayerState*)inner)->flags3F6.b40 &&
        ((PlayerState*)inner)->baddie.controlMode != 0x26)
    {
        ok = 1;
    }
    else
    {
        ok = 0;
    }
    if (ok != 0 && (((PlayerState*)inner)->buttonsHeld & PAD_TRIGGER_L) != 0 && getCurSeqNo() == 0)
    {
        if (!((PlayerState*)inner)->flags3F1.b20 && !((PlayerState*)inner)->flags3F0.b10)
        {
            f32 b;
            f32 a;
            a = ((PlayerState*)state)->baddie.animSpeedB;
            b = ((PlayerState*)state)->baddie.animSpeedA;
            pos.rotX = ((PlayerState*)inner)->yaw;
            pos.rotY = 0;
            pos.rotZ = 0;
            pos.scale = 1.0f;
            pos.x = 0.0f;
            pos.y = 0.0f;
            pos.z = 0.0f;
            setMatrixFromObjectPos(mtx, &pos);
            Matrix_TransformPoint(mtx, a, 0.0f, -b, &((PlayerState*)inner)->smoothVelX, &dummy,
                                  &((PlayerState*)inner)->smoothVelZ);
            ((PlayerState*)inner)->flags3F0.b80 = 0;
            ((PlayerState*)inner)->flags3F0.b40 = 0;
            ((PlayerState*)inner)->flags3F0.b10 = 0;
            ((PlayerState*)inner)->flags3F1.b08 = 1;
            {
                s16 v = ((PlayerState*)inner)->targetYaw;
                ((PlayerState*)inner)->yaw = v;
                ((GameObject*)obj)->anim.rotX = v;
            }
            inner->flags3F1.b20 = 1;
            {
                f32 z = 0.0f;
                inner->aimInputZ = z;
                inner->aimInputX = z;
            }
        }
        if (!((PlayerState*)inner)->flags3F1.b10)
        {
            Camera_setBlendCurveMode(2);
            (*gCameraInterface)
                ->setMode(CAMERA_MODE_FORCE_BEHIND_RESOURCE_ID, 1, 0, sizeof(camp), &camp, 0x1e, 0xff);
            if (gPlayerFrameCounter - gPlayerLastSfxFrame > 2)
            {
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_headcam_in);
            }
            gPlayerLastSfxFrame = gPlayerFrameCounter;
            inner->flags3F1.b10 = 1;
        }
    }
    else
    {
        if (((PlayerState*)inner)->flags3F1.b20)
        {
            s16 v = ((GameObject*)obj)->anim.rotX;
            ((PlayerState*)inner)->yaw = v;
            ((PlayerState*)inner)->targetYaw = v;
            ((PlayerState*)inner)->lastInputHeading = v;
            ((PlayerState*)inner)->baddie.animSpeedB = 0.0f;
        }
        ((PlayerState*)inner)->flags3F1.b20 = 0;
        if (((PlayerState*)inner)->flags3F1.b10 && ((PlayerState*)inner)->curAnimId != 0x48 &&
            ((PlayerState*)inner)->curAnimId != 0x47 && getCurSeqNo() == 0)
        {
            (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
            inner->flags3F1.b10 = 0;
        }
    }
    gPlayerFrameCounter = gPlayerFrameCounter + 1;
    if (!((PlayerState*)inner)->flags3F0.b20 && ((PlayerState*)inner)->waterDepth > 25.0f &&
        ((PlayerState*)state)->baddie.unk1B0 < 120.0f)
    {
        playerEnterDeepWater(obj, inner, state);
        return 0;
    }
    {
        if (!((PlayerState*)inner)->flags3F0.b20 && !((PlayerState*)inner)->flags3F0.b08 &&
            !((PlayerState*)inner)->flags3F0.b04)
        {
            if (((PlayerState*)inner)->flags3F1.b01 || ((PlayerState*)state)->baddie.unk1B0 < 15.0f)
            {
                ((PlayerState*)inner)->staffHoldFrames = 0;
            }
            else
            {
                ((PlayerState*)inner)->staffHoldFrames += 1;
            }
            ((PlayerState*)inner)->staffHoldFrames =
                (((PlayerState*)inner)->staffHoldFrames > 10) ? 10 : ((PlayerState*)inner)->staffHoldFrames;
            if (((PlayerState*)inner)->staffHoldFrames > 2)
            {
                ((PlayerState*)inner)->flags3F0.b80 = 0;
                ((PlayerState*)inner)->flags3F0.b10 = 0;
                ((PlayerState*)inner)->flags3F0.b08 = 0;
                Shield_setMode(gPlayerStaffObject, 2);
                ((PlayerState*)inner)->flags3F0.b02 = 0;
                ((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
                ObjHits_SyncObjectPositionIfDirty((GameObject*)obj);
                ((PlayerState*)inner)->flags3F0.b40 = 0;
                ((PlayerState*)inner)->flags3F0.b04 = 1;
                ((PlayerState*)inner)->flags3F4.b10 = 0;
                ((PlayerState*)inner)->isHoldingObject = 0;
                if (((PlayerState*)inner)->heldObj != NULL)
                {
                    s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.romDefNo;
                    if (t == SMALLBASKET_SEQUENCE_VARIANT_A || t == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                    {
                        SmallBasket_throw((GameObject*)(((PlayerState*)inner)->heldObj));
                    }
                    else
                    {
                        Carryable_putDownAndSavePos((GameObject*)((PlayerState*)inner)->heldObj);
                    }
                    ((PlayerState*)inner)->heldObj->anim.flags =
                        ((PlayerState*)inner)->heldObj->anim.flags & ~0x4000;
                    ((PlayerState*)inner)->heldObj->userData2 = 0;
                    ((PlayerState*)inner)->heldObj = 0;
                }
                ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
                return 3;
            }
        }
        if (!((PlayerState*)inner)->flags3F0.b20 && 0.0f != ((PlayerState*)inner)->verticalVel)
        {
            ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
            return 0x42;
        }
        if (!((PlayerState*)inner)->flags3F0.b20 && !((PlayerState*)inner)->flags3F0.b08 &&
            !((PlayerState*)inner)->flags3F0.b04 && ((PlayerState*)inner)->baddie.targetObj == NULL &&
            !((PlayerState*)inner)->flags3F6.b40 && ((PlayerState*)inner)->baddie.controlMode != 0x26)
        {
            ok = 1;
        }
        else
        {
            ok = 0;
        }
        if (ok != 0 && ((PlayerState*)inner)->heldObj != NULL && ((PlayerState*)inner)->isHoldingObject == 0)
        {
            if ((((PlayerState*)state)->baddie.queuedBitMask & 0x4000) != 0)
            {
                ((PlayerState*)state)->baddie.stateHandler = (int)playerResetMoveTables;
                return 7;
            }
            ((PlayerState*)state)->baddie.stateHandler = (int)playerResetMoveTables;
            return 8;
        }
        if (!((PlayerState*)inner)->flags3F0.b20 && !((PlayerState*)inner)->flags3F0.b08 &&
            !((PlayerState*)inner)->flags3F0.b04 && !((PlayerState*)inner)->flags3F0.b02 &&
            ((PlayerState*)inner)->baddie.targetObj == NULL && !((PlayerState*)inner)->flags3F6.b40 &&
            ((PlayerState*)inner)->baddie.controlMode != 0x26)
        {
            ok = 1;
        }
        else
        {
            ok = 0;
        }
        if (ok != 0)
        {
            r = playerState08((GameObject*)obj, state, fv);
            if (r != 0)
            {
                return r;
            }
        }
        if (((PlayerState*)state)->baddie.targetObj != NULL)
        {
            s16 t = ((PlayerState*)state)->baddie.controlMode;
            if (t != 0x24 && t != 0x25 && t != 0x26 && !((PlayerState*)inner)->flags3F6.b20 &&
                ((PlayerState*)state)->baddie.hasTarget == 1)
            {
                ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedEndIceSpellAndSettleHeading;
                return 0x25;
            }
        }
        {
            int btn = padGetTriggers(0);
            if ((btn & 0x20) != 0)
            {
                if (((PlayerState*)inner)->flags3F4.b40 && !((PlayerState*)inner)->flags3F0.b20 &&
                    !((PlayerState*)inner)->flags3F0.b08 && !((PlayerState*)inner)->flags3F0.b04 &&
                    ((PlayerState*)inner)->curAnimId != 0x44 && ((PlayerState*)inner)->heldObj == NULL &&
                    ((PlayerState*)inner)->baddie.targetObj == NULL && !((PlayerState*)inner)->flags3F6.b40 &&
                    ((PlayerState*)inner)->baddie.controlMode != 0x26 &&
                    (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0 &&
                    ((PlayerState*)inner)->idleDelayTimer == idleZero)
                {
                    ok = 1;
                }
                else
                {
                    ok = 0;
                }
                if (ok != 0 && !((PlayerState*)inner)->flags3F0.b02)
                {
                    Shield_setMode(gPlayerStaffObject, 1);
                    ObjAnim_SetCurrentMove(obj, 0x4f, obj->anim.currentMoveProgress, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 8);
                    if (gPlayerPathObject != NULL && ((PlayerState*)inner)->flags3F4.b40)
                    {
                        ((PlayerState*)inner)->staffActionRequest = 4;
                        ((PlayerState*)inner)->flags3F4.b08 = 1;
                    }
                    ((PlayerState*)state)->baddie.moveSpeed = 0.01f;
                    ((PlayerState*)inner)->flags3F0.b10 = 0;
                    ((PlayerState*)inner)->flags3F0.b40 = 0;
                    ((PlayerState*)inner)->flags3F0.b80 = 0;
                    ((PlayerState*)inner)->flags3F0.b08 = 0;
                    ((PlayerState*)inner)->flags3F0.b04 = 0;
                    ((PlayerState*)inner)->staffHoldFrames = 0;
                    ((PlayerState*)inner)->flags3F0.b02 = 1;
                    ((PlayerState*)inner)->isHoldingObject = 0;
                    if (((PlayerState*)inner)->heldObj != NULL)
                    {
                        s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.romDefNo;
                        if (t == SMALLBASKET_SEQUENCE_VARIANT_A || t == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                        {
                            SmallBasket_throw((GameObject*)(((PlayerState*)inner)->heldObj));
                        }
                        else
                        {
                            Carryable_putDownAndSavePos((GameObject*)((PlayerState*)inner)->heldObj);
                        }
                        ((PlayerState*)inner)->heldObj->anim.flags =
                            ((PlayerState*)inner)->heldObj->anim.flags & ~0x4000;
                        ((PlayerState*)inner)->heldObj->userData2 = 0;
                        ((PlayerState*)inner)->heldObj = 0;
                    }
                    ObjHits_MarkObjectPositionDirty((ObjAnimComponent*)obj);
                    ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreDefaultControl;
                    return 3;
                }
            }
        }
        if (((PlayerState*)inner)->flags3F0.b08 || ((PlayerState*)inner)->flags3F0.b04)
        {
            r = playerCheckIfClimbingOntoWall((int)obj, (int)inner, (int)state, buf, fv, 0x14);
            if (r == 0xc)
            {
                ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
                return 10;
            }
            if (r == 9)
            {
                f32 mid;
                f32 lo;
                f32 hi = ((PlayerState*)inner)->spanTopY - 5.0f;
                mid = 26.0f + ((GameObject*)obj)->anim.localPosY;
                lo = 30.0f + ((PlayerState*)inner)->spanBottomY;
                if (mid >= lo && mid <= hi)
                {
                    doRumble(10.0f);
                    ((PlayerState*)state)->baddie.nextStateExitFn = playerStagedRestoreCameraUnlessClimbing;
                    return 0x12;
                }
            }
        }
        if (((PlayerState*)inner)->flags3F0.b20)
        {
            r = playerCheckIfClimbingOntoWall((int)obj, (int)inner, (int)state, buf, 1.0f, 0x100);
            if (r == 5)
            {
                gPlayerCurrentMoveId = -1;
                ((PlayerState*)state)->baddie.nextStateExitFn = NULL;
                return 0xc;
            }
            if (((PlayerState*)inner)->waterDepth < 24.0f && ((PlayerState*)inner)->flags3F1.b01)
            {
                ((PlayerState*)inner)->flags3F0.b20 = 0;
            }
        }
        return 0;
    }
}

void playerSetMovingAnims(GameObject* p1, PlayerState* obj)
{
    char* t = (char*)lbl_80332EC0;
    ((PlayerState*)obj)->prevMoveAnimIds = ((PlayerState*)obj)->moveAnimIds;
    if (((PlayerState*)obj)->flags3F0.b20)
    {
        if (((PlayerState*)obj)->flags3F1.b20)
        {
            ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x310);
            ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0xd8);
        }
        else
        {
            ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x210);
            ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0xd8);
        }
    }
    else if (((PlayerState*)obj)->heldObj != NULL)
    {
        ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x250);
        ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0x390);
    }
    else if (((PlayerState*)obj)->flags3F1.b20)
    {
        if (((PlayerState*)obj)->staffGrown != 0)
        {
            ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x290);
            ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0x390);
        }
        else
        {
            ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x2d0);
            ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0x390);
        }
    }
    else if (((PlayerState*)obj)->staffGrown != 0)
    {
        ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x1d0);
        ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0x390);
    }
    else
    {
        ((PlayerState*)obj)->moveAnimIds = (s16*)(t + 0x190);
        ((PlayerState*)obj)->moveParamValues = (f32*)(t + 0x390);
    }
}

int playerUpdateAirborneMotion(GameObject* obj, struct PlayerState* inner, struct PlayerState* state)
{
    f32 hdiff;
    int sfx;
    f32 v[6];
    char* p35c;
    PlayerState* ps;
    obj->anim.velocityY = -((0.1f * timeDelta) - obj->anim.velocityY);
    p35c = ((char*)inner) + 0x35c;
    switch (obj->anim.currentMove)
    {
    case 0xa:

    case 0x54:

    case 0x90:
        inner->emissionState = 2;
        break;

    case 0x13:
    {
        f32 zz = 0.0f;
        state->baddie.animSpeedB = zz;
        obj->anim.velocityY = zz;
    }
        if (obj->anim.currentMoveProgress >= (5.0f * ((PlayerState*)state)->baddie.moveSpeed))
        {
            ((PlayerState*)inner)->flags3F2.b08 = 0;
        }
        else if ((((PlayerState*)inner)->fallSeverity >= 2) && (((PlayerState*)inner)->flags3F2.b04 == 0))
        {
            s8 hv;
            CameraShake_Enable();
            CameraShake_SetOffset(10.0f);
            ObjPath_GetPointWorldPosition(obj, 0xb, &v[3], &v[4], &v[5], 0);
            if (((PlayerState*)inner)->surfaceType == 0x1a)
            {
                hv = 0x14;
            }
            else
            {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, NULL, (int)hv, 1, 0, v[3], v[4], v[5]);
            ((PlayerState*)inner)->flags3F2.b04 = 1;
        }
        if ((*((s8*)(&((PlayerState*)state)->baddie.moveDone))) != 0)
        {
            ((PlayerState*)inner)->flags3F0.b04 = 0;
            ((PlayerState*)inner)->flags3F3.b40 = 1;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            return 1;
        }
        if (((PlayerState*)inner)->fallSeverity >= 2)
        {
            ((PlayerState*)inner)->emissionState = 4;
        }
        else
        {
            ((PlayerState*)inner)->emissionState = 3;
        }
        break;

    case 0xb:
    {
        f32 zz = 0.0f;
        ((PlayerState*)state)->baddie.animSpeedB = zz;
        if ((*((s8*)(&((PlayerState*)state)->baddie.moveDone))) != 0)
        {
            if ((*(*((s8**)p35c))) > 0)
            {
                ObjAnim_SetCurrentMove(obj, 0xc, zz, 0);
                ((PlayerState*)state)->baddie.moveSpeed = 0.008f;
            }
            else
            {
                ((PlayerState*)inner)->flags3F0.b04 = 0;
                ((PlayerState*)inner)->staffHoldFrames = 0;
                playerDie(obj);
            }
        }
        (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, timeDelta, 2);
        inner->emissionState = 4;
        break;
    }

    case 0xc:
        if ((state->baddie.eventFlags & 1) != 0 && inner->characterId != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_fox_bigfallgrunt2);
            Sfx_PlayFromObject(obj, SFXTRIG_foot_ladder2);
        }
        if (state->baddie.moveDone != 0) {
            inner->flags3F0.b04 = 0;
            inner->flags3F3.b40 = 1;
            inner->staffHoldFrames = 0;
            return 1;
        }
        (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)state, timeDelta, 2);
        inner->emissionState = 4;
        break;

    default:
        ObjAnim_SetCurrentMove(obj, 0x54, 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x14);
        ((PlayerState*)state)->baddie.moveSpeed = 0.05f;
        ((PlayerState*)inner)->emissionState = 2;
        ((PlayerState*)inner)->fallSeverity = 0;
        ((PlayerState*)inner)->flags3F0.b01 = 0;
        ((PlayerState*)inner)->flags3F2.b08 = 0;
        ((PlayerState*)inner)->flags3F2.b04 = 0;
        ((PlayerState*)inner)->flags3F2.b02 = 0;
        ((PlayerState*)inner)->prevWorldPosY = obj->anim.worldPosY;
        break;
    }

    ps = (PlayerState*)inner;
    hdiff = ((PlayerState*)inner)->prevWorldPosY - obj->anim.worldPosY;
    if ((((PlayerState*)inner)->flags3F1.b01 != 0) && (((PlayerState*)inner)->flags3F0.b01 == 0))
    {
        ((PlayerState*)inner)->flags3F0.b01 = 1;
        sfx = surfaceSfxSelectTrigger(ps->surfaceType, ps->footstepSoundId);
        if (hdiff > 260.0f)
        {
            s8 hv;
            doRumble(20.0f);
            CameraShake_Enable();
            CameraShake_SetOffset(15.0f);
            ObjAnim_SetCurrentMove(obj, 0xb, 0.0f, 0);
            state->baddie.moveSpeed = 0.015f;
            Sfx_PlayFromObject(obj, SFXTRIG_foot_crawl2);
            Sfx_PlayFromObject(obj, SFXTRIG_watery_bubble);
            ObjPath_GetPointWorldPosition(obj, 0xb, &v[3], &v[4], &v[5], 0);
            if (ps->surfaceType == 0x1a)
            {
                hv = 0x14;
            }
            else
            {
                hv = 2;
            }
            ObjHits_RecordPositionHit(obj, NULL, (int)hv, 2, 0, v[3], v[4], v[5]);
            ((PlayerState*)inner)->flags3F2.b08 = 0;
            if (ps->waterDepth > 1.5f)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle3);
            }
        }
        else if (hdiff > 130.0f)
        {
            doRumble(10.0f);
            ObjAnim_SetCurrentMove(obj, 0x13, 0.0f, 0);
            state->baddie.moveSpeed = 0.035f;
            Sfx_PlayFromObject(obj, sfx);
            Sfx_StopFromObject(obj,
                               (u16)((ps->characterId == 0) ? (SFXTRIG_jump2) : (SFXTRIG_sa_climb02)));
            ((PlayerState*)inner)->flags3F2.b08 = 1;
            if (ps->waterDepth > 1.5f)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle3_429);
            }
        }
        else if (hdiff > 52.0f)
        {
            doRumble(10.0f);
            ObjAnim_SetCurrentMove(obj, 0x13, 0.0f, 0);
            state->baddie.moveSpeed = 0.035f;
            Sfx_PlayFromObject(obj, sfx);
            Sfx_PlayFromObject(
                obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_panting2 : SFXTRIG_sa_jump03_var));
            ((PlayerState*)inner)->flags3F2.b08 = 1;
            if (((PlayerState*)inner)->waterDepth > 1.5f)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle3_42a);
            }
        }
        else
        {
            doRumble(5.0f);
            Sfx_PlayFromObject(0, sfx);
            ((PlayerState*)inner)->flags3F0.b04 = 0;
            ((PlayerState*)inner)->staffHoldFrames = 0;
            ((PlayerState*)inner)->flags3F1.b08 = 1;
            ((PlayerState*)inner)->flags3F2.b10 = 1;
            ((PlayerState*)inner)->flags3F2.b08 = 1;
            if (((PlayerState*)inner)->waterDepth > 1.5f)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle3_42b);
            }
        }
        if (hdiff > 52.0f)
        {
            f32 z2 = 0.0f;
            state->baddie.animSpeedC = z2;
            state->baddie.animSpeedA = z2;
        }
        state->baddie.animSpeedB = 0.0f;
    }
    if (((PlayerState*)inner)->flags3F0.b01 == 0)
    {
        if (((PlayerState*)state)->baddie.unk1B0 < 40.0f)
        {
            ((PlayerState*)inner)->flags3F2.b08 = 1;
        }
        if ((hdiff > 260.0f) && (ps->fallSeverity < 3))
        {
            ObjAnim_SetCurrentMove(obj, 0xa, 0.0f, 0);
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x19);
            state->baddie.moveSpeed = 0.01f;
            ps->fallSeverity = 3;
            ((PlayerState*)inner)->flags3F2.b08 = 0;
        }
        else if ((hdiff > 130.0f) && (ps->fallSeverity < 2))
        {
            if (Sfx_IsPlayingFromObject(
                    0, (u16)((((PlayerState*)inner)->characterId == 0) ? (SFXTRIG_jump2) : (SFXTRIG_sa_climb02))) == 0)
            {
                Sfx_PlayFromObject(obj, (u16)((ps->characterId == 0) ? (SFXTRIG_jump2) : (SFXTRIG_sa_climb02)));
            }
            ((PlayerState*)inner)->fallSeverity = 2;
        }
        else if ((hdiff > 52.0f) && (((PlayerState*)inner)->fallSeverity < 1))
        {
            ObjAnim_SetCurrentMove(obj, 0x90, 0.0f, 0);
            ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x19);
            ((PlayerState*)state)->baddie.moveSpeed = 0.1f;
            ((PlayerState*)inner)->fallSeverity = 1;
        }
    }
    if ((((PlayerState*)inner)->flags3F2.b08 != 0) &&
        ((((PlayerState*)inner)->buttonsJustPressed & 0x400) != 0))
    {
        ((PlayerState*)inner)->flags3F2.b02 = 1;
        ((PlayerState*)inner)->buttonsJustPressed = ps->buttonsJustPressed & (~0x400);
    }
    if (((((PlayerState*)inner)->flags3F0.b01 != 0) && (((PlayerState*)inner)->flags3F2.b02 != 0)) &&
        (ps->fallSeverity < 3))
    {
        playerStartStaffAttack(obj, inner, state);
        ((PlayerState*)inner)->flags3F0.b04 = 0;
        ps->staffHoldFrames = 0;
    }
    if ((ps->fallSeverity == 0) && (((PlayerState*)inner)->flags3F4.b10 == 0))
    {
        f32 c;
        ps->targetYawSmoothRate = 60.0f;
        ps->targetYawRateLimit = 0.5f;
        ps->yawSmoothRate = 60.0f;
        ps->yawRateLimit = 0.5f;
        c = 0.2f;
        ps->targetAnimSpeed = c;
        ps->currentSpeed = ps->currentSpeed * c;
    }
    else
    {
        f32 a;
        f32 b;
        ps->targetYawSmoothRate = (a = 60.0f);
        ps->targetYawRateLimit = (b = 0.0f);
        ps->yawSmoothRate = a;
        ps->yawRateLimit = b;
        ps->targetAnimSpeed = b;
        ps->currentSpeed = ps->currentSpeed * b;
    }
    ps->currentSpeed = (ps->currentSpeed < 0.71982f)
                           ? 0.71982f
                           : ((ps->currentSpeed > ps->maxSpeed) ? (ps->maxSpeed) : (ps->currentSpeed));
    if (ps->curAnimId == 0x4b)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, (void*)0, 0, 0xff);
        ps->curAnimId = 0x42;
    }
    return 0;
}

int playerUpdateFallingMotion(GameObject* obj, PlayerState* inner, PlayerState* p3)
{
    obj->anim.velocityY = obj->anim.velocityY - lbl_803DC67C * timeDelta;
    if (((PlayerState*)inner)->fallFrames > 5 && ((PlayerState*)inner)->flags3F1.b01)
    {
        u16 snd;
        doRumble(5.0f);
        Sfx_PlayFromObject(obj, (u16)surfaceSfxSelectTrigger(((PlayerState*)inner)->surfaceType,
                                                                 ((PlayerState*)inner)->footstepSoundId));
        if (((PlayerState*)inner)->characterId == 0)
        {
            snd = 0x2cf;
        }
        else
        {
            snd = 0x25;
        }
        Sfx_PlayFromObject(obj, snd);
        ((PlayerState*)inner)->flags3F0.b08 = 0;
        ((PlayerState*)inner)->flags3F1.b08 = 1;
        ((PlayerState*)inner)->flags3F2.b10 = 1;
    }
    if (obj->anim.worldPosY <= ((PlayerState*)inner)->fallThresholdY ||
        ((((PlayerState*)p3)->baddie.surfaceFlags & 2) && (((PlayerState*)p3)->baddie.surfaceFlags & 0x20) == 0) || ((PlayerState*)p3)->baddie.groundContact != 0)
    {
        GameObject* sub;
        inner->flags3F0.b80 = 0;
        inner->flags3F0.b10 = 0;
        inner->flags3F0.b08 = 0;
        Shield_setMode(gPlayerStaffObject, 2);
        inner->flags3F0.b02 = 0;
        inner->flags360 |= PLAYER_FLAG_TELEPORTED;
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((PlayerState*)inner)->flags3F0.b40 = 0;
        ((PlayerState*)inner)->flags3F0.b04 = 1;
        ((PlayerState*)inner)->flags3F4.b10 = 0;
        ((PlayerState*)inner)->isHoldingObject = 0;
        sub = ((PlayerState*)inner)->heldObj;
        if (sub != NULL)
        {
            s16 id = sub->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
            {
                SmallBasket_throw((GameObject*)sub);
            }
            else
            {
                Carryable_putDownAndSavePos((GameObject*)sub);
            }
            ((PlayerState*)inner)->heldObj->anim.flags &= ~0x4000;
            ((PlayerState*)inner)->heldObj->userData2 = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
    inner->fallFrames += 1;
    {
        u32 v = ((PlayerState*)inner)->fallFrames;
        if (v > 0xa)
            v = 0xa;
        ((PlayerState*)inner)->fallFrames = v;
    }
    inner->emissionState = 1;
    {
        inner->targetYawSmoothRate = 40.0f;
        inner->targetYawRateLimit = 0.9f;
        inner->yawSmoothRate = 40.0f;
        inner->yawRateLimit = 0.9f;
    }
    inner->targetAnimSpeed = lbl_803DC684;
    {
        ((PlayerState*)inner)->currentSpeed =
            (((PlayerState*)inner)->currentSpeed < 0.0f)
                ? 0.0f
                : ((((PlayerState*)inner)->currentSpeed > ((PlayerState*)inner)->maxSpeed)
                       ? ((PlayerState*)inner)->maxSpeed
                       : ((PlayerState*)inner)->currentSpeed);
    }
    return 0;
}

void playerUpdateWaterMotion(GameObject* obj, PlayerState* inner, PlayerState* state)
{
    f32 t[3];
    f32 waterX;
    f32 waterZ;
    MatrixTransform v;
    struct
    {
        u8 pad[6];
        u16 mode;
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 mtx[16];
    f32 angle;
    f32 d;
    f32 accel;
    f32 vel;
    f32 cosv;
    f32 sinv;
    f32 a;
    int playEffect;
    u8 loopCount;
    int i;

    angle = ((PlayerState*)inner)->waterSurfaceY;
    angle = angle + mathSinf(3.1415927f * (f32)(u32) * (u16*)((char*)inner + 0x89c) / 32768.0f);
    ((PlayerState*)inner)->unk89C = 256.0f * timeDelta + (f32)(u32) * (u16*)((char*)inner + 0x89c);
    {
        d = angle - obj->anim.localPosY;
        if (d > 25.0f)
        {
            d = 25.0f;
        }
        accel = d / 25.0f;
        accel *= 0.13f;
        obj->anim.velocityY = accel * timeDelta + obj->anim.velocityY;
    }
    obj->anim.velocityY = obj->anim.velocityY - 0.1f * timeDelta;
    obj->anim.velocityY = obj->anim.velocityY * powfBitEstimate(0.96f, timeDelta);
    {
        vel = obj->anim.velocityY;
        obj->anim.velocityY = (vel < -4.0f) ? -4.0f : ((vel > 1.4f) ? 1.4f : vel);
    }
    playerCalcWaterCurrent(&waterX, &waterZ, 1.0f, obj);
    {
        cosv = mathSinf(3.1415927f * (f32)inner->targetYaw / 32768.0f);
        sinv = mathCosf(3.1415927f * (f32)inner->targetYaw / 32768.0f);
        a = -waterZ * sinv - waterX * cosv;
        ((PlayerState*)inner)->waterCurrentVelB +=
            timeDelta * (0.1f * ((waterX * sinv - waterZ * cosv) - ((PlayerState*)inner)->waterCurrentVelB));
        ((PlayerState*)inner)->waterCurrentVelA += timeDelta * (0.1f * (a - ((PlayerState*)inner)->waterCurrentVelA));
    }
    playEffect = 0;
    if (((PlayerState*)state)->baddie.controlMode == 1)
    {
        if ((((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            Sfx_PlayAtPositionFromObject(obj, obj->anim.localPosX,
                                         ((PlayerState*)inner)->waterSurfaceY, obj->anim.localPosZ, 0xe);
        }
        if (((PlayerState*)inner)->waterDepth < 25.0f &&
            (((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            t[0] = (f32)randomGetRange(-0x14, 0x14) / 10.0f;
            t[2] = (f32)randomGetRange(-0x14, 0x14) / 10.0f;
            playEffect = 1;
        }
    }
    else
    {
        if ((((PlayerState*)state)->baddie.eventFlags & 1) != 0)
        {
            Sfx_PlayAtPositionFromObject(obj, obj->anim.localPosX,
                                         ((PlayerState*)inner)->waterSurfaceY, obj->anim.localPosZ, 0xf);
        }
        if (((PlayerState*)inner)->waterDepth < 25.0f &&
            (((PlayerState*)state)->baddie.eventFlags & 0x200) != 0)
        {
            s8 c;
            t[0] = (f32)randomGetRange(-0x14, 0x14) / 10.0f;
            c = ((PlayerState*)inner)->gaitLevel;
            if (c <= 8)
            {
                t[2] = -15.0f;
            }
            else if (c <= 0xc)
            {
                t[2] = -15.0f;
            }
            else
            {
                t[2] = -15.0f;
            }
            playEffect = 1;
        }
    }
    if (playEffect != 0)
    {
        v.x = obj->anim.localPosX;
        v.y = 0.0f;
        v.z = obj->anim.localPosZ;
        v.rotX = ((PlayerState*)inner)->targetYaw;
        v.rotY = 0;
        v.rotZ = 0;
        v.scale = 1.0f;
        setMatrixFromObjectPos(mtx, &v);
        Matrix_TransformPoint(mtx, t[0], 0.0f, t[2], &t[0], &t[1], &t[2]);
        (*gWaterfxInterface)->spawnRipple(
            t[0], ((PlayerState*)inner)->waterSurfaceY, t[2], 0, 0.0f, 5);
        if (((PlayerState*)inner)->waterDepth > 17.0f && ((PlayerState*)state)->baddie.animSpeedC > 0.4f)
        {
            u16 ang = ((PlayerState*)inner)->targetYaw -
                      getAngle(((PlayerState*)state)->baddie.animSpeedB, ((PlayerState*)state)->baddie.animSpeedA);
            (*gWaterfxInterface)->spawnSimpleRipple(
                t[0], ((PlayerState*)inner)->waterSurfaceY, t[2], ang, 0.0f);
        }
    }
    ObjPath_GetPointWorldPosition(obj, 0x13, &v.x, &v.y, &v.z, 0);
    loopCount = (((PlayerState*)inner)->waterSurfaceY - v.y > 5.0f) ? 1 : 0;
    for (i = 0; i < loopCount; i++)
    {
        pfx.x = v.x + (f32)randomGetRange(-0x64, 0x64) / 20.0f;
        pfx.y = v.y + (f32)randomGetRange(-0x64, 0x64) / 50.0f;
        pfx.z = v.z + (f32)randomGetRange(-0x64, 0x64) / 20.0f;
        pfx.scale = ((PlayerState*)inner)->waterSurfaceY - pfx.y;
        if (pfx.scale > 0.0f)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x202, &pfx, 0x200001, -1, NULL);
        }
    }
}

int playerUpdateQuickTurn(GameObject* obj, PlayerState* inner, PlayerState* state)
{
    f32 h;
    f32 lim;

    ((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HEADING_LOCK;
    ((PlayerState*)state)->baddie.moveSpeed = 0.025f;
    h = obj->anim.currentMoveProgress;
    if (h > 0.1f && h < 0.25f &&
        ((PlayerState*)state)->baddie.animSpeedC >
            ((PlayerState*)inner)->moveParamValues[7] - 0.4f &&
        ((PlayerState*)state)->baddie.inputMagnitude > 0.8f && ((PlayerState*)inner)->yawRateSigned >= 0x96)
    {
        ((PlayerState*)inner)->flags3F0.b40 = 1;
        ((PlayerState*)inner)->flags3F0.b80 = 0;
        ((PlayerState*)inner)->animSoundId = ((PlayerState*)inner)->altAnimSoundId;
        ((PlayerState*)state)->baddie.moveSpeed = 0.033f;
        ObjAnim_SetCurrentMove(obj, ((PlayerState*)inner)->moveAnimIds[29], 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0x10);
        ((PlayerState*)inner)->unk858 = ((PlayerState*)inner)->yaw;
        ((PlayerState*)inner)->animSpeedRate = (0.2f + (((PlayerState*)inner)->moveParamValues[5] +
                                                         ((PlayerState*)state)->baddie.animSpeedC)) /
                                        30.0f;
        ((PlayerState*)inner)->targetYaw = ((PlayerState*)inner)->yaw;
        ((PlayerState*)inner)->yaw += 0x8000;
        ((PlayerState*)state)->baddie.animSpeedC = -((PlayerState*)state)->baddie.animSpeedC;
        ((PlayerState*)state)->baddie.animSpeedA = -((PlayerState*)state)->baddie.animSpeedA;
    }
    if (((PlayerState*)inner)->flags3F0.b80)
    {
        if (((PlayerState*)state)->baddie.animSpeedC <=
                (lim = ((PlayerState*)inner)->moveParamValues[4]) &&
            ((PlayerState*)state)->baddie.animSpeedA <= lim)
        {
            ((PlayerState*)inner)->lastInputHeading = ((PlayerState*)inner)->yaw;
            ((PlayerState*)inner)->flags3F0.b40 = 0;
            ((PlayerState*)inner)->flags3F0.b80 = 0;
            return 1;
        }
        inner->currentSpeed = 0.0f;
        inner->velSmoothRate = inner->velSmoothRateBase;
    }
    return 0;
}

void playerUpdateStaffAttack(GameObject* obj, PlayerState* state, PlayerState* p3)
{
    f32 v;
    u32 b;
    f32 ee0;

    (*gPlayerInterface)->updateAnimRootMotion(obj, (void*)p3, timeDelta, 1);
    if (obj->anim.currentMoveProgress >=
        (ee0 = 1.0f) - 11.0f * ((PlayerState*)p3)->baddie.moveSpeed)
    {
        ((PlayerState*)p3)->baddie.animSpeedA =
            ((PlayerState*)state)->animSpeedRate * ((0.2f + ((PlayerState*)state)->moveParamValues[5]) -
                                             ((PlayerState*)p3)->baddie.animSpeedA) +
            *(f32*)&((PlayerState*)p3)->baddie.animSpeedA;
        ((PlayerState*)p3)->baddie.animSpeedC = ((PlayerState*)p3)->baddie.animSpeedA;
        ((PlayerState*)state)->animSpeedRate = 0.1f * timeDelta + ((PlayerState*)state)->animSpeedRate;
        v = ((PlayerState*)state)->animSpeedRate;
        ((PlayerState*)state)->animSpeedRate = (v < 0.0f) ? 0.0f : ((v > ee0) ? ee0 : v);
    }
    if ((((PlayerState*)p3)->baddie.eventFlags & 0x200) != 0)
    {
        doRumble(5.0f);
        Sfx_PlayFromObject(obj, SFXTRIG_rserv1_c);
        state->pendingFxFlags |= 4;
    }
    {
        f32 fa4 = 20.0f;
        state->targetYawSmoothRate = fa4;
        state->yawSmoothRate = fa4;
    }
    b = ((PlayerState*)state)->flags3F1.b10;
    if (b != 0)
    {
        f32 ea4 = 0.0f;
        ((PlayerState*)state)->targetYawRateLimit = ea4;
        ((PlayerState*)state)->yawRateLimit = ea4;
    }
    else
    {
        f32 ed4 = 2.0f;
        ((PlayerState*)state)->targetYawRateLimit = ed4;
        ((PlayerState*)state)->yawRateLimit = ed4;
    }
    ((PlayerState*)state)->knockbackDrainRate = 4.0f;
    if (obj->anim.currentMoveProgress >= 1.0f)
    {
        short tmp;
        state->flags3F0.b10 = 0;
        gPlayerModelChainStyle = 1;
        ((PlayerState*)state)->flags3F1.b02 = 1;
        ((PlayerState*)state)->flags3F1.b08 = 1;
        *(u8*)&((PlayerState*)state)->gaitLevel = 0xc;
        tmp = ((PlayerState*)state)->yaw;
        ((PlayerState*)state)->targetYaw = tmp;
        ((PlayerState*)state)->lastInputHeading = tmp;
        ObjAnim_SetCurrentMove(obj, gPlayerMoveTableA[(s8) ((PlayerState*)state)->gaitLevel], 0.0f, 0);
        ObjAnim_SetCurrentEventStepFrames(&obj->anim, 1);
    }
}

void playerEnterDeepWater(GameObject* obj, PlayerState* inner, PlayerState* state)
{
    GameObject* sub;
    f32 z;

    ((PlayerState*)inner)->flags3F1.b40 = 0;
    ((PlayerState*)inner)->flags3F0.b40 = 0;
    ((PlayerState*)inner)->flags3F0.b80 = 0;
    ((PlayerState*)inner)->flags3F0.b08 = 0;
    ((PlayerState*)inner)->flags3F0.b04 = 0;
    ((PlayerState*)inner)->staffHoldFrames = 0;
    ((PlayerState*)inner)->flags3F0.b20 = 1;
    ((PlayerState*)inner)->flags3F0.b10 = 0;
    z = 0.0f;
    inner->waterCurrentVelB = z;
    inner->waterCurrentVelA = z;
    Sfx_StopFromObject(obj, (u16)(inner->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02));

    if (gPlayerPathObject != NULL && ((PlayerState*)inner)->flags3F4.b40)
    {
        ((PlayerState*)inner)->staffActionRequest = 1;
        ((PlayerState*)inner)->flags3F4.b08 = 1;
    }
    ((PlayerState*)inner)->isHoldingObject = 0;
    sub = ((PlayerState*)inner)->heldObj;
    if (sub != NULL)
    {
        s16 id = sub->anim.romDefNo;
        if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
        {
            SmallBasket_throw(sub);
        }
        else
        {
            Carryable_putDownAndSavePos(sub);
        }
        *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) &= ~0x4000;
        ((PlayerState*)inner)->heldObj->userData2 = 0;
        ((PlayerState*)inner)->heldObj = 0;
    }
    if (((GameObject*)obj)->anim.velocityY < -2.0f)
    {
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_mv_curtainopen16_212);
        (*gWaterfxInterface)
            ->spawnSplashBurst((void*)obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ, 10.0f);
    }
}

void playerStartWallTransition(GameObject* obj, PlayerState* inner, PlayerState* state)
{
    if (obj->anim.currentMoveProgress > 0.5f)
    {
        ObjAnim_SetCurrentMove(obj, 0x91, 0.0f, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove(obj, 0x12, 0.0f, 0);
    }
    ObjAnim_SetCurrentEventStepFrames(&obj->anim, 0xf);

    ((PlayerState*)inner)->maxSpeed = 1.9f;
    ((PlayerState*)inner)->currentSpeed = 0.75f * (2.3993998f * ((PlayerState*)state)->baddie.inputMagnitude) +
                                          0.15f * ((PlayerState*)state)->baddie.animSpeedC;
    ((PlayerState*)inner)->currentSpeed = (((PlayerState*)inner)->currentSpeed < 0.7f)
                                              ? 0.7f
                                              : ((((PlayerState*)inner)->currentSpeed > ((PlayerState*)inner)->maxSpeed)
                                                     ? ((PlayerState*)inner)->maxSpeed
                                                     : ((PlayerState*)inner)->currentSpeed);
    {
        f32 a = ((PlayerState*)inner)->currentSpeed;
        ((PlayerState*)state)->baddie.animSpeedA = a;
        ((PlayerState*)state)->baddie.animSpeedC = a;
    }

    obj->anim.velocityY = ((PlayerState*)state)->baddie.animSpeedA / 1.9f;
    {
        f32 v = obj->anim.velocityY;
        f32 clamped;
        if (v < 0.0f)
        {
            clamped = 0.0f;
        }
        else if (v > 1.0f)
        {
            clamped = 1.0f;
        }
        else
        {
            clamped = v;
        }
        obj->anim.velocityY = clamped;
    }
    obj->anim.velocityY = obj->anim.velocityY * lbl_803DC680;
    obj->anim.velocityY = (obj->anim.velocityY < 0.5f)
                              ? 0.5f
                              : ((obj->anim.velocityY > lbl_803DC680) ? lbl_803DC680 : obj->anim.velocityY);
    state->baddie.moveSpeed = 1.0f / (2.0f * lbl_803DC680 / lbl_803DC67C);
    inner->groundRefY = obj->anim.worldPosY;
    inner->fallThresholdY = obj->anim.worldPosY - 10.0f;

    inner->flags3F0.b08 = 1;
    inner->flags3F0.b04 = 0;
    inner->staffHoldFrames = 0;
    inner->flags3F0.b10 = 0;
    inner->flags3F0.b80 = 0;
    Shield_setMode(gPlayerStaffObject, 2);
    inner->flags3F0.b02 = 0;
    inner->flags360 |= PLAYER_FLAG_TELEPORTED;
    ObjHits_SyncObjectPositionIfDirty(obj);
    if (((PlayerState*)inner)->flags3F0.b40)
    {
        ((PlayerState*)inner)->yaw += -0x8000;
    }
    ((PlayerState*)inner)->flags3F0.b40 = 0;
    ((PlayerState*)inner)->flags3F1.b01 = 0;
    ((PlayerState*)inner)->fallFrames = 0;
    if (((PlayerState*)inner)->flags3F1.b20)
    {
        int t = *(s16*)obj;
        ((PlayerState*)inner)->yaw = t;
        ((PlayerState*)inner)->targetYaw = t;
        ((PlayerState*)inner)->lastInputHeading = t;
        ((PlayerState*)inner)->baddie.animSpeedB = 0.0f;
    }
    ((PlayerState*)inner)->flags3F1.b20 = 0;
    if (((PlayerState*)inner)->flags3F1.b10 && ((PlayerState*)inner)->curAnimId != 0x48 &&
        ((PlayerState*)inner)->curAnimId != 0x47 && getCurSeqNo() == 0)
    {
        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
        inner->flags3F1.b10 = 0;
    }
    {
        u16 sfxId;
        if (((PlayerState*)inner)->characterId == 0)
        {
            sfxId = 0x2d7;
        }
        else
        {
            sfxId = 0x2d6;
        }
        Sfx_PlayFromObject(obj, sfxId);
    }
    inner->isHoldingObject = 0;
    {
        GameObject* sub = ((PlayerState*)inner)->heldObj;
        if (sub != NULL)
        {
            s16 id = sub->anim.romDefNo;
            if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
            {
                SmallBasket_throw((GameObject*)sub);
            }
            else
            {
                Carryable_putDownAndSavePos((GameObject*)sub);
            }
            ((PlayerState*)inner)->heldObj->anim.flags &= ~0x4000;
            ((PlayerState*)inner)->heldObj->userData2 = 0;
            ((PlayerState*)inner)->heldObj = 0;
        }
    }
}

void playerStartStaffAttack(GameObject* obj, PlayerState* state, PlayerState* p3)
{
    u16 sound;
    u32 b;

    if (((PlayerState*)state)->staffGrown != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0x47f, 0.0f, 0);
    }
    else
    {
        ObjAnim_SetCurrentMove(obj, 0x47b, 0.0f, 0);
    }
    ((PlayerState*)p3)->baddie.moveSpeed = 0.025f;
    ((PlayerState*)state)->targetYaw = ((PlayerState*)state)->yaw;
    ((PlayerState*)state)->animSpeedRate = 0.0f;
    ((PlayerState*)state)->flags3F0.b10 = 1;
    ((PlayerState*)state)->flags3F0.b80 = 0;
    Shield_setMode(gPlayerStaffObject, 2);
    state->flags3F0.b02 = 0;
    state->flags360 |= PLAYER_FLAG_TELEPORTED;
    ObjHits_SyncObjectPositionIfDirty(obj);
    state->flags3F0.b08 = 0;
    state->flags3F0.b04 = 0;
    state->staffHoldFrames = 0;
    state->flags3F0.b40 = 0;
    state->yawRateSigned = 0;
    state->targetYawRateSigned = 0;
    state->yawRate = 0;
    state->targetYawRate = 0;
    gPlayerModelChainStyle = 4;
    ((PlayerState*)state)->isHoldingObject = 0;
    if (((PlayerState*)state)->heldObj != NULL)
    {
        short id = ((GameObject*)((PlayerState*)state)->heldObj)->anim.romDefNo;
        if (id == SMALLBASKET_SEQUENCE_VARIANT_A || id == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
        {
            SmallBasket_throw((GameObject*)(((PlayerState*)state)->heldObj));
        }
        else
        {
            Carryable_putDownAndSavePos((GameObject*)((PlayerState*)state)->heldObj);
        }
        *(s16*)((char*)((PlayerState*)state)->heldObj + 6) &= ~0x4000;
        ((PlayerState*)state)->heldObj->userData2 = 0;
        ((PlayerState*)state)->heldObj = 0;
    }
    b = ((PlayerState*)state)->flags3F1.b20;
    if (b != 0)
    {
        short t = obj->anim.rotX;
        ((PlayerState*)state)->yaw = t;
        ((PlayerState*)state)->targetYaw = t;
        ((PlayerState*)state)->lastInputHeading = t;
        ((PlayerState*)state)->baddie.animSpeedB = 0.0f;
    }
    ((PlayerState*)state)->flags3F1.b20 = 0;
    if (((PlayerState*)state)->waterDepth > 1.0f)
    {
        if (((PlayerState*)state)->characterId == 0)
        {
            sound = 0x427;
        }
        else
        {
            sound = 0x427;
        }
        Sfx_PlayFromObject(obj, sound);
    }
    else
    {
        if (((PlayerState*)state)->characterId == 0)
        {
            sound = 0x3ce;
        }
        else
        {
            sound = 0x2e;
        }
        Sfx_PlayFromObject(obj, sound);
    }
}

void staffAnimate(GameObject* obj, void* state, f32 dt)
{
    int prevChanged;
    int changed;
    int model;
    f32 moveStepScale;
    f32 shrinkRate;
    GameObject* p;

    model = *(int*)((char*)Obj_GetActiveModel((GameObject*)obj) + 0x30);
    prevChanged = 0;

    if (((PlayerState*)state)->staffAnimState != 3)
    {
        u8 b = ((PlayerState*)state)->staffActionRequest;
        if (b == 1)
        {
            staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 0, ((PlayerState*)state)->flags3F4.b08, 0);
            ((PlayerState*)state)->staffGrown = 0;
            if (((PlayerState*)state)->staffAnimState != 0 &&
                ((PlayerState*)state)->staffAnimState != 0xf)
            {
                ((PlayerState*)state)->staffAnimState = 3;
            }
        }
        else if (b == 4)
        {
            staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 1, ((PlayerState*)state)->flags3F4.b08, 0);
            ((PlayerState*)state)->staffGrown = 1;
            if (((PlayerState*)state)->staffAnimState != 0 &&
                ((PlayerState*)state)->staffAnimState != 0xf)
            {
                ((PlayerState*)state)->staffAnimState = 3;
            }
        }
    }

    shrinkRate = 0.025f;
    moveStepScale = -shrinkRate;
    do
    {
        changed = 0;
        switch (((PlayerState*)state)->staffAnimState)
        {
        case 2:
            if (prevChanged != 0)
            {
                Object_ObjAnimSetMove(obj, ((GameObject*)obj)->anim.currentMove,
                                      ((GameObject*)obj)->anim.currentMoveProgress, 0);
                p = ((PlayerState*)state)->cameraTargetObject;
                if (p != NULL && (p->anim.classId == 0x1c || p->anim.classId == 0x2a))
                {
                    Object_ObjAnimSetMove(obj, 0x82, 0.0f, 0);
                }
                else
                {
                    Object_ObjAnimSetMove(obj, 0x8d, 0.0f, 0);
                }
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
            }
            if (((GameObject*)obj)->anim.activeMoveProgress >= 0.45f)
            {
                ((PlayerState*)state)->staffGrown = 1;
            }
            if (((GameObject*)obj)->anim.activeMoveProgress >= 0.85f)
            {
                staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 1, 0, 0);
                ((PlayerState*)state)->staffAnimState = 3;
                changed = 1;
            }
            else
            {
                Object_ObjAnimAdvanceMove(obj, 0.025f, 1.0f, NULL);
            }
            break;
        case 1:
            if (prevChanged != 0)
            {
                Object_ObjAnimSetMove(obj, ((GameObject*)obj)->anim.currentMove,
                                      ((GameObject*)obj)->anim.currentMoveProgress, 0);
                p = ((PlayerState*)state)->cameraTargetObject;
                if (p != NULL && (p->anim.classId == 0x1c || p->anim.classId == 0x2a))
                {
                    Object_ObjAnimSetMove(obj, 0x82, 0.99f, 0);
                }
                else
                {
                    Object_ObjAnimSetMove(obj, 0x8d, 0.99f, 0);
                }
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
            }
            if (((GameObject*)obj)->anim.activeMoveProgress <= 0.45f)
            {
                ((PlayerState*)state)->staffGrown = 0;
            }
            if (((GameObject*)obj)->anim.activeMoveProgress <= 0.15f)
            {
                ((PlayerState*)state)->staffAnimState = 3;
                changed = 1;
            }
            else
            {
                Object_ObjAnimAdvanceMove(obj, moveStepScale, 1.0f, NULL);
            }
            break;
        case 0xf:
            if (prevChanged != 0)
            {
                Object_ObjAnimSetMove(obj, ((GameObject*)obj)->anim.currentMove,
                                      ((GameObject*)obj)->anim.currentMoveProgress, 0);
                Object_ObjAnimSetMove(obj, lbl_8033366C[((PlayerState*)state)->moveVariantIndex], 0.0f, 0);
                ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 0xc);
            }
            if (((GameObject*)obj)->anim.activeMoveProgress >= 1.0f || !staffCanContinueSpin(state))
            {
                ((PlayerState*)state)->staffAnimState = 3;
                ((PlayerState*)state)->moveVariantIndex = 0xff;
                changed = 1;
            }
            else
            {
                Object_ObjAnimAdvanceMove(obj, lbl_8033369C[((PlayerState*)state)->moveVariantIndex], timeDelta, NULL);
            }
            break;
        case 3:
            if (((GameObject*)obj)->anim.activeMove != ((GameObject*)obj)->anim.currentMove)
            {
                Object_ObjAnimSetMove(obj, ((GameObject*)obj)->anim.currentMove,
                                      ((GameObject*)obj)->anim.currentMoveProgress, 0);
            }
            if (*(u16*)((char*)model + 0x58) == 0)
            {
                ((GameObject*)obj)->anim.activeMove = -1;
                ((PlayerState*)state)->staffAnimState = 0;
            }
            else
            {
                Object_ObjAnimAdvanceMove(obj, 0.0f, timeDelta, NULL);
                Object_ObjAnimSetMoveProgress((ObjAnimComponent*)obj, obj->anim.currentMoveProgress);
            }
            break;
        default:
            if (((PlayerState*)state)->staffGrown != 0)
            {
                if (((PlayerState*)state)->staffActionRequest == 0)
                {
                    staffDoGrowShrinkAnim((GameObject*)gPlayerPathObject, 0, 0, 0);
                    ((PlayerState*)state)->staffAnimState = 1;
                    changed = 1;
                }
            }
            else if (((PlayerState*)state)->staffActionRequest == 2)
            {
                ((PlayerState*)state)->staffAnimState = 2;
                changed = 1;
            }
            if (((PlayerState*)state)->moveVariantIndex == 5 || ((PlayerState*)state)->moveVariantIndex == 7)
            {
                ((PlayerState*)state)->staffAnimState = 0xf;
                changed = 1;
            }
            break;
        }
        prevChanged = changed;
    } while (changed != 0);
}

void playerProcessQueuedItemCommand(GameObject* obj, PlayerState* state)
{
    u8 noMatch;
    s16 cmd;
    s16 item;

    if (((PlayerState*)state)->buttonsJustPressed & PAD_BUTTON_Y)
    {
        int yButtonItemResult;
        if (((PlayerState*)state)->buttonsJustPressed & PAD_BUTTON_Y)
        {
            yButtonItemResult = getYButtonItem(&item);
        }
        if (yButtonItemResult == 1)
        {
            buttonDisable(0, PAD_BUTTON_Y);
            ((PlayerState*)state)->buttonsJustPressed &= ~PAD_BUTTON_Y;
            ((PlayerState*)state)->queuedItemCommand = item;
        }
    }

    cmd = ((PlayerState*)state)->queuedItemCommand;
    if (cmd != -1 && cmd != ((PlayerState*)state)->animState && getCurSeqNo() == 0)
    {
        s16 sel = ((PlayerState*)state)->queuedItemCommand;
        noMatch = 0;
        switch (sel)
        {
        case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
        case 0x958:
        case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
            if (playerCanCastBlasterSpell(obj, state, sel) != 0)
            {
                ByteFlags* flags = &((PlayerState*)state)->flags3F1;
                u8 c8;
                if (((PlayerState*)state)->baddie.targetObj != NULL)
                {
                    break;
                }
                c8 = ((PlayerState*)state)->curAnimId;
                if (c8 == 0x49)
                {
                    break;
                }
                if (c8 == 0x52 && !flags->b20 && !flags->b10 && ((PlayerState*)state)->baddie.controlMode != 0x1d)
                {
                    break;
                }
                if (flags->b20)
                {
                    s16 v = obj->anim.rotX;
                    state->yaw = v;
                    state->targetYaw = v;
                    state->lastInputHeading = v;
                    state->baddie.animSpeedB = 0.0f;
                }
                flags->b20 = 0;
                if (flags->b10)
                {
                    u8 c = ((PlayerState*)state)->curAnimId;
                    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0)
                    {
                        (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0x1e, 0xff);
                        flags->b10 = 0;
                    }
                }
                Camera_setBlendCurveMode(2);
                (*gCameraInterface)->setMode(CAMERA_MODE_FORCE_BEHIND_RESOURCE_ID, 1, 0, 0, NULL, 0x2d, 0xff);
                state->flags3F6.b40 = 1;
                (*gPlayerInterface)->setState(obj, (void*)state, 0x2a);
                state->baddie.stateExitFn = (BaddieStateExitFn)playerStagedEndIceSpellAndRestoreCamera;
                playerCastSpell(obj, state, state->queuedItemCommand);
            } else {
                noMatch = 1;
            }
            break;
        case GAMEBIT_STAFF_ABILITY_STAFF_BOOSTER:
            if (playerCanUseStaffBooster(obj, state) != 0) {
                playerCastSpell(obj, state, state->queuedItemCommand);
            } else {
                noMatch = 1;
            }
            break;
        case GAMEBIT_STAFF_ABILITY_GROUND_QUAKE:
        case GAMEBIT_STAFF_ABILITY_SUPER_QUAKE:
            if (playerCanCastQuakeSpell(obj, state) != 0) {
                playerCastSpell(obj, state, state->queuedItemCommand);
            } else {
                noMatch = 1;
            }
            break;
        case GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE: {
            PlayerState* inner = obj->extra;
            int ok;
            if (state->baddie.targetObj != NULL || (inner->playerStatus)->magic < 0xa || inner->flags3F3.b08) {
                ok = 0;
            } else if (state->baddie.controlMode == 1 || state->baddie.controlMode == 2) {
                ok = 1;
            } else {
                ok = 0;
            }
            if (ok && !state->flags3F3.b08) {
                playerCastSpell(obj, state, sel);
            } else {
                noMatch = 1;
            }
            break;
        }
        case GAMEBIT_STAFF_ABILITY_OPEN_PORTAL:
            if (playerCanCastPortalOpenSpell(obj, state) != 0) {
                playerCastSpell(obj, state, state->queuedItemCommand);
            } else {
                noMatch = 1;
            }
            break;
        default:
            playerCastSpell(obj, state, sel);
            break;
        }
        if (noMatch)
        {
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
        }
    }

    state->queuedItemCommand = -1;
}

void playerRunActiveSpells(GameObject* obj, PlayerState* state)
{
    PlayerState* inner;
    u8 result;
    GameObject** p;
    int z[2];
    int v;
    if (playerIsBlasterSpellAvailable(obj, state, GAMEBIT_STAFF_ABILITY_FIRE_BLASTER) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 0);
        mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_Spell0965_Disabled, 1);
        mainSetBits(GAMEBIT_ITEM_FireBlaster_Disabled, 1);
    }
    if (playerIsBlasterSpellAvailable(obj, state, GAMEBIT_STAFF_ABILITY_FREEZE_BLAST) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_Spell0961_Disabled, 1);
    }
    inner = obj->extra;
    if (((PlayerState*)state)->baddie.targetObj != NULL || (inner->playerStatus)->magic < 0xa ||
        inner->flags3F3.b08 != 0)
    {
        result = 0;
    }
    else if (((PlayerState*)state)->baddie.controlMode == 1 || ((PlayerState*)state)->baddie.controlMode == 2)
    {
        result = 1;
    }
    else
    {
        result = 0;
    }
    if (result != 0)
    {
        mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_SharpClawDisguise_Disabled, 1);
    }
    if (playerCanCastPortalOpenSpell(obj, state) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_PortalSpell_Disabled, 1);
    }
    if (playerCanUseStaffBooster(obj, state) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_StaffBooster_Disabled, 1);
    }
    if (playerCanCastQuakeSpell(obj, state) != 0)
    {
        mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 0);
    }
    else
    {
        mainSetBits(GAMEBIT_ITEM_SuperQuake_Disabled, 1);
    }
    switch (((PlayerState*)state)->animState)
    {
    case GAMEBIT_STAFF_ABILITY_FIRE_BLASTER:
        break;
    case GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE:
        if ((getButtonsJustPressed(0) & 0x200) != 0 && ((PlayerState*)state)->flags3F3.b08 != 0 &&
            ((PlayerState*)state)->curAnimId != 0x44)
        {
            playerSetDisguised(obj, 0);
            state->animState = -1;
            state->queuedItemCommand = -1;
            buttonDisable(0, PAD_BUTTON_B);
        }
        ((PlayerState*)state)->stateTimer = ((PlayerState*)state)->stateTimer - timeDelta;
        if (((PlayerState*)state)->stateTimer <= 0.0f)
        {
            if (*(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 4) < 0)
            {
                v = 0;
            }
            else if (*(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 4) >
                     *(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 6))
            {
                v = *(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 6);
            }
            else
            {
                v = *(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 4);
            }
            *(s16*)((char*)*(int*)((char*)(int)obj->extra + 0x35c) + 4) = v;
            ((PlayerState*)state)->stateTimer = 300.0f;
        }
        break;
    case GAMEBIT_STAFF_ABILITY_FREEZE_BLAST:
        if (gPlayerIceSpellSustaining != 0 && getCurSeqNo() != 0)
        {
            ((PlayerState*)state)->animState = -1;
            z[0] = 0;
            gPlayerIceSpellSustaining = z[0];
            z[1] = z[0];
            p = gPlayerSpawnedObjects;
            for (; z[1] < 7; z[1]++)
            {
                if (p[z[1]] != NULL)
                {
                    Obj_FreeObject((GameObject*)p[z[1]]);
                    p[z[1]] = NULL;
                }
            }
            if (gPlayerResource != NULL)
            {
                Resource_Release(gPlayerResource);
                gPlayerResource = NULL;
            }
        }
        break;
    }
}

void playerProcessHitResponse(GameObject* obj, PlayerState* inner, PlayerState* state) {
    int orig;
    int work;
    int newAnim;
    int keepKnock;
    int knockKind;
    int canCounter;
    int anim;
    HitFxDesc desc;
    PartFxSpawnParams buf;
    StaffCollisionColorArgs col;
    int surfIdx;
    int damage;
    GameObject* hitObj;

    col = *(StaffCollisionColorArgs*)lbl_802C2C68;
    knockKind = 0;
    if (*(f32*)((char*)((GameObject*)obj)->extra + 0x838) > 10.0f)
    {
        ((PlayerState*)inner)->knockbackTimer = 0.0f;
    }
    if (gPlayerSfxTimerA > 0)
    {
        gPlayerSfxTimerA = gPlayerSfxTimerA - framesThisStep;
        if (gPlayerSfxTimerA < 0)
        {
            gPlayerSfxTimerA = 0;
        }
    }
    work = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, &surfIdx, (u32*)&damage, &buf.posX, &buf.posY, &buf.posZ);
    orig = work;
    if ((((PlayerState*)inner)->playerStatus)->health <= 0)
    {
        (((PlayerState*)inner)->playerStatus)->health = 1;
    }
    if (ObjHits_IsObjectEnabled((ObjAnimComponent*)obj) == 0 || objGetFlagsE5_2((u8*)obj) != 0 ||
        ((PlayerState*)inner)->flags3F3.b20 != 0 ||
        (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK))
    {
        return;
    }
    if (((PlayerState*)inner)->focusObject != NULL && work != 0)
    {
        work = 0x15;
    }
    keepKnock = 1;
    if (work != 0)
    {
        if (surfIdx != -1)
        {
            buf.posX = buf.posX + playerMapOffsetX;
            buf.posZ = buf.posZ + playerMapOffsetZ;
        }
        if (((PlayerState*)state)->baddie.stateId != 0)
        {
            work = 0x1b;
        }
        if (((PlayerState*)state)->baddie.stateTag == 3 && ((PlayerState*)state)->baddie.lastHitPriority <= work)
        {
            return;
        }
        state->baddie.lastHitPriority = work;
        obj->anim.activeMove = -1;
        newAnim = -1;
        {
            u32 fl = ((PlayerState*)inner)->flagByte3F0;
            if ((fl >> 4 & 1) != 0 || (fl >> 2 & 1) != 0 || (fl >> 3 & 1) != 0 || (fl >> 5 & 1) != 0 ||
                (anim = ((PlayerState*)state)->baddie.controlMode) == 0x36)
            {
                canCounter = 0;
            }
            else if ((u16)(anim - 1) <= 1 || (u16)(anim - 0x24) <= 1 || ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                canCounter = 1;
            }
            else
            {
                canCounter = 0;
            }
        }
        switch (work)
        {
        case 0xb:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 2;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 7:
        case 8:
        case 9:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 3;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 0xc:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 1;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 0xa:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 3;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 4:
            if (canCounter)
            {
                newAnim = 0x1f;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        case 1:
            damage = (((PlayerState*)inner)->playerStatus)->health;
            break;
        case 0x15:
            switch (((PlayerState*)inner)->focusObject->anim.romDefNo)
            {
            case 0x714:
                CameraShake_Enable();
                CameraShake_SetOffset(1.0f);
                break;
            }
            break;
        case 0x16:
            if (inner->flags3F0.b02 == 0) {
                keepKnock = 0;
            }
            if (canCounter && state->baddie.targetObj == NULL) {
                inner->moveVariantIndex = 5;
            }
            break;
        case 0x19:
            CameraShake_Enable();
            CameraShake_SetOffset(1.0f);
            break;
        case 0x1b:
            newAnim = ((PlayerState*)state)->baddie.stateId;
            break;
        case 0x14:
        case 0x1a:
        case 0x1f:
            if (((PlayerState*)inner)->knockbackTimer <= 0.0f)
            {
                knockKind = 1;
            }
            if (((PlayerState*)inner)->flags3F0.b02 == 0)
            {
                keepKnock = 0;
            }
            if (canCounter && ((PlayerState*)state)->baddie.targetObj == NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 5;
            }
            break;
        case 0x1e:
            if (((PlayerState*)inner)->flags3F3.b08 == 0)
            {
                knockKind = 2;
                if (((PlayerState*)inner)->flags3F0.b02 == 0)
                {
                    keepKnock = 0;
                }
                if (canCounter && ((PlayerState*)state)->baddie.targetObj == NULL)
                {
                    ((PlayerState*)inner)->moveVariantIndex = 5;
                }
                break;
            }
            return;
        case 2:
        case 5:
        case 0x12:
        case 0x17:
        case 0x18:
            break;
        default:
            if (canCounter && ((PlayerState*)state)->baddie.targetObj != NULL)
            {
                ((PlayerState*)inner)->moveVariantIndex = 0;
                newAnim = 0x23;
                ((PlayerState*)inner)->stateHandler = 0;
            }
            break;
        }
        if ((((PlayerState*)inner)->flags360 & 0x800) == 0 && knockKind != 0)
        {
            ((PlayerState*)inner)->knockbackTimer = 300.0f;
            ((PlayerState*)inner)->knockbackHitTimer = 200.0f;
            ((PlayerState*)inner)->knockbackDrainRate = 1.0f;
            ((PlayerState*)inner)->knockKindBits.knock = (u8)knockKind;
        }
        if ((((PlayerState*)inner)->flags360 & 0x800) != 0 && keepKnock != 0)
        {
            damage = 0;
            ((PlayerState*)inner)->flags3F6.b10 = 1;
            if (hitObj != NULL && hitObj->anim.romDefNo != 0x2c5)
            {
                if (gPlayerSfxTimerA == 0)
                {
                    Sfx_PlayFromObject(
                        (GameObject*)obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_pole1_c : SFXTRIG_wp_pole1_c));
                }
                gPlayerSfxTimerA = 6;
            }
            if (gPlayerStepSfxTimer == 0)
            {
                char* pt = (char*)Player_GetActiveModel(obj);
                pt = (char*)((ObjModel*)pt)->activeHitVolumeSpheres;
                desc.x = playerMapOffsetX + ((ObjModelHitSphere*)(pt + surfIdx * 0x10))->pos[0];
                desc.y = ((ObjModelHitSphere*)(pt + surfIdx * 0x10))->pos[1];
                desc.z = playerMapOffsetZ + ((ObjModelHitSphere*)(pt + surfIdx * 0x10))->pos[2];
                (*gPartfxInterface)->spawnObject((void*)obj, 0x328, &desc, 0x200001, -1, NULL);
                desc.x -= ((GameObject*)obj)->anim.worldPosX;
                desc.y -= ((GameObject*)obj)->anim.worldPosY;
                desc.z -= ((GameObject*)obj)->anim.worldPosZ;
                if (gPlayerResource == NULL)
                {
                    gPlayerResource = Resource_Acquire(0x5a, 1);
                }
                col.red += randomGetRange(0, 0x9b);
                col.green += randomGetRange(0, 0x9b);
                desc.scale = 1.0f;
                desc.rx = 0;
                desc.ry = 0;
                desc.rz = 0;
                (*gPlayerResource)->spawn((GameObject*)obj, 0, (PartFxSpawnParams*)&desc, 1, -1, &col);
                if (gPlayerResource != NULL)
                {
                    Resource_Release(gPlayerResource);
                }
                gPlayerResource = NULL;
                gPlayerStepSfxTimer = 10;
                return;
            }
            else
            {
                gPlayerStepSfxTimer = gPlayerStepSfxTimer - 1;
                return;
            }
        }
        if (damage != 0)
        {
            {
                int v;
                char* hb = ((GameObject*)obj)->extra;
                s8* hp = *(s8**)((char*)hb + 0x35c);
                v = *hp - damage;
                if (v < 0)
                {
                    v = 0;
                }
                else
                {
                    int hi = hp[1];
                    if (v > hi)
                    {
                        v = hi;
                    }
                }
                *hp = v;
                if (**(s8**)((char*)hb + 0x35c) <= 0)
                {
                    playerDie((GameObject*)obj);
                }
            }
            gPlayerStepSfxTimer = 0;
            if (hitObj != NULL)
            {
                switch (hitObj->anim.romDefNo)
                {
                case 0x11:
                case 0x33:
                case 0x13a:
                case 0x5b7:
                case 0x5b8:
                case 0x5b9:
                case 0x5e1:
                    Sfx_PlayFromObject(hitObj, SFXTRIG_snort);
                    break;
                case 0x5f9:
                case 0x5fa:
                case 0x5fe:
                    Sfx_PlayFromObject(hitObj, SFXTRIG_swd);
                    break;
                case 0x2c5:
                    Sfx_PlayFromObject(hitObj, SFXTRIG_wp_crtsmsh6);
                    break;
                case 0x709:
                    Sfx_PlayFromObject(hitObj, SFXTRIG_wp_fball2_c);
                    break;
                case 0x458:
                case 0x842:
                    Sfx_PlayFromObject(hitObj, SFXTRIG_baddie_mika_death);
                    break;
                }
            }
            switch (orig)
            {
            case 0x16:
                if (hitObj != NULL &&
                    (hitObj->anim.romDefNo == 0x613 || hitObj->anim.romDefNo == 0x70f))
                {
                    Sfx_PlayFromObject(
                        (GameObject*)obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
                }
                else
                {
                    Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_watery_bubble3);
                }
                break;
            case 0x14:
            case 0x1f:
                Sfx_PlayFromObject(
                    (GameObject*)obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_en_cvdrip1c_393);
                if (Sfx_IsPlayingFromObject((GameObject*)obj, SFXTRIG_foot_metal_scuff) == 0)
                {
                    Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_foot_metal_scuff);
                }
                if ((((PlayerState*)inner)->playerStatus)->health > 0)
                {
                    objDoHitParticleFx((void*)obj, 0.014f, &buf, 6, 0);
                }
                break;
            case 0x1c:
                Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_fox_var);
                if ((((PlayerState*)inner)->playerStatus)->health > 0)
                {
                    objDoHitParticleFx((void*)obj, 0.014f, &buf, 8, 0);
                }
                break;
            default:
                Sfx_PlayFromObject(
                    (GameObject*)obj, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
                if (hitObj != NULL)
                {
                    switch (hitObj->anim.romDefNo)
                    {
                    case 0x33:
                        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_snort);
                        if ((((PlayerState*)inner)->playerStatus)->health > 0)
                        {
                            objDoHitParticleFx((void*)obj, 0.014f, &buf, 5, 0);
                        }
                        break;
                    case 0x7c8:
                        if ((((PlayerState*)inner)->playerStatus)->health > 0)
                        {
                            objDoHitParticleFx((void*)obj, 0.014f, &buf, 8, 0);
                        }
                        break;
                    default:
                        if ((((PlayerState*)inner)->playerStatus)->health > 0)
                        {
                            objDoHitParticleFx((void*)obj, 0.014f, &buf, 5, 0);
                        }
                        break;
                    }
                }
                else
                {
                    if ((((PlayerState*)inner)->playerStatus)->health > 0)
                    {
                        objDoHitParticleFx((void*)obj, 0.014f, &buf, 5, 0);
                    }
                }
                break;
            }
            if ((((PlayerState*)inner)->playerStatus)->health > 0)
            {
                Obj_SetModelColorFadeRecursive((GameObject*)obj, 0xb4, 200, 0, 0, 1);
            }
            if (((PlayerState*)state)->baddie.controlMode == 0x1a)
            {
                objfx_shakeCameraByDistance((GameObject*)obj, 5000.0f);
            }
            ((PlayerState*)inner)->idleHoldTimer = 0.0f;
            ((PlayerState*)inner)->idleWaitTimer = randomGetRange(800, 0x44c);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (((PlayerState*)inner)->heldObj != NULL)
            {
                s16 t = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.romDefNo;
                if (t == SMALLBASKET_SEQUENCE_VARIANT_A || t == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                {
                    SmallBasket_throw((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    Carryable_putDownAndSavePos((GameObject*)((PlayerState*)inner)->heldObj);
                }
                *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) =
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) & ~0x4000;
                ((PlayerState*)inner)->heldObj->userData2 = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            if (newAnim != -1 && ((PlayerState*)state)->baddie.controlMode != newAnim &&
                (((PlayerState*)inner)->playerStatus)->health > 0)
            {
                (*gPlayerInterface)->setState((void*)obj, (void*)state, newAnim);
                ((PlayerState*)state)->baddie.stateExitFn = (BaddieStateExitFn)((PlayerState*)inner)->stateHandler;
            }
        }
        else
        {
            gPlayerStepSfxTimer = 0;
        }
    }
    else
    {
        gPlayerStepSfxTimer = 0;
    }
}

void playerUpdateKnockbackTimers(GameObject* obj, PlayerState* state)
{
    f32 v;
    f32 posWork[6];
    f32 zero;

    if (((PlayerState*)state)->surfaceType == 0x1a)
    {
        return;
    }
    if (((PlayerState*)state)->flags3F0.b10 == 0)
    {
        v = sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                  (obj->anim.velocityX * obj->anim.velocityX +
                   obj->anim.velocityY * obj->anim.velocityY));
        ((PlayerState*)state)->knockbackDrainRate = v;
        v = ((PlayerState*)state)->knockbackDrainRate;
        ((PlayerState*)state)->knockbackDrainRate =
            (v < 1.0f) ? 1.0f : ((v > 3.0f) ? 3.0f : v);
    }
    ((PlayerState*)state)->knockbackTimer =
        ((PlayerState*)state)->knockbackTimer - timeDelta * ((PlayerState*)state)->knockbackDrainRate;
    if (((PlayerState*)state)->knockbackTimer <= (zero = 0.0f))
    {
        if (Sfx_IsPlayingFromObject(obj, SFXTRIG_foot_metal_scuff))
        {
            Sfx_StopFromObject(obj, SFXTRIG_foot_metal_scuff);
            Sfx_PlayFromObject(obj, SFXTRIG_foot_metal_land);
        }
        state->knockbackTimer = 0.0f;
        return;
    }
    ((PlayerState*)state)->knockbackHitTimer = ((PlayerState*)state)->knockbackHitTimer - timeDelta;
    if (((PlayerState*)state)->knockbackHitTimer <= zero)
    {
        ObjPath_GetPointWorldPosition(obj, 0xb, &posWork[3], &posWork[4], &posWork[5], 0);
        ObjHits_RecordPositionHit(obj, NULL, 0x1f, 1, -1, posWork[3], posWork[4], posWork[5]);
        state->knockbackHitTimer = 200.0f;
    }
}

void playerStaffInit(GameObject* obj, PlayerState* state)
{
    GameObject* child;
    int b;

    if (gPlayerPathObject == NULL && (u8)Obj_CanSetupObject() != 0)
    {
        child = objSetupObject(Obj_AllocObjectSetup(0x18, 0x69), 4, -1, -1, obj->anim.parent);
        gPlayerPathObject = child;
        ObjLink_AttachChild(obj, child, 2);
    }
    if (gPlayerPathObject != NULL)
    {
        gPlayerPathObject->anim.parent = (void*)obj->anim.parent;
    }

    ((PlayerState*)state)->chargeLevel -= 0.5f * timeDelta;
    if (((PlayerState*)state)->chargeLevel < 0.0f)
    {
        ((PlayerState*)state)->chargeLevel = 0.0f;
    }
    ((PlayerState*)state)->boulderChargeLevel -= 0.5f * timeDelta;
    if (((PlayerState*)state)->boulderChargeLevel < 0.0f)
    {
        ((PlayerState*)state)->boulderChargeLevel = 0.0f;
    }

    hudSetMagicCostPreview((u8)(int)state->chargeLevel);

    if (obj != NULL)
    {
        b = ((&obj->anim)->bankIndex != 0);
    }
    else
    {
        b = 0;
    }
    if (b == 0 && mainGetBit(GAMEBIT_ITEM_Staff_Got))
    {
        staffToggle(obj, 0);
    }
}

void playerDoEyeAnims(GameObject* obj, char* state)
{
    s16* vec9 = objFindJointPoseVector(obj, 9);
    s16* vec0 = objFindJointPoseVector(obj, 0);
    u8 doBlink = 0;
    PlayerState* inner = obj->extra;
    f32 f31v;
    f32 f30v;

    if ((((PlayerState*)state)->playerStatus)->health > 0)
    {
        characterDoEyeAnims(obj, (void*)(state + 0x364));
    }
    else
    {
        ObjTextureRuntimeSlot* t5 = objFindTexture(obj, 5, 0);
        ObjTextureRuntimeSlot* t4 = objFindTexture(obj, 4, 0);
        if (t5 != NULL)
        {
            t5->textureId = 0x200;
        }
        if (t4 != NULL)
        {
            t4->textureId = 0x200;
        }
    }
    if ((((PlayerState*)state)->flags360 & 0x2000000u) == 0)
    {
        ((PlayerState*)state)->headPitch =
            (f32)((PlayerState*)state)->headPitch * powfBitEstimate(0.9f, timeDelta);
        ((PlayerState*)state)->headYaw = (f32)((PlayerState*)state)->headYaw * powfBitEstimate(0.85f, timeDelta);
        ((PlayerState*)state)->bodyLeanAngle =
            (f32)((PlayerState*)state)->bodyLeanAngle * powfBitEstimate(0.85f, timeDelta);
        ((PlayerState*)state)->bodyLeanHalf =
            (f32)((PlayerState*)state)->bodyLeanHalf * powfBitEstimate(0.85f, timeDelta);
    }
    if (((PlayerState*)state)->flags3F0.b20)
    {
        f31v = inner->baddie.animSpeedC / ((PlayerState*)state)->moveParamValues[6];
        f31v = (f31v < 0.0f) ? 0.0f : ((f31v > 1.0f) ? 1.0f : f31v);
        f30v = 1.0f - f31v;
    }
    if (vec9 != NULL)
    {
        if (((PlayerState*)state)->flags3F0.b20)
        {
            f32 k = 0.5f;
            vec9[2] =
                k * ((f32)((PlayerState*)state)->headPitch * f30v + (f32)((PlayerState*)state)->bodyLeanHalf * f31v);
            vec9[1] =
                k * ((f32)((PlayerState*)state)->bodyLeanHalf * f30v + (f32)((PlayerState*)state)->headPitch * f31v);
        }
        else
        {
            vec9[2] = ((PlayerState*)state)->headPitch;
            vec9[1] = ((PlayerState*)state)->bodyLeanHalf;
        }
    }
    if (vec0 != NULL)
    {
        vec0[0] = -((PlayerState*)state)->headYaw;
        if (((PlayerState*)state)->flags3F0.b20)
        {
            int h4 = ((PlayerState*)state)->bodyLeanAngle / 2;
            int h0 = -(((PlayerState*)state)->headPitch / 2);
            f32 k = 0.5f;
            vec0[1] = k * ((f32)h4 * f30v + (f32)h0 * f31v);
            vec0[2] = k * ((f32)h0 * f30v + (f32)h4 * f31v);
        }
        else
        {
            vec0[1] = ((PlayerState*)state)->bodyLeanAngle / 2;
            vec0[2] = -(((PlayerState*)state)->headPitch / 2);
        }
    }
    if (!((PlayerState*)state)->flags3F0.b20)
    {
        obj->anim.rotZ = ((PlayerState*)state)->headPitch / 4;
    }
    else
    {
        obj->anim.rotZ = (f32)obj->anim.rotZ * powfBitEstimate(0.9f, timeDelta);
    }
    {
        int e;
        if (((PlayerState*)state)->baddie.controlMode == 1)
        {
            e = 1;
        }
        else
        {
            e = 0;
        }
        playerUpdateBlinkAnimation(obj, (char*)state + 0x364, e);
    }
    if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
    {
        if (((PlayerState*)state)->flags3F1.b20)
        {
            gPlayerModelChainStyle = 5;
        }
        else
        {
            if (playerGetStateValue(obj, 2) == 0 && (((PlayerState*)state)->playerStatus)->health > 4 &&
                gPlayerModelChainStyle == 1 && randomGetRange(0, 0x12c) == 1)
            {
                gPlayerModelChainStyle = 2;
                doBlink = 1;
            }
            if (doBlink == 0 && gPlayerModelChainStyle == 2 && randomGetRange(0, 5) == 1)
            {
                gPlayerModelChainStyle = 1;
            }
        }
        {
            s16* vec1 = objFindJointPoseVector(obj, 1);
            if (vec1 != NULL)
            {
                vec1[0] = 0x1c2;
                vec1[1] = 0;
                vec1[2] = 0;
            }
        }
    }
}

void playerUpdateMotionState(GameObject* obj, void* inner, BaddieState* baddieState) {
    int d;
    GameObject* cam;
    f32 dx;
    f32 dz;
    f32 spd;
    f32 t;
    f32 u;
    int idx;
    int leanRate;
    f32* leanCurve;
    f32 one;
    f32 v;

    if ((((PlayerState*)inner)->flags360 & 0x800000) != 0) {
        s16 a = obj->anim.rotX;
        ((PlayerState*)inner)->yaw = a;
        ((PlayerState*)inner)->targetYaw = a;
        ((PlayerState*)inner)->lastInputHeading = a;
        baddieState->inputMagnitude = 0.0f;
    }
    baddieState->previousInputMagnitude = baddieState->inputMagnitude;
    ((PlayerState*)inner)->prevYaw = ((PlayerState*)inner)->yaw;
    ((PlayerState*)inner)->prevTargetYaw = ((PlayerState*)inner)->targetYaw;
    baddieState->inputMagnitude =
        sqrtf(baddieState->moveInputX * baddieState->moveInputX +
              baddieState->moveInputZ * baddieState->moveInputZ);
    if (baddieState->inputMagnitude > 56.0f)
    {
        baddieState->inputMagnitude = 56.0f;
    }
    baddieState->inputMagnitude /= 56.0f;
    ((PlayerState*)inner)->inputMagnitude =
        baddieState->inputMagnitude - *(f32*)&baddieState->trackedObj;
    if (baddieState->inputMagnitude < 0.05f)
    {
        baddieState->inputMagnitude = 0.0f;
        ((PlayerState*)inner)->inputHeading = ((PlayerState*)inner)->lastInputHeading;
    }
    else
    {
        ((PlayerState*)inner)->inputHeading =
            getAngle(baddieState->moveInputX, -baddieState->moveInputZ) & 0xffff;
        ((PlayerState*)inner)->inputHeading =
            ((PlayerState*)inner)->inputHeading - baddieState->cameraYaw;
        if ((((PlayerState*)inner)->flags360 & 0x1000000) == 0)
        {
            ((PlayerState*)inner)->lastInputHeading = ((PlayerState*)inner)->inputHeading;
        }
    }
    d = ((PlayerState*)inner)->inputHeading - (u16)((PlayerState*)inner)->yaw;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->yawRate = (int)((f32)d / 182.044f);
    if (((PlayerState*)inner)->turnDeadzoneScale != (v = 0.0f))
    {
        f32 dead = ((PlayerState*)inner)->turnDeadzoneScale * baddieState->animSpeedA;
        if ((f32)((PlayerState*)inner)->yawRate < dead && (f32)((PlayerState*)inner)->yawRate > -dead)
        {
            ((PlayerState*)inner)->yawRate = 0;
        }
    }
    if (d < 0)
    {
        ((PlayerState*)inner)->yawRateSigned = -((PlayerState*)inner)->yawRate;
    }
    else
    {
        ((PlayerState*)inner)->yawRateSigned = ((PlayerState*)inner)->yawRate;
    }
    if (baddieState->inputMagnitude < 0.05f)
    {
        baddieState->inputSector = 0;
    }
    else
    {
        d = d + 0xa000;
        if (d < 0)
        {
            d = d + 0xffff;
        }
        if (d > 0xffff)
        {
            d = d - 0xffff;
        }
        baddieState->inputSector = (u8)(4 - d / 0x4000);
    }
    d = ((PlayerState*)inner)->inputHeading - (u16)((PlayerState*)inner)->targetYaw;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->targetYawRate = (int)((f32)d / 182.044f);
    if (((PlayerState*)inner)->turnDeadzoneScale != (v = 0.0f))
    {
        f32 dead = ((PlayerState*)inner)->turnDeadzoneScale * baddieState->animSpeedA;
        if ((f32)((PlayerState*)inner)->targetYawRate < dead && (f32)((PlayerState*)inner)->targetYawRate > -dead)
        {
            ((PlayerState*)inner)->targetYawRate = 0;
        }
    }
    if (d < 0)
    {
        ((PlayerState*)inner)->targetYawRateSigned = -((PlayerState*)inner)->targetYawRate;
    }
    else
    {
        ((PlayerState*)inner)->targetYawRateSigned = ((PlayerState*)inner)->targetYawRate;
    }
    d = ((PlayerState*)inner)->inputHeading - (u16)((PlayerState*)inner)->bodyLeanAngle;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->bodyLeanRate = (int)((f32)d / 182.044f);
    if (d < 0)
    {
        ((PlayerState*)inner)->bodyLeanRateSigned = -((PlayerState*)inner)->bodyLeanRate;
    }
    else
    {
        ((PlayerState*)inner)->bodyLeanRateSigned = ((PlayerState*)inner)->bodyLeanRate;
    }
    ((PlayerState*)inner)->cameraTargetObject = (void*)(*gCameraInterface)->getTarget();
    cam = (GameObject*)*(char**)((char*)inner + 0x4b8);
    if (cam != NULL)
    {
        dx = cam->anim.localPosX - obj->anim.localPosX;
        dz = cam->anim.localPosZ - obj->anim.localPosZ;
        ((PlayerState*)inner)->targetObjectYaw = getAngle(-dx, -dz) & 0xffff;
        ((PlayerState*)inner)->targetObjectDist = sqrtf(dx * dx + dz * dz);
        ((PlayerState*)inner)->targetObjModelType =
            cam->anim.modelInstance->hitVolumes->flags & 0xf;
    }
    d = ((PlayerState*)inner)->targetObjectYaw - (u16)((PlayerState*)inner)->targetYaw;
    if (d > 0x8000)
    {
        d = d - 0xffff;
    }
    if (d < -0x8000)
    {
        d = d + 0xffff;
    }
    ((PlayerState*)inner)->targetObjectBearing = (int)(f32)d;
    if (d < 0)
    {
        ((PlayerState*)inner)->targetObjectBearingAbs = -((PlayerState*)inner)->targetObjectBearing;
    }
    else
    {
        ((PlayerState*)inner)->targetObjectBearingAbs = ((PlayerState*)inner)->targetObjectBearing;
    }
    if (((PlayerState*)inner)->flags3F1.b20 != 0)
    {
        spd = sqrtf(baddieState->animSpeedA * baddieState->animSpeedA +
                    baddieState->animSpeedB * baddieState->animSpeedB);
        t = 0.0f;
        if (spd < t)
        {
            t = 0.0f;
        }
        else
        {
            t = ((PlayerState*)inner)->maxSpeed;
            if (spd > t)
            {
                t = ((PlayerState*)inner)->maxSpeed;
            }
            else
            {
                t = spd;
            }
        }
        if (1.0f == ((PlayerState*)inner)->targetAnimSpeed)
        {
            ((PlayerState*)inner)->velSmoothRate = 0.25f;
        }
        else
        {
            u = t * ((PlayerState*)inner)->curveSpeedScale;
            idx = (int)u;
            ((PlayerState*)inner)->velSmoothRate =
                1.0f /
                Curve_EvalCatmullRom((void*)(((PlayerState*)inner)->paramCurve0 + (idx + 1)),
                                     u - (f32)idx, 0);
        }
    }
    else
    {
        spd = baddieState->animSpeedA;
        if (spd < 0.0f) {
            t = 0.0f;
        } else if (spd > ((PlayerState*)inner)->maxSpeed) {
            t = ((PlayerState*)inner)->maxSpeed;
        } else {
            t = spd;
        }
        u = t * ((PlayerState*)inner)->curveSpeedScale;
        idx = (int)u;
        ((PlayerState*)inner)->velSmoothRate =
            1.0f /
            Curve_EvalCatmullRom((void*)(((PlayerState*)inner)->paramCurve0 + (idx + 1)), u - (f32)idx, 0);
    }
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->targetYawSmoothRate =
        Curve_EvalCatmullRom((void*)(((PlayerState*)inner)->paramCurve1 + (idx + 1)), u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->targetYawRateLimit =
        Curve_EvalCatmullRom((void*)(((PlayerState*)inner)->paramCurve2 + (idx + 1)), u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->yawSmoothRate =
        Curve_EvalCatmullRom((void*)(((PlayerState*)inner)->paramCurve3 + (idx + 1)), u - (f32)idx, 0);
    u = t * ((PlayerState*)inner)->curveSpeedScale;
    idx = (int)u;
    ((PlayerState*)inner)->yawRateLimit =
        Curve_EvalCatmullRom((void*)(((PlayerState*)inner)->paramCurve4 + (idx + 1)), u - (f32)idx, 0);
    if (((PlayerState*)inner)->flags3F0.b20 != 0)
    {
        f32 k;
        ((PlayerState*)inner)->targetYawSmoothRate = ((PlayerState*)inner)->targetYawSmoothRate * (k = 4.0f);
        ((PlayerState*)inner)->yawSmoothRate = ((PlayerState*)inner)->yawSmoothRate * k;
        ((PlayerState*)inner)->velSmoothRate *= 0.25f;
    }
    else
    {
        if (1.0f != ((PlayerState*)inner)->yawSmoothScale)
        {
            f32 frac = (baddieState->animSpeedA - ((PlayerState*)inner)->moveParamValues[4]) /
                       (((PlayerState*)inner)->maxSpeed - ((PlayerState*)inner)->moveParamValues[4]);
            ((PlayerState*)inner)->yawSmoothRate =
                ((PlayerState*)inner)->yawSmoothRate * ((((PlayerState*)inner)->yawSmoothScale - 1.0f) *
                            ((frac < 0.0f) ? 0.0f : ((frac > 1.0f) ? 1.0f : frac)) +
                        1.0f);
        }
    }
    leanCurve = ((PlayerState*)inner)->leanCurve;
    if (leanCurve != NULL) {
        leanRate = ((PlayerState*)inner)->targetYawRateSigned;
        ((PlayerState*)inner)->leanCurveScale =
            Curve_EvalCatmullRom((void*)(leanCurve + (leanRate / 5 + 1)), (f32)(leanRate % 5) / 5.0f, 0);
    } else {
        ((PlayerState*)inner)->leanCurveScale = 1.0f;
    }
    one = 1.0f;
    ((PlayerState*)inner)->leanCurveScale = one;
    if (((PlayerState*)inner)->flags3F0.b20 == 0 && ((PlayerState*)inner)->waterDepth > (v = 0.0f))
    {
        ((PlayerState*)inner)->speedScale = (((PlayerState*)inner)->waterDepth - 7.0f) / 18.0f;
        v = (((PlayerState*)inner)->speedScale < 0.0f)
                ? 0.0f
                : ((((PlayerState*)inner)->speedScale > one) ? one : ((PlayerState*)inner)->speedScale);
        ((PlayerState*)inner)->speedScale = v;
        ((PlayerState*)inner)->speedScale = -(0.5f * ((PlayerState*)inner)->speedScale - 1.0f);
    }
    else
    {
        if (baddieState->spawnRotY > 0)
        {
            ((PlayerState*)inner)->speedScale = (f32)baddieState->spawnRotY / 8192.0f;
            v = ((PlayerState*)inner)->speedScale;
            ((PlayerState*)inner)->speedScale = v < 0.0f ? 0.0f : v > 1.0f ? 1.0f : v;
            ((PlayerState*)inner)->speedScale = -(0.3f * ((PlayerState*)inner)->speedScale - 1.0f);
        }
        else
        {
            ((PlayerState*)inner)->speedScale = 1.0f;
        }
    }
    if (((PlayerState*)inner)->heldObj != NULL)
    {
        ((PlayerState*)inner)->speedScale -= 0.1f;
    }
    v = ((PlayerState*)inner)->speedScale;
    t = v < 0.5f ? 0.5f : v > 1.0f ? 1.0f : v;
    ((PlayerState*)inner)->speedScale = t;
    ((PlayerState*)inner)->flags360 &= ~0x1800000LL;
}

void playerUpdateInputTimers(GameObject* obj, PlayerState* state, f32 fv)
{
    f32 v;

    if ((((PlayerState*)state)->buttonsHeld & PAD_BUTTON_A) && playerCanCastQuakeSpell(obj, state))
    {
        ((PlayerState*)state)->flags3F4.b20 = 1;
        ((PlayerState*)state)->buttonHoldTimer += fv;
        v = ((PlayerState*)state)->buttonHoldTimer;
        ((PlayerState*)state)->buttonHoldTimer =
            (v < 0.0f) ? 0.0f : ((v > 180.0f) ? 180.0f : v);
    }
    else
    {
        ((PlayerState*)state)->flags3F4.b20 = 0;
        ((PlayerState*)state)->buttonHoldTimer = 0.0f;
    }

    ((PlayerState*)state)->rumbleCooldown -= fv;
    if (((PlayerState*)state)->rumbleCooldown < 0.0f)
    {
        ((PlayerState*)state)->rumbleCooldown = 0.0f;
    }
    ((PlayerState*)state)->particleBurstCooldown -= fv;
    if (((PlayerState*)state)->particleBurstCooldown < 0.0f)
    {
        ((PlayerState*)state)->particleBurstCooldown = 0.0f;
    }
    ((PlayerState*)state)->targetSuppressTimer -= fv;
    if (((PlayerState*)state)->targetSuppressTimer < 0.0f)
    {
        ((PlayerState*)state)->targetSuppressTimer = 0.0f;
    }
    ((PlayerState*)state)->idleDelayTimer -= fv;
    if (((PlayerState*)state)->idleDelayTimer < 0.0f)
    {
        ((PlayerState*)state)->idleDelayTimer = 0.0f;
    }
}

void playerDoControls(GameObject* obj, PlayerState* state, f32 fv)
{
    u8 c;

    ((PlayerState*)state)->stickX = 0;
    ((PlayerState*)state)->stickY = 0;
    ((PlayerState*)state)->buttonsHeld = 0;
    ((PlayerState*)state)->buttonsJustPressed = 0;
    ((PlayerState*)state)->buttonsJustPressedIfNotBusy = 0;
    if ((((PlayerState*)state)->flags360 & 0x200000) == 0u && ((PlayerState*)state)->characterId != -1 &&
        (c = ((PlayerState*)state)->curAnimId) != 0x44 && c != 0x4e)
    {
        ((PlayerState*)state)->stickX = padGetStickX(0);
        ((PlayerState*)state)->stickY = padGetStickY(0);
        ((PlayerState*)state)->buttonsHeld = (u16)getButtonsHeld(0);
        ((PlayerState*)state)->buttonsJustPressed = (u16)getButtonsJustPressed(0);
        ((PlayerState*)state)->buttonsJustPressedIfNotBusy = (u16)getButtonsJustPressedIfNotBusy(0);
    }
    state->stickXf = (f32)state->stickX;
    state->stickYf = (f32)state->stickY;
    playerUpdateInputTimers(obj, state, fv);
}

void playerClampVelocityAndMove(GameObject* obj, f32 fv)
{
    f32 x, y, z;
    f32 v;

    v = obj->anim.velocityX;
    obj->anim.velocityX = (v < -5.0f) ? -5.0f : ((v > 5.0f) ? 5.0f : v);

    v = obj->anim.velocityY;
    obj->anim.velocityY = (v < -4.0f) ? -4.0f : ((v > 4.0f) ? 4.0f : v);

    v = obj->anim.velocityZ;
    obj->anim.velocityZ = (v < -5.0f) ? -5.0f : ((v > 5.0f) ? 5.0f : v);

    y = obj->anim.velocityY * fv;
    if (y > 10.0f)
    {
        y = 10.0f;
    }
    x = obj->anim.velocityX * fv;
    z = obj->anim.velocityZ * fv;
    objMove(obj, x, y, z);
}

void playerUpdateVelocityFromMotion(GameObject* a, void* b, BaddieState* baddieState, f32 unusedTimeDelta)
{
    MatrixTransform v;
    f32 mtx[16];
    f32 oy;
    f32 f31v;
    f32 f30v;
    s8 flags = baddieState->movementFlags;

    if ((flags & 2) == 0 && (flags & 1) == 0)
    {
        f31v = baddieState->animSpeedA;
        f30v = baddieState->animSpeedB;
        if (((PlayerState*)b)->flags3F0.b20)
        {
            f31v = f31v + ((PlayerState*)b)->waterCurrentVelA;
            f30v = f30v + ((PlayerState*)b)->waterCurrentVelB;
        }
        v.rotX = ((PlayerState*)b)->yaw;
        v.rotY = 0;
        v.rotZ = 0;
        v.scale = 1.0f;
        v.x = 0.0f;
        v.y = 0.0f;
        v.z = 0.0f;
        setMatrixFromObjectPos(mtx, &v);
        Matrix_TransformPoint(mtx, f30v, 0.0f, -f31v, &a->anim.velocityX, &oy, &a->anim.velocityZ);
        a->anim.velocityX = a->anim.velocityX + ((PlayerState*)b)->pushVelX;
        a->anim.velocityZ = a->anim.velocityZ + ((PlayerState*)b)->pushVelZ;
    } else {
        int cosI = (int)mathSinf(3.1415927f * (f32)((PlayerState*)b)->yaw / 32768.0f);
        int sinI = (int)mathCosf(3.1415927f * (f32)((PlayerState*)b)->yaw / 32768.0f);
        baddieState->animSpeedB = a->anim.velocityX * (f32)sinI - a->anim.velocityZ * (f32)cosI;
        baddieState->animSpeedA = -a->anim.velocityZ * (f32)sinI - a->anim.velocityX * (f32)cosI;
    }

    if ((baddieState->flags0 & 0x200000) == 0) {
        a->anim.velocityY = a->anim.velocityY * powfBitEstimate(0.97f, timeDelta);
        a->anim.velocityY = a->anim.velocityY - baddieState->gravity * timeDelta;
    }
}

extern f32 lbl_803E7EA4;
extern f32 lbl_803E7EE0;
extern f32 lbl_803E7F14;

void playerUpdateSurfaceResponse(GameObject* obj, PlayerState* state, PlayerState* cfg, f32 dt)
{
    u32 b;
    void* found;
    int iv;
    f32 fv2;
    f32 clamp;
    f32 velMag;
    f32 damp;
    f32 r;
    f32 pos[3];
    f32 queryParams[4];
    TrackGroundHit** nearList;
    f32 pushX;
    f32 pushZ;

    found = 0;
    {
        f32 z = lbl_803E7EE0;
        ((PlayerState*)state)->targetAnimSpeed = z;
        ((PlayerState*)state)->yawSmoothScale = z;
    }
    ((PlayerState*)state)->velSmoothRateBase = 0.06f;
    ((PlayerState*)state)->surfaceType = 0;
    b = ((PlayerState*)state)->flags3F0.b20;
    if (b == 0 || (b != 0 && -1e+05f != ((PlayerState*)cfg)->baddie.waterSurfaceY))
    {
        ((PlayerState*)state)->waterSurfaceY = ((PlayerState*)cfg)->baddie.waterSurfaceY;
    }
    if (-1e+05f != ((PlayerState*)state)->waterSurfaceY)
    {
        ((PlayerState*)state)->waterDepth = ((PlayerState*)state)->waterSurfaceY - obj->anim.worldPosY;
    }
    else
    {
        ((PlayerState*)state)->waterDepth = lbl_803E7EA4;
    }
    ((PlayerState*)state)->flags3F1.b01 = 0;
    clamp = lbl_803E7EA4;
    pushX = lbl_803E7EA4;
    pushZ = lbl_803E7EA4;
    if ((((PlayerState*)cfg)->baddie.surfaceFlags & 0x10) != 0)
    {
        ((PlayerState*)state)->flags3F1.b01 = 1;
        ((PlayerState*)state)->surfaceType = ((PlayerState*)cfg)->baddie.paletteSlot;
        switch (((PlayerState*)state)->surfaceType)
        {
        case SURFACE_ICE:
            state->targetAnimSpeed = 0.055f;
            state->yawSmoothScale = 1.75f;
            state->velSmoothRateBase = 0.13f;
            break;
        case SURFACE_SNOW:
            fv2 = lbl_803E7EE0;
            ((PlayerState*)state)->targetAnimSpeed = fv2;
            ((PlayerState*)state)->yawSmoothScale = fv2;
            ((PlayerState*)state)->velSmoothRateBase = 0.05f;
            break;
        case 6:
            if ((((PlayerState*)state)->hitIntervalTimer -= dt) <= 0)
            {
                ((PlayerState*)state)->hitIntervalTimer = 0x3c;
                ObjHits_RecordObjectHit(obj, NULL, 0x14, 2, 0);
            }
            break;
        case SURFACE_CONVEYOR:
            queryParams[0] = 500.0f;
            found = (void*)objGetNearestTypeTo(CONVEYOR_SURFACE_OBJGROUP, obj, queryParams);
            if (found != 0)
            {
                DIM2_CONVEYOR_INTERFACE(found)
                    ->getScrollVector((GameObject*)found, obj, lbl_803E7EE0, &pushX, &pushZ);
            }
            break;
        case SURFACE_LAVA:
            if ((((PlayerState*)state)->hitIntervalTimer -= dt) <= 0)
            {
                ((PlayerState*)state)->hitIntervalTimer = 0x3c;
                ObjPath_GetPointWorldPosition(obj, 0xb, &pos[0], &pos[1], &pos[2], 0);
                ObjHits_RecordPositionHit(obj, NULL, 0x14, 2, -1, pos[0], pos[1], pos[2]);
            }
            break;
        case SURFACE_INSTANT_DEATH:
            ObjHits_RecordObjectHit(obj, NULL, 1, 0, 0);
            break;
        case 28:
            if (mainGetBit(0x21) == 0)
            {
                ((PlayerState*)state)->periodicHitTimer += dt;
                if (0x78 < ((PlayerState*)state)->periodicHitTimer)
                {
                    ((PlayerState*)state)->periodicHitTimer -= 0x78;
                    ObjPath_GetPointWorldPosition(obj, 0xb, &pos[0], &pos[1], &pos[2], 0);
                    ObjHits_RecordPositionHit(obj, NULL, 0x16, 2, -1, pos[0], pos[1], pos[2]);
                }
            }
            break;
        case 32:
            if (((PlayerState*)cfg)->baddie.animSpeedA > 0.5f)
            {
                fv2 = 0.05f + ((PlayerState*)state)->sinkOffsetY;
                ((PlayerState*)state)->sinkOffsetY = (fv2 < clamp) ? fv2 : clamp;
            }
            else
            {
                ((PlayerState*)state)->sinkOffsetY = -(0.04f * dt - ((PlayerState*)state)->sinkOffsetY);
                if (gPlayerSinkSfxTimer > clamp)
                {
                    gPlayerSinkSfxTimer = gPlayerSinkSfxTimer - dt;
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_208);
                    gPlayerSinkSfxTimer = (f32)randomGetRange(0x27, 0x3c);
                }
            }
            iv = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY,
                                      obj->anim.localPosZ, &nearList, 0, 0x20);
            velMag = -((PlayerState*)state)->sinkOffsetY;
            if (1 < iv &&
                (velMag = velMag + (nearList[0]->height - nearList[iv - 1]->height), velMag > 25.0f))
            {
                PlayerState* inner;
                PlayerStatus* p = ((PlayerState*)(inner = obj->extra))->playerStatus;
                iv = p->health;
                iv = iv - 1;
                if (iv < 0)
                {
                    iv = 0;
                }
                else if (iv > p->maxHealth)
                {
                    iv = p->maxHealth;
                }
                p->health = (s8)iv;
                if ((inner->playerStatus)->health <= 0)
                {
                    playerDie(obj);
                }
            }
            break;
        case 31:
            mainSetBits(0x643, 1);
            break;
        default:
            state->hitIntervalTimer = 0;
            {
                f32 zero;
                f32 sink = state->sinkOffsetY;
                zero = lbl_803E7EA4;
                if (sink < zero) {
                    fv2 = 0.1f * cfg->baddie.animSpeedA + sink;
                    state->sinkOffsetY = (fv2 < zero) ? fv2 : zero;
                    velMag = -state->sinkOffsetY;
                }
            }
            break;
        }
        if (velMag != lbl_803E7EA4) {
            damp = lbl_803E7F14;
            r = -(0.05f * velMag - lbl_803E7EE0);
            damp = (damp > r) ? damp : r;
            obj->anim.velocityX = obj->anim.velocityX * powfBitEstimate(damp, dt);
            obj->anim.velocityZ = obj->anim.velocityZ * powfBitEstimate(damp, dt);
        }
    }
    r = interpolate(pushX - ((PlayerState*)state)->pushVelX, 0.02f, timeDelta);
    ((PlayerState*)state)->pushVelX = ((PlayerState*)state)->pushVelX + r;
    r = interpolate(pushZ - ((PlayerState*)state)->pushVelZ, 0.02f, timeDelta);
    ((PlayerState*)state)->pushVelZ = ((PlayerState*)state)->pushVelZ + r;
    if (found == 0)
    {
        ((PlayerState*)state)->pushVelX = ((PlayerState*)state)->pushVelX * powfBitEstimate(0.9f, timeDelta);
        ((PlayerState*)state)->pushVelZ = ((PlayerState*)state)->pushVelZ * powfBitEstimate(0.9f, timeDelta);
    }
    if (((PlayerState*)state)->pushVelX > -0.01f && ((PlayerState*)state)->pushVelX < 0.01f)
    {
        ((PlayerState*)state)->pushVelX = lbl_803E7EA4;
    }
    if (((PlayerState*)state)->pushVelZ > -0.01f && ((PlayerState*)state)->pushVelZ < 0.01f)
    {
        ((PlayerState*)state)->pushVelZ = lbl_803E7EA4;
    }
}

void playerProcessMessages(GameObject* obj, int inner, int state)
{
    GameObject* p;
    int param = 0;
    int msg;

    while (ObjMsg_Pop((GameObject*)obj, (u32*)&msg, (u32*)&p, (u32*)&param) != 0)
    {
        switch (msg)
        {
        case 0x80002:
            ((PlayerState*)inner)->queuedItemCommand = (s16)param;
            if (((PlayerState*)state)->baddie.targetObj != NULL &&
                (param == GAMEBIT_STAFF_ABILITY_FIRE_BLASTER || param == GAMEBIT_STAFF_ABILITY_FREEZE_BLAST))
            {
                ((PlayerState*)inner)->deferredItemCommand = (s16)param;
                ((PlayerState*)inner)->queuedItemCommand = -1;
            }
            break;
        case 0x60003:
        {
            f32 dz;
            f32 dx;
            f32 d;
            f32 zz;
            dx = p->anim.localPosX - obj->anim.localPosX;
            dz = p->anim.localPosZ - obj->anim.localPosZ;
            zz = dz * dz;
            d = sqrtf(zz + dx * dx);
            if (d > 1.0f)
            {
                dx = dx / d;
                dz = dz / d;
            }
            {
                f32 spd = 2.5f;
                obj->anim.velocityX = spd * dx;
                obj->anim.velocityZ = spd * dz;
                obj->anim.velocityY = spd;
            }
            (*gPlayerInterface)->setState((void*)obj, (void*)state, 0x21);
            ((PlayerState*)state)->baddie.stateExitFn = NULL;
            Player_ApplyStatusDamage((GameObject*)obj, param);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (((PlayerState*)inner)->heldObj != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.romDefNo;
                if (typ == SMALLBASKET_SEQUENCE_VARIANT_A || typ == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                {
                    SmallBasket_throw((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    Carryable_putDownAndSavePos((GameObject*)((PlayerState*)inner)->heldObj);
                }
                ((PlayerState*)inner)->heldObj->anim.flags =
                    ((PlayerState*)inner)->heldObj->anim.flags & ~0x4000;
                ((PlayerState*)inner)->heldObj->userData2 = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            break;
        }
        case 0x60004:
        {
            f32 dz;
            f32 dx = p->anim.localPosX - obj->anim.localPosX;
            f32 d;
            dz = p->anim.localPosZ - obj->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
            if (d > 1.0f)
            {
                dx = dx / d;
                dz = dz / d;
            }
            {
                f32 spd = 2.5f;
                obj->anim.velocityX = spd * -dx;
                obj->anim.velocityZ = spd * -dz;
                obj->anim.velocityY = spd;
            }
            (*gPlayerInterface)->setState((void*)obj, (void*)state, 0x21);
            ((PlayerState*)state)->baddie.stateExitFn = NULL;
            Player_ApplyStatusDamage((GameObject*)obj, param);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (((PlayerState*)inner)->heldObj != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.romDefNo;
                if (typ == SMALLBASKET_SEQUENCE_VARIANT_A || typ == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                {
                    SmallBasket_throw((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    Carryable_putDownAndSavePos((GameObject*)((PlayerState*)inner)->heldObj);
                }
                ((PlayerState*)inner)->heldObj->anim.flags =
                    ((PlayerState*)inner)->heldObj->anim.flags & ~0x4000;
                ((PlayerState*)inner)->heldObj->userData2 = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            Sfx_PlayFromObject((GameObject*)obj,
                               (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_foxcom : SFXTRIG_sabrepush163));
            break;
        }
        case 0x60005:
        {
            f32 dz;
            f32 dx = p->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            f32 d;
            dz = p->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
            d = sqrtf(dx * dx + dz * dz);
            if (d > 1.0f)
            {
                dx = dx / d;
                dz = dz / d;
            }
            {
                f32 spd = 2.5f;
                ((GameObject*)obj)->anim.velocityX = spd * -dx;
                ((GameObject*)obj)->anim.velocityZ = spd * -dz;
                ((GameObject*)obj)->anim.velocityY = spd;
            }
            (*gPlayerInterface)->setState((void*)obj, (void*)state, 0x21);
            ((PlayerState*)state)->baddie.stateExitFn = NULL;
            ObjAnim_SetCurrentMove(obj, 0x450, 0.0f, 0);
            Player_ApplyStatusDamage((GameObject*)obj, param);
            ((PlayerState*)inner)->isHoldingObject = 0;
            if (((PlayerState*)inner)->heldObj != NULL)
            {
                s16 typ = ((GameObject*)((PlayerState*)inner)->heldObj)->anim.romDefNo;
                if (typ == SMALLBASKET_SEQUENCE_VARIANT_A || typ == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                {
                    SmallBasket_throw((GameObject*)(((PlayerState*)inner)->heldObj));
                }
                else
                {
                    Carryable_putDownAndSavePos((GameObject*)((PlayerState*)inner)->heldObj);
                }
                ((PlayerState*)inner)->heldObj->anim.flags =
                    ((PlayerState*)inner)->heldObj->anim.flags & ~0x4000;
                ((PlayerState*)inner)->heldObj->userData2 = 0;
                ((PlayerState*)inner)->heldObj = 0;
            }
            break;
        }
        case 0x7000a:
        {
            void* t;
            s16 bit;
            ((PlayerState*)inner)->triggerGameBitPtr = (s16*)param;
            t = *(void**)((char*)p + 0x64);
            if (t != NULL)
            {
                *(u32*)((char*)t + 0x30) &= ~0x4LL;
            }
            bit = *((PlayerState*)inner)->triggerGameBitPtr;
            if (bit > 0)
            {
                if (mainGetBit(bit) != 0)
                {
                    ObjMsg_SendToObject((void*)p, 0x7000b, (void*)obj, 0);
                    break;
                }
                else
                {
                    f32 k;
                    f32 lim;
                    f32 r = p->anim.rootMotionScale / p->anim.modelInstance->rootMotionScaleBase;
                    lim = 30.0f;
                    k = 0.99f;
                    while (r * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale) > lim)
                    {
                        *(f32*)((char*)p + 8) = *(f32*)((char*)p + 8) * k;
                        r = *(f32*)((char*)p + 8) / *(f32*)(*(int*)((char*)p + 0x50) + 4);
                    }
                    mainSetBits(*((PlayerState*)inner)->triggerGameBitPtr, 1);
                    (*gObjectTriggerInterface)->setObjects(*(s16*)((char*)p + 0x46), NULL, 0);
                    (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                }
            }
            else
            {
                f32 k;
                f32 lim;
                f32 r = p->anim.rootMotionScale / p->anim.modelInstance->rootMotionScaleBase;
                lim = 30.0f;
                k = 0.99f;
                while (r * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale) > lim)
                {
                    *(f32*)((char*)p + 8) = *(f32*)((char*)p + 8) * k;
                    r = *(f32*)((char*)p + 8) / *(f32*)(*(int*)((char*)p + 0x50) + 4);
                }
                (*gObjectTriggerInterface)->setObjects(p->anim.romDefNo, NULL, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
            ((PlayerState*)inner)->interactObject = (GameObject*)p;
            ((PlayerState*)inner)->unk688 = ((PlayerState*)inner)->triggerGameBitPtr[1];
            t = *(void**)((char*)((PlayerState*)inner)->interactObject + 0x64);
            if (t != NULL)
            {
                *(int*)((char*)t + 0x30) = 0x1000;
            }
            if (gPlayerPathObject != 0 && ((PlayerState*)inner)->flags3F4.b40 != 0)
            {
                ((PlayerState*)inner)->staffActionRequest = 1;
                ((PlayerState*)inner)->flags3F4.b08 = 1;
            }
            break;
        }
        case 0x100008:
            ((PlayerState*)inner)->isHoldingObject = 1;
            if ((void*)((PlayerState*)inner)->heldObj == NULL)
            {
                int* mdl;
                ((PlayerState*)inner)->heldObj = (GameObject*)p;
                mdl = (int*)Obj_GetActiveModel(((PlayerState*)inner)->heldObj);
                if (mdl != NULL && (void*)*mdl != NULL && (*(u16*)(*mdl + 2) & 0x8000) == 0)
                {
                    *(u8*)((char*)((PlayerState*)inner)->heldObj + 0xf2) = ((GameObject*)obj)->lightColorSlot;
                }
                ((PlayerState*)inner)->unk7FC = (f32)(param >> 0x10) / 10.0f;
                (*gPlayerInterface)->setState((void*)obj, (void*)state, 5);
                ((PlayerState*)state)->baddie.stateExitFn = (BaddieStateExitFn)playerStagedMarkTeleported;
                if (gPlayerPathObject != 0 && ((PlayerState*)inner)->flags3F4.b40 != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 1;
                    ((PlayerState*)inner)->flags3F4.b08 = 1;
                }
            }
            break;
        case 0x100010:
            ((PlayerState*)inner)->isHoldingObject = 1;
            if ((void*)((PlayerState*)inner)->heldObj == NULL)
            {
                int* mdl;
                ((PlayerState*)inner)->heldObj = (GameObject*)p;
                mdl = (int*)Obj_GetActiveModel(((PlayerState*)inner)->heldObj);
                if (mdl != NULL && (void*)*mdl != NULL && (*(u16*)(*mdl + 2) & 0x8000) == 0)
                {
                    *(u8*)((char*)((PlayerState*)inner)->heldObj + 0xf2) = ((GameObject*)obj)->lightColorSlot;
                }
                ((PlayerState*)inner)->unk7FC = (f32)(param >> 0x10);
                (*gPlayerInterface)->setState((void*)obj, (void*)state, 5);
                ((PlayerState*)state)->baddie.stateExitFn = (BaddieStateExitFn)playerStagedMarkTeleported;
                if (gPlayerPathObject != 0 && ((PlayerState*)inner)->flags3F4.b40 != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 1;
                    ((PlayerState*)inner)->flags3F4.b08 = 1;
                }
            }
            break;
        }
    }
}

int player_SeqFn(int obj, int obj2, ObjSeqState* seq, int endFlag)
{
    char* tbl = (char*)lbl_80332EC0;
    PlayerSeqPlacement* placement = (PlayerSeqPlacement*)((GameObject*)obj2)->anim.placementData;
    int inner = (int)((GameObject*)obj)->extra;
    int result = 0;
    int va;
    int vb;
    f32 npos[3];
    f32 pz;
    f32 py;
    f32 px;
    int objCount;
    f32 nearArg;

    va = (int)objFindJointPoseVector((GameObject*)(obj), 0);
    vb = (int)objFindJointPoseVector((GameObject*)(obj), 9);
    seq->freeCallback = (ObjAnimSequenceFreeCallback)playerRestoreAfterSequence;
    if (gPlayerStaffObject != NULL)
    {
        Shield_setMode(gPlayerStaffObject, 0);
    }
    playerStaffInit((GameObject*)obj, (PlayerState*)inner);
    if ((void*)gPlayerEggObject == NULL && (u8)Obj_CanSetupObject() != 0)
    {
        ObjLink_AttachChild((GameObject*)obj,
                            (GameObject*)(gPlayerEggObject =
                                (int)objSetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                                     ((GameObject*)obj)->anim.parent)),
                            3);
    }
    if ((void*)gPlayerEggObject != NULL)
    {
        ((GameObject*)gPlayerEggObject)->anim.parent = (void*)((GameObject*)obj)->anim.parent;
        if (((PlayerState*)inner)->characterId == 0)
        {
            ((GameObject*)gPlayerEggObject)->anim.flags |= 0x4000;
        }
    }
    if (gPlayerStaffObject == NULL && (u8)Obj_CanSetupObject() != 0)
    {
        gPlayerStaffObject =
            (GameObject*)objSetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1, ((GameObject*)obj)->anim.parent);
    }
    if (gPlayerStaffObject != NULL)
    {
        ObjPath_GetPointWorldPosition((GameObject*)obj, 4, &gPlayerStaffObject->anim.localPosX,
                                      &gPlayerStaffObject->anim.localPosY, &gPlayerStaffObject->anim.localPosZ, 0);
    }
    if (((((PlayerState*)inner)->flags3F3.b08) != 0 || ((PlayerState*)inner)->animState == 0x40) &&
        (((PlayerState*)inner)->flags3F4.b80) == 0)
    {
        playerSetDisguised((GameObject*)obj, 0);
        ((PlayerState*)inner)->animState = -1;
    }
    ObjHits_DisableObject((GameObject*)obj);
    ((PlayerState*)inner)->flags360 &= ~2LL;
    if ((s8)seq->movementState != 0)
    {
        s8 c;
        ((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_AIM_READY;
        {
            f32 fz = 0.0f;
            ((PlayerState*)inner)->knockbackTimer = fz;
            ((PlayerState*)inner)->knockbackHitTimer = fz;
        }
        if (((PlayerState*)inner)->flags3F2.b80 == 0)
        {
            if (gPlayerPathObject != NULL && (((PlayerState*)inner)->flags3F4.b40) != 0)
            {
                ((PlayerState*)inner)->staffActionRequest = 1;
                ((PlayerState*)inner)->flags3F4.b08 = 1;
            }
            ((PlayerState*)inner)->isHoldingObject = 0;
            {
                GameObject* p = ((PlayerState*)inner)->heldObj;
                if (p != NULL)
                {
                    s16 sp = p->anim.romDefNo;
                    if (sp == SMALLBASKET_SEQUENCE_VARIANT_A || sp == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                    {
                        SmallBasket_throw(p);
                    }
                    else
                    {
                        Carryable_putDownAndSavePos(p);
                    }
                    *(s16*)((char*)((PlayerState*)inner)->heldObj + 6) &= ~0x4000;
                    ((PlayerState*)inner)->heldObj->userData2 = 0;
                    ((PlayerState*)inner)->heldObj = 0;
                }
            }
        }
        if (placement->movementEnabled == 0 || (c = (s8)seq->movementState) == 3 || c == 2)
        {
            seq->flags = seq->savedFlags;
            if ((s8)seq->movementState != 2)
            {
                seq->posOffsetScale = 1.0f;
                seq->posOffsetX = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj2)->anim.localPosX;
                seq->posOffsetY = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj2)->anim.localPosY;
                seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj2)->anim.localPosZ;
                seq->rotOffsetX = ((PlayerState*)inner)->targetYaw - (u16) * (s16*)obj2;
                if (seq->rotOffsetX > 0x8000)
                {
                    seq->rotOffsetX = seq->rotOffsetX - 0xffff;
                }
                if (seq->rotOffsetX < -0x8000)
                {
                    seq->rotOffsetX = seq->rotOffsetX + 0xffff;
                }
                seq->rotOffsetY = ((GameObject*)obj)->anim.rotY - (u16) * (s16*)((char*)obj2 + 2);
                if (seq->rotOffsetY > 0x8000)
                {
                    seq->rotOffsetY = seq->rotOffsetY - 0xffff;
                }
                if (seq->rotOffsetY < -0x8000)
                {
                    seq->rotOffsetY = seq->rotOffsetY + 0xffff;
                }
                seq->rotOffsetZ = (u16) * (s16*)((char*)obj2 + 4) - (u16)((GameObject*)obj)->anim.rotZ;
                if (seq->rotOffsetZ > 0x8000)
                {
                    seq->rotOffsetZ = seq->rotOffsetZ - 0xffff;
                }
                if (seq->rotOffsetZ < -0x8000)
                {
                    seq->rotOffsetZ = seq->rotOffsetZ + 0xffff;
                }
                seq->movementState = 2;
            }
            seq->posOffsetScale = -(seq->posOffsetDecay * timeDelta - seq->posOffsetScale);
            if (seq->posOffsetScale <= 0.0f)
            {
                seq->movementState = 0;
            }
            ((GameObject*)obj)->anim.activeMove = -1;
            ((PlayerState*)inner)->bodyLeanHalf = 0;
            ((PlayerState*)inner)->headPitch = 0;
            ((PlayerState*)inner)->bodyLeanAngle = 0;
            ((PlayerState*)inner)->headYaw = 0;
        }
        else if (c == 4)
        {
            f32 dy;
            f32 dz;
            f32 dx;
            int d;
            seq->flags &= ~0x4c;
            seq->savedFlags &= ~0x48;
            obj2 = (int)getFocusedNpc();
            if (objFindJointPoseVector((GameObject*)(obj2), 0) != 0)
            {
                objGetJointWorldPosition((GameObject*)(obj2), 0, npos);
            }
            else
            {
                ObjHitVolumeRuntimeTransform* pv = ((GameObject*)obj2)->anim.hitVolumeTransforms;
                if (pv == NULL)
                {
                    npos[0] = ((GameObject*)obj2)->anim.worldPosX;
                    npos[1] = ((GameObject*)obj2)->anim.worldPosY;
                    npos[2] = ((GameObject*)obj2)->anim.worldPosZ;
                }
                else
                {
                    npos[0] = pv->jointX;
                    npos[1] = pv->jointY;
                    npos[2] = pv->jointZ;
                }
            }
            ObjPath_GetPointWorldPosition((GameObject*)obj, 5, &px, &py, &pz, 0);
            dx = ((GameObject*)obj)->anim.worldPosX - npos[0];
            dy = (((PlayerState*)inner)->pathBearingEyeY + ((GameObject*)obj)->anim.worldPosY) - npos[1];
            dz = ((GameObject*)obj)->anim.worldPosZ - npos[2];
            {
                s16 ang = (s16)getAngle(dx, dz);
                lbl_803DE4B0 = ang;
                d = ang - (u16) ((PlayerState*)inner)->targetYaw;
            }
            if (d > 0x8000)
            {
                d -= 0xffff;
            }
            if (d < -0x8000)
            {
                d += 0xffff;
            }
            ((PlayerState*)inner)->bodyLeanAimBase = -*(s16*)(va + 2);
            ((PlayerState*)inner)->headYawAimBase = -*(s16*)va;
            if (d >= 0)
            {
                if (d > 0x2aaa)
                {
                    ((PlayerState*)inner)->bodyLeanAimDelta = -0x2aaa;
                    ((PlayerState*)inner)->aimTurnYaw = d - 0x2aaa;
                }
                else
                {
                    ((PlayerState*)inner)->bodyLeanAimDelta = -d;
                    ((PlayerState*)inner)->aimTurnYaw = 0;
                }
            }
            else if (d < -0x2aaa)
            {
                ((PlayerState*)inner)->bodyLeanAimDelta = 0x2aaa;
                ((PlayerState*)inner)->aimTurnYaw = d + 0x2aaa;
            }
            else
            {
                ((PlayerState*)inner)->bodyLeanAimDelta = -d;
                ((PlayerState*)inner)->aimTurnYaw = 0;
            }
            ((PlayerState*)inner)->headYawAimDelta = (s16)getAngle(dy, sqrtf(dx * dx + dz * dz));
            {
                int v = ((PlayerState*)inner)->headYawAimDelta;
                if (v < -0x1000)
                {
                    v = -0x1000;
                }
                else if (v > 0x1000)
                {
                    v = 0x1000;
                }
                ((PlayerState*)inner)->headYawAimDelta = v;
            }
            seq->rotOffsetZ = 0;
            seq->posOffsetScale = 0.0f;
            seq->posOffsetDecay = 0.033333335f;
            seq->movementState = 5;
            {
                int mv;
                if ((u32)((PlayerState*)inner)->heldObj != 0)
                {
                    mv = 8;
                }
                else
                {
                    mv = 0;
                }
                if (((GameObject*)obj)->anim.currentMove != mv)
                {
                    ObjAnim_SetCurrentMove((void*)obj, mv, 0.0f, 0);
                    ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent*)obj, 1);
                }
            }
            ObjAnim_AdvanceCurrentMove((void*)obj, 0.005f, timeDelta, 0);
            result = 1;
        }
        else if (c == 5)
        {
            seq->flags &= ~0x4c;
            seq->savedFlags &= ~0x48;
            ObjHits_EnableObject((GameObject*)obj);
            if (seq->posOffsetScale >= 1.0f && (*gCameraInterface)->isZooming() == 0)
            {
                ((PlayerState*)inner)->bodyLeanHalf = 0;
                ((PlayerState*)inner)->headPitch = 0;
                if ((s8)endFlag == 0)
                {
                    seq->movementState = 0;
                }
                else
                {
                    seq->movementState = 6;
                }
                if (((PlayerState*)inner)->focusObject != NULL)
                {
                    (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x18);
                    *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))playerStagedClearActiveMove;
                }
                else
                {
                    (*gPlayerInterface)->setState((void*)obj, (void*)inner, 1);
                    *(void (**)(int, int))((char*)inner + 0x304) = (void (*)(int, int))playerStagedRestoreDefaultControl;
                    ((PlayerState*)inner)->baddie.prevControlMode = 1;
                }
            }
            else
            {
                f32 prev = seq->posOffsetScale;
                f32 one;
                int dd;
                seq->posOffsetScale = seq->posOffsetDecay * timeDelta + prev;
                if (seq->posOffsetScale > 1.0f)
                {
                    seq->posOffsetScale = 1.0f;
                }
                prev = seq->posOffsetScale - prev;
                ((PlayerState*)inner)->targetYaw += (s16)(prev * (f32) ((PlayerState*)inner)->aimTurnYaw);
                *(s16*)obj = ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
                dd = ((PlayerState*)inner)->bodyLeanAimBase - (u16) ((PlayerState*)inner)->bodyLeanAimDelta;
                if (dd > 0x8000)
                {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000)
                {
                    dd = dd + 0xffff;
                }
                *(s16*)(va + 2) = (s16)((f32)dd * seq->posOffsetScale + (f32) ((PlayerState*)inner)->bodyLeanAimBase);
                dd = ((PlayerState*)inner)->headYawAimBase - (u16) ((PlayerState*)inner)->headYawAimDelta;
                if (dd > 0x8000)
                {
                    dd = dd - 0xffff;
                }
                if (dd < -0x8000)
                {
                    dd = dd + 0xffff;
                }
                *(s16*)va = (s16)((f32)dd * seq->posOffsetScale + (f32) ((PlayerState*)inner)->headYawAimBase);
                *(s16*)(vb + 2) = (s16)((f32) ((PlayerState*)inner)->bodyLeanHalf * ((one = 1.0f) - seq->posOffsetScale));
                *(s16*)(vb + 4) = (s16)((f32) ((PlayerState*)inner)->headPitch * (one - seq->posOffsetScale));
                ((GameObject*)obj)->anim.rotZ = *(s16*)(vb + 4) / 4;
                ((PlayerState*)inner)->bodyLeanAngle = *(s16*)(va + 2);
                ((PlayerState*)inner)->headYaw = -*(s16*)va;
            }
            ObjAnim_AdvanceCurrentMove((void*)obj, 0.005f, timeDelta, 0);
            result = 1;
        }
        else if (c == 6)
        {
            seq->flags &= ~0x4c;
            seq->savedFlags &= ~0x48;
            ObjHits_EnableObject((GameObject*)obj);
            if ((s8)endFlag == 0)
            {
                seq->movementState = 0;
            }
            ObjAnim_AdvanceCurrentMove((void*)obj, 0.005f, timeDelta, 0);
            result = 0;
        }
        else
        {
            f32 dx2;
            f32 dz2;
            f32 dist;
            f32 d2;
            if (c != 1)
            {
                seq->posOffsetX = ((GameObject*)obj)->anim.localPosX;
                seq->posOffsetY = ((GameObject*)obj)->anim.localPosY;
                seq->posOffsetZ = ((GameObject*)obj)->anim.localPosZ;
                gPlayerSeqWalkPrevDist = 10000.0f;
                gPlayerSeqWalkStallFrames = 0;
            }
            result = 1;
            seq->flags = 0;
            seq->movementState = 1;
            {
                f32 ax = seq->posOffsetX - ((GameObject*)obj)->anim.localPosX;
                f32 az = seq->posOffsetZ - ((GameObject*)obj)->anim.localPosZ;
                dist = sqrtf(ax * ax + az * az);
            }
            dx2 = ((GameObject*)obj2)->anim.localPosX - seq->posOffsetX;
            dz2 = ((GameObject*)obj2)->anim.localPosZ - seq->posOffsetZ;
            d2 = sqrtf(dx2 * dx2 + dz2 * dz2);
            if (dist <= gPlayerSeqWalkPrevDist)
            {
                gPlayerSeqWalkStallFrames += 1;
            }
            if (dist >= d2 || gPlayerSeqWalkStallFrames > 5)
            {
                int dd3 = ((PlayerState*)inner)->targetYaw - (u16) * (s16*)obj2;
                if (dd3 > 0x8000)
                {
                    dd3 -= 0xffff;
                }
                if (dd3 < -0x8000)
                {
                    dd3 += 0xffff;
                }
                if (dd3 > 0x4000)
                {
                    dd3 = 0x4000;
                }
                if (dd3 < -0x4000)
                {
                    dd3 = -0x4000;
                }
                ((PlayerState*)inner)->targetYaw -= (dd3 * framesThisStep) >> 3;
                ((PlayerState*)inner)->yaw = ((PlayerState*)inner)->targetYaw;
                if (gPlayerSeqWalkStallFrames > 6)
                {
                    dd3 = 0;
                }
                if (dd3 < 0x100 && dd3 > -0x100)
                {
                    seq->flags = seq->savedFlags;
                    seq->movementState = 0;
                    seq->prevFrame = seq->curFrame - 1;
                    ((GameObject*)obj)->anim.activeMove = -1;
                    result = 0;
                }
                else
                {
                    f32 fz3 = 0.0f;
                    ((PlayerState*)inner)->baddie.moveInputX = fz3;
                    ((PlayerState*)inner)->baddie.moveInputZ = fz3;
                    (*gPlayerInterface)->setOverride((void*)obj2);
                    ((PlayerState*)inner)->baddie.pressedButtons = 0;
                    *(int*)&((PlayerState*)inner)->baddie.heldButtons = 0;
                    ((GameObject*)obj)->userData1 = 0;
                    ((PlayerState*)inner)->baddie.cameraYaw = 0;
                    ((PlayerState*)inner)->baddie.physicsActive = 1;
                    ((PlayerState*)inner)->baddie.flags4 = ((PlayerState*)inner)->baddie.flags4 & ~0x100000;
                    ((PlayerState*)inner)->emissionState = 0;
                    playerUpdateMotionState((GameObject*)obj, (void*)inner, &((PlayerState*)inner)->baddie);
                    (*gPlayerInterface)->update((void*)obj, (void*)inner, timeDelta, timeDelta, gPlayerStateHandlers,
                        &gPlayerDefaultStateHandler);
                }
            }
            else
            {
                dx2 = dx2 / d2;
                dz2 = dz2 / d2;
                {
                    f32 k = 40.0f;
                    ((PlayerState*)inner)->baddie.moveInputX = k * -dx2;
                    ((PlayerState*)inner)->baddie.moveInputZ = k * dz2;
                }
                ((GameObject*)obj)->anim.localPosX = dist * dx2 + seq->posOffsetX;
                ((GameObject*)obj)->anim.localPosZ = dist * dz2 + seq->posOffsetZ;
                (*gPlayerInterface)->setOverride((void*)obj2);
                ((PlayerState*)inner)->baddie.pressedButtons = 0;
                *(int*)&((PlayerState*)inner)->baddie.heldButtons = 0;
                ((GameObject*)obj)->userData1 = 0;
                ((PlayerState*)inner)->baddie.cameraYaw = 0;
                ((PlayerState*)inner)->baddie.physicsActive = 1;
                ((PlayerState*)inner)->baddie.flags4 = ((PlayerState*)inner)->baddie.flags4 & ~0x100000;
                ((PlayerState*)inner)->emissionState = 0;
                playerUpdateMotionState((GameObject*)obj, (void*)inner, &((PlayerState*)inner)->baddie);
                (*gPlayerInterface)->update((void*)obj, (void*)inner, timeDelta, timeDelta, gPlayerStateHandlers,
                    &gPlayerDefaultStateHandler);
            }
            gPlayerSeqWalkPrevDist = dist;
        }
        if ((s8)seq->movementState == 0)
        {
            (*gPlayerInterface)->setState((void*)obj, (void*)inner, 1);
            *(void (**)(int, int))((char*)inner + 0x304) = (void (*)(int, int))playerStagedRestoreDefaultControl;
            ((PlayerState*)inner)->baddie.prevControlMode = 1;
        }
    }
    else
    {
        seq->flags |= seq->savedFlags & ~0x400;
        ((PlayerState*)inner)->baddie.movementFlags = 0;
        {
            f32 fz2 = 0.0f;
            ((PlayerState*)inner)->baddie.moveInputX = fz2;
            ((PlayerState*)inner)->baddie.moveInputZ = fz2;
        }
        ((PlayerState*)inner)->baddie.cameraYaw = 0;
        ((PlayerState*)inner)->baddie.pressedButtons = 0;
        *(int*)&((PlayerState*)inner)->baddie.heldButtons = 0;
        if (seq->flags & 1)
        {
            ((PlayerState*)inner)->baddie.flags4 |= 0x100000;
            ((PlayerState*)inner)->baddie.physicsActive = 0;
        }
        for (vb = 0; vb < seq->eventCount; vb++)
        {
            switch (seq->eventIds[vb])
            {
            case 3:
            {
                f32 best;
                u8 found;
                void* objs = objGetAllOfType(10, &objCount);
                found = 0;
                best = 10000.0f;
                for (endFlag = 0, obj2 = (int)objs; endFlag < objCount; endFlag++)
                {
                    va = *(int*)obj2;
                    if ((u32)va != 0 && arrayIndexOf((int*)(tbl + 0x13c), 9, ((GameObject*)va)->anim.romDefNo) != -1)
                    {
                        f32 dsq = vec3f_distanceSquared((f32*)(va + 0x18), (f32*)(obj + 0x18));
                        if (dsq < best || found == 0)
                        {
                            best = dsq;
                            ((PlayerState*)inner)->focusObject = (GameObject*)va;
                            found = 1;
                        }
                    }
                    obj2 += 4;
                }
                if (found != 0)
                {
                    ((PlayerState*)inner)->unk6A4 = 1.0f;
                    ((PlayerState*)inner)->unk6A8 = ((PlayerState*)inner)->savedPosX;
                    ((PlayerState*)inner)->unk6AC = ((PlayerState*)inner)->savedPosY;
                    ((PlayerState*)inner)->unk6B0 = ((PlayerState*)inner)->savedPosZ;
                    va = (int)((PlayerState*)inner)->focusObject;
                    VEHICLE_INTERFACE(va)->setMountState((GameObject*)va, VEHICLE_Mounted);
                    ((GameObject*)obj)->anim.flags |= 8;
                    ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                    ((GameObject*)obj)->anim.modelState->shadowAlphaStep = 0;
                    seq->flags &= ~4;
                    switch (((GameObject*)va)->anim.romDefNo)
                    {
                    case 0x72:
                    case 0x38c:
                        Music_Trigger(MUSICTRIG_drako_2, 1);
                        mainSetBits(0xc1f, 0);
                        ((PlayerState*)inner)->moveSequence = (s16*)(tbl + 0x3f0);
                        ((PlayerState*)inner)->moveSequenceFlags = 3;
                        ObjAnim_SetCurrentMove((void*)obj, 0x17, 0.0f, 1);
                        break;
                    case 0x8c:
                        ((PlayerState*)inner)->moveSequence = (s16*)(tbl + 0x408);
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove((void*)obj, 0x7b, 0.0f, 1);
                        if (getSbGalleon() != NULL)
                        {
                            (*gCameraInterface)->setFocus((void*)va, 0);
                            (*gObjectTriggerInterface)->setCamVars(0x4a, 1, 0, 0x78);
                        }
                        break;
                    case 0x416:
                        Music_Trigger(MUSICTRIG_WLC_Puzzle, 1);
                        ((PlayerState*)inner)->moveSequence = (s16*)(tbl + 0x438);
                        ((PlayerState*)inner)->moveSequenceFlags = 8;
                        ObjAnim_SetCurrentMove((void*)obj, *(s16*)(tbl + 0x438), 0.0f, 1);
                        break;
                    case 0x419:
                        Music_Trigger(MUSICTRIG_starfox_rwing_1_e6, 1);
                        ((PlayerState*)inner)->moveSequence = (s16*)(tbl + 0x408);
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove((void*)obj, 0x7b, 0.0f, 1);
                        break;
                    case 0x484:
                        Music_Trigger(MUSICTRIG_starfox_rwing_1_e6, 1);
                        ((PlayerState*)inner)->moveSequence = (s16*)(tbl + 0x420);
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove((void*)obj, 0xf8, 0.0f, 1);
                        break;
                    default:
                        Music_Trigger(MUSICTRIG_inside_warlock, 1);
                    case 0x714:
                        ((PlayerState*)inner)->moveSequence = (s16*)(tbl + 0x420);
                        ((PlayerState*)inner)->moveSequenceFlags = 4;
                        ObjAnim_SetCurrentMove((void*)obj, 0xf8, 0.0f, 1);
                    }
                    if (arrayIndexOf((int*)(tbl + 0x160), 4, ((GameObject*)va)->anim.romDefNo) != -1)
                    {
                        (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x1a);
                        *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))playerStagedClearActiveMove;
                    }
                    else
                    {
                        (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x18);
                        *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))playerStagedClearActiveMove;
                    }
                }
                break;
            }
            case 2:
                if (playerStopRidingObject((GameObject*)obj) != 0)
                {
                    seq->flags |= 4;
                }
                break;
            case 4:
                obj2 = (int)((PlayerState*)inner)->focusObject;
                (*gCameraInterface)->setFocus((void*)obj2, 0);
                (*gObjectTriggerInterface)->setCamVars(0x45, 0, 0, 0);
                ((PlayerState*)inner)->moveSequence = 0;
                if ((u32)obj2 != 0 && ((GameObject*)obj2)->anim.romDefNo == 0x22)
                {
                    (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x16);
                    ((PlayerState*)inner)->baddie.stateExitFn = NULL;
                }
                else
                {
                    (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x18);
                    *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))playerStagedClearActiveMove;
                }
                break;
            case 0xb:
            {
                GameObject* gb = ((PlayerState*)inner)->focusObject;
                if ((u32)gb != 0 && gb->anim.romDefNo == 0x416)
                {
                    (*gCameraInterface)->setFocus((void*)gb, 0);
                    (*gCameraInterface)->loadTriggeredCamAction(0, 0x69, 0);
                    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);
                }
                else if ((u32)gb != 0 && arrayIndexOf((int*)(tbl + 0x160), 4, gb->anim.romDefNo) != -1)
                {
                    (*gObjectTriggerInterface)->setCamVars(CAMERA_MODE_CLOUDRUNNER_RESOURCE_ID, 0, 0, 0);
                }
                else
                {
                    (*gCameraInterface)->loadTriggeredCamAction(0, 0x1d, 0);
                    (*gObjectTriggerInterface)->setCamVars(0x42, 4, 0, 0);
                }
                break;
            }
            case 6:
                (*gObjectTriggerInterface)->setCamVars(CAMERA_MODE_VIEWFINDER_RESOURCE_ID, 0, 0, 0);
                (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x17);
                ((PlayerState*)inner)->baddie.stateExitFn = NULL;
                break;
            case 7:
                seq->flags &= ~3;
                obj2 = (int)((GameObject*)obj)->extra;
                (*gPlayerInterface)->setState((void*)obj, (void*)obj2, 0x3e);
                ((PlayerState*)obj2)->baddie.stateExitFn = NULL;
                ((PlayerState*)obj2)->flags360 |= 1LL;
                ((GameObject*)obj)->anim.flags |= 8;
                break;
            case 8:
            {
                seq->flags = seq->savedFlags;
                obj2 = (int)((GameObject*)obj)->extra;
                (*gPlayerInterface)->setState((void*)obj, (void*)obj2, 1);
                *(void (**)(int, int))(obj2 + 0x304) = (void (*)(int, int))playerStagedRestoreDefaultControl;
                ((PlayerState*)obj2)->flags360 &= ~0x1LL;
                ((GameObject*)obj)->anim.flags &= ~8;
                break;
            }
            case 0xa:
                if (gPlayerPathObject != NULL && (((PlayerState*)inner)->flags3F4.b40) != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 2;
                    ((PlayerState*)inner)->flags3F4.b08 = 0;
                }
                break;
            case 0x18:
                if (gPlayerPathObject != NULL && (((PlayerState*)inner)->flags3F4.b40) != 0)
                {
                    ((PlayerState*)inner)->staffActionRequest = 0;
                    ((PlayerState*)inner)->flags3F4.b08 = 0;
                }
                break;
            case 0xd:
            {
                f32 spd;
                f32 dy2;
                (*gObjectTriggerInterface)
                    ->setObjects(((GameObject*)((GameObject*)obj)->ownerObj)->anim.romDefNo,
                                 ((GameObject*)obj)->ownerObj, 0);
                {
                    GameObject* prt = ((GameObject*)obj)->ownerObj;
                    obj2 = (int)prt->extra;
                    if (*(u32*)&prt->anim.hitReactState != 0)
                    {
                        spd = (f32) * (s16*)((int)prt->anim.hitReactState + 0x5a);
                    }
                    else
                    {
                        spd = prt->anim.hitboxScale * prt->anim.rootMotionScale;
                    }
                    dy2 = (prt->anim.hitVolumeTransforms->jointY - prt->anim.localPosY) -
                          29.0f;
                }
                (*gObjectTriggerInterface)
                    ->setOverridePos(spd * -mathSinf(3.1415927f * (f32) ((PlayerState*)obj2)->targetYaw / 32768.0f), dy2,
                                     spd * -mathCosf(3.1415927f * (f32) ((PlayerState*)obj2)->targetYaw / 32768.0f));
                (*gObjectTriggerInterface)->runSequence(((GameObject*)obj)->userData1, (void*)obj, -1);
                break;
            }
            case 0xf:
                Obj_SetParent((GameObject*)obj, NULL, 1);
                break;
            case 0x10:
            {
                GameObject* t;
                nearArg = 400.0f;
                t = objGetNearestTypeTo(6, (GameObject*)obj, &nearArg);
                if (t != NULL)
                {
                    Obj_SetParent((GameObject*)obj, t, 1);
                }
                break;
            }
            case 0x17:
                va = (int)((GameObject*)obj)->extra;
                if (((PlayerState*)va)->heldObj != NULL)
                {
                    ((PlayerState*)va)->isHoldingObject = 0;
                    {
                        GameObject* p17 = ((PlayerState*)va)->heldObj;
                        if ((u32)p17 != 0)
                        {
                            s16 romDefNo = p17->anim.romDefNo;
                            if (romDefNo == SMALLBASKET_SEQUENCE_VARIANT_A || romDefNo == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                            {
                                SmallBasket_throw((GameObject*)(p17));
                            }
                            else
                            {
                                Carryable_putDownAndSavePos((GameObject*)p17);
                            }
                            ((PlayerState*)va)->heldObj->anim.flags &= ~0x4000;
                            ((PlayerState*)va)->heldObj->userData2 = 0;
                            ((PlayerState*)va)->heldObj = NULL;
                        }
                    }
                    ((PlayerState*)va)->flags360 |= 0x800000LL;
                    (*gPlayerInterface)->setState((void*)obj, (void*)va, 1);
                    *(void (**)(int, int))(va + 0x304) = (void (*)(int, int))playerStagedRestoreDefaultControl;
                }
                break;
            case 0x14:
            {
                ((PlayerState*)inner)->flags360 |= 0x40000LL;
                break;
            }
            case 0x15:
            {
                ((PlayerState*)inner)->flags360 &= ~0x40000LL;
                break;
            }
            case 0x16:
            {
                ((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WATER_SPLASH_PENDING;
                break;
            }
            case 0x12:
            {
                ((PlayerState*)inner)->flags360 |= 0x8000LL;
                break;
            }
            case 0x13:
                loadUiDll(1);
                break;
            case 0x19:
                (*gMapEventInterface)->gotoRestartPoint();
                break;
            case 0x1c:
                staffToggle((GameObject*)(obj), 0);
                break;
            case 0x1d:
                (*gPlayerInterface)->setState((void*)obj, (void*)inner, 0x1a);
                *(void (**)(int))((char*)inner + 0x304) = (void (*)(int))playerStagedClearActiveMove;
                break;
            case 0x1e:
                (*gPlayerInterface)->setState((void*)obj, (void*)inner, 1);
                *(void (**)(int, int))((char*)inner + 0x304) = (void (*)(int, int))playerStagedRestoreDefaultControl;
                break;
            case 0x1f:
                ObjModelChain_ResetFirstUpdate((ObjModelChain*)gPlayerModelChain);
                ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 1);
                break;
            case 0x20:
                ObjModelChain_SetEnabled((ObjModelChain*)gPlayerModelChain, 0);
                break;
            case 0x21:
                gPlayerModelChainStyle = 2;
                break;
            case 0x22:
                gPlayerModelChainStyle = 1;
                break;
            case 0x1a:
                if (((PlayerState*)inner)->interactObject != 0)
                {
                    ObjDef* def = ((GameObject*)((PlayerState*)inner)->interactObject)->anim.modelInstance;
                    int snd = def->npcDialogueTextId;
                    if (snd > -1)
                    {
                        (*gGameUIInterface)->showNpcDialogue(snd, 0x154, 300, 0);
                    }
                    else
                    {
                        (*gGameUIInterface)->showNpcDialogue(def->helpTextIds[0], 0x154, 300, 0);
                    }
                }
                break;
            case 1:
                if (((PlayerState*)inner)->interactObject != 0)
                {
            ObjMsg_SendToObject((void*)((PlayerState*)inner)->interactObject, 0x7000b, (void*)obj, 0);
                    ((PlayerState*)inner)->interactObject = 0;
                }
                break;
            case 0x25:
                ((PlayerState*)inner)->pendingFxFlags ^= 1;
                break;
            case 0x26:
                ((PlayerState*)inner)->pendingFxFlags ^= 2;
                break;
            case 0x27:
                setHudForceShowMask(1);
                break;
            case 0x28:
            {
                int h;
                int mapVal;
                switch (coordsToMapCell(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosZ))
                {
                case 0x13:
                    mapVal = 0x10;
                    break;
                case 0xc:
                    mapVal = 0x14;
                    break;
                case 0xd:
                    mapVal = 0x18;
                    break;
                case 2:
                    mapVal = 0x1c;
                    break;
                }
                h = (int)((GameObject*)obj)->extra;
                if ((s8) * (s8*)(*(int*)(h + 0x35c) + 1) <= mapVal - 4)
                {
                    int vv = mapVal;
                    if (mapVal < 0)
                    {
                        vv = 0;
                    }
                    else if (mapVal > 0x50)
                    {
                        vv = 0x50;
                    }
                    ((PlayerState*)h)->playerStatus->maxHealth = vv;
                    vv = mapVal;
                    h = (int)((GameObject*)obj)->extra;
                    if (mapVal < 0)
                    {
                        vv = 0;
                    }
                    else
                    {
                        s8 cur2 = *(s8*)(*(int*)(h + 0x35c) + 1);
                        if (mapVal > cur2)
                        {
                            vv = cur2;
                        }
                    }
                    ((PlayerState*)h)->playerStatus->health = vv;
                }
                break;
            }
            case 0x29:
                setHudForceShowMask(0);
                break;
            case 0x2a:
                if ((*gMapEventInterface)->getMapAct(0xb) == 7)
                {
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x1fb, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x1ff, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x249, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x1fd, 0);
                }
                else
                {
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x217, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x216, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x22e, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x218, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x84, 0);
                    getEnvfxActImmediately((void*)obj, (void*)obj, 0x8a, 0);
                }
                skySetLightIndex(0, 0.0f);
                break;
            case 0x2d:
                Rcp_SetSpiritVisionEnabled(1);
                break;
            case 0x2e:
                Rcp_SetSpiritVisionEnabled(0);
                break;
            case 0x2b:
                ((GameObject*)obj)->anim.modelState->flags &= ~(long long)OBJ_MODEL_STATE_SHADOW_VISIBLE;
                break;
            case 0x2c:
                ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
                break;
            case 0x31:
                viewFinderSetZoomTo50();
                break;
            case 0x32:
                viewFinderSetZoom(Camera_GetFovY());
                break;
            }
        }
        if (*(int*)&((PlayerState*)((GameObject*)obj)->extra)->flags360 & 1)
        {
            seq->flags &= ~3;
        }
    }
    if (lbl_803DE458 != 0)
    {
        seq->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        lbl_803DE458 = 0;
    }
    {
        int g = (int)((PlayerState*)inner)->focusObject;
        if ((u32)g != 0 && VEHICLE_INTERFACE(g)->getMountState((GameObject*)g) == 2)
        {
            seq->flags &= ~3;
        }
    }
    if (((PlayerState*)inner)->flags3F2.b40 != 0)
    {
        characterDoEyeAnims((GameObject*)obj, (char*)inner + 0x364);
    }
    if (gPlayerModelChainStyle == 2)
    {
        gPlayerModelChainStyle = 1;
    }
    if (gPlayerPathObject->anim.classId == 0x2d)
    {
        objSetAnimField48to0((GameObject*)gPlayerPathObject);
    }
    staffAnimate((GameObject*)obj, (void*)inner, timeDelta);
    if (gPlayerPathObject != NULL && (((PlayerState*)inner)->flags3F4.b40) != 0)
    {
        gPlayerPathObject->objectFlags &= ~7;
        if (((PlayerState*)inner)->staffGrown == 0)
        {
            gPlayerPathObject->objectFlags |= 2;
        }
    }
    ((PlayerState*)inner)->flags360 |= PLAYER_FLAG_TELEPORTED;
    objAudioDispatchAnimEvents((GameObject*)obj, &seq->animEvents, ((PlayerState*)inner)->animSoundId,
                               (void*)((char*)inner + 0x3c4), (void*)((char*)inner + 4),
                               ((PlayerState*)inner)->baddie.animSpeedA, 1.0f);
    return result;
}

void playerUpdateTargetSelection(GameObject* obj, PlayerState* inner, PlayerState* inner2)
{
    GameObject* target = (GameObject*)(*gCameraInterface)->getOverrideTarget();
    u32 v = inner->flags3F4.b40;

    if (v != 0)
    {
        if ((((PlayerState*)inner)->flags360 & 0x10) != 0)
        {
            if (gPlayerPathObject != NULL && v != 0)
            {
                ((PlayerState*)inner)->staffActionRequest = 2;
                ((PlayerState*)inner)->flags3F4.b08 = 0;
            }
            ((PlayerState*)inner2)->baddie.hasTarget = 1;
            if (target != NULL)
            {
                ((PlayerState*)inner2)->baddie.targetObj = (void*)target;
            }
            else
            {
                f32 dist = 500.0f;
                ((PlayerState*)inner2)->baddie.targetObj = objGetNearestTypeTo(3, obj, &dist);
            }
        }
        else
        {
            if (target != NULL)
            {
                if ((GameObject*)((PlayerState*)inner2)->baddie.targetObj != target)
                {
                    ((PlayerState*)inner2)->baddie.hasTarget = 0;
                    if ((target->anim.hitVolumeBounds->flags & 0xf) == 1)
                    {
                        if (gPlayerPathObject != NULL)
                        {
                            u32 targetFlag = ((PlayerState*)inner)->flags3F4.b40;
                            if (targetFlag != 0)
                            {
                                ((PlayerState*)inner)->staffActionRequest = 2;
                                ((PlayerState*)inner)->flags3F4.b08 = 0;
                            }
                        }
                        ((PlayerState*)inner2)->baddie.hasTarget = 1;
                    }
                }
                ((PlayerState*)inner2)->baddie.targetObj = (void*)target;
            }
            else
            {
                ((PlayerState*)inner2)->baddie.targetObj = 0;
                ((PlayerState*)inner2)->baddie.hasTarget = 0;
            }
        }
        if ((int*)((PlayerState*)inner2)->baddie.targetObj != NULL)
        {
            enemy_getCurveParams((GameObject*)((PlayerState*)inner2)->baddie.targetObj, (int*)&((PlayerState*)inner)->flags884,
                        &((PlayerState*)inner)->animSpeedDecay, &((PlayerState*)inner)->animSpeedStart);
        }
        else
        {
            ((PlayerState*)inner)->deferredItemCommand = -1;
        }
    }
}

void playerAnimate(GameObject* obj, PlayerState* state, f32 fv)
{
    u8 buf[0x40];

    state->baddie.gravity = 0.15f;
    state->baddie.moveInputX = state->stickXf;
    state->baddie.moveInputZ = state->stickYf;
    state->baddie.pressedButtons = state->buttonsJustPressed;
    state->baddie.heldButtons = state->buttonsHeld;
    Player_GetObjHitsState(obj)->hitVolumePriority = 0;
    Player_GetObjHitsState(obj)->hitVolumeId = 0;
    Player_GetObjHitsState(obj)->objectPairPriority = 0;
    Player_GetObjHitsState(obj)->objectPairHitVolume = 0;
    state->baddie.physicsActive = 1;
    state->baddie.flags4 &= ~0x8100000;
    playerShadowClearPositionOverride(obj);
    ((PlayerState*)state)->emissionState = 0;
    ((PlayerState*)state)->flags360 &= ~PLAYER_FLAG_NO_POS_VELOCITY;
    *(int*)state |= 0x1000000;
    playerUpdateMotionState(obj, (void*)state, &((PlayerState*)state)->baddie);
    if ((s8)playerCheckIfClimbingOntoWall((int)obj, (int)state, (int)state, buf, fv, 0x60) == 8)
    {
        ((PlayerState*)state)->baddie.targetObj = 0;
        ((PlayerState*)state)->baddie.hasTarget = 0;
        (*gCameraInterface)->setTarget(0);
        if (gPlayerPathObject != 0 && ((PlayerState*)state)->flags3F4.b40)
        {
            ((PlayerState*)state)->staffActionRequest = 1;
            ((PlayerState*)state)->flags3F4.b08 = 1;
        }
        (*gPlayerInterface)->setState(obj, (void*)state, 0xa);
        state->baddie.stateExitFn = NULL;
    }
    (*gPlayerInterface)->update(obj, (void*)state, fv, fv, gPlayerStateHandlers, &gPlayerDefaultStateHandler);
    state->baddie.flags0 &= ~0x1000000;
}

void playerFree(GameObject* obj, int flag)
{
    int off;
    int i;
    PlayerState* inner = obj->extra;

    if ((u32)gPlayerEggObject != 0)
    {
        Obj_FreeObject((GameObject*)gPlayerEggObject);
        ObjLink_DetachChild(obj, (GameObject*)gPlayerEggObject);
        gPlayerEggObject = 0;
    }
    if (gPlayerPathObject != NULL)
    {
        Obj_FreeObject((GameObject*)gPlayerPathObject);
        ObjLink_DetachChild(obj, (GameObject*)gPlayerPathObject);
        gPlayerPathObject = NULL;
    }
    if (gPlayerStaffObject != NULL)
    {
        gPlayerStaffObject = NULL;
    }
    for (i = 0, off = 0; i < inner->moveSlotCount; i++)
    {
        s16* e = ((PlayerMoveSlot*)(inner->moveSlots + off))->weaponDa.entries;
        if (e != NULL)
            mm_free(e);
        off += 0xb0;
    }
    objFreeObjectType((GameObject*)obj, 0);
    objFreeObjectType((GameObject*)obj, PLAYER_OBJGROUP);
    ObjModelChain_Free((ObjModelChain*)gPlayerModelChain);
}


void playerRenderFuzz(GameObject* obj, int p2, int fuzzPass)
{
    PlayerState* inner = obj->extra;
    f32 sx, sy, sz;
    u32 v;
    u32 m;

    if ((s8)p2 != -1)
    {
        if ((inner->flags360 & 0x4001) != 0)
        {
            return;
        }
    }
    v = inner->flags3F3.b08;
    if (v != 0)
    {
        return;
    }
    if ((u32)obj->anim.alpha < 2)
    {
        return;
    }
    if (inner->focusObject != NULL)
    {
        if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
            arrayIndexOf(lbl_803DC6C4, 2, inner->baddie.controlMode) != -1)
        {
            GameObject* p = inner->focusObject;
            VEHICLE_INTERFACE(p)->handleRiderScale(p, obj->anim.modelInstance->rootMotionScaleBase);
        }
    }
    if ((inner->flags360 & 0x8000000) != 0)
    {
        sx = obj->anim.localPosX;
        sy = obj->anim.localPosY;
        sz = obj->anim.localPosZ;
        obj->anim.localPosX = obj->anim.modelState->overrideWorldPosX;
        obj->anim.localPosY = obj->anim.modelState->overrideWorldPosY;
        obj->anim.localPosZ = obj->anim.modelState->overrideWorldPosZ;
        obj->anim.modelState->overrideWorldPosX = sx;
        obj->anim.modelState->overrideWorldPosY = sy;
        obj->anim.modelState->overrideWorldPosZ = sz;
    }
    obj->anim.localPosY = obj->anim.localPosY + inner->sinkOffsetY;
    m = (u32)(fuzzPass & 0xff);
    if (m == 1)
    {
        objRenderFuzz(obj);
    }
    else if (m == 2)
    {
        objRenderFuzzShadowShells(obj);
    }
    else if (m == 4)
    {
        objRenderFuzzShells(obj);
    }
    objSetCurrentMatrix(NULL);
    obj->anim.localPosY = obj->anim.localPosY - inner->sinkOffsetY;
    if ((inner->flags360 & 0x8000000) != 0)
    {
        obj->anim.modelState->overrideWorldPosX = obj->anim.localPosX;
        obj->anim.modelState->overrideWorldPosY = obj->anim.localPosY;
        obj->anim.modelState->overrideWorldPosZ = obj->anim.localPosZ;
        obj->anim.localPosX = sx;
        obj->anim.localPosY = sy;
        obj->anim.localPosZ = sz;
    }
}

void playerRender(int obj, int a, int b, int c, int d, int flag)
{
    PlayerState* in2;
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 sx;
    f32 sy;
    f32 sz;
    f32 qz;
    f32 qy;
    f32 qx;
    f32 pz;
    f32 py;
    f32 px;
    struct
    {
        u16 mode;
        u8 pad[6];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 vel[3];

    if ((s8)flag == -1 || (inner->flags360 & 0x4001) == 0)
    {
        if (inner->focusObject != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf(lbl_803DC6C4, 2, inner->baddie.controlMode) != -1))
        {
            playerSyncTransformToFocusObject((GameObject*)obj, (PlayerState*)inner, inner->focusObject, a, b, c, d, 1);
        }
        if (inner->teleportAnimActive == 1)
        {
            playerDrawTeleportAnim((GameObject*)(obj));
        }
        (*gPlayerShadowInterface)->renderObject((GameObject*)obj);
        if (inner->focusObject != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf(lbl_803DC6C4, 2, inner->baddie.controlMode) != -1))
        {
            {
                char* held = (char*)inner->focusObject;
                ObjDef* mi = ((GameObject*)obj)->anim.modelInstance;
                VEHICLE_INTERFACE(held)->handleRiderScale((GameObject*)held, mi->rootMotionScaleBase);
            }
        }
        if ((inner->flags360 & 0x8000000) != 0)
        {
            sx = ((GameObject*)obj)->anim.localPosX;
            sy = ((GameObject*)obj)->anim.localPosY;
            sz = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.modelState->overrideWorldPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.modelState->overrideWorldPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.modelState->overrideWorldPosZ;
        }
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + inner->sinkOffsetY;
        objRenderModelAndHitVolumes((GameObject*)obj, a, b, c, d, 1.0f);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - inner->sinkOffsetY;
        if ((inner->flags360 & 0x8000000) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = sx;
            ((GameObject*)obj)->anim.localPosY = sy;
            ((GameObject*)obj)->anim.localPosZ = sz;
        }
        if ((s8)flag != 0)
        {
            playerRenderPostEffects((GameObject*)obj, (PlayerState*)inner, a, b, c);
        }
        ObjPath_GetPointWorldPositionArray((GameObject*)obj, 6, 2, (f32*)((char*)inner + 0x3c4));
        ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, (f32*)((char*)inner + 0x768), (f32*)((char*)inner + 0x76c),
                                      (f32*)((char*)inner + 0x770), 0);
        if (playerHasKrazoaSpirit(1, 0) != 0)
        {
            if ((void*)gPlayerHeldObject == NULL)
            {
                int i;
                ModelFileHeader* m = Obj_GetActiveModel((GameObject*)obj)->file;
                for (i = 0; i < m->renderOpCount; i++)
                {
                    Shader* op = ObjModel_GetRenderOp(m, i);
                    if (op->layerCount == 2)
                    {
                        Shader_getLayer(op, 1);
                        gPlayerHeldObject = (int)op;
                        op->flags |= 0x100000LL;
                        break;
                    }
                }
            }
        }
        else if ((void*)gPlayerHeldObject != NULL)
        {
            *(u32*)((char*)gPlayerHeldObject + 0x3c) = *(u32*)((char*)gPlayerHeldObject + 0x3c) & ~0x100000LL;
            {
                int zero = 0;
                gPlayerHeldObject = zero;
            }
        }
        {
            in2 = ((GameObject*)obj)->extra;
            if (in2->heldObj != NULL && *(int*)((char*)(int)in2->heldObj + 0xf8) == 1)
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 8, &px, &py, &pz, 0);
                ObjPath_GetPointWorldPosition((GameObject*)obj, 9, &qx, &qy, &qz, 0);
                px = 0.5f * (px + qx);
                py = 0.5f * (py + qy);
                pz = 0.5f * (pz + qz);
                if (*(s16*)((char*)(int)in2->heldObj + 0x46) == 0x112)
                {
                    py += 2.0f;
                }
                *(f32*)((char*)(int)in2->heldObj + 0xc) = *(f32*)((char*)(int)in2->heldObj + 0x18) =
                    px;
                *(f32*)((char*)(int)in2->heldObj + 0x10) =
                    *(f32*)((char*)(int)in2->heldObj + 0x1c) = py;
                *(f32*)((char*)(int)in2->heldObj + 0x14) =
                    *(f32*)((char*)(int)in2->heldObj + 0x20) = pz;
                if ((s16*)((GameObject*)obj)->anim.parent != NULL)
                {
                    *(s16*)(int)in2->heldObj =
                        *(s16*)((GameObject*)obj)->anim.parent + ((GameObject*)obj)->anim.rotX;
                }
                else
                {
                    *(s16*)(int)in2->heldObj = in2->targetYaw;
                }
                VEHICLE_INTERFACE(in2->heldObj)
                    ->render((GameObject*)in2->heldObj, 0, 0, 0, 0, -1);
            }
        }
        if (inner->knockbackTimer > 0.0f || (inner->pendingFxFlags & 2) != 0)
        {
            PlayerIntPair tbl = sPlayerKnockFxIds;

            objDoParticleFx((GameObject*)obj, 0.4f,
                                   tbl.v[inner->knockKindBits.knock - 1] & 0xff,
                                   1.0f, NULL);
        }
        if ((inner->pendingFxFlags & 1) != 0)
        {
            objDoParticleFx((GameObject*)obj, 0.4f, 8, 1.0f, NULL);
        }
        if (inner->waterDepth > 0.0f)
        {
            if ((inner->pendingFxFlags & 4) != 0)
            {
                inner->flags360 |= PLAYER_FLAG_WATER_SPLASH_PENDING;
                inner->pendingFxFlags = inner->pendingFxFlags & ~0x4;
            }
        }
        else
        {
            if (gPlayerSurfacePfxModeTable[inner->surfaceType] == 6 ||
                gPlayerSurfacePfxModeTable[inner->surfaceType] == 3)
            {
                if ((inner->pendingFxFlags & 8) != 0)
                {
                    u8 n;
                    vel[0] = 0.05f * ((GameObject*)obj)->anim.velocityX;
                    vel[1] = 0.05f * ((GameObject*)obj)->anim.velocityY;
                    vel[2] = 0.05f * ((GameObject*)obj)->anim.velocityZ;
                    pfx.x = 8.0f * ((GameObject*)obj)->anim.velocityX + inner->footPoints[0][0];
                    pfx.y = 8.0f * ((GameObject*)obj)->anim.velocityY + inner->footPoints[0][1];
                    pfx.z = 8.0f * ((GameObject*)obj)->anim.velocityZ + inner->footPoints[0][2];
                    pfx.scale = 0.7f;
                    pfx.mode = gPlayerSurfacePfxModeTable[inner->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    pfx.x = 8.0f * ((GameObject*)obj)->anim.velocityX + inner->footPoints[1][0];
                    pfx.y = 8.0f * ((GameObject*)obj)->anim.velocityY + inner->footPoints[1][1];
                    pfx.z = 8.0f * ((GameObject*)obj)->anim.velocityZ + inner->footPoints[1][2];
                    pfx.scale = 0.7f;
                    pfx.mode = gPlayerSurfacePfxModeTable[inner->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    inner->pendingFxFlags = inner->pendingFxFlags & ~0x8;
                }
                if ((inner->pendingFxFlags & 4) != 0)
                {
                    u8 n2;
                    vel[0] = 0.25f * ((GameObject*)obj)->anim.velocityX;
                    vel[1] = 0.25f * ((GameObject*)obj)->anim.velocityY;
                    vel[2] = 0.25f * ((GameObject*)obj)->anim.velocityZ;
                    pfx.x = ((GameObject*)obj)->anim.worldPosX;
                    pfx.y = 5.0f + ((GameObject*)obj)->anim.worldPosY;
                    pfx.z = ((GameObject*)obj)->anim.worldPosZ;
                    pfx.scale = 1.0f;
                    pfx.mode = gPlayerSurfacePfxModeTable[inner->surfaceType];
                    for (n2 = 0; n2 < 10; n2++)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    inner->pendingFxFlags = inner->pendingFxFlags & ~0x4;
                }
            }
        }
    }
}

void playerDoHitDetection(struct GameObject* obj)
{
    char* inner = ((GameObject*)obj)->extra;
    f32 dt = timeDelta;
    f32 spd;
    int sub;
    PlayerMoveSlot* hd;
    u32 fl;
    f32 x;
    f32 y;
    f32 z;

    ((PlayerState*)inner)->flags360 = (s32)((PlayerState*)inner)->flags360 & ~PLAYER_FLAG_WORLDPOS_OVERRIDE;
    if (((PlayerState*)inner)->flags3F2.b20 != 0 &&
        (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)
    {
        ((PlayerState*)inner)->baddie.physicsActive = 0;
    }
    (*gPathControlInterface)->update((void*)obj, (void*)(inner + 4), timeDelta);
    (*gPathControlInterface)->apply((void*)obj, (void*)(inner + 4));
    (*gPathControlInterface)->advance((void*)obj, (void*)(inner + 4), timeDelta);
    ObjModelChain_AdvancePhase((ObjModelChain*)gPlayerModelChain);
    if (!(((PlayerState*)inner)->cutsceneTimer >= 6.0f))
    {
        (*gPlayerInterface)->updateVelocityState((void*)obj, (void*)inner, gPlayerStateHandlers);
        if (((PlayerState*)inner)->baddie.stateTag == 1)
        {
            if (gPlayerPathObject != 0 && ((PlayerState*)inner)->flags3F4.b40 != 0 &&
                (*(void**)((sub = *(int*)((char*)gPlayerPathObject + 0x54)) + 0x50) != NULL ||
                 (*(s8*)(sub + 0xad) != 0 && *(s8*)(sub + 0xac) != 0xe)))
            {
                {
                    u8 one = 1;
                    Player_GetObjHitsState((GameObject*)(obj))->suppressOutgoingHits = one;
                }
                ((PlayerState*)inner)->boulderChargeLevel = 0.0f;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                {
                    hd = (PlayerMoveSlot*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags88 & 1) != 0)
                    {
                        ((PlayerState*)inner)->cutsceneTimer = 9.0f;
                    }
                    hd = (PlayerMoveSlot*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags88 & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval = hd->hitInterval[((PlayerState*)inner)->activeHitWindow];
                        hd = (PlayerMoveSlot*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                        hd = (PlayerMoveSlot*)((u8*)hd + ((PlayerState*)inner)->activeHitWindow);
                        ((PlayerState*)inner)->hitCountMax = hd->hitCountMax[0];
                        ((PlayerState*)inner)->hitTimer = (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject = *(GameObject**)(sub + 0x50);
                    }
                }
                {
                    GameObject* hitObj = *(GameObject**)(sub + 0x50);
                    if (hitObj != NULL)
                    {
                        if ((hitObj->anim.modelInstance->effectFlags & 4) != 0)
                        {
                            doRumble(10.0f);
                        }
                        if ((hitObj->anim.modelInstance->effectFlags & 8) != 0)
                        {
                            gPlayerHitReactionVariant = 1;
                        }
                    }
                    else if (*(s8*)(sub + 0xad) != 0)
                    {
                        doRumble(10.0f);
                        gPlayerHitReactionVariant = 1;
                    }
                }
                {
                    u8 c = ((PlayerState*)inner)->moveSlotIndex;
                    if (c == 0xf)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 1;
                    }
                    else if (c == 0x1b)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 2;
                    }
                    else if (c == 0x11)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 0;
                    }
                    else
                    {
                        ((PlayerState*)inner)->attackVariantMode = 1;
                    }
                }
            }
            if (Player_GetObjHitsState((GameObject*)(obj))->lastHitObject != 0)
            {
                Player_GetObjHitsState((GameObject*)(obj))->suppressOutgoingHits = 1;
                ((PlayerState*)inner)->boulderChargeLevel = 0.0f;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                {
                    hd = (PlayerMoveSlot*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags88 & 1) != 0)
                    {
                        ((PlayerState*)inner)->cutsceneTimer = 9.0f;
                    }
                    hd = (PlayerMoveSlot*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags88 & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval = hd->hitInterval[((PlayerState*)inner)->activeHitWindow];
                        hd = (PlayerMoveSlot*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                        hd = (PlayerMoveSlot*)((u8*)hd + ((PlayerState*)inner)->activeHitWindow);
                        ((PlayerState*)inner)->hitCountMax = hd->hitCountMax[0];
                        ((PlayerState*)inner)->hitTimer = (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject =
                            (GameObject*)Player_GetObjHitsState((GameObject*)(obj))->lastHitObject;
                    }
                }
            }
        }
        if ((((PlayerState*)inner)->flags360 & 2) != 0)
        {
            ObjAnimComponent* h = *(void**)((char*)inner + 0xdc);
            if (h != NULL &&
                ((fl = h->modelInstance->flags) & OBJDEF_FLAG_HITBOX_GROUP) != 0 &&
                (fl & 0x8000) == 0)
            {
                Obj_SetParent((GameObject*)obj, (GameObject*)h, 1);
            }
            else if (((GameObject*)obj)->anim.parent != NULL && h == NULL)
            {
                Obj_SetParent((GameObject*)obj, NULL, 1);
            }
        }
        ((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HITDETECT;
        if (((PlayerState*)inner)->focusObject != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf(lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            VEHICLE_INTERFACE(((PlayerState*)inner)->focusObject)
                ->getCameraPosition((GameObject*)((PlayerState*)inner)->focusObject, &x, &y, &z);
            (*gCameraInterface)->overridePos(x, y, z);
            playerSyncTransformToFocusObject(obj, (PlayerState*)inner, ((PlayerState*)inner)->focusObject, 0, 0, 0, 0, 0);
        }
        if (((PlayerState*)inner)->baddie.physicsActive == 1 && (((PlayerState*)inner)->baddie.flags4 & 0x100000) == 0)
        {
            if ((((PlayerState*)inner)->flags360 & 0x2000) == 0 && (((PlayerState*)inner)->baddie.surfaceFlags & 0x33) != 0)
            {
                ((GameObject*)obj)->anim.velocityY =
                    (((GameObject*)obj)->anim.worldPosY - ((GameObject*)obj)->anim.previousWorldPosY) / dt;
                if (((GameObject*)obj)->anim.velocityY < -4.0f)
                {
                    ((GameObject*)obj)->anim.velocityY = -4.0f;
                }
                if (((GameObject*)obj)->anim.velocityY > 0.0f)
                {
                    ((GameObject*)obj)->anim.velocityY = 0.0f;
                }
            }
            if ((*(int*)inner & 0x800000) != 0 && 0.0f == ((PlayerState*)inner)->pushVelX &&
                0.0f == ((PlayerState*)inner)->pushVelZ)
            {
                spd = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                            ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
                if (((GameObject*)obj)->anim.parent != NULL)
                {
                    ((GameObject*)obj)->anim.velocityX =
                        (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX) / dt;
                    ((GameObject*)obj)->anim.velocityZ =
                        (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) / dt;
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityX =
                        (((GameObject*)obj)->anim.worldPosX - ((GameObject*)obj)->anim.previousWorldPosX) / dt;
                    ((GameObject*)obj)->anim.velocityZ =
                        (((GameObject*)obj)->anim.worldPosZ - ((GameObject*)obj)->anim.previousWorldPosZ) / dt;
                }
                if (((((PlayerState*)inner)->baddie.surfaceFlags & 2) != 0 && (((PlayerState*)inner)->baddie.surfaceFlags & 0x20) == 0) ||
                    ((PlayerState*)inner)->baddie.groundContact != 0 || (Player_GetObjHitsState((GameObject*)(obj))->flags & 8) != 0)
                {
                    if (((PlayerState*)inner)->rumbleCooldown <= 0.0f &&
                        ((PlayerState*)inner)->baddie.animSpeedA > 1.8928598f)
                    {
                        doRumble(5.0f);
                        ((PlayerState*)inner)->rumbleCooldown = 30.0f;
                        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_foot_run_jingle4);
                    }
                    dt = mathSinf((3.1415927f * (f32)((PlayerState*)inner)->yaw) / 32768.0f);
                    {
                        f32 cosYaw = mathCosf((3.1415927f * (f32)((PlayerState*)inner)->yaw) / 32768.0f);
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            -((GameObject*)obj)->anim.velocityZ * cosYaw - ((GameObject*)obj)->anim.velocityX * dt;
                    }
                    ((PlayerState*)inner)->baddie.animSpeedA *= 1.5f;
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        f32 lo = 0.71982f * ((PlayerState*)inner)->baddie.inputMagnitude;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < lo) ? lo
                                     : ((c > ((PlayerState*)inner)->maxSpeed) ? ((PlayerState*)inner)->maxSpeed : c);
                    }
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < 0.0f) ? 0.0f : ((c > spd) ? spd : c);
                    }
                    if (((PlayerState*)inner)->flags3F0.b40 == 0)
                    {
                        ((PlayerState*)inner)->baddie.animSpeedC = ((PlayerState*)inner)->baddie.animSpeedA;
                    }
                }
                *(int*)inner &= ~0x800000;
            }
        }
        if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
        {
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
        }
        {
            GameObject* g = getSbGalleon();
            if (g != NULL && SB_Galleon_getCameraState(g) == 2)
            {
                ((GameObject*)obj)->anim.modelState->overrideWorldPosX =
                    ((GameObject*)obj)->anim.localPosX - *(f32*)((char*)g + 0xc);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosY =
                    ((GameObject*)obj)->anim.localPosY - *(f32*)((char*)g + 0x10);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosZ =
                    ((GameObject*)obj)->anim.localPosZ - *(f32*)((char*)g + 0x14);
                vecRotateZXY((void*)g, &((GameObject*)obj)->anim.modelState->overrideWorldPosX);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosX =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosX + *(f32*)((char*)g + 0xc);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosY =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosY + *(f32*)((char*)g + 0x10);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosZ =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosZ + *(f32*)((char*)g + 0x14);
                ((GameObject*)obj)->anim.modelState->flags |= 0x2020;
                ((GameObject*)obj)->anim.rotZ = *(s16*)((char*)g + 4);
                ((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WORLDPOS_OVERRIDE;
            }
        }
        ((PlayerState*)inner)->flags360 &= ~0x400000LL;
    }
}


void playerUpdateWhileTimeStopped(GameObject* obj)
{
    PlayerState* inner = ((GameObject*)obj)->extra;
    f32 v = inner->cutsceneTimer;
    f32 zero = 0.0f;
    if (v > zero)
    {
        inner->cutsceneTimer = v - 1.0f;
        v = inner->cutsceneTimer;
        if (v <= zero)
        {
            cutsceneEnterExit(0, 0);
            inner->cutsceneEnded = 1;
        }
        else if (6.0f == v)
        {
            cutsceneEnterExit(1, 0);
            setTimeStop(0xfd);
        }
    }
}

void playerUpdate(GameObject* obj)
{
    char* inner = obj->extra;
    Camera* cam = Camera_GetCurrent();
    f32 zero;
    f32 six;
    f32 t = ((PlayerState*)inner)->cutsceneTimer;
    if (t >= (six = 6.0f))
    {
        if (t > (zero = 0.0f))
        {
            ((PlayerState*)inner)->cutsceneTimer = t - 1.0f;
            if (((PlayerState*)inner)->cutsceneTimer <= zero)
            {
                cutsceneEnterExit(0, 0);
                ((PlayerState*)inner)->cutsceneEnded = 1;
            }
            else if (six == ((PlayerState*)inner)->cutsceneTimer)
            {
                cutsceneEnterExit(1, 0);
                setTimeStop(0xfd);
            }
        }
    }
    else
    {
        if (getCurUiDll() == 4 || (((PlayerState*)inner)->flags360 & 0x200000) != 0)
        {
            return;
        }
        if (((PlayerState*)inner)->flags3F3.b08 != 0)
        {
            setBButtonIcon(10);
        }
        if (obj->anim.parent == NULL && ((PlayerState*)inner)->focusObject == NULL &&
            isInBounds(obj->anim.localPosX, obj->anim.localPosZ) == 0)
        {
            ((PlayerState*)inner)->baddie.targetObj = 0;
            ((PlayerState*)inner)->unk7EC = 0;
            (*gCameraInterface)->setTarget(0);
            {
                f32 z = 0.0f;
                ((PlayerState*)inner)->baddie.animSpeedC = z;
                ((PlayerState*)inner)->baddie.animSpeedB = z;
                ((PlayerState*)inner)->baddie.animSpeedA = z;
                obj->anim.velocityX = z;
                obj->anim.velocityY = z;
                obj->anim.velocityZ = z;
            }
            playerRefreshCollisionState(obj, (int)inner, 0xff);
        }
        else
        {
            f32 dt;
            f32 ym;
            int i;
            int v;
            u8 hov;
            u8* bits;
            UiMsgBlock m;
            ((PlayerState*)inner)->curAnimId = (*gCameraInterface)->getMode();
            if (((PlayerState*)inner)->curAnimId == 0x44 && ((PlayerState*)inner)->baddie.controlMode != 1)
            {
                (*gPlayerInterface)->setState(obj, (void*)inner, 1);
                {
                    f32 z = 0.0f;
                    ((PlayerState*)inner)->baddie.animSpeedC = z;
                    ((PlayerState*)inner)->baddie.animSpeedB = z;
                    ((PlayerState*)inner)->baddie.animSpeedA = z;
                    obj->anim.velocityX = z;
                    obj->anim.velocityY = z;
                    obj->anim.velocityZ = z;
                }
                ((PlayerState*)inner)->baddie.stateExitFn = (BaddieStateExitFn)playerStagedRestoreDefaultControl;
            }
            playerProcessMessages(obj, (int)inner, (int)inner);
            playerUpdateTargetSelection(obj, (PlayerState*)inner, (PlayerState*)inner);
            playerStaffInit(obj, (PlayerState*)inner);
            if ((void*)gPlayerEggObject == NULL && (u8)Obj_CanSetupObject() != 0)
            {
                gPlayerEggObject = (int)objSetupObject(Obj_AllocObjectSetup(0x18, 0x66a), 4, -1, -1,
                                                        obj->anim.parent);
                ObjLink_AttachChild(obj, (GameObject*)gPlayerEggObject, 3);
            }
            if ((void*)gPlayerEggObject != NULL)
            {
                ((GameObject*)gPlayerEggObject)->anim.parent = (void*)obj->anim.parent;
                if (((PlayerState*)inner)->characterId == 0)
                {
                    *(s16*)(gPlayerEggObject + 6) = *(s16*)(gPlayerEggObject + 6) | 0x4000;
                }
            }
            if (gPlayerStaffObject == NULL && (u8)Obj_CanSetupObject() != 0)
            {
                gPlayerStaffObject = (GameObject*)objSetupObject(Obj_AllocObjectSetup(0x24, 0x773), 5, -1, -1,
                                                                  obj->anim.parent);
            }
            if (gPlayerStaffObject != NULL)
            {
                ObjPath_GetPointWorldPosition(obj, 4, (void*)&gPlayerStaffObject->anim.localPosX,
                                              (void*)&gPlayerStaffObject->anim.localPosY,
                                              (void*)&gPlayerStaffObject->anim.localPosZ, 0);
            }
            if ((s16*)obj->anim.parent != NULL)
            {
                v = (*(s16*)obj->anim.parent & 0xffffU) - ((0x8000U - cam->yaw) & 0xffff);
                if (v > 0x8000)
                {
                    v -= 0xffff;
                }
                if (v < -0x8000)
                {
                    v += 0xffff;
                }
                ((PlayerState*)inner)->baddie.cameraYaw = (s16)(v + 0x8000);
            }
            else
            {
                ((PlayerState*)inner)->baddie.cameraYaw = cam->yaw;
            }
            ((PlayerState*)inner)->probeHitDist = 100000.0f;
            ((PlayerState*)inner)->cameraFlags = 0;
            ((PlayerState*)inner)->baddie.queuedBitMask = 0;
            bits = (u8*)inner;
            for (i = 0; i < ((PlayerState*)inner)->queuedBitCount; i++)
            {
                ((PlayerState*)inner)->baddie.queuedBitMask |= 1 << bits[i + 0x8b9];
            }
            ((PlayerState*)inner)->flags360 &= 0xfffff4ff;
            dt = *(f32*)&timeDelta;
            playerDoControls(obj, (PlayerState*)inner, dt);
            playerAnimate(obj, (PlayerState*)inner, dt);
            staffAnimate(obj, (void*)inner, dt);
            playerUpdateSurfaceResponse(obj, (PlayerState*)inner, (PlayerState*)inner, dt);
            playerUpdateVelocityFromMotion(obj, (void*)inner, &((PlayerState*)inner)->baddie, dt);
            {
                f32 t = obj->anim.velocityX;
                obj->anim.velocityX =
                    (t < -5.0f) ? -5.0f : ((t > 5.0f) ? 5.0f : t);
                t = obj->anim.velocityY;
                obj->anim.velocityY =
                    (t < -4.0f) ? -4.0f : ((t > 4.0f) ? 4.0f : t);
                t = obj->anim.velocityZ;
                obj->anim.velocityZ =
                    (t < -5.0f) ? -5.0f : ((t > 5.0f) ? 5.0f : t);
            }
            ym = obj->anim.velocityY * dt;
            if (ym > 10.0f)
            {
                ym = 10.0f;
            }
            objMove(obj, obj->anim.velocityX * dt, ym, obj->anim.velocityZ * dt);
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
            m = *(UiMsgBlock*)lbl_802C2C50;
            (*gGameUIInterface)->isOneOfItemsBeingUsed((s32*)&m, 6);
            playerDoEyeAnims(obj, inner);
            {
                if ((((PlayerState*)inner)->stepEventTimer -= framesThisStep) < 0)
                {
                    ((PlayerState*)inner)->stepEventTimer = lbl_803DC6A8[((PlayerState*)inner)->gaitStepLevel];
                    ((PlayerState*)inner)->stepDustCount = lbl_803DC6B0[((PlayerState*)inner)->gaitStepLevel];
                }
            }
            playerUpdateKnockbackTimers(obj, (PlayerState*)inner);
            if (((PlayerState*)inner)->teleportAnimActive == 1)
            {
                ((PlayerState*)inner)->teleportAnimProgress =
                    ((PlayerState*)inner)->teleportAnimRate * timeDelta + ((PlayerState*)inner)->teleportAnimProgress;
                if (((PlayerState*)inner)->teleportAnimProgress >= 40.0f)
                {
                    ((PlayerState*)inner)->teleportAnimProgress = 40.0f;
                    ((PlayerState*)inner)->teleportAnimRate = 0.0f;
                }
                else if (((PlayerState*)inner)->teleportAnimProgress <= 0.0f)
                {
                    ((PlayerState*)inner)->teleportAnimProgress = 0.0f;
                    ((PlayerState*)inner)->teleportAnimRate = 0.2f;
                }
            }
            playerProcessHitResponse(obj, (PlayerState*)inner, (PlayerState*)inner);
            if (((PlayerState*)inner)->heldObj != NULL &&
                Obj_IsObjectAlive((GameObject*)((PlayerState*)inner)->heldObj) == 0)
            {
                ((PlayerState*)inner)->isHoldingObject = 0;
                {
                    GameObject* held = (GameObject*)((PlayerState*)inner)->heldObj;
                    if (held != NULL)
                    {
                        s16 typ = held->anim.romDefNo;
                        if (typ == SMALLBASKET_SEQUENCE_VARIANT_A || typ == SMALLBASKET_SEQUENCE_DISGUISE_GATED)
                        {
                            SmallBasket_throw(held);
                        }
                        else
                        {
                            Carryable_putDownAndSavePos(held);
                        }
                        ((PlayerState*)inner)->heldObj->anim.flags =
                            ((PlayerState*)inner)->heldObj->anim.flags & ~0x4000;
                        ((PlayerState*)inner)->heldObj->userData2 = 0;
                        ((PlayerState*)inner)->heldObj = 0;
                    }
                }
            }
            if ((*(u8*)((char*)obj->extra + 0xc4) & 0x40) != 0)
            {
                v = (int)-(4.0f * timeDelta - (f32)(u32)obj->sphereMapIntensity);
            }
            else
            {
                v = (int)(4.0f * timeDelta + (f32)(u32)obj->sphereMapIntensity);
            }
            if (v < (u8)skyGetSlotBlendAlpha(2))
            {
                v = (u8)skyGetSlotBlendAlpha(2);
            }
            else if (v > 0xff)
            {
                v = 0xff;
            }
            obj->sphereMapIntensity = (u8)v;
            playerRunActiveSpells(obj, (PlayerState*)inner);
            playerProcessQueuedItemCommand(obj, (PlayerState*)inner);
            if (((PlayerState*)inner)->flags3F3.b20 != 0 && (*gScreenTransitionInterface)->isFinished() != 0)
            {
                (*gMapEventInterface)->gotoRestartPoint();
            }
            if (((PlayerState*)inner)->flags3F3.b20 == 0 && (((PlayerState*)inner)->baddie.queuedBitMask & 1) != 0)
            {
                GameObject* po = obj;
                if (Sfx_IsPlayingFromObject(
                        (GameObject*)po, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02)) == 0)
                {
                    Sfx_PlayFromObject(
                        0, (u16)(((PlayerState*)inner)->characterId == 0 ? SFXTRIG_jump2 : SFXTRIG_sa_climb02));
                }
                ((PlayerState*)inner)->flags3F3.b20 = 1;
                (*gScreenTransitionInterface)->start(0x1e, SCREEN_TRANSITION_BLACK);
                Pause_ResetMenuFrameCounter();
            }
            if (gPlayerPathObject != 0 && ((PlayerState*)inner)->flags3F4.b40 != 0)
            {
                gPlayerPathObject->objectFlags = gPlayerPathObject->objectFlags & ~7;
                if (((PlayerState*)inner)->staffGrown == 0)
                {
                    gPlayerPathObject->objectFlags = gPlayerPathObject->objectFlags | 2;
                }
            }
            hov = ((PlayerState*)inner)->flags3F4.b40;
            if (hov != 0)
            {
                if (((PlayerState*)inner)->staffGrown != 0)
                {
                    setAButtonIcon(1);
                }
                else
                {
                    int ok;
                    if (((PlayerState*)inner)->heldObj != NULL || hov == 0 ||
                        ((PlayerState*)inner)->flags3F0.b20 != 0 ||
                        ((PlayerState*)inner)->flags3F0.b10 != 0)
                    {
                        ok = 0;
                    }
                    else
                    {
                        ok = 1;
                    }
                    if (ok)
                    {
                        setAButtonIcon(0xb);
                    }
                }
                if (((PlayerState*)inner)->staffGrown != 0)
                {
                    setBButtonIcon(0xc);
                }
            }
            (*gCameraInterface)->func1C(((PlayerState*)inner)->cameraFlags);
            ((PlayerState*)inner)->isHoldingObject = 0;
            ((PlayerState*)inner)->queuedBitCount = 0;
            ((GameObject*)obj)->anim.rotX = ((PlayerState*)inner)->targetYaw;
            objAudioDispatchEventMask(obj, ((PlayerState*)inner)->baddie.eventFlags,
                                      ((PlayerState*)inner)->animSoundId, (void*)(inner + 0x3c4),
                                      (void*)(inner + 4), ((PlayerState*)inner)->baddie.animSpeedA, 1.0f);
        }
    }
}

void objLoadPlayerFromSave(GameObject* obj)
{
    char* base = (char*)lbl_80332EC0;
    int off;
    PlayerState* inner = ((GameObject*)obj)->extra;
    int i;
    f32 fz;
    SaveGameCharacterPosition* me;
    u8* pathState;

    gPlayerHitReactionVariant = 0;
    objAddObjectType(obj, 0);
    objAddObjectType(obj, PLAYER_OBJGROUP);
    objSetSlot(obj, 0x3c);
    ObjMsg_AllocQueue(obj, 0x14);
    obj->animEventCallback = (void*)player_SeqFn;
    obj->anim.placementData = 0;
    inner->heldObj = 0;
    inner->playerStatus = (PlayerStatus*)(*gMapEventInterface)->getCurCharacterState();
    *(u16*)&inner->characterId = (*gMapEventInterface)->getCurChar();
    Obj_SetActiveModelIndex((GameObject*)obj, inner->characterId);
    me = (SaveGameCharacterPosition*)(*gMapEventInterface)->getCurCharPos();
    ((GameObject*)obj)->anim.rotX = (s16)(me->angle << 8);
    inner->targetYaw = ((GameObject*)obj)->anim.rotX;
    inner->yaw = ((GameObject*)obj)->anim.rotX;
    inner->lastInputHeading = ((GameObject*)obj)->anim.rotX;
    fz = 1.0f;
    inner->timeScale = fz;
    inner->queuedItemCommand = -1;
    inner->animState = -1;
    inner->targetAnimSpeed = 1.0f;
    inner->yawSmoothScale = 1.0f;
    inner->velSmoothRateBase = 0.06f;
    inner->flags3F1.b01 = 1;
    inner->idleDelayTimer = 20.0f;
    inner->walkAnimSoundId = 3;
    inner->runAnimSoundId = 4;
    inner->footstepSoundId = 5;
    inner->altAnimSoundId = 6;
    inner->animSoundId = inner->walkAnimSoundId;
    inner->unk8BF = 0;
    (*gPlayerInterface)->init((void*)obj, (void*)inner, 0x42, 1);
    inner->baddie.orientationAxesOut = inner->orientationAxes;
    pathState = (u8*)&inner->baddie + 4;
    (*gPathControlInterface)->init(pathState, 1, 0x400a7, 1);
    (*gPathControlInterface)->setLocalPointCollision(pathState, 1, base + 0x130, &lbl_803DC6C0, 1);
    (*gPathControlInterface)->setup(pathState, 2, base + 0x118, lbl_803DC6B8, lbl_803DC6A4);
    pathState[0x258] = 0x64;
    playerRefreshCollisionState((GameObject*)obj, (int)inner, 0xff);
    Player_GetObjHitsState((GameObject*)(obj))->trackContactMask = 0x29;
    ((GameObject*)obj)->anim.alpha = 0xff;
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->flags |= 0x4008;
    }
    (*(void (*)(GameUIInterface*))(*(int*)((char*)*gGameUIInterface + 0x14)))(*gGameUIInterface);
    gPlayerChildObject = (void*)(off = 0);
    inner->flags3F4.b40 = 1;
    inner->moveAnimIds = (s16*)(base + 0x190);
    inner->moveSlots = (int)(base + 0x854);
    inner->moveSlotCount = 0x1c;
    inner->paramCurve0 = (f32*)(base + 0x450);
    inner->paramCurve0Count = 0x29;
    inner->paramCurve1 = (f32*)(base + 0x4f4);
    inner->paramCurve1Count = 0x29;
    inner->paramCurve2 = (f32*)(base + 0x598);
    inner->paramCurve2Count = 0x2e;
    inner->paramCurve3 = (f32*)(base + 0x650);
    inner->paramCurve3Count = 0x29;
    inner->paramCurve4 = (f32*)(base + 0x6f4);
    inner->paramCurve4Count = 0x2e;
    inner->curveSpeedScale = 10.0f;
    for (i = 0; i < inner->moveSlotCount; i++)
    {
        PlayerMoveSlot* slot;
        ((PlayerMoveSlot*)(inner->moveSlots + off))->weaponDa.entries =
            (s16*)mmAlloc(0x800, 0x1a, 0);
        slot = (PlayerMoveSlot*)(inner->moveSlots + off);
        objGetWeaponDa((u8*)obj, ((GameObject*)obj)->anim.romDefNo, &slot->weaponDa,
                       ((s16*)(base + 0x7fc))[slot->moveTableIndex], 0);
        off += 0xb0;
    }
    playerCacheMoveRootHeights(obj);
    gPlayerSelectedItem = GAMEBIT_STAFF_ABILITY_FIRE_BLASTER;
    gPlayerEggObject = 0;
    base += 0x1b94;
    for (i = 0; (u32)i < 0xb; i++)
    {
        if (mainGetBit(*(s16*)base) != 0)
        {
            inner->staffUnlockedFlags = (u8)(inner->staffUnlockedFlags | (1 << i));
        }
        base += 2;
    }
    if (inner->characterId == 0)
    {
        inner->pathBearingEyeY = 28.8f;
        inner->characterHeightOffset = 33.0f;
    }
    else
    {
        inner->pathBearingEyeY = 25.3f;
        inner->characterHeightOffset = 27.8f;
    }
    gPlayerModelChain = (int)ObjModelChain_Alloc(&gPlayerModelChainConfig, 1);
    ((GameObject*)obj)->afterBonesCallback = playerDoTailAnims;
    if (gPlayerPendingHealth != 0)
    {
        int v = gPlayerPendingHealth;
        int hi;
        PlayerState* in1;
        PlayerState* in2;
        in1 = (PlayerState*)((GameObject*)obj)->extra;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > 0x50)
        {
            v = 0x50;
        }
        (in1->playerStatus)->maxHealth = (s8)v;
        v = gPlayerPendingHealth;
        in2 = (PlayerState*)((GameObject*)obj)->extra;
        if (v < 0)
        {
            v = 0;
        }
        else
        {
            hi = (in2->playerStatus)->maxHealth;
            if (v > hi)
            {
                v = hi;
            }
        }
        (in2->playerStatus)->health = (s8)v;
        gPlayerPendingHealth = 0;
    }
    gPlayerHeldObject = 0;
}

void playerInitFuncPtrsEntry(void)
{
    playerInitFuncPtrs();
}

void playerInitFuncPtrs(void)
{
    int* p = gPlayerStateHandlers;
    p[0] = (int)playerState00;
    p[1] = (int)playerStateIdle;
    p[2] = (int)playerStateMoving;
    p[3] = (int)playerStateIceSpell;
    p[4] = (int)playerState04;
    p[5] = (int)playerState05;
    p[6] = (int)playerState06;
    p[7] = (int)playerStateThrowing;
    p[8] = (int)playerState08;
    p[9] = (int)playerState09;
    p[10] = (int)playerStateGrabLedge;
    p[11] = (int)playerState0B;
    p[12] = (int)playerStateClimbLedge;
    p[13] = (int)playerState0D;
    p[14] = (int)playerStateClimbOntoLadder;
    p[15] = (int)playerStateOnLadder;
    p[16] = (int)playerStateSlideDownLadder;
    p[17] = (int)playerState11;
    p[18] = (int)playerStateClimbOntoWall;
    p[19] = (int)playerStateClimbWall;
    p[20] = (int)playerStateClimbUpFromWall;
    p[21] = (int)playerStateClimbDownFromWall;
    p[22] = (int)playerStateMountBike;
    p[23] = (int)playerState17;
    p[24] = (int)playerStateOnBike;
    p[25] = (int)playerState19;
    p[26] = (int)playerStateOnCloudRunner;
    p[27] = (int)playerState1B;
    p[28] = (int)playerState1C;
    p[29] = (int)playerState1D;
    p[30] = (int)playerState1E;
    p[31] = (int)playerState1F;
    p[32] = (int)playerState20;
    p[33] = (int)playerState21;
    p[34] = (int)playerState22;
    p[35] = (int)playerState23;
    p[36] = (int)playerState24;
    p[37] = (int)playerState25;
    p[38] = (int)playerStateAttack;
    p[39] = (int)playerState27;
    p[40] = (int)playerState28;
    p[41] = (int)playerState29;
    p[42] = (int)playerStateStartAimStaff;
    p[43] = (int)playerStateStopAimStaff;
    p[44] = (int)playerStateAimStaff;
    p[45] = (int)playerStateTryCastSpell;
    p[46] = (int)playerStateShootFireball;
    p[47] = (int)playerStateFireLaser;
    p[48] = (int)playerState30;
    p[49] = (int)playerState31;
    p[50] = (int)playerStateStaffBoost;
    p[51] = (int)playerStateStaffLiftRock;
    p[52] = (int)playerState34;
    p[53] = (int)playerState35;
    p[54] = (int)playerStateSuperQuake;
    p[55] = (int)playerState37;
    p[56] = (int)playerState38;
    p[57] = (int)playerState39;
    p[58] = (int)playerState3A;
    p[59] = (int)playerState3B;
    p[60] = (int)playerState3C;
    p[61] = (int)playerState3D;
    p[62] = (int)playerStateNop3E;
    p[63] = (int)playerState3F;
    p[64] = (int)playerState40;
    p[65] = (int)playerState41;
    gPlayerDefaultStateHandler = playerStateNoOp;
}

int gPlayerStateHandlers[66];
f32 gPlayerMoveRootHeights[16];
LightmapVertex gPlayerHudVtxBuf[8];
