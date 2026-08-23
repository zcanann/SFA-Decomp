/*
 * Pushable object family (DLL slot 239 / 0xEF).
 *
 * Shared collision and movement code drives push/pull blocks, two magic-gem
 * variants, the Wall City hit-ID puzzle, a floating ice block, a metal block,
 * and the Volcano Force Point curtain block.
 */
#include "main/vecmath.h"
#include "dlls/objects/239.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_interface.h"
#include "main/debug.h"
#include "main/dll/dll_005B_modgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/maketex_api.h"
#include "main/model.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/object_transform.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objtexture.h"
#include "main/resource.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "sys/objects.h"
#include "main/camera.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/dll/player_api.h"
#include "main/dll/savegame_object_api.h"
#include "main/maketex.h"
#include "sys/objects/lifecycle.h"

typedef struct PushableCollisionProbe {
    f32 radii[4];   /* 0x00 */
    s8 unk10;       /* 0x10 */
    u8 pad11[3];    /* 0x11 */
    u8 unk14;       /* 0x14 */
    u8 pad15[0x17]; /* 0x15 */
    s16 unk2C;      /* 0x2C */
    s16 pad2E;      /* 0x2E */
} PushableCollisionProbe;

/* object group this object joins while active */
#define PUSHABLE_OBJECT_GROUP   5
#define PUSHABLE_OBJECT_TYPE_ID 0x48
#define PUSHABLE_MAX_POINTS     4
#define PUSHABLE_POINT_MASK     0xF
#define PUSHABLE_NO_GAME_BIT    -1
#define PUSHABLE_NO_HIT_ID      -1
#define PUSHABLE_OBJECT_SLOT    0x5A
#define PUSHABLE_MSG_QUEUE_SIZE 4

/* PushableState.flags */
#define PUSHABLE_FLAG_RESTORED          0x01
#define PUSHABLE_FLAG_MOVED             0x02
#define PUSHABLE_FLAG_AIRBORNE          0x04
#define PUSHABLE_FLAG_NO_GROUND_CONTACT 0x08
#define PUSHABLE_FLAG_PUSH_SFX_DUE      0x20
#define PUSHABLE_FLAG_INITIALIZED       0x40
#define PUSHABLE_FLAG_PUSH_LOCKED       0x80
#define PUSHABLE_FLAG_PUSH_NEG_X        0x100
#define PUSHABLE_FLAG_PUSH_POS_X        0x200
#define PUSHABLE_FLAG_PUSH_NEG_Z        0x400
#define PUSHABLE_FLAG_PUSH_POS_Z        0x800
#define PUSHABLE_FLAG_AIR_STATE_MASK    (PUSHABLE_FLAG_AIRBORNE | PUSHABLE_FLAG_NO_GROUND_CONTACT)
#define PUSHABLE_FLAG_PUSH_DIR_MASK     0xF00

/* pushable-block variant seqIds (retail OBJECTS.bin names, all DLL 0xEF) */
#define PUSHABLE_SEQ_ID_WC_PUSH_BLOCK    0x7DF /* "WCPushBlock" */
#define PUSHABLE_SEQ_ID_DIM_PUSH_BLOCK   0x1CB /* "DIMPushBloc..." */
#define PUSHABLE_SEQ_ID_DIM2_ICE_BLOCK   0x108 /* "DIM2IceBloc..." */
#define PUSHABLE_SEQ_ID_MAGIC_GEM_21E    0x21E
#define PUSHABLE_SEQ_ID_MAGIC_GEM_411    0x411
#define PUSHABLE_SEQ_ID_VFP_BLOCK2       0x54A /* "VFP_Block2" */
#define PUSHABLE_SEQ_ID_5AE              0x5AE
#define PUSHABLE_SEQ_ID_METAL_PUSH_BLOCK 0x85A /* "MetalPushBl..." */

#define PUSHABLE_ZERO                   0.0f
#define PUSHABLE_CURTAIN_TRIGGER_X      -175.0f
#define PUSHABLE_CURTAIN_POSITION_X     188.0
#define PUSHABLE_CURTAIN_POSITION_Z     186.0
#define PUSHABLE_INITIAL_CULL_DISTANCE  10000.0f
#define PUSHABLE_MIN_GROUND_CLEARANCE   10.0f
#define PUSHABLE_UNIT_SCALE             1.0f
#define PUSHABLE_COLLISION_RADIUS       0.5f
#define PUSHABLE_PI                     3.1415927410125732f
#define PUSHABLE_HALF_TURN              32768.0f
#define PUSHABLE_KNOCKBACK_SPEED        4.0f
#define PUSHABLE_PROBE_HEIGHT           15.0f
#define PUSHABLE_FORWARD_PROBE_DISTANCE 8.0f
#define PUSHABLE_SIDE_PROBE_DISTANCE    9.5f
#define PUSHABLE_GROUND_DAMPING         0.985f
#define PUSHABLE_AIR_DAMPING            0.94f
#define PUSHABLE_STOP_THRESHOLD         0.05f
#define PUSHABLE_NEG_STOP_THRESHOLD     -0.05f
#define PUSHABLE_GRAVITY                0.1f
#define PUSHABLE_SWEEP_Y_PADDING        200.0f
#define PUSHABLE_MAX_GROUND_STEP        50.0f
#define PUSHABLE_MIN_GROUND_NORMAL_Y    0.707f
#define PUSHABLE_AIRBORNE_TIMER         20.0f
#define PUSHABLE_SCALE_DENOM            65535.0f

#define PUSHABLE_MAGIC_GEM_TARGET_OBJECT_GROUP  0x11
#define PUSHABLE_MAGIC_GEM_INITIAL_DISTANCE     10000.0f
#define PUSHABLE_MAGIC_GEM_ROOT_MOTION_CUTOFF   0.001f
#define PUSHABLE_MAGIC_GEM_ROOT_MOTION_DECAY    0.02f
#define PUSHABLE_MAGIC_GEM_HIDE_Y_OFFSET        300.0f
#define PUSHABLE_MAGIC_GEM_EYE_OPEN_MIN         150.0f
#define PUSHABLE_MAGIC_GEM_NEGATE               -1.0f
#define PUSHABLE_MAGIC_GEM_NEAR_Z_MIN           10.0f
#define PUSHABLE_MAGIC_GEM_NEAR_X_MAX           30.0f
#define PUSHABLE_MAGIC_GEM_NEAR_Z_MAX           40.0f
#define PUSHABLE_MAGIC_GEM_BLINK_INTERVAL_SCALE 0.01f
#define PUSHABLE_MAGIC_GEM_EYE_OPEN_MAX         225.0f
#define PUSHABLE_MAGIC_GEM_EYE_POSITION_MAX     255.0f
#define PUSHABLE_MAGIC_GEM_BLINK_SCALE_BASE     0.25f
#define PUSHABLE_MAGIC_GEM_EYE_OPEN_SPEED       1.2f
#define PUSHABLE_MAGIC_GEM_EYE_DRIFT_SPEED      0.6f
#define PUSHABLE_MAGIC_GEM_EFFECT_DLL_ID        0x5B
#define PUSHABLE_MAGIC_GEM_EFFECT_ID            0x14
#define PUSHABLE_MAGIC_GEM_INITIAL_COLOR        10
#define PUSHABLE_MAGIC_GEM_BLINK_WAIT_MIN       0x19
#define PUSHABLE_MAGIC_GEM_BLINK_WAIT_MAX       0x4B
#define PUSHABLE_MAGIC_GEM_BLINK_TIME_MIN       0x28
#define PUSHABLE_MAGIC_GEM_BLINK_TIME_MAX       0x46

#define PUSHABLE_MSG_SET_SENDER          0xF0003
#define PUSHABLE_MSG_FREE                0xE
#define PUSHABLE_MSG_MAGIC_GEM_DISTANCE  0x40001
#define PUSHABLE_MAGIC_GEM_NEAR_GAME_BIT 0x1C9
#define PUSHABLE_SEQUENCE_GAME_BIT       0x103

#define PUSHABLE_SEQUENCE_SAVE_DELAY       0x3C
#define PUSHABLE_ACTIVE_SAVE_DELAY         0x78
#define PUSHABLE_SEQUENCE_MOVEMENT_NONE    0
#define PUSHABLE_SEQUENCE_MOVEMENT_OFFSET  2
#define PUSHABLE_SEQUENCE_DEFAULT_USERDATA 2
#define PUSHABLE_SEQUENCE_KNOCKBACK_RESULT 4
#define PUSHABLE_SEQUENCE_TARGET_CLASS_ID  0x24

#define PUSHABLE_DIRECTION_NONE  0
#define PUSHABLE_DIRECTION_NEG_X 1
#define PUSHABLE_DIRECTION_POS_X 2
#define PUSHABLE_DIRECTION_NEG_Z 3
#define PUSHABLE_DIRECTION_POS_Z 4
#define PUSHABLE_DIRECTION_DOWN  5

#define PUSHABLE_WC_MAP_ID_HIT_10 0x49B2C
#define PUSHABLE_WC_MAP_ID_HIT_11 0x49B5D
#define PUSHABLE_WC_MAP_ID_HIT_12 0x49B5E
#define PUSHABLE_FORCE_HIT_ID_MAP 0x30398

#define PUSHABLE_WATER_SURFACE_TYPE      0xE
#define PUSHABLE_WC_ACTIVATED_TEXTURE_ID 0x100

#define PUSHABLE_ANGLE_HALF_TURN        0x8000
#define PUSHABLE_ANGLE_FULL_TURN        0xFFFF
#define PUSHABLE_ANGLE_UNITS_PER_DEGREE 0xB6
#define PUSHABLE_ANGLE_30_DEGREES       0x1E
#define PUSHABLE_ANGLE_60_DEGREES       0x3C
#define PUSHABLE_ANGLE_120_DEGREES      0x78
#define PUSHABLE_ANGLE_150_DEGREES      0x96

STATIC_ASSERT(offsetof(PushableCollisionProbe, radii) == 0x0);
STATIC_ASSERT(offsetof(PushableCollisionProbe, unk10) == 0x10);
STATIC_ASSERT(offsetof(PushableCollisionProbe, pad11) == 0x11);
STATIC_ASSERT(offsetof(PushableCollisionProbe, unk14) == 0x14);
STATIC_ASSERT(offsetof(PushableCollisionProbe, pad15) == 0x15);
STATIC_ASSERT(offsetof(PushableCollisionProbe, unk2C) == 0x2C);
STATIC_ASSERT(offsetof(PushableCollisionProbe, pad2E) == 0x2E);
STATIC_ASSERT(sizeof(PushableCollisionProbe) == 0x30);

int gPushableSavedIdentCount;
int gPushableSavedIdents[0x28];

ObjectDescriptor14 gPushableObjDescriptor = {
    0,                                                  /* reserved0 */
    0,                                                  /* reserved1 */
    0,                                                  /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_14_SLOTS,                   /* slotCountAndFlags */
    0,                                                  /* initialise */
    0,                                                  /* release */
    0,                                                  /* slot02 */
    (ObjectDescriptorCallback)pushable_init,            /* init */
    (ObjectDescriptorCallback)pushable_update,          /* update */
    (ObjectDescriptorCallback)pushable_hitDetect,       /* hitDetect */
    (ObjectDescriptorCallback)pushable_render,          /* render */
    (ObjectDescriptorCallback)pushable_free,            /* free */
    (ObjectDescriptorCallback)pushable_getObjectTypeId, /* getObjectTypeId */
    pushable_getExtraSize,    /* slot09 */
    (ObjectDescriptorCallback)pushable_push,        /* slot0A */
    (ObjectDescriptorCallback)pushable_isWithinCullDistance,          /* slot0B */
    (ObjectDescriptorCallback)pushable_setModelFlag,      /* slot0C */
    (ObjectDescriptorCallback)pushable_isRestored,         /* slot0D */
};

char sPushPullObjectHitpointOverflow[] = "PUSHPULL OBJECT: hitpoint overflow\n";
const PushableRadii gPushableDefaultBox = {{0.0f, 0.0f, 0.0f, 0.0f}};

static void pushable_driftEyePos(f32* pos, f32 driftSpeed, f32 limit)
{
    *pos += driftSpeed;
    if (*pos > limit) {
        *pos = limit;
    } else if (*pos < PUSHABLE_ZERO) {
        *pos = limit;
    }
}

int pushable_updateCurtain(GameObject* obj, PushableState* state) {
    ObjPlacement* placement;
    GameObject* player;

    placement = (ObjPlacement*)obj->anim.placementData;
    player = Obj_GetPlayerObject();
    if (((state->flags & PUSHABLE_FLAG_PUSH_LOCKED) != 0) || (playerGetStateValue(player, 10) != 0)) {
        Sfx_StopObjectChannel(obj, 8);
        return 0;
    }
    Sfx_PlayFromObject(obj, SFXTRIG_treedrum16);
    state->flags |= PUSHABLE_FLAG_MOVED;
    if ((state->flags & PUSHABLE_FLAG_AIRBORNE) == 0) {
        pushable_resolveCollisions(obj, state);
    }
    if (obj->anim.localPosX <= PUSHABLE_CURTAIN_TRIGGER_X + placement->posX) {
        mainSetBits(state->gameBit, 1);
        state->flags |= PUSHABLE_FLAG_PUSH_LOCKED;
        obj->anim.localPosX = (f32)(placement->posX - PUSHABLE_CURTAIN_POSITION_X);
        obj->anim.localPosY = placement->posY;
        obj->anim.localPosZ = (f32)(PUSHABLE_CURTAIN_POSITION_Z + placement->posZ);
        Sfx_PlayFromObject(obj, SFXTRIG_curtainopen16);
    }
    if (mainGetBit(GAMEBIT_PushableRelated0A1A) != 0) {
        obj->anim.localPosX = placement->posX;
        obj->anim.localPosY = placement->posY;
        obj->anim.localPosZ = placement->posZ;
    }
    return 0;
}

void pushable_initWcPushBlock(GameObject* obj, PushableState* state) {
    PushableObjectDef* placement = (PushableObjectDef*)obj->anim.placementData;

    switch (placement->base.ident) {
    case PUSHABLE_WC_MAP_ID_HIT_10:
        state->requiredHitId = 10;
        break;
    case PUSHABLE_WC_MAP_ID_HIT_11:
        state->requiredHitId = 11;
        obj->anim.bankIndex = 1;
        break;
    case PUSHABLE_WC_MAP_ID_HIT_12:
        state->requiredHitId = 12;
        obj->anim.bankIndex = 1;
        break;
    }

    if (mainGetBit(placement->gameBit) != 0) {
        ObjTextureRuntimeSlot* texture;
        state->flags = (u16)(state->flags | PUSHABLE_FLAG_PUSH_LOCKED);
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            texture->textureId = 256;
        }
    }
}

int pushable_updateMagicGem(GameObject* obj, PushableState* state) {
    Dll5BInterface** effectInterface;
    u8 nearTarget;
    ObjTextureRuntimeSlot* texture;
    f32 value;
    f32 absoluteDeltaX;
    f32 absoluteDeltaZ;
    f32 cutoff;
    f32 eyeScaledX;
    f32 eyeScaledY;
    f32 nearestDistance[2];

    nearTarget = 0;
    nearestDistance[0] = PUSHABLE_MAGIC_GEM_INITIAL_DISTANCE;
    pushable_handleMsgs(obj, 0);
    if (mainGetBit(state->gameBit) != 0) {
        value = obj->anim.rootMotionScale;
        cutoff = PUSHABLE_MAGIC_GEM_ROOT_MOTION_CUTOFF;
        if (value > cutoff) {
            obj->anim.rootMotionScale -= PUSHABLE_MAGIC_GEM_ROOT_MOTION_DECAY * timeDelta;
            if (obj->anim.rootMotionScale <= cutoff) {
                obj->anim.rootMotionScale = PUSHABLE_ZERO;
                obj->anim.localPosY -= PUSHABLE_MAGIC_GEM_HIDE_Y_OFFSET;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        }
        return 1;
    }
    if (state->nearestObj == NULL) {
        state->nearestObj =
            objGetNearestTypeTo(PUSHABLE_MAGIC_GEM_TARGET_OBJECT_GROUP, obj, nearestDistance);
    }
    if (state->nearestObj == NULL) {
        return 0;
    }
    if (state->eyeOpenAmount < PUSHABLE_MAGIC_GEM_EYE_OPEN_MIN) {
        state->eyeOpenAmount = PUSHABLE_MAGIC_GEM_EYE_OPEN_MIN;
    }
    absoluteDeltaZ = state->nearestObj->anim.localPosZ - obj->anim.localPosZ;
    if (absoluteDeltaZ < PUSHABLE_ZERO) {
        absoluteDeltaZ *= PUSHABLE_MAGIC_GEM_NEGATE;
    }
    value = state->magicGemDistanceThreshold;
    if (value < PUSHABLE_MAGIC_GEM_NEAR_Z_MIN + absoluteDeltaZ) {
        return 0;
    }
    absoluteDeltaX = state->nearestObj->anim.localPosX - obj->anim.localPosX;
    if (absoluteDeltaX < PUSHABLE_ZERO) {
        absoluteDeltaX *= PUSHABLE_MAGIC_GEM_NEGATE;
    }
    if (absoluteDeltaX > PUSHABLE_MAGIC_GEM_NEAR_X_MAX) {
        return 0;
    }
    if ((value >= PUSHABLE_MAGIC_GEM_NEAR_Z_MIN + absoluteDeltaZ) &&
        (value <= PUSHABLE_MAGIC_GEM_NEAR_Z_MAX + absoluteDeltaZ)) {
        nearTarget = 1;
        mainSetBits(PUSHABLE_MAGIC_GEM_NEAR_GAME_BIT, 1);
    }
    texture = objFindTexture(obj, 0, 0);
    state->blinkPhase += state->blinkStep * timeDelta;
    if (state->blinkPhase >= state->blinkInterval) {
        state->blinkStep *= PUSHABLE_MAGIC_GEM_NEGATE;
    } else if (state->blinkPhase < PUSHABLE_ZERO) {
        state->blinkInterval =
            PUSHABLE_MAGIC_GEM_BLINK_INTERVAL_SCALE *
            (f32)randomGetRange(PUSHABLE_MAGIC_GEM_BLINK_WAIT_MIN, PUSHABLE_MAGIC_GEM_BLINK_WAIT_MAX);
        state->blinkStep = state->blinkInterval / (f32)randomGetRange(PUSHABLE_MAGIC_GEM_BLINK_TIME_MIN,
                                                                           PUSHABLE_MAGIC_GEM_BLINK_TIME_MAX);
        state->blinkPhase = PUSHABLE_ZERO;
    }
    if (texture != NULL) {
        state->eyeOpenAmount += state->eyeOpenSpeed;
        if (state->eyeOpenAmount >= PUSHABLE_MAGIC_GEM_EYE_OPEN_MAX) {
            mainSetBits(state->gameBit, 1);
            if (nearTarget) {
                mainSetBits(PUSHABLE_MAGIC_GEM_NEAR_GAME_BIT, 0);
            }
            effectInterface = Resource_Acquire(PUSHABLE_MAGIC_GEM_EFFECT_DLL_ID, 1);
            (*effectInterface)->spawn(obj, PUSHABLE_MAGIC_GEM_EFFECT_ID, NULL, 2, -1, NULL);
            (*effectInterface)->spawn(obj, PUSHABLE_MAGIC_GEM_EFFECT_ID, NULL, 2, -1, NULL);
            Resource_Release(effectInterface);
            Sfx_PlayFromObject(obj, SFXTRIG_espar5_c);
        } else {
            pushable_driftEyePos(&state->eyePosX, state->eyeDriftSpeedX, PUSHABLE_MAGIC_GEM_EYE_POSITION_MAX);
            pushable_driftEyePos(&state->eyePosY, state->eyeDriftSpeedY, PUSHABLE_MAGIC_GEM_EYE_POSITION_MAX);
            eyeScaledX = state->eyePosX * (PUSHABLE_MAGIC_GEM_BLINK_SCALE_BASE + state->blinkPhase);
            eyeScaledY = state->eyePosY * (PUSHABLE_MAGIC_GEM_BLINK_SCALE_BASE + state->blinkPhase);
            texture->colorR = (u8)(int)state->eyeOpenAmount;
            texture->colorG = (u8)(int)eyeScaledX;
            texture->colorB = (u8)(int)eyeScaledY;
        }
    }
    return 0;
}

void pushable_initMagicGem(GameObject* obj, PushableState* state) {
    PushableObjectDef* placement;
    ObjTextureRuntimeSlot* texture;
    f32 sharedValue;
    f32 eyePosition;
    f32 limit;

    placement = (PushableObjectDef*)obj->anim.placementData;
    state->eyeOpenSpeed = PUSHABLE_MAGIC_GEM_EYE_OPEN_SPEED;
    sharedValue = PUSHABLE_MAGIC_GEM_EYE_DRIFT_SPEED;
    state->eyeDriftSpeedX = sharedValue;
    state->eyeDriftSpeedY = sharedValue;
    state->blinkInterval =
        PUSHABLE_MAGIC_GEM_BLINK_INTERVAL_SCALE *
        (f32)randomGetRange(PUSHABLE_MAGIC_GEM_BLINK_WAIT_MIN, PUSHABLE_MAGIC_GEM_BLINK_WAIT_MAX);
    state->blinkStep = state->blinkInterval /
                       (f32)randomGetRange(PUSHABLE_MAGIC_GEM_BLINK_TIME_MIN, PUSHABLE_MAGIC_GEM_BLINK_TIME_MAX);
    sharedValue = PUSHABLE_ZERO;
    state->blinkPhase = sharedValue;
    state->gameBit = placement->gameBit;
    state->gameBit2 = placement->gameBit2;
    state->magicGemDistanceThreshold = sharedValue;
    state->nearestObj = NULL;
    mainSetBits(state->gameBit, 0);
    texture = objFindTexture(obj, 0, 0);

    state->eyePosX = state->eyePosX + state->eyeDriftSpeedX;
    eyePosition = state->eyePosX;
    limit = PUSHABLE_MAGIC_GEM_EYE_POSITION_MAX;
    if (eyePosition > limit) {
        state->eyePosX = limit;
    } else if (eyePosition < PUSHABLE_ZERO) {
        state->eyePosX = limit;
    }

    state->eyePosY = state->eyePosY + state->eyeDriftSpeedY;
    eyePosition = state->eyePosY;
    limit = PUSHABLE_MAGIC_GEM_EYE_POSITION_MAX;
    if (eyePosition > limit) {
        state->eyePosY = limit;
    } else if (eyePosition < PUSHABLE_ZERO) {
        state->eyePosY = limit;
    }

    texture->colorR = PUSHABLE_MAGIC_GEM_INITIAL_COLOR;
    texture->colorG = PUSHABLE_MAGIC_GEM_INITIAL_COLOR;
    texture->colorB = PUSHABLE_MAGIC_GEM_INITIAL_COLOR;
}

void pushable_resolveCollisions(GameObject* obj, PushableState* state) {
    PushableObjectDef* placement;
    int pointIndex;
    s8 unresolvedMask;
    f32* probeCoordinates;
    int iteration;
    f32 scale;
    f32 savedX;
    f32 savedY;
    f32 savedZ;
    MatrixTransform transform;
    f32 transformMtx[16];
    f32 worldPoints[21];
    TrackLineIntersectResult collision;

    placement = (PushableObjectDef*)obj->anim.placementData;
    probeCoordinates = (f32*)state->probeLocal;
    Obj_GetPlayerObject();
    savedX = obj->anim.localPosX;
    savedY = obj->anim.localPosY;
    savedZ = obj->anim.localPosZ;
    unresolvedMask = PUSHABLE_POINT_MASK;
    iteration = 0;
    scale = PUSHABLE_UNIT_SCALE;
    while (unresolvedMask != 0) {
        unresolvedMask = PUSHABLE_POINT_MASK;
        iteration = iteration + 1;
        if (iteration > PUSHABLE_MAX_POINTS) {
            obj->anim.localPosX = savedX;
            obj->anim.localPosY = savedY;
            obj->anim.localPosZ = savedZ;
            break;
        }
        pointIndex = 0;
        for (; pointIndex < state->pointCount; pointIndex++) {
            transform.rotX = obj->anim.rotX;
            transform.rotY = obj->anim.rotY;
            transform.rotZ = obj->anim.rotZ;
            transform.scale = scale;
            transform.x = obj->anim.localPosX;
            transform.y = obj->anim.localPosY;
            transform.z = obj->anim.localPosZ;
            setMatrixFromObjectPos(transformMtx, &transform);
            Matrix_TransformPoint(transformMtx, probeCoordinates[pointIndex * 3], probeCoordinates[pointIndex * 3 + 1],
                                  probeCoordinates[pointIndex * 3 + 2], &worldPoints[pointIndex * 3],
                                  &worldPoints[pointIndex * 3 + 1], &worldPoints[pointIndex * 3 + 2]);
            if ((1 << pointIndex & PUSHABLE_POINT_MASK) != 0) {
                if (trackGetLineIntersect((f32*)&state->cornerWorld[pointIndex], &worldPoints[pointIndex * 3],
                                       PUSHABLE_COLLISION_RADIUS, 1, &collision, obj, 8, 0xd, (u8)(pointIndex + 3),
                                       10) == 0) {
                    unresolvedMask = (s8)(unresolvedMask & ~(1 << pointIndex));
                } else {
                    int angle;
                    int angleDelta;
                    if (collision.kind != PUSHABLE_NO_HIT_ID && (state->flags & PUSHABLE_FLAG_RESTORED) == 0) {
                        int gameBit;
                        state->flags |= PUSHABLE_FLAG_RESTORED;
                        gameBit = placement->gameBit;
                        if (gameBit > PUSHABLE_NO_GAME_BIT) {
                            switch (obj->anim.romDefNo) {
                            case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
                            case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
                                break;
                            case PUSHABLE_SEQ_ID_WC_PUSH_BLOCK:
                                state->flags &= ~PUSHABLE_FLAG_RESTORED;
                                if (collision.kind == state->requiredHitId) {
                                    ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);
                                    if (texture != NULL) {
                                        texture->textureId = PUSHABLE_WC_ACTIVATED_TEXTURE_ID;
                                    }
                                    mainSetBits(placement->gameBit, 1);
                                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                                    state->flags |= PUSHABLE_FLAG_PUSH_LOCKED;
                                }
                                break;
                            case PUSHABLE_SEQ_ID_DIM_PUSH_BLOCK:
                                if (collision.kind == 1) {
                                    mainSetBits(gameBit, 1);
                                    Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
                                    state->flags |= PUSHABLE_FLAG_PUSH_LOCKED;
                                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                                    saveGame_saveObjectPos(obj);
                                }
                                break;
                            default: {
                                s8 requiredHitId = placement->requiredHitId;
                                if (requiredHitId > PUSHABLE_NO_HIT_ID && requiredHitId == collision.kind) {
                                    mainSetBits(gameBit, 1);
                                    Sfx_PlayFromObject(0, SFXTRIG_menuups16k);
                                }
                                break;
                            }
                            }
                        }
                    }
                    mathSinf(PUSHABLE_PI * (f32)state->yaw / PUSHABLE_HALF_TURN);
                    mathCosf(PUSHABLE_PI * (f32)state->yaw / PUSHABLE_HALF_TURN);
                    angle = getAngle(collision.normalX, collision.normalZ);
                    angleDelta = state->yaw - (angle & PUSHABLE_ANGLE_FULL_TURN);
                    if (angleDelta > PUSHABLE_ANGLE_HALF_TURN) {
                        angleDelta -= PUSHABLE_ANGLE_FULL_TURN;
                    }
                    if (angleDelta < -PUSHABLE_ANGLE_HALF_TURN) {
                        angleDelta += PUSHABLE_ANGLE_FULL_TURN;
                    }
                    angleDelta = angleDelta / PUSHABLE_ANGLE_UNITS_PER_DEGREE;
                    if (angleDelta > -PUSHABLE_ANGLE_30_DEGREES && angleDelta < PUSHABLE_ANGLE_30_DEGREES) {
                        state->flags |= PUSHABLE_FLAG_PUSH_NEG_X;
                        state->pushAmountX = PUSHABLE_ZERO;
                    } else if (angleDelta > PUSHABLE_ANGLE_150_DEGREES || angleDelta < -PUSHABLE_ANGLE_150_DEGREES) {
                        state->flags |= PUSHABLE_FLAG_PUSH_POS_X;
                        state->pushAmountX = PUSHABLE_ZERO;
                    } else if (angleDelta > PUSHABLE_ANGLE_60_DEGREES && angleDelta < PUSHABLE_ANGLE_120_DEGREES) {
                        state->flags |= PUSHABLE_FLAG_PUSH_POS_Z;
                        state->pushAmountZ = PUSHABLE_ZERO;
                    } else if (angleDelta < -PUSHABLE_ANGLE_60_DEGREES && angleDelta > -PUSHABLE_ANGLE_120_DEGREES) {
                        state->flags |= PUSHABLE_FLAG_PUSH_NEG_Z;
                        state->pushAmountZ = PUSHABLE_ZERO;
                    }
                    memcpy(&state->cornerWorld[pointIndex], &worldPoints[pointIndex * 3], sizeof(Vec3f));
                    transformMtx[12] = worldPoints[pointIndex * 3];
                    transformMtx[13] = worldPoints[pointIndex * 3 + 1];
                    transformMtx[14] = worldPoints[pointIndex * 3 + 2];
                    Matrix_TransformPoint(transformMtx, -probeCoordinates[pointIndex * 3],
                                          -probeCoordinates[pointIndex * 3 + 1], -probeCoordinates[pointIndex * 3 + 2],
                                          &obj->anim.localPosX, &obj->anim.localPosY, &obj->anim.localPosZ);
                }
            }
        }
    }
    memcpy(state->cornerWorld, worldPoints, state->pointCount * sizeof(Vec3f));
}

u32 pushable_SeqFn(GameObject* obj, MatrixTransform* referenceTransform, ObjSeqState* animUpdate) {
    u32 gameBitValue;
    GameObject* player;
    PushableState* state;
    f32 deltaX;
    f32 deltaZ;
    f32 distance;
    f32 knockbackSpeed;

    state = obj->extra;
    state->savePosDelay = PUSHABLE_SEQUENCE_SAVE_DELAY;
    if (obj->seqIndex != -1) {
        (*gCameraInterface)->setTargetReticleOverride(obj);
    }
    animUpdate->savedFlags = -1;
    if ((s8)animUpdate->movementState != 0) {
        if ((s8)animUpdate->movementState != 2) {
            animUpdate->posOffsetScale = PUSHABLE_UNIT_SCALE;
            animUpdate->posOffsetX = obj->anim.localPosX - referenceTransform->x;
            animUpdate->posOffsetY = obj->anim.localPosY - referenceTransform->y;
            animUpdate->posOffsetZ = obj->anim.localPosZ - referenceTransform->z;
            animUpdate->rotOffsetX = obj->anim.rotX - (u16)referenceTransform->rotX;
            if (animUpdate->rotOffsetX > 0x8000) {
                animUpdate->rotOffsetX = animUpdate->rotOffsetX - 0xffff;
            }
            if (animUpdate->rotOffsetX < -0x8000) {
                animUpdate->rotOffsetX = animUpdate->rotOffsetX + 0xffff;
            }
            animUpdate->rotOffsetY = obj->anim.rotY - (u16)referenceTransform->rotY;
            if (animUpdate->rotOffsetY > 0x8000) {
                animUpdate->rotOffsetY = animUpdate->rotOffsetY - 0xffff;
            }
            if (animUpdate->rotOffsetY < -0x8000) {
                animUpdate->rotOffsetY = animUpdate->rotOffsetY + 0xffff;
            }
            animUpdate->rotOffsetZ = (u16)referenceTransform->rotZ - (u16)obj->anim.rotZ;
            if (animUpdate->rotOffsetZ > 0x8000) {
                animUpdate->rotOffsetZ = animUpdate->rotOffsetZ - 0xffff;
            }
            if (animUpdate->rotOffsetZ < -0x8000) {
                animUpdate->rotOffsetZ = animUpdate->rotOffsetZ + 0xffff;
            }
            animUpdate->movementState = PUSHABLE_SEQUENCE_MOVEMENT_OFFSET;
        }
        animUpdate->posOffsetScale = -(animUpdate->posOffsetDecay * timeDelta - animUpdate->posOffsetScale);
        if (animUpdate->posOffsetScale <= PUSHABLE_ZERO) {
            animUpdate->movementState = PUSHABLE_SEQUENCE_MOVEMENT_NONE;
        }
    }
    if (obj->userData2 == 0) {
        obj->userData2 = PUSHABLE_SEQUENCE_DEFAULT_USERDATA;
    }
    if ((obj->anim.romDefNo == PUSHABLE_SEQ_ID_MAGIC_GEM_21E) || (obj->anim.romDefNo == PUSHABLE_SEQ_ID_MAGIC_GEM_411)) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if ((obj->anim.hitboxTransformState->contactObjectCount > 0) &&
            ((((GameObject*)obj->anim.hitboxTransformState->contactObjects[0])->anim.classId ==
                  PUSHABLE_SEQUENCE_TARGET_CLASS_ID &&
              (gameBitValue = mainGetBit(PUSHABLE_SEQUENCE_GAME_BIT), gameBitValue == 0)))) {
            mainSetBits(PUSHABLE_SEQUENCE_GAME_BIT, 1);
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            player = Obj_GetPlayerObject();
            deltaX = obj->anim.localPosX - player->anim.localPosX;
            deltaZ = obj->anim.localPosZ - player->anim.localPosZ;
            distance = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
            if (distance) {
                deltaX = deltaX / distance;
                deltaZ = deltaZ / distance;
            }
            knockbackSpeed = PUSHABLE_KNOCKBACK_SPEED;
            state->knockbackVelX = knockbackSpeed * deltaX;
            state->knockbackVelY = PUSHABLE_ZERO;
            state->knockbackVelZ = knockbackSpeed * deltaZ;
            return PUSHABLE_SEQUENCE_KNOCKBACK_RESULT;
        }
    }
    return 0;
}

void pushable_handleMsgs(GameObject* obj, int unused) {
    PushableState* state;
    GameObject* messageSender;
    u32 messageId;
    u32 messageParam;

    (void)unused;

    state = obj->extra;
    messageParam = 0;
    while (ObjMsg_Pop(obj, &messageId, (u32*)&messageSender, &messageParam) != 0) {
        switch (messageId) {
        case PUSHABLE_MSG_SET_SENDER:
            state->msgSenderObj = messageSender;
            break;
        case PUSHABLE_MSG_FREE:
            if ((obj->anim.romDefNo != PUSHABLE_SEQ_ID_MAGIC_GEM_21E) &&
                (obj->anim.romDefNo != PUSHABLE_SEQ_ID_MAGIC_GEM_411)) {
                Obj_FreeObject(obj);
            }
            break;
        case PUSHABLE_MSG_MAGIC_GEM_DISTANCE:
            if (obj->anim.romDefNo == PUSHABLE_SEQ_ID_MAGIC_GEM_21E) {
                state->magicGemDistanceThreshold = *(f32*)messageParam;
            }
            if (obj->anim.romDefNo == PUSHABLE_SEQ_ID_MAGIC_GEM_411) {
                state->magicGemDistanceThreshold = *(f32*)messageParam;
            }
            break;
        }
    }
}

int pushable_isRestored(GameObject* obj) {
    return ((PushableState*)obj->extra)->flags & PUSHABLE_FLAG_RESTORED;
}

void pushable_setModelFlag(GameObject* obj, int modelNo) {
    PushableState* state = obj->extra;
    u32 flags = state->modelFlags;

    state->modelFlags = flags | (1 << modelNo);
}

int pushable_isWithinCullDistance(GameObject* obj, GameObject* other) {
    PushableState* state;
    f32 deltaToOther[3];
    f32* delta;

    state = obj->extra;
    delta = deltaToOther;
    delta[0] = other->anim.localPosX - obj->anim.localPosX;
    delta[1] = other->anim.localPosY - obj->anim.localPosY;
    delta[2] = other->anim.localPosZ - obj->anim.localPosZ;
    return sqrtf(delta[2] * delta[2] + (delta[0] * delta[0] + delta[1] * delta[1])) < state->cullDistance;
}

int pushable_push(GameObject* obj, GameObject* target, int active, f32 pushX, f32 pushZ) {
    PushableCollisionProbe* collisionProbe;
    PushableState* state;
    char pushDirection;
    GameObject* player;
    int blocked;
    char* historyCursor;
    f32* worldPoint;
    f32* localPoint;
    f32* delta;
    int historyEntryCount;
    PushableCollisionProbe collisionProbeStorage;
    char hitBuffer[64];
    f32 transformMtx[16];
    f32 worldPoints[12];
    f32 deltas[12];
    MatrixTransform transform;
    TrackQueryBounds sweep;
    f32 probeStart[3];
    f32 probeEnd[3];
    f32 transformedY;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    pushDirection = PUSHABLE_DIRECTION_NONE;
    historyEntryCount = 5;
    historyCursor = (char*)state + 0x14;
    while (historyCursor -= 4, historyEntryCount--) {
        *(f32*)(historyCursor + 0x118) = *(f32*)(historyCursor + 0x114);
        *(f32*)(historyCursor + 0x12c) = *(f32*)(historyCursor + 0x128);
    }
    state->posHistX[0] = obj->anim.localPosX;
    state->posHistZ[0] = obj->anim.localPosZ;
    probeStart[0] = target->anim.localPosX;
    probeStart[1] = PUSHABLE_PROBE_HEIGHT + target->anim.localPosY;
    probeStart[2] = target->anim.localPosZ;
    (collisionProbe = &collisionProbeStorage)->radii[0] = PUSHABLE_FORWARD_PROBE_DISTANCE;
    collisionProbe->unk10 = -1;
    collisionProbe->unk14 = 3;
    collisionProbe->unk2C = 0;
    blocked = 0;
    if (pushX > PUSHABLE_ZERO) {
        probeEnd[0] =
            PUSHABLE_FORWARD_PROBE_DISTANCE * mathSinf(PUSHABLE_PI * state->yaw / PUSHABLE_HALF_TURN) + probeStart[0];
        probeEnd[1] = probeStart[1];
        probeEnd[2] =
            PUSHABLE_FORWARD_PROBE_DISTANCE * mathCosf(PUSHABLE_PI * state->yaw / PUSHABLE_HALF_TURN) + probeStart[2];
        hitDetect_calcSweptSphereBounds(&sweep, probeStart, probeEnd, collisionProbe->radii, 1);
        trackIntersectBroadphase(NULL, &sweep, 0x208, 1);
        blocked = trackGetIntersect(NULL, probeStart, probeEnd, 1, &hitBuffer, 8);
        if (blocked == 0) {
            blocked = trackGetLineIntersect(probeStart, probeEnd, collisionProbe->radii[0], 0, NULL, obj, 1, -1, 0xff, 0);
        }
        if (blocked != 0) {
            f32 pushAmount;
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_POS_X;
            pushAmount = PUSHABLE_ZERO;
            state->pushAmountX = pushAmount;
            state->pushAmountZ = pushAmount;
        }
    } else if (pushZ > PUSHABLE_ZERO) {
        probeEnd[0] =
            PUSHABLE_SIDE_PROBE_DISTANCE * mathSinf(PUSHABLE_PI * (f32)(state->yaw + 0x4000) / PUSHABLE_HALF_TURN) +
            probeStart[0];
        probeEnd[1] = probeStart[1];
        probeEnd[2] =
            PUSHABLE_SIDE_PROBE_DISTANCE * mathCosf(PUSHABLE_PI * (f32)(state->yaw + 0x4000) / PUSHABLE_HALF_TURN) +
            probeStart[2];
        hitDetect_calcSweptSphereBounds(&sweep, probeStart, probeEnd, collisionProbe->radii, 1);
        trackIntersectBroadphase(NULL, &sweep, 0x208, 1);
        blocked = trackGetIntersect(NULL, probeStart, probeEnd, 1, &hitBuffer, 8);
        if (blocked == 0) {
            blocked = trackGetLineIntersect(probeStart, probeEnd, collisionProbe->radii[0], 0, NULL, obj, 1, -1, 0xff, 0);
        }
        if (blocked != 0) {
            f32 pushAmount;
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_POS_Z;
            pushAmount = PUSHABLE_ZERO;
            state->pushAmountX = pushAmount;
            state->pushAmountZ = pushAmount;
        }
    } else if (pushZ < PUSHABLE_ZERO) {
        probeEnd[0] =
            PUSHABLE_SIDE_PROBE_DISTANCE * mathSinf(PUSHABLE_PI * (f32)(state->yaw - 0x4000) / PUSHABLE_HALF_TURN) +
            probeStart[0];
        probeEnd[1] = probeStart[1];
        probeEnd[2] =
            PUSHABLE_SIDE_PROBE_DISTANCE * mathCosf(PUSHABLE_PI * (f32)(state->yaw - 0x4000) / PUSHABLE_HALF_TURN) +
            probeStart[2];
        hitDetect_calcSweptSphereBounds(&sweep, probeStart, probeEnd, collisionProbe->radii, 1);
        trackIntersectBroadphase(NULL, &sweep, 0x208, 1);
        blocked = trackGetIntersect(NULL, probeStart, probeEnd, 1, &hitBuffer, 8);
        if (blocked == 0) {
            blocked = trackGetLineIntersect(probeStart, probeEnd, collisionProbe->radii[0], 0, NULL, obj, 1, -1, 0xff, 0);
        }
        if (blocked != 0) {
            f32 pushAmount;
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_NEG_Z;
            pushAmount = PUSHABLE_ZERO;
            state->pushAmountX = pushAmount;
            state->pushAmountZ = pushAmount;
        }
    }
    if (playerIsDisguised(player) == 0 && state->moveFlags.pushPromptEnabled == 0) {
        blocked = 1;
        if (pushX > PUSHABLE_ZERO) {
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_POS_X;
        } else if (pushX < PUSHABLE_ZERO) {
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_NEG_X;
        } else if (pushZ > PUSHABLE_ZERO) {
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_POS_Z;
        } else {
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_NEG_Z;
        }
        {
            f32 zero = PUSHABLE_ZERO;
            state->pushAmountX = zero;
            state->pushAmountZ = zero;
        }
    }
    if (active != 0 && (state->flags & PUSHABLE_FLAG_NO_GROUND_CONTACT) == 0) {
        state->flags = state->flags | PUSHABLE_FLAG_MOVED;
        state->pushSfxTimer -= 1;
        if (state->pushSfxTimer <= 0) {
            state->pushSfxTimer = randomGetRange(0x28, 0x3c);
            state->flags = state->flags | PUSHABLE_FLAG_PUSH_SFX_DUE;
        }
        if ((state->flags & PUSHABLE_FLAG_PUSH_LOCKED) != 0) {
            f32 zero = PUSHABLE_ZERO;
            state->pushAmountX = zero;
            state->pushAmountZ = zero;
        } else if (blocked == 0) {
            state->pushAmountX = pushX;
            state->pushAmountZ = pushZ;
        }
        state->yaw = target->anim.rotX;
        transform.rotX = target->anim.rotX;
        transform.rotY = 0;
        transform.rotZ = 0;
        transform.scale = PUSHABLE_UNIT_SCALE;
        transform.x = PUSHABLE_ZERO;
        transform.y = PUSHABLE_ZERO;
        transform.z = PUSHABLE_ZERO;
        setMatrixFromObjectPos(transformMtx, &transform);
        Matrix_TransformPoint(transformMtx, state->pushAmountZ, PUSHABLE_ZERO, state->pushAmountX, &obj->anim.velocityX,
                              &transformedY, &obj->anim.velocityZ);
        state->moveFlags.activelyPushed = 1;
        objMove(obj, obj->anim.velocityX, PUSHABLE_ZERO, obj->anim.velocityZ);
        Obj_BuildTransformMatrices(obj);
        {
            int pointIndex;
            pointIndex = 0;
            worldPoint = worldPoints;
            localPoint = (f32*)state;
            delta = deltas;
            for (; pointIndex < state->pointCount; pointIndex++) {
                Obj_TransformLocalPointToWorld(localPoint[6], localPoint[7],
                                               localPoint[8], worldPoint, worldPoint + 1,
                                               worldPoint + 2, obj);
                delta[0] = obj->anim.localPosX - worldPoint[0];
                delta[1] = obj->anim.localPosY - worldPoint[1];
                delta[2] = obj->anim.localPosZ - worldPoint[2];
                worldPoint += 3;
                localPoint += 3;
                delta += 3;
            }
        }
        if ((state->flags & PUSHABLE_FLAG_AIRBORNE) == 0) {
            pushable_resolveCollisions(obj, state);
        }
        Obj_BuildTransformMatrices(obj);
        if (PUSHABLE_ZERO != state->pushAmountX || PUSHABLE_ZERO != state->pushAmountZ) {
            PushableState* movedState;
            PushableObjectDef* placement;
            u16 flags;
            placement = (PushableObjectDef*)obj->anim.placementData;
            movedState = obj->extra;
            flags = movedState->flags;
            if ((flags & PUSHABLE_FLAG_RESTORED) != 0) {
                s16 gameBit;
                movedState->flags = flags & ~PUSHABLE_FLAG_RESTORED;
                gameBit = placement->gameBit;
                if (gameBit > -1) {
                    switch (obj->anim.romDefNo) {
                    case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
                        break;
                    case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
                        break;
                    case PUSHABLE_SEQ_ID_WC_PUSH_BLOCK:
                        break;
                    default:
                        if (placement->requiredHitId > PUSHABLE_NO_HIT_ID) {
                            mainSetBits(gameBit, 0);
                        }
                        break;
                    }
                }
            }
        }
        {
            f32 travelX = obj->anim.localPosX - state->posHistX[4];
            f32 travelZ = obj->anim.localPosZ - state->posHistZ[4];
            if (travelX * travelX + travelZ * travelZ > PUSHABLE_UNIT_SCALE &&
                (state->flags & PUSHABLE_FLAG_PUSH_SFX_DUE) != 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_birdymornin11);
                state->flags = state->flags & ~PUSHABLE_FLAG_PUSH_SFX_DUE;
            }
        }
    } else {
        int pointIndex;
        ObjHitboxTransformState* transformState = obj->anim.hitboxTransformState;
        f32* modelMtx = (f32*)((char*)transformState + ((transformState->activeMatrixIndex + 2) << 4) * 4);
        pointIndex = 0;
        localPoint = (f32*)state;
        for (; pointIndex < state->pointCount; pointIndex++) {
            Matrix_TransformPoint(modelMtx, localPoint[6], localPoint[7],
                                  localPoint[8], &localPoint[30],
                                  &localPoint[31], &localPoint[32]);
            localPoint += 3;
        }
    }
    {
        u16 flags = state->flags;
        if ((flags & PUSHABLE_FLAG_PUSH_NEG_X) != 0) {
            pushDirection = PUSHABLE_DIRECTION_NEG_X;
        } else if ((flags & PUSHABLE_FLAG_PUSH_POS_X) != 0) {
            pushDirection = PUSHABLE_DIRECTION_POS_X;
        } else if ((flags & PUSHABLE_FLAG_PUSH_NEG_Z) != 0) {
            pushDirection = PUSHABLE_DIRECTION_NEG_Z;
        } else if ((flags & PUSHABLE_FLAG_PUSH_POS_Z) != 0) {
            pushDirection = PUSHABLE_DIRECTION_POS_Z;
        } else if ((flags & PUSHABLE_FLAG_NO_GROUND_CONTACT) != 0) {
            pushDirection = PUSHABLE_DIRECTION_DOWN;
        }
        state->flags &= ~PUSHABLE_FLAG_PUSH_DIR_MASK;
    }
    return pushDirection;
}

int pushable_getExtraSize(void) {
    return sizeof(PushableState);
}

int pushable_getObjectTypeId(void) {
    return PUSHABLE_OBJECT_TYPE_ID;
}

void pushable_free(GameObject* obj) {
    PushableObjectDef* placement = (PushableObjectDef*)obj->anim.placementData;
    PushableState* state = obj->extra;
    s16 sequenceId = obj->anim.romDefNo;
    int savedIdentIndex;

    switch (sequenceId) {
    case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
        mainSetBits(state->gameBit, 0);
        break;
    case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
        mainSetBits(state->gameBit, 0);
        break;
    default:
        if (placement->gameBit > PUSHABLE_NO_GAME_BIT && sequenceId != PUSHABLE_SEQ_ID_VFP_BLOCK2 &&
            sequenceId != PUSHABLE_SEQ_ID_5AE && sequenceId != PUSHABLE_SEQ_ID_DIM2_ICE_BLOCK &&
            state->savePosEnabled != 0) {
            saveGame_saveObjectPos(obj);
        }
        break;
    }
    if ((state->flags & PUSHABLE_FLAG_RESTORED) != 0) {
        int ident = placement->base.ident;
        savedIdentIndex = gPushableSavedIdentCount;
        gPushableSavedIdentCount = savedIdentIndex + 1;
        gPushableSavedIdents[savedIdentIndex] = ident;
    }
    objFreeObjectType(obj, PUSHABLE_OBJECT_GROUP);
}

void pushable_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if (visible != 0) {
        PushableState* state = obj->extra;
        switch (obj->anim.romDefNo) {
        case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
            if (mainGetBit(state->gameBit) == 0) {
                break;
            }
            return;
        case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
            if (mainGetBit(state->gameBit) == 0) {
                break;
            }
            return;
        case PUSHABLE_SEQ_ID_VFP_BLOCK2: {
            f32 timer = state->renderTimer;
            f32 zero = PUSHABLE_ZERO;
            if (timer > zero) {
                state->renderTimer = timer - timeDelta;
                if (state->renderTimer <= zero) {
                    state->renderTimer = zero;
                } else {
                    objSetGlowColor(0xc8, 0, 0, 0xff);
                }
            }
            break;
        }
        }
        {
            ObjAnimBank* activeModelSlot = obj->anim.banks[obj->anim.bankIndex];
            activeModelSlot->animDef->flags = activeModelSlot->animDef->flags | 2;
        }
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, PUSHABLE_UNIT_SCALE);
    }
}

void pushable_hitDetect(GameObject* obj) {
    TrackGroundHit* groundHit;
    s8 hitCount;
    GameObject* player;
    PushableState* state;
    int j;
    int groundPointCount;
    int waterHitCount;
    int i;
    f32 waterDepthSum;
    Vec3f worldPoints[PUSHABLE_MAX_POINTS];
    f32 transformMtx[16];
    TrackQueryBounds sweep;
    MatrixTransform transform;
    f32 groundHeights[PUSHABLE_MAX_POINTS];
    PushableRadii radii;
    TrackGroundHit** groundHits;
    f32 groundHeightSum;

    radii = gPushableDefaultBox;
    player = Obj_GetPlayerObject();
    state = obj->extra;
    state->airborneTimer -= timeDelta;
    if (state->airborneTimer <= PUSHABLE_ZERO) {
        state->airborneTimer = PUSHABLE_ZERO;
    }
    if (state->moveFlags.activelyPushed == 0) {
        f32 damping;
        if (playerGetSurfaceType(player) == 0xd) {
            damping = PUSHABLE_GROUND_DAMPING;
        } else {
            damping = PUSHABLE_AIR_DAMPING;
        }
        state->pushAmountX *= damping;
        if (state->pushAmountX < PUSHABLE_STOP_THRESHOLD && state->pushAmountX > PUSHABLE_NEG_STOP_THRESHOLD) {
            state->pushAmountX = PUSHABLE_ZERO;
        }
        state->pushAmountZ *= damping;
        if (state->pushAmountZ < PUSHABLE_STOP_THRESHOLD && state->pushAmountZ > PUSHABLE_NEG_STOP_THRESHOLD) {
            state->pushAmountZ = PUSHABLE_ZERO;
        }
        if (PUSHABLE_ZERO != state->pushAmountX || PUSHABLE_ZERO != state->pushAmountZ) {
            transform.rotX = state->yaw;
            transform.rotY = 0;
            transform.rotZ = 0;
            transform.scale = PUSHABLE_UNIT_SCALE;
            transform.x = PUSHABLE_ZERO;
            transform.y = PUSHABLE_ZERO;
            transform.z = PUSHABLE_ZERO;
            setMatrixFromObjectPos(transformMtx, &transform);
            Matrix_TransformPoint(transformMtx, state->pushAmountZ, PUSHABLE_ZERO, state->pushAmountX,
                                  &obj->anim.velocityX, &groundHeightSum, &obj->anim.velocityZ);
            objMove(obj, obj->anim.velocityX, PUSHABLE_ZERO, obj->anim.velocityZ);
            if ((state->flags & PUSHABLE_FLAG_AIRBORNE) == 0) {
                pushable_resolveCollisions(obj, state);
            }
            state->flags |= PUSHABLE_FLAG_MOVED;
        }
    }
    state->moveFlags.pushPromptEnabled = 1;
    switch (obj->anim.romDefNo) {
    case PUSHABLE_SEQ_ID_DIM2_ICE_BLOCK:
        if (mainGetBit(GAMEBIT_PushableRelated0272) != 0) {
            return;
        }
        break;
    case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
        if (mainGetBit(state->gameBit) != 0) {
            return;
        }
        break;
    case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
        if (mainGetBit(state->gameBit) != 0) {
            return;
        }
        break;
    case PUSHABLE_SEQ_ID_METAL_PUSH_BLOCK:
        state->moveFlags.pushPromptEnabled = 0;
        break;
    case PUSHABLE_SEQ_ID_VFP_BLOCK2:
        break;
    }
    if ((state->flags & PUSHABLE_FLAG_AIRBORNE) != 0) {
        obj->anim.velocityY -= PUSHABLE_GRAVITY * timeDelta;
        obj->anim.localPosY += obj->anim.velocityY * timeDelta;
    }
    if ((state->flags & PUSHABLE_FLAG_MOVED) != 0 || (state->flags & PUSHABLE_FLAG_AIRBORNE) != 0) {
        Obj_BuildTransformMatrices(obj);
        for (i = 0; i < state->pointCount; i++) {
            Obj_TransformLocalPointToWorld(state->cornerLocal[i].x, state->cornerLocal[i].y, state->cornerLocal[i].z,
                                           &worldPoints[i].x, &worldPoints[i].y, &worldPoints[i].z, obj);
        }
        hitDetect_calcSweptSphereBounds(&sweep, (f32*)state->cornerWorld, (f32*)worldPoints, radii.values,
                                        PUSHABLE_MAX_POINTS);
        sweep.minY -= PUSHABLE_SWEEP_Y_PADDING;
        sweep.maxY += PUSHABLE_SWEEP_Y_PADDING;
        trackIntersectBroadphase(obj, &sweep, 1, 1);
        groundHeightSum = PUSHABLE_ZERO;
        groundPointCount = 0;
        waterHitCount = 0;
        for (i = 0; i < state->pointCount; i++) {
            Vec3f* point = &worldPoints[i];
            f32* groundHeight = &groundHeights[i];
            f32 y = point->y;
            s8 foundGround;

            *groundHeight = y;
            waterDepthSum = PUSHABLE_ZERO;
            hitCount = trackGetHeight(obj, point->x, y, point->z, &groundHits, -1, 0);
            foundGround = 0;
            if (hitCount != 0) {
                for (j = 0; j < hitCount; j++) {
                    groundHit = groundHits[j];
                    if ((s8)groundHit->surfaceType == PUSHABLE_WATER_SURFACE_TYPE) {
                        f32 waterDepth = groundHit->height - obj->anim.localPosY;
                        if (waterDepth > PUSHABLE_ZERO) {
                            waterDepthSum += waterDepth;
                            waterHitCount++;
                        }
                    } else if (foundGround == 0) {
                        f32 probeY = groundHit->height;
                        if (probeY < PUSHABLE_MIN_GROUND_CLEARANCE + point->y &&
                            probeY > point->y - PUSHABLE_MAX_GROUND_STEP &&
                            groundHit->normalY > PUSHABLE_MIN_GROUND_NORMAL_Y) {
                            GameObject* contactObj;
                            *groundHeight = probeY;
                            groundHeightSum += probeY;
                            contactObj = groundHits[j]->object;
                            if (contactObj != NULL) {
                                ObjHits_AddContactObject(contactObj, obj);
                            }
                            groundPointCount++;
                            foundGround = 1;
                        }
                    }
                }
            }
        }
        state->prevWaterDepth = state->waterDepth;
        if (waterHitCount != 0) {
            state->waterDepth = waterDepthSum / waterHitCount;
        } else {
            state->waterDepth = PUSHABLE_ZERO;
        }
        if (groundPointCount != 0 && state->airborneTimer <= PUSHABLE_ZERO) {
            obj->anim.velocityY = PUSHABLE_ZERO;
            obj->anim.localPosY = PUSHABLE_COLLISION_RADIUS + groundHeightSum / groundPointCount;
            state->flags &= ~PUSHABLE_FLAG_AIR_STATE_MASK;
        } else {
            if ((state->flags & PUSHABLE_FLAG_AIRBORNE) == 0) {
                state->airborneTimer = PUSHABLE_AIRBORNE_TIMER;
            }
            state->flags |= PUSHABLE_FLAG_AIR_STATE_MASK;
        }
    }
    Obj_BuildTransformMatrices(obj);
    for (i = 0; i < state->pointCount; i++) {
        Obj_TransformLocalPointToWorld(state->probeLocal[i].x, state->probeLocal[i].y, state->probeLocal[i].z,
                                       &state->cornerWorld[i].x, &state->cornerWorld[i].y, &state->cornerWorld[i].z,
                                       obj);
    }
}

void pushable_update(GameObject* obj) {
    PushableState* state;
    ObjPlacement* placement;
    GameObject* player;

    placement = obj->anim.placement;
    state = obj->extra;
    state->flags = state->flags & ~PUSHABLE_FLAG_MOVED;
    state->moveFlags.activelyPushed = 0;
    if (PUSHABLE_ZERO != obj->anim.velocityY) {
        state->flags = state->flags | PUSHABLE_FLAG_MOVED;
    }
    if (state->moveFlags.pushPromptEnabled == 0 && playerIsDisguised(Obj_GetPlayerObject()) == 0) {
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    } else {
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_IN_RANGE) != 0 && mainGetBit(GAMEBIT_PushableRelated0913) == 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        mainSetBits(GAMEBIT_PushableRelated0913, 1);
        return;
    }
    player = Obj_GetPlayerObject();
    if ((player != NULL && playerGetStateValue(player, 10) != 0) || (state->flags & PUSHABLE_FLAG_AIRBORNE) != 0) {
        state->savePosDelay = PUSHABLE_ACTIVE_SAVE_DELAY;
    }
    if (state->savePosDelay != 0) {
        state->savePosDelay -= 1;
    } else if (state->savePosEnabled != 0) {
        pushable_savePos(obj);
    }
    switch (obj->anim.romDefNo) {
    case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
        if (pushable_updateMagicGem(obj, state) == 0) {
            break;
        }
        return;
    case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
        if (pushable_updateMagicGem(obj, state) == 0) {
            break;
        }
        return;
    case PUSHABLE_SEQ_ID_VFP_BLOCK2:
        if (mainGetBit(state->gameBit) != 0) {
            obj->anim.localPosX = (f32)((f64)placement->posX - PUSHABLE_CURTAIN_POSITION_X);
            obj->anim.localPosY = placement->posY;
            obj->anim.localPosZ = (f32)(PUSHABLE_CURTAIN_POSITION_Z + (f64)placement->posZ);
        }
        ((int (*)(int, PushableState*))pushable_updateCurtain)((int)obj, state);
        break;
    case PUSHABLE_SEQ_ID_DIM2_ICE_BLOCK:
        if (PUSHABLE_ZERO == state->prevWaterDepth && state->waterDepth > PUSHABLE_ZERO) {
            Sfx_PlayFromObject(obj, SFXTRIG_curtainopen16);
            mainSetBits(GAMEBIT_PushableRelated0272, 1);
        }
        if (mainGetBit(GAMEBIT_PushableRelated0272) != 0) {
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
        }
        break;
    }
    {
        s16 sequenceId = obj->anim.romDefNo;
        if (sequenceId != PUSHABLE_SEQ_ID_VFP_BLOCK2 && sequenceId != PUSHABLE_SEQ_ID_5AE &&
            sequenceId != PUSHABLE_SEQ_ID_DIM2_ICE_BLOCK && state->savePosEnabled != 0 &&
            (state->flags & PUSHABLE_FLAG_NO_GROUND_CONTACT) == 0) {
            saveGame_saveObjectPos(obj);
        }
    }
}

void pushable_init(GameObject* obj, PushableObjectDef* setup) {
    PushableState* state;
    ModelFileHeader* model;
    int* activeModelSlot;
    int i;
    f32* modelMtx;
    f32 vertex[3];

    if (setup->base.ident == PUSHABLE_FORCE_HIT_ID_MAP) {
        setup->requiredHitId = 1;
    } else {
        setup->requiredHitId = PUSHABLE_NO_HIT_ID;
    }
    obj->anim.rotX = setup->rotXByte << 8;
    obj->anim.localPosY = PUSHABLE_COLLISION_RADIUS + setup->base.posY;
    objAddObjectType(obj, PUSHABLE_OBJECT_GROUP);
    objSetSlot(obj, PUSHABLE_OBJECT_SLOT);
    obj->animEventCallback = pushable_SeqFn;
    state = obj->extra;
    state->pointCount = 0;
    activeModelSlot = (int*)((ObjAnimComponent*)obj)->banks[((ObjAnimComponent*)obj)->bankIndex];
    model = (ModelFileHeader*)*activeModelSlot;
    state->unkB0 = setup->unk1C;
    state->scale = (f32) * &setup->scaleRaw / PUSHABLE_SCALE_DENOM;
    state->scale = state->scale * obj->anim.modelInstance->rootMotionScaleBase;
    state->cullDistance = state->scale * (f32)modelFileHeaderGetCullDistance((ModelFileHeader*)*activeModelSlot) +
                          PUSHABLE_MIN_GROUND_CLEARANCE;
    {
        f32 z0 = PUSHABLE_ZERO;
        state->renderTimer = z0;
        state->gameBit = setup->gameBit;
        ObjAnim_SetCurrentMove(obj, 0, z0, 0);
    }
    ObjMsg_AllocQueue(obj, PUSHABLE_MSG_QUEUE_SIZE);
    ObjHits_EnableObject(obj);
    {
        f32 minY = PUSHABLE_INITIAL_CULL_DISTANCE;
        for (i = 0; i < model->vertexCount; i++) {
            Model_GetVertexPosition(model, i, vertex);
            if (vertex[1] < minY) {
                minY = vertex[1];
            }
        }
        for (i = 0; i < model->vertexCount; i++) {
            Model_GetVertexPosition(model, i, vertex);
            if (vertex[1] == minY) {
                int j;
                int found;
                f32 vx;
                f32 vz;

                found = 0;
                j = 0;
                vx = vertex[0];
                vz = vertex[2];

                for (; j < state->pointCount; j++) {
                    if (vx == state->cornerLocal[j].x && vz == state->cornerLocal[j].z) {
                        found = 1;
                        j = state->pointCount;
                    }
                }
                if (found == 0) {
                    state->cornerLocal[state->pointCount].x = *(f32*)vertex;
                    state->cornerLocal[state->pointCount].y = vertex[1];
                    state->cornerLocal[state->pointCount].z = vertex[2];
                    state->pointCount += 1;
                }
            }
        }
    }
    if (state->pointCount > PUSHABLE_MAX_POINTS) {
        state->pointCount = PUSHABLE_MAX_POINTS;
        debugPrintf(sPushPullObjectHitpointOverflow);
    }
    {
        ObjHitboxTransformState* transformState = obj->anim.hitboxTransformState;
        modelMtx = (f32*)((char*)transformState + ((transformState->activeMatrixIndex + 2) << 4) * 4);
    }
    {
        for (i = 0; i < state->pointCount; i++) {
            state->probeLocal[i].x = state->cornerLocal[i].x;
            state->probeLocal[i].y = state->cornerLocal[i].y;
            state->probeLocal[i].z = state->cornerLocal[i].z;
            if (state->probeLocal[i].x < PUSHABLE_ZERO) {
                state->probeLocal[i].x += PUSHABLE_COLLISION_RADIUS;
            } else {
                state->probeLocal[i].x -= PUSHABLE_COLLISION_RADIUS;
            }
            if (state->probeLocal[i].z < PUSHABLE_ZERO) {
                state->probeLocal[i].z += PUSHABLE_COLLISION_RADIUS;
            } else {
                state->probeLocal[i].z -= PUSHABLE_COLLISION_RADIUS;
            }
            if (state->cornerLocal[i].x < PUSHABLE_ZERO) {
                state->cornerLocal[i].x += PUSHABLE_UNIT_SCALE;
            } else {
                state->cornerLocal[i].x -= PUSHABLE_UNIT_SCALE;
                state->cornerIdxPosX = i;
            }
            if (state->cornerLocal[i].z < PUSHABLE_ZERO) {
                state->cornerLocal[i].z += PUSHABLE_UNIT_SCALE;
            } else {
                state->cornerLocal[i].z -= PUSHABLE_UNIT_SCALE;
                state->cornerIdxPosZ = i;
            }
            Matrix_TransformPoint(modelMtx, state->probeLocal[i].x, state->probeLocal[i].y, state->probeLocal[i].z,
                                  &state->cornerWorld[i].x, &state->cornerWorld[i].y, &state->cornerWorld[i].z);
        }
    }
    for (i = 0; i < state->pointCount; i++) {
        if (i != state->cornerIdxPosX && state->cornerLocal[i].x < PUSHABLE_ZERO) {
            if ((int)state->cornerLocal[i].z == (int)state->cornerLocal[state->cornerIdxPosX].z) {
                state->cornerIdxNegX = i;
            }
        }
        if (i != state->cornerIdxPosZ && state->cornerLocal[i].z < PUSHABLE_ZERO) {
            if ((int)state->cornerLocal[i].x == (int)state->cornerLocal[state->cornerIdxPosZ].x) {
                state->cornerIdxNegZ = i;
            }
        }
    }
    state->savePosEnabled = 1;
    switch (obj->anim.romDefNo) {
    case PUSHABLE_SEQ_ID_MAGIC_GEM_21E:
        ((void (*)(GameObject*, PushableState*))pushable_initMagicGem)(obj, state);
        break;
    case PUSHABLE_SEQ_ID_MAGIC_GEM_411:
        ((void (*)(GameObject*, PushableState*))pushable_initMagicGem)(obj, state);
        break;
    case PUSHABLE_SEQ_ID_WC_PUSH_BLOCK:
        ((void (*)(GameObject*, PushableState*))pushable_initWcPushBlock)(obj, state);
        break;
    case PUSHABLE_SEQ_ID_DIM_PUSH_BLOCK:
        if (setup->gameBit > PUSHABLE_NO_GAME_BIT && mainGetBit(setup->gameBit) != 0) {
            state->flags = state->flags | (PUSHABLE_FLAG_RESTORED | PUSHABLE_FLAG_PUSH_LOCKED);
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            pushable_savePos(obj);
        }
        state->savePosEnabled = 0;
        break;
    default:
        if (setup->gameBit > PUSHABLE_NO_GAME_BIT && mainGetBit(setup->gameBit) != 0) {
            state->flags = state->flags | PUSHABLE_FLAG_RESTORED;
        }
        break;
    }
    {
        ObjModelState* modelState = obj->anim.modelState;
        if (modelState != NULL) {
            modelState->flags = modelState->flags | 0xA10;
            obj->anim.modelState->shadowTintA = 0x60;
            obj->anim.modelState->shadowTintB = 0x40;
        }
    }
    state->flags = state->flags | PUSHABLE_FLAG_INITIALIZED;
    if (arrayIndexOf(gPushableSavedIdents, gPushableSavedIdentCount, setup->base.ident) != -1) {
        state->flags = state->flags | PUSHABLE_FLAG_RESTORED;
        arrayRemoveUnordered(gPushableSavedIdents, &gPushableSavedIdentCount, setup->base.ident);
    }
}
