/* Runs the final Andross boss fight from the Arwing. */
#include "main/dll/dll_02BC_andross.h"
#include "main/audio/music_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "main/dll/tricky.h"
#include "main/newshadows.h"
#include "game/objects/object.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/objtype.h"
#include "main/obj_list.h"
#include "main/obj_path.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/dll_02BE_androssbrain.h"
#include "main/dll/dll_02BB_gflevelcon.h"
#include "main/dll/dll_02BD_androsshand.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/model.h"
#include "main/rcp_dolphin_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/object_render.h"
#include "main/maketex_sequence_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"

s16 gAndrossSwayPhaseX;
s16 gAndrossSwayPhaseY;
s16 gAndrossRingProjectilePitchSource;
s16 gAndrossProjectileYaw;
int gAndrossRingProjectilePitch;
int gAndrossProjectilePitch;
f32 gAndrossDistortPhase;

#define ARW_ARWING_BOMB_OBJ 0x605 /* retail OBJECTS.bin "ARWArwingBo", DLL 0x29C */

/* retail "ANDSilverRi" (silver ring); cached into state->silverRing w/ silverRingLifetime */
#define ANDROSS_CHILD_OBJ_SILVER_RING 0x819

/* projectiles; retail OBJECTS.bin names ANDAsteroid / AndrossRing / ANDSuckAste */
#define ANDROSS_CHILD_OBJ_ASTEROID      0x80d
#define ANDROSS_CHILD_OBJ_RING          0x7e4
#define ANDROSS_CHILD_OBJ_SUCK_ASTEROID 0x859
/* retail "ARWBombColl" (DLL 0x29F arwbombcoll), attached at the nearest 0x7e5 arwing */
#define ANDROSS_CHILD_OBJ_ARW_BOMB 0x608

#define ANDROSS_MAP_SHRINE 0xb /* Krazoa shrine map warped to on fight completion */

enum AndrossPartSignal {
    ANDROSS_SIGNAL_BRAIN_HIT = 1,       /* a part reported a hit (androssbrain/androsshand -> setPartSignal) */
    ANDROSS_SIGNAL_BOTH_HANDS_DEAD = 6, /* leftHandObj + rightHandObj dead bits, tested/set/cleared as a unit */
    ANDROSS_SIGNAL_BRAIN_DEFEATED = 8   /* brain destroyed -> victory path (androssbrain) */
};

typedef struct AndrossChildSetup {
    ObjPlacement base;
    u8 unk18[8];
    s16 flags;
} AndrossChildSetup;

void andross_spawnBombCollector(GameObject* obj, AndrossState* state) {
    f32 maxDist = 10000.0f;
    GameObject* target;
    ObjPlacement* setup;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return;
    }
    target = ObjList_FindNearestObjectByDefNo(obj, 0x7e5, &maxDist);
    if (target == NULL) {
        return;
    }
    setup = Obj_AllocObjectSetup(0x24, ANDROSS_CHILD_OBJ_ARW_BOMB);
    setup->posX = target->anim.localPosX;
    setup->posY = target->anim.localPosY;
    setup->posZ = target->anim.localPosZ;
    setup->color[0] = 1;
    setup->color[1] = 1;
    state->bombCollector = loadObjectAtObject(obj, setup);
    if (state->bombCollector != NULL) {
        state->bombCollector->anim.alpha = 0xff;
        state->bombCollector->anim.renderAlpha = 0xff;
        state->bombCollectorLifetime = 0x12c;
    }
}

void andross_steerAsteroids(GameObject* obj, AndrossState* state) {
    GameObject** objects;
    GameObject* asteroid;
    int index;
    int count;
    int objectDefNo;

    GameObject** objectList = objGetAllOfType(2, &count);
    for (index = 0, objects = objectList; index < count; objects++, index++) {
        asteroid = *objects;
        objectDefNo = ((ObjPlacement*)asteroid->anim.placementData)->objectId;
        if (objectDefNo == ANDROSS_CHILD_OBJ_ASTEROID || objectDefNo == ANDROSS_CHILD_OBJ_SUCK_ASTEROID) {
            f32 dx = state->cachedPosX - asteroid->anim.localPosX;
            f32 dy = state->cachedPosY - asteroid->anim.localPosY;
            f32 dz = state->cachedPosZ - asteroid->anim.localPosZ;
            asteroid->anim.rotX = getAngle(dx, dz);
            asteroid->anim.rotY = -(s16)getAngle(dy, dz);
            arwprojectile_placeForward(asteroid, (f32)gAndrossProjectileForwardStep);
        }
    }
}

void andross_spawnSuckAsteroid(GameObject* obj, AndrossState* state) {
    f32 angle;
    int spawnRadius;
    GfProjectileSetup* setup;
    GameObject* projectile;
    int yaw;
    s16 radialAngle;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return;
    }
    yaw = gAndrossProjectileYaw;
    gAndrossRingProjectilePitch = gAndrossRingProjectilePitchSource;
    radialAngle = randomGetRange(-0x8000, 0x7fff);
    spawnRadius = randomGetRange(0x64, 0x12c);
    setup = (GfProjectileSetup*)Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_SUCK_ASTEROID);
    angle = 3.1415927f * (f32)radialAngle / 32768.0f;
    setup->head.posX = (f32)spawnRadius * mathSinf(angle) + state->arwingObj->anim.localPosX;
    setup->head.posY = (f32)spawnRadius * mathCosf(angle) + state->arwingObj->anim.localPosY;
    setup->head.posZ = state->cachedPosZ - 500.0f;
    setup->yawHi = (obj->anim.rotX + yaw) >> 8;
    setup->pitch = gAndrossRingProjectilePitch;
    setup->roll = 0;
    setup->head.color[0] = 1;
    setup->head.color[1] = 1;
    projectile = loadObjectAtObject(obj, &setup->head);
    if (projectile != NULL) {
        projectile->anim.rootMotionScale = gAndrossRingProjectileScale;
        arwprojectile_setLifetime(projectile, gAndrossRingProjectileLifetime);
        arwprojectile_placeForward(projectile, 7.0f);
    }
}

void andross_spawnAsteroid(GameObject* obj, AndrossState* state) {
    GameObject* projectile;
    int yawOffset;
    int pitch;
    GfProjectileSetup* setup;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return;
    }
    yawOffset = (s16)(randomGetRange(-0x1f40, 0x1f40) - 0x8000);
    pitch = randomGetRange(-0x1f40, 0x1f40) >> 8;
    setup = (GfProjectileSetup*)Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_ASTEROID);
    setup->head.posX = state->cachedPosX;
    setup->head.posY = state->cachedPosY;
    setup->head.posZ = state->cachedPosZ;
    setup->yawHi = (obj->anim.rotX + yawOffset) >> 8;
    setup->pitch = pitch;
    setup->roll = 0;
    setup->head.color[0] = 1;
    setup->head.color[1] = 1;
    projectile = loadObjectAtObject(obj, &setup->head);
    if (projectile != NULL) {
        projectile->anim.rootMotionScale = 5.0f;
        arwprojectile_setLifetime(projectile, 0x6e);
        arwprojectile_placeForward(projectile, 7.0f);
    }
}

void andross_spawnAimedRing(GameObject* obj, AndrossState* state, int unused) {
    f32 dx, dz, horizontalDistance;
    int yaw;
    GfProjectileSetup* setup;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject == 0) {
        return;
    }
    dx = state->cachedPosX - state->arwingObj->anim.localPosX;
    dz = state->cachedPosZ - state->arwingObj->anim.localPosZ;
    horizontalDistance = sqrtf(dx * dx + dz * dz);
    yaw = (u16)getAngle(dx, dz);
    gAndrossProjectilePitch =
        (u16)getAngle(state->cachedPosY - state->arwingObj->anim.localPosY, horizontalDistance) >> 8;
    setup = (GfProjectileSetup*)Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_RING);
    setup->head.posX = state->cachedPosX;
    setup->head.posY = state->cachedPosY;
    setup->head.posZ = state->cachedPosZ;
    setup->yawHi = (obj->anim.rotX + yaw) >> 8;
    setup->pitch = gAndrossProjectilePitch;
    setup->roll = 0;
    setup->head.color[0] = 1;
    setup->head.color[1] = 1;
    obj = loadObjectAtObject(obj, &setup->head);
    if (obj != NULL) {
        arwprojectile_setLifetime(obj, gAndrossAimedProjectileLifetime);
        arwprojectile_placeForward(obj, (f32)gAndrossAimedProjectileSpeed);
    }
}

void andross_processPartHits(GameObject* obj, AndrossState* state) {
    u32 hitVolume;
    int hitType;
    GameObject* hitObj;
    int hasHit;
    u8 primaryTextureState;
    u8 textureIndex;
    s8 textureState;
    ObjTextureRuntimeSlot* texture;

    hasHit = ObjHits_GetPriorityHit(obj, &hitObj, &hitType, &hitVolume);
    {
        u8 partIndex;
        for (partIndex = 0; partIndex < ARRAY_COUNT(state->partHitTimer); partIndex++) {
            int remainingTimer = state->partHitTimer[partIndex] - framesThisStep;
            if (remainingTimer < 0) {
                remainingTimer = 0;
            }
            state->partHitTimer[partIndex] = remainingTimer;
        }
    }
    if (hasHit) {
        switch (hitType) {
        case 0:
        case 1:
        case 2: {
            if (state->partHealth[hitType] != 0 && state->partHitTimer[hitType] == 0) {
                state->partHealth[hitType] -= 1;
                state->partHitTimer[hitType] = 6;
                if (state->partHealth[hitType] != 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff);
                } else {
                    Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11);
                }
                switch (hitType) {
                case 0:
                    state->rotXSpeed = -0xfa;
                    break;
                case 1:
                    state->rotXSpeed = 0xfa;
                    break;
                case 2:
                    state->rotYSpeed = -0xc8;
                    break;
                }
            }
            break;
        }
        case 3: {
            if (hitObj->anim.romDefNo == ARW_ARWING_BOMB_OBJ && state->partHitTimer[hitType] == 0 &&
                state->partHealth[hitType] != 0 && state->actionState == 0xc) {
                Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                state->partHealth[hitType] -= 1;
                state->partHitTimer[hitType] = 0xc8;
            }
            break;
        }
        }
    }
    {
        u8 partIndex;
        for (partIndex = 0; partIndex < ARRAY_COUNT(state->partTextureState); partIndex++) {
            int index = partIndex;
            if (state->partHealth[index] != 0) {
                if (state->partHitTimer[index] != 0) {
                    state->partTextureState[index] = 1;
                } else {
                    state->partTextureState[index] = 0;
                }
            } else {
                state->partTextureState[index] = 2;
            }
            textureState = state->partTextureState[index];
            primaryTextureState = textureState;
            textureIndex = gAndrossPartTextureIndices[index];
            if ((u32)textureIndex < 2 && (u8)textureState == 1) {
                primaryTextureState = 0;
            }
            texture = objFindTexture(obj, textureIndex * 2, 0);
            texture->textureId = primaryTextureState << 8;
            if ((u32)textureIndex == 2 && (u8)textureState == 1) {
                textureState = 0;
            }
            texture = objFindTexture(obj, textureIndex * 2 + 1, 0);
            texture->textureId = (u8)textureState << 8;
        }
    }
}

void andross_setPartSignal(GameObject* obj, u8 signal) {
    AndrossState* state;

    if (obj == NULL) {
        return;
    }
    state = obj->extra;
    state->signalFlags |= signal;
}

#define ANDROSS_CLAMP(value, low, high) ((value) < (low) ? (low) : ((value) > (high) ? (high) : (value)))

int andross_trackArwingVelocity(AndrossState* state, f32 clampRange, f32 scale, f32 zVelocity) {
    f32 clampedSpeed;
    f32 dx, dy, dz, distance;
    int heading;
    int targetReached;
    Vec3f vel;

    targetReached = 0;
    dx = state->cachedPosX - state->arwingObj->anim.localPosX;
    dy = state->cachedPosY - state->arwingObj->anim.localPosY;
    dz = state->cachedPosZ - state->arwingObj->anim.localPosZ;
    distance = sqrtf(dx * dx + dy * dy);
    heading = (s16)getAngle(dx, dy);
    if ((s16)getAngle(distance, dz) > 12000 && dz > gAndrossForwardDistanceThreshold) {
        targetReached = 1;
    }

    clampedSpeed = ANDROSS_CLAMP(distance / scale, -clampRange, clampRange);
    state->velX = clampedSpeed * mathSinf(3.1415927f * heading / 32768.0f);
    state->velY = clampedSpeed * mathCosf(3.1415927f * heading / 32768.0f);

    arwarwing_getVelocity(&vel, state->arwingObj);
    state->velX -= vel.x * gAndrossArwingVelDamp;
    state->velY -= vel.y * gAndrossArwingVelDamp;
    state->velZ = zVelocity;

    return targetReached;
}

#define ANDROSS_DISTORT_PHASE_WRAP 6.28318f

static inline f32 andross_getSwayPosition(f32 sway, f32 phase, f32 base) {
    return sway * phase + base;
}

static void andross_updateDistortion(GameObject* obj, AndrossState* state, f32 progress) {
    f32 radius;
    obj->anim.alpha = state->fadeAlpha * 255.0f;
    if (progress < 0.5f) {
        radius = 1000.0f - 2.0f * (800.0f * progress);
        if (progress < 0.01f) {
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
        }
    } else {
        radius = 200.0f;
    }

    gAndrossDistortPhase += gAndrossDistortPhaseStep;
    if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
        gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
    }

    turnOnDistortionFilter(&state->cachedPosX, radius, &gAndrossDistortFilterParam, gAndrossDistortPhase);
    state->fadeAlpha = 0.0f;
}

static inline void andross_setModelAlpha(ModelFileHeader* model, f32 fade) {
    int i;
    for (i = 0; i < model->renderOpCount; i++) {
        Shader* renderOp = ObjModel_GetRenderOp(model, i);
        renderOp->alphaOverride = fade * 255.0f;
    }
}

static inline void andross_setMove(GameObject* obj, int move) {
    AndrossState* state = obj->extra;

    ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
    state->animSpeed = gAndrossMoveAnimSpeeds[move];
}

static inline void andross_setMoveSpeed(GameObject* obj, int move, f32 speed) {
    AndrossState* state = obj->extra;

    ObjAnim_SetCurrentMove(obj, move, 0.0f, 0);
    state->animSpeed = speed;
}

#define ANDROSS_HANDLE_BRAIN_HIT(obj, bossState)                                                                       \
    do {                                                                                                               \
        u8 received;                                                                                                   \
        AndrossState* signalSource;                                                                                    \
        received = 0;                                                                                                  \
        signalSource = (obj)->extra;                                                                                   \
        if ((signalSource->signalFlags & ANDROSS_SIGNAL_BRAIN_HIT) != 0) {                                             \
            signalSource->signalFlags &= ~ANDROSS_SIGNAL_BRAIN_HIT;                                                    \
            received = 1;                                                                                              \
        }                                                                                                              \
        if (received) {                                                                                                \
            (bossState)->actionPending = 1;                                                                            \
        }                                                                                                              \
    } while (0)

static inline void andross_updateHitCue(AndrossState* state) {
    u8 cueIndex;

    for (cueIndex = 0; cueIndex < 6; cueIndex++) {
        if (mainGetBit(cueIndex + GAMEBIT_AndrossRelated0108) != 0) {
            state->timer = 0x3c;
            return;
        }
    }
    state->timer -= framesThisStep;
    if (state->timer <= 0) {
        mainSetBits(randomGetRange(0, 5) + GAMEBIT_AndrossRelated0108, 1);
        state->timer = 0x3c;
    }
}

static inline void andross_updateAimTarget(GameObject* boss, int objectDefNo) {
    GameObject* target;
    int sequenceId;
    f32 searchDistance = 10000.0f;

    target = ObjList_FindNearestObjectByDefNo(boss, objectDefNo, &searchDistance);
    if (target == NULL) {
        return;
    }
    if (target->pendingParentObj != NULL) {
        target = target->pendingParentObj;
    }
    if (target->anim.classId != 0x10 || (sequenceId = animatedObjGetSeqId(target->extra), sequenceId != 0x598)) {
        target->anim.placement->posX = boss->anim.localPosX;
        target->anim.placement->posY = boss->anim.localPosY;
        target->anim.placement->posZ = boss->anim.localPosZ;
    }
}

static inline void andross_updateSway(AndrossState* state, f32 maxOffsetX, f32 maxOffsetY, f32 swayX, f32 swayY) {
    f32 offsetX;
    f32 offsetY;
    f32 phase;

    gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
    gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
    offsetX = state->arwingObj->anim.localPosX - state->homePosX;
    offsetY = state->arwingObj->anim.localPosY - state->homePosY;
    offsetX = ANDROSS_CLAMP(offsetX, -maxOffsetX, maxOffsetX);
    offsetY = ANDROSS_CLAMP(offsetY, -maxOffsetY, maxOffsetY);
    phase = mathSinf(3.1415927f * gAndrossSwayPhaseX / 32768.0f);
    state->targetPosX = andross_getSwayPosition(swayX, phase, state->homePosX + offsetX);
    phase = mathSinf(3.1415927f * gAndrossSwayPhaseY / 32768.0f);
    state->targetPosY = andross_getSwayPosition(swayY, phase, state->homePosY + offsetY);
    state->targetPosZ = state->homePosZ;
}

static inline void andross_centerOnHomePosition(AndrossState* state) {
    f32 offsetX;
    f32 offsetY;
    f32 phase;

    gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
    gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
    {
        f32 deltaX = state->arwingObj->anim.localPosX - state->homePosX;
        f32 deltaY = state->arwingObj->anim.localPosY - state->homePosY;
        offsetX = ANDROSS_CLAMP(deltaX, 0.0f, 0.0f);
        offsetY = ANDROSS_CLAMP(deltaY, 0.0f, 0.0f);
    }
    phase = mathSinf(3.1415927f * gAndrossSwayPhaseX / 32768.0f);
    state->targetPosX = andross_getSwayPosition(0.0f, phase, state->homePosX + offsetX);
    phase = mathSinf(3.1415927f * gAndrossSwayPhaseY / 32768.0f);
    state->targetPosY = andross_getSwayPosition(0.0f, phase, state->homePosY + offsetY);
    state->targetPosZ = state->homePosZ;
}

static inline void andross_moveArwingTowardTarget(AndrossState* state, f32 velocityScale) {
    Vec3f velocity;
    Vec3f velocityArg;
    f32 delta;

    delta = state->cachedPosX - state->arwingObj->anim.localPosX;
    velocity.x = delta * velocityScale;
    delta = state->cachedPosY - state->arwingObj->anim.localPosY;
    velocity.y = delta * velocityScale;
    delta = state->cachedPosZ - state->arwingObj->anim.localPosZ;
    velocity.z = delta * velocityScale;
    velocityArg = velocity;
    arwarwing_setVelocity(state->arwingObj, &velocityArg);
}

#define ANDROSS_SET_ARWING_THRUST(state, distance, thrustScale, thrust, thrustArg)                                     \
    do {                                                                                                               \
        (thrust).x = 0.0f;                                                                                             \
        (thrust).y = 0.0f;                                                                                             \
        (thrust).z = (distance) * (thrustScale);                                                                       \
        (thrustArg) = (thrust);                                                                                        \
        arwarwing_setVelocity((state)->arwingObj, &(thrustArg));                                                       \
    } while (0)

static inline int andross_areAllPartsDestroyed(AndrossState* state) {
    u32 hitsRemaining = state->partHealth[0];

    hitsRemaining += state->partHealth[1];
    hitsRemaining += state->partHealth[2];
    return (hitsRemaining & 0xffff) == 0;
}

#define ANDROSS_BOTH_HANDS_READY(rightState, currentHandState)                                                         \
    (((currentHandState) != ANDROSSHAND_STATE_EXIT) && ((currentHandState) != ANDROSSHAND_STATE_ENTER) &&              \
     (((currentHandState) = (rightState)->handState) != ANDROSSHAND_STATE_EXIT) &&                                     \
     ((currentHandState) != ANDROSSHAND_STATE_ENTER))

#define ANDROSS_SPAWN_DELTA(state, index, indexedState)                                                                \
    ((indexedState = (AndrossState*)((u8*)(state) + (index) * sizeof(Vec3f)))->spawnDelta[0])

void andross_updateBombCollector(GameObject* obj, AndrossState* state) {
    if (state->bombCollector != NULL) {
        state->bombCollector->anim.localPosZ -= 3.0f;
        state->bombCollectorLifetime -= framesThisStep;
        if (state->bombCollectorLifetime < 0) {
            arwbombcoll_setLifetime(state->bombCollector, 5);
            state->bombCollectorLifetime = 0;
            state->bombCollector = NULL;
        }
        return;
    }

    if (state->spawnCooldown >= 0.0f) {
        state->spawnCooldown -= timeDelta;
        if (state->spawnCooldown < 0.0f) {
            andross_spawnBombCollector(obj, state);
        }
    } else if (mainGetBit(GAMEBIT_AndrossRelated0012) != 0) {
        state->spawnCooldown = randomGetRange(1, 0x14);
        mainSetBits(GAMEBIT_AndrossRelated0012, 0);
    }
}

int andross_SeqFn(GameObject* obj) {
    AndrossState* state = obj->extra;

    state->fadeAlpha = 0.0f;
    andross_setModelAlpha(Obj_GetActiveModel(obj)->file, state->fadeAlpha);
    return 0;
}

int andross_getExtraSize(void) {
    return sizeof(AndrossState);
}

int andross_getObjectTypeId(void) {
    return 0;
}

void andross_free(GameObject* obj) {
    newshadows_freeDistortionTexture();
    Rcp_DisableDistortionFilter();
}

void andross_render(GameObject* obj, int gdl, int mtxs, int vtxs, int pols) {
    objRenderModelAndHitVolumes(obj, gdl, mtxs, vtxs, pols, 1.0f);
}

void andross_hitDetect(void) {
}

int gAndrossSpawnObjectIds[] = {
    0x0004AA57,
    0x0004AA66,
    0x0004AA96,
    0x0004AA97,
};

f32 gAndrossMoveAnimSpeeds[23] = {
    0.01f, 0.01f, 0.005f, 0.005f, 0.08f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f,
    0.03f, 0.03f, 0.02f,  0.02f,  0.01f, 0.02f,  0.02f,  0.02f,  0.02f,  0.007f, 0.003f,
};

ObjectDescriptor gAndrossObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)andross_init,
    (ObjectDescriptorCallback)andross_update,
    (ObjectDescriptorCallback)andross_hitDetect,
    (ObjectDescriptorCallback)andross_render,
    (ObjectDescriptorCallback)andross_free,
    (ObjectDescriptorCallback)andross_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)andross_getExtraSize,
};

void andross_update(GameObject* boss) {
    AndrossState* state = boss->extra;
    u8 actionChanged = 0;
    u8 phaseChanged = 0;
    u8 spawnIndex;
    u8 pathIndex = 0;
    int currentState;
    int rotationDelta;
    s16 rotationError;
    s16 ringSpawnDelays[2];
    Vec3f thrustB;
    Vec3f thrustA;
    Vec3f thrustBArg;
    Vec3f thrustAArg;
    if (state->startupDelay != 0) {
        state->startupDelay -= 1;
        return;
    }
    if (state->leftHandObj == NULL) {
        state->leftHandObj = ObjList_FindObjectById(0x47b78);
    }
    if (state->rightHandObj == NULL) {
        state->rightHandObj = ObjList_FindObjectById(0x47b6a);
    }
    if (state->brainObj == NULL) {
        state->brainObj = ObjList_FindObjectById(0x47dd9);
    }
    if (state->arwingObj == NULL) {
        state->arwingObj = getArwing();
        if (state->arwingObj != NULL) {
            state->savedPosZ = state->arwingObj->anim.localPosZ;
            arwarwing_setFlightHalfWidth(state->arwingObj, gAndrossFlightHalfWidth);
        } else {
            return;
        }
    }
    for (spawnIndex = 0; spawnIndex < ARRAY_COUNT(gAndrossSpawnObjectIds); spawnIndex++) {
        GameObject** spawnSlot;
        AndrossState* indexedState;
        u32 spawnArrayIndex = spawnIndex;

        spawnSlot = &state->spawnObj[spawnArrayIndex];

        if (*spawnSlot == NULL) {
            *spawnSlot = ObjList_FindObjectById(gAndrossSpawnObjectIds[spawnArrayIndex]);
            if (*spawnSlot != NULL) {
                ANDROSS_SPAWN_DELTA(state, spawnArrayIndex, indexedState).x =
                    (*spawnSlot)->anim.localPosX - boss->anim.localPosX;
                indexedState->spawnDelta[0].y = (*spawnSlot)->anim.localPosY - boss->anim.localPosY;
                indexedState->spawnDelta[0].z = (*spawnSlot)->anim.localPosZ - boss->anim.localPosZ;
            }
        } else {
            (*spawnSlot)->anim.localPosX =
                boss->anim.localPosX + ANDROSS_SPAWN_DELTA(state, spawnArrayIndex, indexedState).x;
            (*spawnSlot)->anim.localPosY = boss->anim.localPosY + indexedState->spawnDelta[0].y;
            (*spawnSlot)->anim.localPosZ = boss->anim.localPosZ + indexedState->spawnDelta[0].z;
        }
    }
    currentState = state->fightPhase;
    if (currentState != state->prevFightPhase) {
        phaseChanged = 1;
    }
    state->prevFightPhase = currentState;
    state->velX = 0.0f;
    state->velY = 0.0f;
    state->velZ = 0.0f;
    if (-0x4000 < state->targetRotX && boss->anim.rotX < 0x4000) {
        pathIndex = 1;
    }
    ObjPath_GetPointWorldPosition(boss, pathIndex, &state->cachedPosX, &state->cachedPosY, &state->cachedPosZ, 0);
    if (pathIndex == 1) {
        state->cachedPosY += 30.0f;
        state->cachedPosZ += 30.0f;
    }
    switch (state->fightPhase) {
    case 1:
        if (phaseChanged) {
            if (state->handsInitialized != 0) {
                state->handsInitialized = 0;
            } else {
                androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_EXIT, 1);
                androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_EXIT, 1);
            }
            state->partHealth[0] = 10;
            state->partHealth[1] = 10;
            state->partHealth[2] = 10;
        }
        if (state->actionPending != 0) {
            switch (state->actionState) {
            default:
            case 3:
            case 0x17:
                state->actionState = 0;
                break;
            case 0:
                state->actionState = 1;
                break;
            case 0x16:
                if (state->arwingFlightActive != 0) {
                    state->actionState = 0x17;
                } else {
                    state->actionState = 0;
                }
                break;
            }
            state->actionPending = 0;
        }
        break;
    case 2:
        if (phaseChanged) {
            state->signalFlags &= ~ANDROSS_SIGNAL_BOTH_HANDS_DEAD;
            if (state->actionState == 0x16) {
                androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_ENTER, 1);
                androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_ENTER, 1);
            }
        }
        if (state->actionPending != 0) {
            switch (state->actionState) {
            default:
            case 5:
            case 0x16:
                state->actionState = 6;
                break;
            case 6:
                state->actionState = 7;
                break;
            case 7:
                state->actionState = 10;
                break;
            case 10:
                state->actionState = 0x12;
                break;
            case 0x14:
                state->actionState = 0xb;
                break;
            case 0x11:
                state->actionState = 0x16;
                state->targetRotX = 0x8000;
                state->fightPhase--;
            }
            state->actionPending = 0;
        }
        break;
    case 3:
        if (phaseChanged) {
            state->partHealth[0] = 0xf;
            state->partHealth[1] = 0xf;
            state->partHealth[2] = 0xf;
            state->actionState = 0;
            state->attackCycleCount = 0;
        }
        if (state->actionPending != 0) {
            switch (state->actionState) {
            default:
            case 0:
                state->actionState = 1;
                break;
            case 3:
                state->actionState = 4;
                break;
            case 4:
                state->attackCycleCount++;
                if (state->attackCycleCount > 3) {
                    state->fightPhase--;
                    state->actionState = 0x16;
                    state->targetRotX = 0;
                } else {
                    state->actionState = 0;
                }
                break;
            }
            state->actionPending = 0;
        }
        break;
    case 4:
        if (state->actionPending != 0) {
            switch (state->actionState) {
            default:
            case 5:
            case 0x16:
                state->actionState = 6;
                break;
            case 6:
                state->actionState = 7;
                break;
            case 7:
                state->actionState = 10;
                break;
            case 10:
                state->actionState = 0x12;
                break;
            case 0x14:
                state->actionState = 0xb;
                break;
            case 0xf:
                state->actionState = 9;
                break;
            case 9:
                state->actionState = 8;
                break;
            case 0x11:
                state->actionState = 0x18;
            }
            state->actionPending = 0;
        }
        break;
    case 5:
        if (phaseChanged) {
            state->actionState = 0xd;
            state->actionToggle = 0;
        }
        if (state->actionPending != 0) {
            switch (state->actionState) {
            default:
            case 0x1b:
                state->partHealth[3] = 3;
            case 0xf:
                state->actionState = 0x12;
                state->actionToggle = 0;
                break;
            case 0x14:
                switch (state->actionToggle) {
                case 0:
                    state->actionState = 0x15;
                    break;
                case 1:
                    state->actionState = 0xb;
                    break;
                }
                state->actionToggle ^= 1;
                break;
            case 0x15:
                state->actionState = 0x12;
                break;
            case 0x11:
                state->actionState = 0x18;
                break;
            case 0x19:
                state->fightPhase = 6;
                break;
            case 0x1a:
                state->actionState = 0x1b;
            }
            state->actionPending = 0;
        }
        break;
    case 6:
        if (phaseChanged) {
            state->actionState = 0x1c;
            state->actionToggle = 0;
        }
        break;
    }
    currentState = state->actionState;
    if (currentState != state->prevActionState) {
        actionChanged++;
    }
    state->prevActionState = currentState;
    switch (state->actionState) {
    case 0:
        if (actionChanged) {
            andross_setMove(boss, 0);
            if (state->fightPhase == 1) {
                state->durationTimer = 180.0f;
            } else {
                state->durationTimer = 100.0f;
            }
        }
        andross_updateSway(state, 300.0f, 50.0f, 200.0f, 20.0f);
        state->durationTimer -= timeDelta;
        if (state->durationTimer < 0.0f) {
            state->actionPending = 1;
        }
        if (andross_areAllPartsDestroyed(state)) {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(GAMEBIT_AndrossRelated000D, 0);
        }
        break;
    case 1:
        if (actionChanged) {
            andross_setMove(boss, 0xc);
        }
        andross_updateSway(state, 300.0f, 50.0f, 200.0f, 20.0f);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionState = 2;
            state->actionPending = 0;
        }
        if (andross_areAllPartsDestroyed(state)) {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(GAMEBIT_AndrossRelated000D, 0);
        }
        break;
    case 2:
        if (actionChanged) {
            andross_setMove(boss, 0xe);
            state->durationTimer = 300.0f;
            state->actionTimer = -1;
        }
        andross_updateSway(state, 300.0f, 50.0f, 200.0f, 20.0f);
        Sfx_KeepAliveLoopedObjectSound(boss, SFXTRIG_and_roar1);
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0) {
            andross_spawnAimedRing(boss, state, 0);
            state->actionTimer = gAndrossRingSpawnInterval;
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < 0.0f) {
            state->actionState = 3;
            state->actionPending = 0;
        }
        if (andross_areAllPartsDestroyed(state)) {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(GAMEBIT_AndrossRelated000D, 0);
        }
        break;
    case 3:
        if (actionChanged) {
            andross_setMove(boss, 0xd);
        }
        andross_updateSway(state, 300.0f, 200.0f, 200.0f, 20.0f);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 4:
        if (actionChanged) {
            andross_setMove(boss, 0);
            mainSetBits(GAMEBIT_AndrossRelated000D, 1);
            state->durationTimer = 400.0f;
        }
        andross_updateSway(state, 300.0f, 200.0f, 200.0f, 20.0f);
        state->durationTimer -= timeDelta;
        if (state->durationTimer < 0.0f) {
            state->actionPending = 1;
            mainSetBits(GAMEBIT_AndrossRelated000D, 0);
        }
        if (andross_areAllPartsDestroyed(state)) {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(GAMEBIT_AndrossRelated000D, 0);
        }
        break;
    case 0x15:
        if (actionChanged) {
            andross_setMove(boss, 0);
            mainSetBits(GAMEBIT_AndrossRelated000D, 1);
            state->durationTimer = 400.0f;
        }
        andross_updateHitCue(state);
        andross_updateSway(state, 300.0f, 200.0f, 200.0f, 20.0f);
        state->durationTimer -= timeDelta;
        if (state->durationTimer < 0.0f) {
            state->actionPending = 1;
            mainSetBits(GAMEBIT_AndrossRelated000D, 0);
        }
        break;
    case 6:
        if (actionChanged) {
            andross_setMove(boss, 0);
            androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_SWIPE, 0);
        }
        andross_updateSway(state, 150.0f, 50.0f, 100.0f, 20.0f);
        ANDROSS_HANDLE_BRAIN_HIT(boss, state);
        break;
    case 7:
        if (actionChanged) {
            androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_SWIPE, 0);
        }
        andross_updateSway(state, 150.0f, 50.0f, 100.0f, 20.0f);
        ANDROSS_HANDLE_BRAIN_HIT(boss, state);
        break;
    case 9:
        if (actionChanged) {
            androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_SHOOT, 0);
        }
        andross_updateSway(state, 300.0f, 200.0f, 200.0f, 20.0f);
        ANDROSS_HANDLE_BRAIN_HIT(boss, state);
        break;
    case 8:
        if (actionChanged) {
            androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_SHOOT, 0);
        }
        andross_updateSway(state, 300.0f, 200.0f, 200.0f, 20.0f);
        ANDROSS_HANDLE_BRAIN_HIT(boss, state);
        break;
    case 10:
        if ((state->signalFlags & ANDROSS_SIGNAL_BOTH_HANDS_DEAD) == ANDROSS_SIGNAL_BOTH_HANDS_DEAD) {
            state->fightPhase++;
            if (state->fightPhase < 5) {
                Sfx_PlayFromObject(boss, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
                state->actionState = 0x16;
                state->targetRotX = 0x8000;
            }
        } else {
            andross_updateSway(state, 150.0f, 50.0f, 100.0f, 20.0f);
            if (actionChanged) {
                androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_GRAB, 0);
                androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_GRAB, 0);
            }
            ANDROSS_HANDLE_BRAIN_HIT(boss, state);
        }
        break;
    case 0xb:
    case 0xd: {
        f32 progress;
        f32 distortionRadius;

        if (actionChanged) {
            andross_setMove(boss, 1);
            if (state->fightPhase < 5) {
                androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_IDLE, 0);
                androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_IDLE, 0);
            } else {
                androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_DEAD, 1);
                androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_DEAD, 1);
                state->signalFlags |= ANDROSS_SIGNAL_BOTH_HANDS_DEAD;
            }
        }
        if ((state->fightPhase == 5) && (state->actionState == 0xb)) {
            andross_updateHitCue(state);
        }
        andross_updateSway(state, 20.0f, 50.0f, 20.0f, 10.0f);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            switch (state->actionState) {
            default:
            case 0xb:
                state->actionState = 0xc;
                break;
            case 0xd:
                state->actionState = 0xe;
                break;
            }
        }
        progress = 0.5f * boss->anim.currentMoveProgress;
        if (progress < 0.5f) {
            distortionRadius = 1000.0f - 2.0f * (800.0f * progress);
            if (progress < 0.01f) {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        } else {
            distortionRadius = 200.0f;
        }
        gAndrossDistortPhase += gAndrossDistortPhaseStep;
        if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
            gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
        }
        turnOnDistortionFilter(&state->cachedPosX, distortionRadius, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        break;
    }
    case 0xe: {
        f32 progress;
        f32 distortionRadius;

        progress = 0.5f * boss->anim.currentMoveProgress + 0.5f;
        if (progress < 0.5f) {
            distortionRadius = 1000.0f - 2.0f * (800.0f * progress);
            if (progress < 0.01f) {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        } else {
            distortionRadius = 200.0f;
        }
        gAndrossDistortPhase += gAndrossDistortPhaseStep;
        if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
            gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
        }
        turnOnDistortionFilter(&state->cachedPosX, distortionRadius, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (actionChanged) {
            andross_setMove(boss, 2);
            state->partHealth[3] = 0;
            mainSetBits(GAMEBIT_AndrossRelated0010, 0);
            state->actionTimer = gAndrossMissileAttackDuration;
            state->durationTimer = 0.0f;
        }
        andross_updateSway(state, 300.0f, 150.0f, 20.0f, 10.0f);
        andross_trackArwingVelocity(state, gAndrossMissileClampRange, gAndrossMissileVelocityScale,
                                    gAndrossMissileForwardVelocity);
        Sfx_KeepAliveLoopedObjectSound(boss, SFXTRIG_and_missileloop);
        if ((state->actionTimer != 0) && (state->actionTimer -= framesThisStep, state->actionTimer <= 0)) {
            state->actionTimer = 0;
            mainSetBits(GAMEBIT_AndrossRelated000F, 1);
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < 0.0f) {
            andross_spawnSuckAsteroid(boss, state);
            state->durationTimer += gAndrossMissileSpawnInterval;
        }
        andross_steerAsteroids(boss, state);
        if (mainGetBit(GAMEBIT_AndrossRelated0010) != 0) {
            mainSetBits(GAMEBIT_AndrossRelated0010, 0);
            state->actionState = 0x1a;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
                gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam, gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    }
    case 0xc: {
        f32 progress;
        f32 distortionRadius;

        progress = 0.5f * boss->anim.currentMoveProgress + 0.5f;
        if (progress < 0.5f) {
            distortionRadius = 1000.0f - 2.0f * (800.0f * progress);
            if (progress < 0.01f) {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        } else {
            distortionRadius = 200.0f;
        }
        gAndrossDistortPhase += gAndrossDistortPhaseStep;
        if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
            gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
        }
        turnOnDistortionFilter(&state->cachedPosX, distortionRadius, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (actionChanged) {
            andross_setMove(boss, 2);
            if (state->fightPhase < 5) {
                state->partHealth[3] = 1;
            }
            state->actionTimer = gAndrossCentralAttackDuration;
            state->durationTimer = 0.0f;
        }
        Sfx_KeepAliveLoopedObjectSound(boss, SFXTRIG_and_missileloop);
        if (state->fightPhase == 5) {
            andross_updateHitCue(state);
        }
        andross_updateSway(state, 50.0f, 20.0f, 20.0f, 10.0f);
        {
            s8 targetReached =
                andross_trackArwingVelocity(state, gAndrossCentralMissileClampRange,
                                            gAndrossCentralMissileVelocityScale, gAndrossCentralMissileForwardVelocity);

            if (targetReached != 0) {
                state->actionState = 0xf;
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
                gAndrossDistortPhase += gAndrossDistortPhaseStep;
                if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
                    gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
                }
                turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam, gAndrossDistortPhase);
                Rcp_DisableDistortionFilter();
            }
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < 0.0f) {
            andross_spawnSuckAsteroid(boss, state);
            state->durationTimer += gAndrossCentralMissileSpawnInterval;
        }
        andross_steerAsteroids(boss, state);
        if (state->partHitTimer[3] != 0) {
            if (state->fightPhase == 5) {
                state->actionState = 0x19;
            } else {
                state->actionState = 0xf;
            }
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
                gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam, gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        } else {
            if (state->arwingObj->anim.localPosZ > state->cachedPosZ) {
                state->actionState = 0x10;
                state->arwingFlightActive = 1;
                state->arwingObj->anim.localPosZ = state->cachedPosZ;
                state->velZ = 0.0f;
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
                gAndrossDistortPhase += gAndrossDistortPhaseStep;
                if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
                    gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
                }
                turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam, gAndrossDistortPhase);
                Rcp_DisableDistortionFilter();
                break;
            }
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0) {
            state->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > ANDROSS_DISTORT_PHASE_WRAP) {
                gAndrossDistortPhase -= ANDROSS_DISTORT_PHASE_WRAP;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam, gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    }
    case 0xf:
        if (actionChanged) {
            andross_setMove(boss, 0x10);
        }
        andross_updateSway(state, 200.0f, 50.0f, 100.0f, 20.0f);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 0x10:
        if (actionChanged) {
            andross_setMoveSpeed(boss, 0x10, 0.04f);
        }
        andross_centerOnHomePosition(state);
        andross_moveArwingTowardTarget(state, gAndrossArwingApproachVelocityScale);
        state->camOffsetAccum = (-300.0f > -(5.0f * timeDelta - state->camOffsetAccum))
                                    ? -300.0f
                                    : -(5.0f * timeDelta - state->camOffsetAccum);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->arwingObj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            state->actionState = 0x11;
        }
        break;
    case 0x11:
        if (actionChanged) {
            Sfx_PlayFromObject(boss, SFXTRIG_and_falcoflyby);
            andross_setMove(boss, 0x15);
            arwarwing_addHealth(state->arwingObj, -4);
        }
        state->camOffsetAccum = (-300.0f > -(5.0f * timeDelta - state->camOffsetAccum))
                                    ? -300.0f
                                    : -(5.0f * timeDelta - state->camOffsetAccum);
        andross_centerOnHomePosition(state);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 0x12:
        if (actionChanged) {
            andross_setMove(boss, 0x12);
            androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_IDLE, 0);
            androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_IDLE, 0);
            if ((state->fightPhase == 5) && (state->actionToggle != 0)) {
                mainSetBits(GAMEBIT_AndrossRelated000E, 1);
            }
        }
        state->fadeAlpha -= 0.05f;
        state->fadeAlpha = (0.0f > state->fadeAlpha) ? 0.0f : state->fadeAlpha;
        andross_setModelAlpha(Obj_GetActiveModel(boss)->file, state->fadeAlpha);
        if ((state->fightPhase == 5) && (state->actionToggle == 0)) {
            andross_updateHitCue(state);
        }
        andross_updateSway(state, 300.0f, 50.0f, 100.0f, 20.0f);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionState = 0x13;
        }
        break;
    case 0x13: {
        s16 previousDuration;
        u8 ringSpawnIndex;
        AndrossChildSetup* ringSetup;
        s16 spawnDelay;
        u8 canSetupObject;

        if (actionChanged) {
            andross_setMove(boss, 0x13);
            if (state->fightPhase == 5) {
                state->durationTimer = 500.0f;
            } else {
                state->durationTimer = 300.0f;
            }
            state->actionTimer = -1;
        }
        Sfx_KeepAliveLoopedObjectSound(boss, SFXTRIG_and_spitout);
        if ((state->fightPhase == 5) && (state->actionToggle == 0)) {
            andross_updateHitCue(state);
        }
        andross_updateSway(state, 500.0f, 70.0f, 100.0f, 20.0f);
        state->actionTimer -= framesThisStep;
        previousDuration = state->durationTimer;
        state->durationTimer -= framesThisStep;
        if (state->fightPhase == 5) {
            ringSpawnDelays[0] = 300;
            ringSpawnDelays[1] = 600;
        } else {
            ringSpawnDelays[0] = 0x122;
            ringSpawnDelays[1] = 0x28;
        }
        for (ringSpawnIndex = 0; ringSpawnIndex < 2; ringSpawnIndex++) {
            if (state->silverRing == NULL && state->actionTimer <= (spawnDelay = ringSpawnDelays[ringSpawnIndex]) &&
                previousDuration > spawnDelay) {
                canSetupObject = Obj_CanSetupObject();
                if (canSetupObject > 0) {
                    ringSetup = (AndrossChildSetup*)Obj_AllocObjectSetup(sizeof(AndrossChildSetup),
                                                                         ANDROSS_CHILD_OBJ_SILVER_RING);
                    ringSetup->base.posX = state->cachedPosX;
                    ringSetup->base.posY = state->cachedPosY;
                    ringSetup->base.posZ = state->cachedPosZ;
                    ringSetup->base.color[0] = 1;
                    ringSetup->base.color[1] = 1;
                    ringSetup->flags = -1;
                    state->silverRing = loadObjectAtObject(boss, &ringSetup->base);
                    if (state->silverRing != NULL) {
                        state->silverRing->anim.alpha = 0xff;
                        state->silverRing->anim.renderAlpha = 0xff;
                        state->silverRingLifetime = gAndrossSpawnedObjectLifetime;
                    }
                }
            }
        }
        if (state->actionTimer < 0) {
            andross_spawnAsteroid(boss, state);
            state->actionTimer = gAndrossAsteroidSpawnInterval;
        }
        if (state->durationTimer < 0.0f) {
            state->actionState = 0x14;
        }
        break;
    }
    case 0x14:
        if (actionChanged) {
            andross_setMove(boss, 0x14);
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0)) {
            andross_updateHitCue(state);
        }
        andross_updateSway(state, 300.0f, 100.0f, 200.0f, 20.0f);
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 0x19:
    case 0x1a:
        if (actionChanged) {
            Sfx_PlayFromObject(boss, SFXTRIG__UNK_832);
            andross_setMove(boss, 4);
        }
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 0x1b:
        if (actionChanged) {
            mainSetBits(GAMEBIT_AndrossRelated0010, 0);
            state->actionTimer = 0x1e;
            arwarwing_resetFlightState(state->arwingObj);
            state->arwingObj->anim.localPosZ = state->savedPosZ;
            state->camOffsetAccum = 0.0f;
        }
        state->targetPosX = state->homePosX;
        state->targetPosY = state->homePosY;
        state->targetPosZ = state->homePosZ;
        if ((mainGetBit(GAMEBIT_AndrossRelated0010) != 0) && (state->actionTimer-- == 0)) {
            mainSetBits(GAMEBIT_AndrossRelated0010, 0);
            state->actionPending = 1;
        }
        break;
    case 0x1c:
        if (actionChanged) {
            androssbrain_setState(state->brainObj, ANDROSSBRAIN_VULNERABLE, 0);
            ObjHits_DisableObject(boss);
            state->actionTimer = 0x3c;
            state->durationTimer = 3.0f;
            state->targetPosX = state->homePosX;
            state->targetPosY = state->homePosY;
            state->targetPosZ = state->homePosZ;
            boss->anim.velocityX = 0.0f;
            boss->anim.velocityY = 0.0f;
            boss->anim.velocityZ = 0.0f;
            state->springStiffness = 0.01f;
            state->springDamping = 0.93f;
        }
        state->fadeAlpha += 0.05f;
        state->fadeAlpha = (0.8f < state->fadeAlpha) ? 0.8f : state->fadeAlpha;
        andross_updateHitCue(state);
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0) {
            state->durationTimer -= 1.0f;
            if (state->durationTimer < 0.0f) {
                state->actionToggle++;
                if (state->actionToggle > 3) {
                    state->fightPhase = 5;
                    state->prevFightPhase = 5;
                    state->actionToggle = 0;
                    state->actionState = 0x12;
                    androssbrain_setState(state->brainObj, ANDROSSBRAIN_SHIELDED, 0);
                    ObjHits_EnableObject(boss);
                } else {
                    state->actionState = 0x1d;
                }
            } else {
                state->actionTimer = randomGetRange(0x14, 0x1e);
                state->targetPosX = randomGetRange((int)-gAndrossSpawnRandX, gAndrossSpawnRandX) + state->homePosX;
                state->targetPosY = randomGetRange((int)-gAndrossSpawnRandY, gAndrossSpawnRandY) + state->homePosY;
                state->targetPosZ = randomGetRange((int)-gAndrossSpawnRandZ, gAndrossSpawnRandZ) + state->homePosZ;
            }
        }
        if ((state->signalFlags & ANDROSS_SIGNAL_BRAIN_DEFEATED) != 0) {
            arwingHudSetVisible(2);
            mainSetBits(GAMEBIT_AndrossRelated0001, 1);
            mainSetBits(GAMEBIT_AndrossRelated04B1, 1);
            state->actionState = 0x1e;
            unlockLevel(0, 0, 1);
            {
                int mapDirIndex = mapGetDirIdx(ANDROSS_MAP_SHRINE);
                mapUnload(mapDirIndex, 0x20000000);
            }
            Music_Trigger(MUSICTRIG_Mound_Music, 0);
        }
        andross_setModelAlpha(Obj_GetActiveModel(boss)->file, state->fadeAlpha);
        break;
    case 0x1d:
        if (actionChanged) {
            androssbrain_setState(state->brainObj, ANDROSSBRAIN_VULNERABLE, 0);
            ObjHits_DisableObject(boss);
            state->actionTimer = gAndrossBrainAttackDuration;
            state->targetPosX = state->arwingObj->anim.localPosX;
            state->targetPosY = state->arwingObj->anim.localPosY + gAndrossSpawnOffsetY;
            state->targetPosZ = state->arwingObj->anim.localPosZ + gAndrossSpawnOffsetZ;
            boss->anim.velocityX = 0.0f;
            boss->anim.velocityY = 0.0f;
            boss->anim.velocityZ = 0.0f;
            Sfx_PlayFromObject(boss, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0) {
            state->actionState = 0x1c;
        }
        break;
    case 0x16:
        if (actionChanged) {
            Sfx_PlayFromObject(boss, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            andross_setMove(boss, 0);
        }
        if (state->arwingFlightActive != 0) {
            andross_moveArwingTowardTarget(state, gAndrossArwingReturnVelocityScale);
            state->camOffsetAccum = (-600.0f > -(15.0f * timeDelta - state->camOffsetAccum))
                                        ? -600.0f
                                        : -(15.0f * timeDelta - state->camOffsetAccum);
        }
        rotationError = state->targetRotX - (u16)boss->anim.rotX;
        if (rotationError > 0x8000) {
            rotationError = rotationError - 0xffff;
        }
        if (rotationError < -0x8000) {
            rotationError += 0xffff;
        }
        rotationDelta = rotationError;
        if (rotationDelta < 0) {
            rotationDelta = -rotationDelta;
        }
        if (rotationDelta < 2000) {
            AndrossHandState* leftHandState = state->leftHandObj->extra;
            AndrossHandState* rightHandState = state->rightHandObj->extra;
            s8 handState;

            handState = leftHandState->handState;
            if (ANDROSS_BOTH_HANDS_READY(rightHandState, handState)) {
                state->actionPending = 1;
            }
        }
        break;
    case 5: {
        AndrossHandState* leftHandState;
        AndrossHandState* rightHandState;
        s8 handState;
        f32 moveProgress;

        leftHandState = state->leftHandObj->extra;
        rightHandState = state->rightHandObj->extra;

        if (actionChanged) {
            Sfx_PlayFromObject(boss, SFXTRIG_drak_roar1);
            andross_setMove(boss, 0x16);
            state->laughPlayed = 0;
            state->ringPlayed = 0;
        }
        moveProgress = boss->anim.currentMoveProgress;
        if (moveProgress < 0.6) {
            moveProgress = mathSinf(((3.1415927f * (float)(65536.0 * (0.25 * (moveProgress / 0.6)))) / 32768.0f));
            state->targetPosZ = (500.0f * moveProgress + state->homePosZ);
        } else {
            moveProgress =
                mathSinf(((3.1415927f * (float)(65536.0 * (0.75 * ((moveProgress - 0.6) / 0.4) + 0.25))) / 32768.0f));
            state->targetPosZ = gAndrossMoveTailDistance * moveProgress + state->homePosZ;
        }
        if ((boss->anim.currentMoveProgress > 0.5) && (state->ringPlayed == 0)) {
            Sfx_PlayFromObject(boss, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            state->ringPlayed = 1;
        }
        if ((boss->anim.currentMoveProgress > 0.65) && (state->laughPlayed == 0)) {
            Sfx_PlayFromObject(boss, SFXTRIG_and_laugh);
            state->laughPlayed = 1;
        }
        handState = leftHandState->handState;
        if (ANDROSS_BOTH_HANDS_READY(rightHandState, handState)) {
            if (boss->anim.currentMoveProgress >= 1.0f) {
                state->actionPending = 1;
            } else if (boss->anim.currentMoveProgress > 0.5) {
                state->targetRotX = 0;
                androsshand_setState(state->leftHandObj, ANDROSSHAND_STATE_ENTER, (state->fightPhase == 4) + 1);
                androsshand_setState(state->rightHandObj, ANDROSSHAND_STATE_ENTER, (state->fightPhase == 4) + 1);
                state->signalFlags &= ~ANDROSS_SIGNAL_BOTH_HANDS_DEAD;
            }
        }
        break;
    }
    case 0x17:
        if (actionChanged) {
            andross_setMove(boss, 3);
            state->soundTimer = 0.0f;
            state->roarPlayed = 0;
        }
        state->soundTimer += timeDelta;
        if ((state->soundTimer > 60.0f) && (state->roarPlayed == 0)) {
            Sfx_PlayFromObject(boss, SFXTRIG_drak_pain1);
            state->roarPlayed = 1;
        }
        if (boss->anim.currentMoveProgress <= gAndrossArwingPullProgressLimit) {
            state->cachedPosX = boss->anim.localPosX;
            state->cachedPosY = boss->anim.localPosY - 130.0f;
            state->cachedPosZ = boss->anim.localPosZ - 350.0f;
            andross_moveArwingTowardTarget(state, gAndrossArwingPullVelocityScale);
        } else {
            f32 arwingDistance = state->savedPosZ - state->arwingObj->anim.localPosZ;

            state->camOffsetAccum =
                (0.0f < 15.0f * timeDelta + state->camOffsetAccum) ? 0.0f : 15.0f * timeDelta + state->camOffsetAccum;
            state->arwingFlightActive = 0;
            state->arwingObj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            rotationDelta =
                (int)((f32)(s16)arwarwing_getRotY(state->arwingObj) + arwingDistance * gAndrossArwingRotationScale);
            arwarwing_setRotY(state->arwingObj, rotationDelta);
            ANDROSS_SET_ARWING_THRUST(state, arwingDistance, gAndrossArwingThrustScale, thrustB, thrustBArg);
        }
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 0x18:
        if (actionChanged) {
            andross_setMove(boss, 0x11);
            state->roarPlayed = 0;
        }
        if (boss->anim.currentMoveProgress <= gAndrossArwingReleaseProgressLimit) {
            andross_moveArwingTowardTarget(state, gAndrossArwingReleaseVelocityScale);
        } else {
            f32 arwingDistance = state->savedPosZ - state->arwingObj->anim.localPosZ;

            state->camOffsetAccum =
                (0.0f < 10.0f * timeDelta + state->camOffsetAccum) ? 0.0f : 10.0f * timeDelta + state->camOffsetAccum;
            state->arwingFlightActive = 0;
            state->arwingObj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            rotationDelta = (int)((f32)(s16)arwarwing_getRotY(state->arwingObj) +
                                  arwingDistance * gAndrossArwingReleaseRotationScale);
            arwarwing_setRotY(state->arwingObj, rotationDelta);
            ANDROSS_SET_ARWING_THRUST(state, arwingDistance, gAndrossArwingReleaseThrustScale, thrustA, thrustAArg);
            if (state->roarPlayed == 0) {
                Sfx_PlayFromObject(boss, SFXTRIG_drak_pain1);
                state->roarPlayed = 1;
            }
        }
        if (boss->anim.currentMoveProgress >= 1.0f) {
            state->actionPending = 1;
        }
        break;
    case 0x1e:
        if (mainGetBit(GAMEBIT_AndrossRelated0002) != 0 || mainGetBit(GAMEBIT_AndrossRelated0003) != 0 ||
            mainGetBit(GAMEBIT_AndrossRelated0004) != 0) {
            mainSetBits(GAMEBIT_WM_ObjGroups, 0);
            (*gMapEventInterface)->setMapAct(ANDROSS_MAP_SHRINE, 7);
            unlockLevel(0, 0, 1);
            loadMapAndParent(mapGetDirIdx(ANDROSS_MAP_SHRINE));
            {
                int mapDirIndex = mapGetDirIdx(ANDROSS_MAP_SHRINE);
                lockLevel(mapDirIndex, 1);
            }
            warpToMap(0x4e, 0);
            state->fadeAlpha = 0.0f;
            state->actionState = 0x1f;
        }
        break;
    case 0x1f:
        break;
    }
    {
        f32 camActionParam = -180.0f + state->camOffsetAccum;
        (*gCameraInterface)->releaseAction(&camActionParam, 4);
    }
    boss->anim.velocityX += state->springStiffness * (state->targetPosX - boss->anim.localPosX);
    boss->anim.velocityY += state->springStiffness * (state->targetPosY - boss->anim.localPosY);
    boss->anim.velocityZ += state->springStiffness * (state->targetPosZ - boss->anim.localPosZ);
    boss->anim.velocityX *= state->springDamping;
    boss->anim.velocityY *= state->springDamping;
    boss->anim.velocityZ *= state->springDamping;
    boss->anim.localPosX += boss->anim.velocityX;
    boss->anim.localPosY += boss->anim.velocityY;
    boss->anim.localPosZ += boss->anim.velocityZ;

    if (state->velZ == 0.0f) {
        if (state->arwingFlightActive != 0) {
            andross_trackArwingVelocity(state, gAndrossArwingFlightClampRange, gAndrossArwingFlightVelocityScale, 0.0f);
        } else {
            state->velZ = gAndrossArwingFollowScale * (state->savedPosZ - state->arwingObj->anim.localPosZ);
        }
    }

    if (state->arwingObj->pendingParentObj == NULL) {
        Vec3f velocity = state->velocity;
        arwarwing_addVelocity(state->arwingObj, &velocity);
    }

    rotationError = state->targetRotX - (u16)boss->anim.rotX;
    if (rotationError > 0x8000) {
        rotationError = rotationError - 0xffff;
    }

    if (rotationError < -0x8000) {
        rotationError += 0xffff;
    }

    state->rotXSpeed +=
        (rotationError / gAndrossRotationTargetDivisor - state->rotXSpeed) / gAndrossRotationSmoothingDivisor;
    state->rotYSpeed +=
        (-boss->anim.rotY / gAndrossRotationTargetDivisor - state->rotYSpeed) / gAndrossRotationSmoothingDivisor;
    boss->anim.rotX += state->rotXSpeed;
    boss->anim.rotY += state->rotYSpeed;

    ObjAnim_AdvanceCurrentMove(boss, state->animSpeed, timeDelta, 0);
    andross_processPartHits(boss, state);
    andross_updateBombCollector(boss, state);
    if (state->silverRing != NULL) {
        state->silverRing->anim.localPosZ -= 3.0f;
        state->silverRingLifetime -= framesThisStep;
        if (state->silverRingLifetime < 0) {
            Obj_FreeObject(state->silverRing);
            state->silverRingLifetime = 0;
            state->silverRing = NULL;
        }
    }

    if (state->fightPhase < 6) {
        andross_updateAimTarget(boss, 0x7e5);
        andross_updateAimTarget(boss, 0x1e);
        andross_updateAimTarget(boss, 0x76f);
        andross_updateAimTarget(boss, 0x814);
        andross_updateAimTarget(boss, 0x6cf);
    }
}

void andross_init(GameObject* obj, ObjPlacement* setup) {
    AndrossState* state = obj->extra;

    state->homePosX = setup->posX;
    state->homePosY = setup->posY;
    state->homePosZ = setup->posZ;
    state->actionTimer = 0;
    state->actionState = 0;
    state->prevActionState = -1;
    state->animSpeed = 0.005f;
    state->startupDelay = 5;
    state->fightPhase = 1;
    state->prevFightPhase = -1;
    state->targetRotX = -0x8000;
    obj->anim.rotX = -0x8000;
    state->spawnCooldown = -1.0f;
    state->camOffsetAccum = 0.0f;
    state->springStiffness = 0.003f;
    state->springDamping = 0.93f;
    state->handsInitialized = 1;
    ObjHits_SetTargetMask(obj, 4);
    obj->animEventCallback = andross_SeqFn;
    newshadows_createDistortionTexture();
    andross_setModelAlpha(Obj_GetActiveModel(obj)->file, 0.0f);
    mainSetBits(GAMEBIT_AndrossRelated000D, 0);
    unlockLevel(0, 0, 1);
}

int gAndrossRotationTargetDivisor = 20;
int gAndrossRotationSmoothingDivisor = 10;
int gAndrossFlightHalfWidth = 600;
int gAndrossRingSpawnInterval = 2;
f32 gAndrossMissileClampRange = 3.0f;
f32 gAndrossMissileVelocityScale = 5.0f;
f32 gAndrossMissileForwardVelocity = 0.02f;
int gAndrossMissileAttackDuration = 200;
int gAndrossMissileSpawnInterval = 10;
f32 gAndrossCentralMissileClampRange = 2.0f;
f32 gAndrossCentralMissileVelocityScale = 120.0f;
f32 gAndrossCentralMissileForwardVelocity = 0.03f;
int gAndrossCentralAttackDuration = 600;
int gAndrossCentralMissileSpawnInterval = 10;
f32 gAndrossArwingApproachVelocityScale = 0.1f;
int gAndrossAsteroidSpawnInterval = 2;
f32 gAndrossSpawnRandX = 300.0f;
f32 gAndrossSpawnRandY = 200.0f;
f32 gAndrossSpawnRandZ = 50.0f;
f32 gAndrossSpawnOffsetY = -100.0f;
f32 gAndrossSpawnOffsetZ = 280.0f;
int gAndrossBrainAttackDuration = 40;
f32 gAndrossArwingReturnVelocityScale = 0.01f;
int gAndrossMoveTailDistance = 300;
f32 gAndrossArwingPullProgressLimit = 0.38f;
f32 gAndrossArwingPullVelocityScale = 0.07f;
f32 gAndrossArwingThrustScale = 0.05f;
f32 gAndrossArwingRotationScale = 10.0f;
f32 gAndrossArwingReleaseProgressLimit = 0.38f;
f32 gAndrossArwingReleaseVelocityScale = 0.04f;
f32 gAndrossArwingReleaseThrustScale = 0.05f;
f32 gAndrossArwingReleaseRotationScale = 10.0f;
f32 gAndrossArwingFollowScale = 0.0005f;
f32 gAndrossArwingFlightClampRange = 2.0f;
f32 gAndrossArwingFlightVelocityScale = 100.0f;
s16 gAndrossSwayPhaseStepX = 150;
s16 gAndrossSwayPhaseStepY = 280;
f32 gAndrossForwardDistanceThreshold = 50.0f;
f32 gAndrossArwingVelDamp = 0.2f;
u8 gAndrossPartTextureIndices[4] = {1, 0, 2, 0};
u32 gAndrossDistortFilterParam = 0x0000ff00;
f32 gAndrossDistortPhaseStep = 0.006f;
f32 gAndrossDistortPhaseReset = 3.142f;
int gAndrossAimedProjectileSpeed = 10;
int gAndrossAimedProjectileLifetime = 90;
int gAndrossRingProjectileLifetime = 110;
f32 gAndrossRingProjectileScale = 5.0f;
int gAndrossProjectileForwardStep = 7;
int gAndrossSpawnedObjectLifetime = 200;
