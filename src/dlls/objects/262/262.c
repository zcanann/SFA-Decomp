/*
 * Scarab (DLL 0x106) - GreenScarab/RedScarab/GoldScarab/RainScarab money
 * beetles.
 */
#include "dlls/objects/262.h"
#include "dolphin/mtx/vec.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/model.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/track_bbox_api.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/frustum.h"
#include "main/audio/sfx_limited_object_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/player_api.h"
#include "main/obj_message.h"
#include "sys/objects/lifecycle.h"

#define SCARAB_ORIENTATION_DIRECTION     0
#define SCARAB_ORIENTATION_GROUND_NORMAL 1
#define SCARAB_ORIENTATION_VELOCITY      2

#define SCARAB_DESTRUCT_DELAY           0x50
#define SCARAB_STUN_TIMER               0xFA
#define SCARAB_TRIGGER_HIT_KIND         0xE
#define SCARAB_SUPPRESS_BURST_GAMEBIT   0x1D9
#define SCARAB_RAIN_COLOR_COUNT         7
#define SCARAB_DIRECTIONAL_BURST_CHANCE 0x14
#define SCARAB_PICKUP_PARTICLE_COUNT    0x28

/* Shared item-pickup ObjMsg protocol (see DLL 0xED collectible / object 255). */
#define SCARAB_MSG_IN_RANGE     0x7000A /* player is close enough to collect */
#define SCARAB_MSG_PICKUP       0x7000B /* award money and despawn */
#define SCARAB_MSG_PLAYER_BURST 0x60004 /* knock the player back */

u8 gScarabGreenColors[4] = {2, 0x13, 0x16, 0};
u8 gScarabRedColors[4] = {0x14, 0x17, 0, 0};
u8 gScarabGoldColors[4] = {0, 0, 0, 0x0C};
u8 gScarabRainColorCycle[8] = {0x14, 0, 6, 0x13, 5, 7, 4, 0};
f32 gScarabMinGroundNormalY = 0.707f;
f32 gScarabMaxGroundHeightDelta = 10.0f;
f32 gScarabGroundHeadingScale = 1.0f;
f32 gScarabReturnHeadingScale = 1.0f;

f32 gScarabSweptHitInfo[4];

const Vec3f sScarabStartInit = {0.0f, 0.0f, 0.0f};
const Vec3f sScarabEndInit = {0.0f, 0.0f, 0.0f};

typedef struct ScarabCollisionResults {
    f32 hitInfo[4][4]; /* 0x00 */
    f32 radii[4];      /* 0x40 */
    union {
        u8 hitAxes[12];
        s8 signedHitAxes[12];
    }; /* 0x50 */
    u32 solidFlags[4]; /* 0x5C */
} ScarabCollisionResults;

typedef union ScarabMoneyValues {
    u32 packed;
    u8 values[4];
} ScarabMoneyValues;

const ScarabMoneyValues gScarabMoneyValues = {0x01050A32};

typedef struct ScarabSweepSphere {
    f32 radii[4];   /* 0x00 */
    s8 hitAxis;     /* 0x10 */
    u8 pad11[3];    /* 0x11 */
    u8 flags;       /* 0x14 */
    u8 pad15[0x1B]; /* 0x15 */
} ScarabSweepSphere;

typedef struct ScarabCollisionScratch {
    TrackBBoxHit bboxHit;     /* 0x00 */
    u8 hitResults[0x40];      /* 0x54 */
    ScarabSweepSphere sphere; /* 0x94 */
} ScarabCollisionScratch;

STATIC_ASSERT(offsetof(ScarabCollisionResults, hitInfo) == 0x0);
STATIC_ASSERT(offsetof(ScarabCollisionResults, radii) == 0x40);
STATIC_ASSERT(offsetof(ScarabCollisionResults, hitAxes) == 0x50);
STATIC_ASSERT(offsetof(ScarabCollisionResults, signedHitAxes) == 0x50);
STATIC_ASSERT(offsetof(ScarabCollisionResults, solidFlags) == 0x5C);
STATIC_ASSERT(sizeof(ScarabCollisionResults) == 0x6C);
STATIC_ASSERT(offsetof(ScarabMoneyValues, packed) == 0x0);
STATIC_ASSERT(offsetof(ScarabMoneyValues, values) == 0x0);
STATIC_ASSERT(sizeof(ScarabMoneyValues) == 0x4);
STATIC_ASSERT(offsetof(ScarabSweepSphere, radii) == 0x0);
STATIC_ASSERT(offsetof(ScarabSweepSphere, hitAxis) == 0x10);
STATIC_ASSERT(offsetof(ScarabSweepSphere, pad11) == 0x11);
STATIC_ASSERT(offsetof(ScarabSweepSphere, flags) == 0x14);
STATIC_ASSERT(offsetof(ScarabSweepSphere, pad15) == 0x15);
STATIC_ASSERT(sizeof(ScarabSweepSphere) == 0x30);
STATIC_ASSERT(offsetof(ScarabCollisionScratch, bboxHit) == 0x0);
STATIC_ASSERT(offsetof(ScarabCollisionScratch, sphere) ==
              offsetof(ScarabCollisionScratch, hitResults) + 0x40);

static int Scarab_resolveCollision(GameObject* obj) {
    ObjHitsPriorityState* hitState;
    TrackQueryBounds sweptBounds;
    f32 endPoints[12];
    f32 startPoints[12];
    ScarabCollisionResults results;
    int hitIndex;
    u8 hitMask;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState != NULL) {
        endPoints[0] = obj->anim.localPosX;
        endPoints[1] = obj->anim.localPosY;
        endPoints[2] = obj->anim.localPosZ;
        startPoints[0] = obj->anim.previousLocalPosX;
        startPoints[1] = obj->anim.previousLocalPosY;
        startPoints[2] = obj->anim.previousLocalPosZ;
        results.radii[0] = 8.0f;
        results.signedHitAxes[0] = -1;
        results.hitAxes[4] = 0x3;
    } else {
        return 0;
    }

    hitDetect_calcSweptSphereBounds(&sweptBounds, startPoints, endPoints, results.radii, 1);
    trackIntersectBroadphase(obj, &sweptBounds, hitState->trackContactMask, 1);
    hitMask = trackGetIntersect(obj, startPoints, endPoints, 1, &results, 0);
    if (hitMask != 0) {
        if ((hitMask & 1) != 0) {
            hitIndex = 0;
        } else if ((hitMask & 2) != 0) {
            hitIndex = 1;
        } else if ((hitMask & 4) != 0) {
            hitIndex = 2;
        } else {
            hitIndex = 3;
        }

        *(u8*)&hitState->contactHitVolume = results.hitAxes[hitIndex];
        hitState->contactPosX = endPoints[hitIndex * 3];
        hitState->contactPosY = endPoints[hitIndex * 3 + 1];
        hitState->contactPosZ = endPoints[hitIndex * 3 + 2];
        gScarabSweptHitInfo[0] = results.hitInfo[hitIndex][0];
        gScarabSweptHitInfo[1] = results.hitInfo[hitIndex][1];
        gScarabSweptHitInfo[2] = results.hitInfo[hitIndex][2];
        gScarabSweptHitInfo[3] = results.hitInfo[hitIndex][3];

        if (results.solidFlags[hitIndex] != 0) {
            hitState->contactFlags = *(u8*)&hitState->contactFlags | OBJHITS_CONTACT_FLAG_KIND_NONZERO;
            obj->anim.localPosX = hitState->contactPosX;
            obj->anim.localPosY = hitState->contactPosY;
            obj->anim.localPosZ = hitState->contactPosZ;
            hitState->localPosX = obj->anim.previousLocalPosX;
            hitState->localPosY = obj->anim.previousLocalPosY;
            hitState->localPosZ = obj->anim.previousLocalPosZ;
            return 1;
        }
        hitState->contactFlags = *(u8*)&hitState->contactFlags | OBJHITS_CONTACT_FLAG_KIND0;
        obj->anim.localPosX = hitState->contactPosX;
        obj->anim.localPosY = hitState->contactPosY;
        obj->anim.localPosZ = hitState->contactPosZ;
        hitState->localPosX = obj->anim.previousLocalPosX;
        hitState->localPosY = obj->anim.previousLocalPosY;
        hitState->localPosZ = obj->anim.previousLocalPosZ;
        return 1;
    }
    return 0;
}

static void Scarab_applyOrientation(GameObject* obj, const TrackGroundHit* groundHit, u8 mode, const f32* direction) {
    f32* velocityCache = obj->extra;
    PartFxSpawnParams rotation;
    f32 normal[3];

    if (mode == SCARAB_ORIENTATION_GROUND_NORMAL) {
        normal[0] = groundHit->normalX;
        normal[1] = groundHit->normalY;
        normal[2] = groundHit->normalZ;
    } else if (mode == SCARAB_ORIENTATION_DIRECTION) {
        normal[0] = direction[0];
        normal[1] = direction[1];
        normal[2] = direction[2];
    } else if (mode == SCARAB_ORIENTATION_VELOCITY) {
        f32 magnitudeSquared;
        f32 normalizationScale;
        f32 zero = 0.0f;

        obj->anim.velocityX = direction[0];
        obj->anim.velocityZ = direction[2];
        magnitudeSquared = obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ;
        if (magnitudeSquared != zero) {
            magnitudeSquared = sqrtf(magnitudeSquared);
        }
        obj->anim.velocityX = obj->anim.velocityX / (normalizationScale = 2.0f * magnitudeSquared);
        obj->anim.velocityZ = obj->anim.velocityZ / normalizationScale;
        velocityCache[0] = obj->anim.velocityX;
        velocityCache[1] = obj->anim.velocityZ;
        obj->anim.rotX = (u16)getAngle(-direction[0], -direction[2]);
        return;
    }

    rotation.posX = 0.0f;
    rotation.posY = 0.0f;
    rotation.posZ = 0.0f;
    rotation.scale = 1.0f;
    rotation.rotZ = 0;
    rotation.rotY = 0;
    rotation.rotX = obj->anim.rotX;

    vecRotateZXY(&rotation.rotX, normal);

    if (groundHit != NULL) {
        u16 rollAngle = getAngle(normal[0], normal[1]);

        obj->anim.rotY = (u16)getAngle(normal[2], normal[1]);
        obj->anim.rotZ = rollAngle;
    } else {
        obj->anim.rotZ = 0;
        obj->anim.rotY = getAngle(direction[0] + direction[2], direction[1]);
        if (obj->anim.rotY < 0) {
            obj->anim.rotY *= -1;
        }
        obj->anim.rotX = getAngle(direction[0], direction[2]);
    }
}

int Scarab_getExtraSize(void) {
    return SCARAB_STATE_SIZE;
}

void Scarab_free(GameObject* obj) {
    (void)obj;
}

void Scarab_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    ScarabState* state;
    ObjModel* model;
    u8* shellColors;
    int colorIndex;

    state = obj->extra;
    model = Obj_GetActiveModel(obj);
    if (obj->anim.romDefNo == SCARAB_OBJECT_RAIN) {
        colorIndex = 0;
        shellColors = gScarabRainColorCycle;
        for (; colorIndex < SCARAB_RAIN_COLOR_COUNT; colorIndex++) {
            if (*shellColors == model->textureRefs->swapSelector) {
                colorIndex++;
                if (colorIndex == SCARAB_RAIN_COLOR_COUNT) {
                    colorIndex = 0;
                }
                model->textureRefs->swapSelector = gScarabRainColorCycle[colorIndex];
                break;
            }
            shellColors++;
        }
    }

    if (state->destructDelayTimer == 0) {
        if (obj->userData2 != 0) {
            if (visible != -1) {
                return;
            }
        } else if (visible == 0) {
            return;
        }

        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        if ((visible != 0) && (obj->anim.alpha != 0)) {
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, state->burstModel, 1, SCARAB_DIRECTIONAL_BURST_CHANCE, 2.5f, 0,
                                        0);
        }
    }
}

void Scarab_update(GameObject* obj) {
    ScarabCollisionScratch collisionScratch;
    PartFxSpawnParams rotation;
    TrackQueryBounds sweepBounds;
    Vec3f startPosition;
    Vec3f endPosition;
    Vec homeDirection;
    TrackGroundHit** groundHits;
    u32 message;
    f32 animationPhase;
    ScarabMoneyValues queuedMoneyValues;
    ScarabMoneyValues pickupMoneyValues;
    ScarabMoneyValues rainMoneyValues;
    int bestGroundHitIndex;
    int collisionDetected;
    GameObject* player;
    ScarabState* state;
    s8 behaviorState;
    s16 lifetime;
    f32 bestDistance;
    f32 deltaY;
    f32 heading;
    f32 speed;
    f32 zeroMagnitudeSquared;
    u32 angle;
    int yawDelta;
    int hitCount;
    int hitIndex;
    u8 hitMask;

    bestGroundHitIndex = 0;
    groundHits = NULL;
    startPosition = sScarabStartInit;
    endPosition = sScarabEndInit;
    collisionDetected = bestGroundHitIndex;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if ((state->pickupFlags & SCARAB_PICKUP_PENDING) != 0) {
        while (ObjMsg_Pop(obj, &message, 0, 0) != 0) {
            switch (message) {
            case SCARAB_MSG_PICKUP:
                queuedMoneyValues = gScarabMoneyValues;
                playerAddMoney(player, queuedMoneyValues.values[state->moneyKind]);
                state->destructDelayTimer = SCARAB_DESTRUCT_DELAY;
                state->lifetime = 0;
                state->pickupFlags &= ~SCARAB_PICKUP_PENDING;
                break;
            }
        }
        if ((state->pickupFlags & SCARAB_PICKUP_PENDING) != 0) {
            return;
        }
    }
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, SFXTRIG_scarab_runloop, 3);
    lifetime = state->lifetime;
    if (lifetime == 0) {
        state->destructDelayTimer -= framesThisStep;
        if (state->destructDelayTimer <= 0) {
            state->destructDelayTimer = 0;
            Obj_FreeObject(obj);
        }
    } else {
        behaviorState = state->behaviorState;
        if (behaviorState == SCARAB_STATE_TUMBLING) {
            if (obj->anim.hitReactState != NULL) {
                ObjHits_EnableObject(obj);
            }
            obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
            if (obj->anim.velocityY > -15.0f) {
                obj->anim.velocityY = -0.06f * timeDelta + obj->anim.velocityY;
            }
            obj->anim.rotZ = obj->anim.rotZ + state->rollSpeed * framesThisStep;
            if (Scarab_resolveCollision(obj) != 0) {
                collisionDetected = 1;
            }
            if (collisionDetected == 0) {
                collisionDetected = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 1.0f, 0,
                                                          &collisionScratch.bboxHit, obj, 8, -1, 0, 0);
            }
            if (collisionDetected != 0) {
                obj->anim.rotZ = 0;
                state->behaviorState = SCARAB_STATE_SCURRYING;
                state->scurryInitialYaw = obj->anim.rotX;
                if (obj->anim.romDefNo == SCARAB_OBJECT_GREEN) {
                    {
                        f32 bounceScale = 0.15f;
                        state->speedX = bounceScale * obj->anim.velocityX;
                        state->speedZ = bounceScale * obj->anim.velocityZ;
                    }
                } else if (obj->anim.romDefNo == SCARAB_OBJECT_RED) {
                    {
                        f32 bounceScale = 0.65f;
                        state->speedX = bounceScale * obj->anim.velocityX;
                        state->speedZ = bounceScale * obj->anim.velocityZ;
                    }
                } else if (obj->anim.romDefNo == SCARAB_OBJECT_GOLD) {
                    {
                        f32 bounceScale = 1.2f;
                        state->speedX = bounceScale * obj->anim.velocityX;
                        state->speedZ = bounceScale * obj->anim.velocityZ;
                    }
                } else if (obj->anim.romDefNo == SCARAB_OBJECT_RAIN) {
                    {
                        f32 bounceScale = 0.45f;
                        state->speedX = bounceScale * obj->anim.velocityX;
                        state->speedZ = bounceScale * obj->anim.velocityZ;
                    }
                } else if (obj->anim.romDefNo == SCARAB_OBJECT_BLUE_BEAN) {
                    f32 zero = 0.0f;
                    state->speedX = zero;
                    state->speedZ = zero;
                }
            }
        } else if (behaviorState == SCARAB_STATE_GOLD_CLIMB && lifetime != 0) {
            if (state->goldClimbTimer < state->goldClimbDuration) {
                f32 riseSpeed = 0.2f;
                state->goldClimbTimer = riseSpeed * timeDelta + state->goldClimbTimer;
                endPosition.x = riseSpeed * (obj->anim.velocityX * timeDelta) + obj->anim.localPosX;
                endPosition.y = riseSpeed * timeDelta + obj->anim.localPosY;
                endPosition.z = riseSpeed * (obj->anim.velocityZ * timeDelta) + obj->anim.localPosZ;
                startPosition.x = obj->anim.localPosX;
                startPosition.y = obj->anim.localPosY;
                startPosition.z = obj->anim.localPosZ;
                {
                    ScarabSweepSphere* sphere;
                    (sphere = &collisionScratch.sphere)->radii[0] = 0.0f;
                    sphere->hitAxis = -1;
                    sphere->flags = 0;
                    hitDetect_calcSweptSphereBounds(&sweepBounds, &startPosition.x, &endPosition.x, sphere->radii, 1);
                }
                trackIntersectBroadphase(obj, &sweepBounds, 0, 1);
                hitCount =
                    trackGetIntersect(obj, (f32*)&startPosition, (f32*)&endPosition, 1, collisionScratch.hitResults, 0);
                obj->anim.localPosX = endPosition.x;
                obj->anim.localPosY = endPosition.y;
                obj->anim.localPosZ = endPosition.z;
                if (hitCount != 0) {
                    Scarab_applyOrientation(
                        obj, NULL, SCARAB_ORIENTATION_DIRECTION,
                        (f32*)((u8*)&collisionScratch + offsetof(ScarabCollisionScratch, hitResults)));
                }
            }
            if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == SCARAB_TRIGGER_HIT_KIND) {
                state->stunTimer = SCARAB_STUN_TIMER;
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c);
                obj->anim.velocityX = player->anim.localPosX - obj->anim.localPosX;
                obj->anim.velocityZ = player->anim.localPosZ - obj->anim.localPosZ;
                obj->anim.rotX = 0;
                speed = obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ;
                zeroMagnitudeSquared = 0.0f;
                if (speed != zeroMagnitudeSquared) {
                    speed = sqrtf(speed);
                }
                obj->anim.velocityX = obj->anim.velocityX / (deltaY = 2.0f * speed);
                obj->anim.velocityZ = obj->anim.velocityZ / deltaY;
                obj->anim.rotY = 0;
                obj->anim.velocityY = 2.2f;
                rotation.posX = 0.0f;
                rotation.posY = 0.0f;
                rotation.posZ = 0.0f;
                rotation.scale = 1.0f;
                rotation.rotZ = 0;
                rotation.rotY = 0;
                rotation.rotX = randomGetRange(-10000, 10000);
                vecRotateZXY(&rotation.rotX, &obj->anim.velocityX);
                angle = (u16)getAngle(obj->anim.velocityX, -obj->anim.velocityZ);
                yawDelta = obj->anim.rotX - angle;
                if (yawDelta > 0x8000) {
                    yawDelta += -0xFFFF;
                }
                if (yawDelta < -0x8000) {
                    yawDelta += 0xFFFF;
                }
                obj->anim.rotX = yawDelta;
                state->behaviorState = SCARAB_STATE_TUMBLING;
                state->goldClimbTimer = 0.0f;
                {
                    f32 movementScale = 8.0f;
                    obj->anim.localPosX = movementScale * (obj->anim.velocityX * timeDelta) + obj->anim.localPosX;
                    obj->anim.localPosY = movementScale * (obj->anim.velocityY * timeDelta) + obj->anim.localPosY;
                    obj->anim.localPosZ = movementScale * (obj->anim.velocityZ * timeDelta) + obj->anim.localPosZ;
                }
            }
        } else if (behaviorState == SCARAB_STATE_SCURRYING && lifetime != 0) {
            if (state->stunTimer == 0) {
                bestGroundHitIndex = 0;
                bestDistance = 10000.0f;
                hitCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                          &groundHits, 1, 0);
                for (hitIndex = 0; hitIndex < hitCount; hitIndex++) {
                    deltaY = groundHits[hitIndex]->height - obj->anim.localPosY;
                    if (!(deltaY > gScarabMaxGroundHeightDelta)) {
                        deltaY = (deltaY >= 0.0f) ? deltaY : -deltaY;
                        if (deltaY < bestDistance) {
                            bestGroundHitIndex = hitIndex;
                            bestDistance = deltaY;
                        }
                    }
                }
                if (groundHits != NULL) {
                    obj->anim.localPosY = groundHits[bestGroundHitIndex]->height;
                    deltaY = groundHits[bestGroundHitIndex]->normalY;
                    deltaY = (deltaY >= 0.0f) ? deltaY : -deltaY;
                    if (deltaY < gScarabMinGroundNormalY) {
                        collisionDetected = 1;
                    } else {
                        Scarab_applyOrientation(obj, groundHits[bestGroundHitIndex], SCARAB_ORIENTATION_GROUND_NORMAL,
                                                (f32*)collisionScratch.hitResults);
                    }
                } else {
                    obj->anim.localPosY = state->initialY;
                }
                if (obj->anim.romDefNo != SCARAB_OBJECT_RAIN) {
                    obj->anim.rotX = (s16)(obj->anim.rotX + randomGetRange(-1460, 1460));
                }
                obj->anim.velocityX = state->speedX;
                {
                    f32 zero = 0.0f;
                    obj->anim.velocityY = zero;
                    obj->anim.velocityZ = state->speedZ;
                    rotation.posX = zero;
                    rotation.posY = zero;
                    rotation.posZ = zero;
                }
                rotation.scale = 1.0f;
                rotation.rotZ = 0;
                rotation.rotY = 0;
                rotation.rotX = obj->anim.rotX - state->scurryInitialYaw;
                vecRotateZXY(&rotation.rotX, &obj->anim.velocityX);
                state->lifetime -= framesThisStep;
                if (state->lifetime <= 0) {
                    if (ViewFrustum_IsSphereVisible(&obj->anim.localPosX,
                                                    obj->anim.hitboxScale * obj->anim.rootMotionScale) == 0) {
                        state->lifetime = 0;
                    } else {
                        state->lifetime = 1;
                    }
                }
                if (collisionDetected != 0) {
                    f32 movementScale;
                    angle =
                        (u16)getAngle(groundHits[bestGroundHitIndex]->normalX, groundHits[bestGroundHitIndex]->normalZ);
                    heading = angle;
                    heading = gScarabGroundHeadingScale * heading + 32768.0f;
                    obj->anim.rotX = heading;
                    obj->anim.localPosX =
                        timeDelta * ((movementScale = 8.0f) * groundHits[bestGroundHitIndex]->normalX) +
                        obj->anim.localPosX;
                    obj->anim.localPosZ =
                        timeDelta * (movementScale * groundHits[bestGroundHitIndex]->normalZ) + obj->anim.localPosZ;
                    obj->anim.velocityX = groundHits[bestGroundHitIndex]->normalX;
                    obj->anim.velocityZ = groundHits[bestGroundHitIndex]->normalZ;
                }
                if (collisionDetected == 0) {
                    obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
                    obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
                    speed =
                        sqrtf(obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityZ * obj->anim.velocityZ);
                    ObjAnim_SampleRootCurvePhase(&obj->anim, speed, &animationPhase);
                    ObjAnim_AdvanceCurrentMove(obj, animationPhase, timeDelta, NULL);
                }
                collisionDetected = trackGetLineIntersect(&obj->anim.previousLocalPosX, &obj->anim.localPosX, 1.0f, 0,
                                                          &collisionScratch.bboxHit, obj, 8, -1, 0, 0);
                {
                    ScarabSweepSphere* sphere;
                    (sphere = &collisionScratch.sphere)->radii[0] = 1.0f;
                    sphere->hitAxis = -1;
                    sphere->flags = 10;
                    hitDetect_calcSweptSphereBounds(&sweepBounds, &obj->anim.previousLocalPosX, &obj->anim.localPosX,
                                                    sphere->radii, 1);
                }
                trackIntersectBroadphase(obj, &sweepBounds, 0, 1);
                hitMask = trackGetIntersect(obj, &obj->anim.previousLocalPosX, &obj->anim.localPosX, 1,
                                            collisionScratch.hitResults, 0);
                if (collisionDetected != 0 ||
                    Vec_distance(&obj->anim.worldPosX, &((ObjPlacement*)obj->anim.placementData)->posX) > 300.0f ||
                    ((hitMask & 1) != 0 && (hitMask & 0x10) == 0)) {
                    PSVECSubtract((Vec*)&((ObjPlacement*)obj->anim.placementData)->posX, &obj->anim.localPos,
                                  &homeDirection);
                    angle = (u16)getAngle(homeDirection.x, homeDirection.z);
                    heading = angle;
                    heading = gScarabReturnHeadingScale * heading + 32768.0f;
                    obj->anim.rotX = heading;
                }
            } else {
                bestDistance = 10000.0f;
                hitCount = trackGetHeight(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                          &groundHits, 1, 0);
                for (hitIndex = 0; hitIndex < hitCount; hitIndex++) {
                    deltaY = groundHits[hitIndex]->height - obj->anim.localPosY;
                    if (deltaY < 0.0f) {
                        deltaY *= -1.0f;
                    }
                    if (deltaY < bestDistance) {
                        bestGroundHitIndex = hitIndex;
                        bestDistance = deltaY;
                    }
                }
                if (groundHits != NULL) {
                    obj->anim.localPosY = groundHits[bestGroundHitIndex]->height;
                    Scarab_applyOrientation(obj, groundHits[bestGroundHitIndex], SCARAB_ORIENTATION_GROUND_NORMAL,
                                            (f32*)collisionScratch.hitResults);
                } else {
                    obj->anim.localPosY = state->initialY;
                }
                state->stunTimer -= framesThisStep;
                if (state->stunTimer <= 0) {
                    state->stunTimer = 0;
                }
            }
            if ((state->stunTimer != 0 || obj->anim.romDefNo != SCARAB_OBJECT_RAIN) &&
                Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < 25.0f) {
                deltaY = obj->anim.localPosY - player->anim.localPosY;
                deltaY = (deltaY >= 0.0f) ? deltaY : -deltaY;
                if (deltaY < 20.0f) {
                    if (mainGetBit(GAMEBIT_SawScarab) == 0) {
                        state->messageParamA = -1;
                        state->messageParamB = 0;
                        state->messageParamC = 1.0f;
                        ObjMsg_SendToObject(player, SCARAB_MSG_IN_RANGE, obj, (u32)&state->messageParamA);
                        mainSetBits(GAMEBIT_SawScarab, 1);
                        state->pickupFlags |= SCARAB_PICKUP_PENDING;
                    } else {
                        pickupMoneyValues = gScarabMoneyValues;
                        playerAddMoney(player, pickupMoneyValues.values[state->moneyKind]);
                        state->destructDelayTimer = SCARAB_DESTRUCT_DELAY;
                        state->lifetime = 0;
                    }
                    if (obj->anim.hitReactState != NULL) {
                        ObjHits_DisableObject(obj);
                    }
                    Sfx_PlayFromObject(obj, (u16)state->collectSfxId);
                    itemPickupDoParticleFx(obj, 1.0f, state->particleId, SCARAB_PICKUP_PARTICLE_COUNT);
                }
            }
            if (state->stunTimer == 0 && obj->anim.romDefNo == SCARAB_OBJECT_RAIN) {
                if (Vec_xzDistance(&player->anim.worldPosX, &obj->anim.worldPosX) < 20.0f) {
                    deltaY = obj->anim.localPosY - player->anim.localPosY;
                    deltaY = (deltaY >= 0.0f) ? deltaY : -deltaY;
                    if (deltaY < 20.0f) {
                        if (mainGetBit(SCARAB_SUPPRESS_BURST_GAMEBIT) == 0) {
                            ObjMsg_SendToObject(player, SCARAB_MSG_PLAYER_BURST, obj, 1);
                        }
                        {
                            f32 knockbackDistance = 26.0f;
                            obj->anim.localPosX = knockbackDistance * -obj->anim.velocityX + obj->anim.localPosX;
                            obj->anim.localPosZ = knockbackDistance * -obj->anim.velocityZ + obj->anim.localPosZ;
                        }
                        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_45);
                    }
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == SCARAB_TRIGGER_HIT_KIND) {
                    state->stunTimer = SCARAB_STUN_TIMER;
                    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c);
                }
            } else if (state->stunTimer != 0 && obj->anim.romDefNo == SCARAB_OBJECT_RAIN &&
                       ObjHits_GetPriorityHit(obj, 0, 0, 0) == SCARAB_TRIGGER_HIT_KIND) {
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_46);
                rainMoneyValues = gScarabMoneyValues;
                playerAddMoney(player, rainMoneyValues.values[state->moneyKind]);
                state->destructDelayTimer = SCARAB_DESTRUCT_DELAY;
                state->lifetime = 0;
            }
        }
    }
}

void Scarab_init(GameObject* obj, const ScarabPlacement* placement) {
    ScarabState* state = obj->extra;
    ObjModel* model;
    state->behaviorState = SCARAB_STATE_TUMBLING;
    state->lifetime = placement->activeTimer;
    state->rollSpeed = randomGetRange(0x3E8, 0xFA0);
    state->goldClimbDuration = randomGetRange(0x32, 0x64);
    state->initialY = placement->base.posY;
    model = Obj_GetActiveModel(obj);
    switch (obj->anim.romDefNo) {
    case SCARAB_OBJECT_GREEN:
        model->textureRefs->swapSelector = gScarabGreenColors[randomGetRange(0, 2)];
        state->collectSfxId = 0x41;
        state->particleId = 4;
        state->burstModel = 2;
        state->moneyKind = SCARAB_MONEY_GREEN;
        break;
    case SCARAB_OBJECT_RED:
        model->textureRefs->swapSelector = gScarabRedColors[randomGetRange(0, 1)];
        state->collectSfxId = 0x42;
        state->particleId = 1;
        state->burstModel = 5;
        state->moneyKind = SCARAB_MONEY_RED;
        break;
    case SCARAB_OBJECT_GOLD:
        model->textureRefs->swapSelector = gScarabGoldColors[randomGetRange(0, 3)];
        state->collectSfxId = 0x43;
        state->particleId = 2;
        state->burstModel = 4;
        state->moneyKind = SCARAB_MONEY_GOLD;
        break;
    case SCARAB_OBJECT_RAIN:
    default:
        model->textureRefs->swapSelector = 5;
        state->collectSfxId = 0x44;
        state->particleId = 6;
        state->burstModel = 1;
        state->moneyKind = SCARAB_MONEY_RAIN;
        break;
    }
    ObjMsg_AllocQueue(obj, 2);
}

ObjectDescriptor gScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)Scarab_init,
    (ObjectDescriptorCallback)Scarab_update,
    0,
    (ObjectDescriptorCallback)Scarab_render,
    (ObjectDescriptorCallback)Scarab_free,
    0,
    Scarab_getExtraSize,
};
