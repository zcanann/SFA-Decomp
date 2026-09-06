/*
 * DLL 0x023F (DB_egg) - the "dbegg" floating egg object.
 *
 * A buoyant egg driven by a mode state machine (DbEggState.mode, byte at
 * +0x118; flags119 at +0x119). dbegg_update dispatches per mode:
 *   1  settled/idle            2  drifting on water (flocking + buoyancy)
 *   4  inert                   5  falling, seeking water/ground surface
 *   6  player-pickup prompt    7  sinking after release
 *   8  respawn wait            9  curve-follow path
 *   0xa curve init             0xb held (velocity from message +0x10c..)
 *   0xc gated respawn          0xd homing-to-target reposition
 * Surface probing (water tri type 0xe vs ground) is dbegg_probeSurface; sibling-egg
 * flocking repulsion is dbegg_computeFlocking. Buoyancy/clamp/turn constants live in
 * the lbl_803E61xx/.. pool. dbegg_setupFromDef seeds mode from the placement
 * config's primary/ready condition game bits; behaviorMode selects variant
 * flags119 bits (held, curve, model-1, group-32).
 *
 * Game bits: 0x3c4 (egg grabbed, global gate), 0x86d, 0x426/0x428 (sink
 * progress + count), 0x42a (respawn), 0x44d, and the placement's
 * triggerGameBit. Messages are pumped by dbegg_processMessages (ObjMsg type
 * 17; subtypes 16-20).
 */
#include "dlls/objects/575_DB_egg.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/debug.h"
#include "sys/objects.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/curve.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/waterfx_interface.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/pad.h"
#include "main/objhits.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/track_dolphin_api.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/pad.h"
#include "main/lightmap_api.h"
#include "main/track_bbox_api.h"
#include "main/object_update_list.h"

#define DBEGG_OBJGROUP         0x24
#define DBEGG_SIBLING_OBJGROUP 0x14
#define DBEGG_MSG_IN_RANGE     0x7000a  /* sent to player when grab is offered */
#define DBEGG_MSG_PLAYER_GRAB  0x100008 /* tells player to grab/hold the egg */

/* ambient particle spawned randomly while dormant in DBEGG_MODE_RESPAWN_WAIT */
#define DBEGG_PARTFX_RESPAWN_WAIT 0x3be
/* speed-scaled trail spawned while homing to the target in DBEGG_MODE_HOMING */
#define DBEGG_PARTFX_HOMING_TRAIL 0x345

typedef enum DbEggMode {
    DBEGG_MODE_SETTLED = 1,         /* settled / idle on the surface */
    DBEGG_MODE_DRIFTING = 2,        /* drifting on water: flocking + buoyancy */
    DBEGG_MODE_RELEASED = 3,        /* released / inactive (no longer updated) */
    DBEGG_MODE_INERT = 4,           /* inert (hitbox suppressed) */
    DBEGG_MODE_FALLING = 5,         /* falling, seeking the water/ground surface */
    DBEGG_MODE_PICKUP_PROMPT = 6,   /* offering the player a pickup prompt */
    DBEGG_MODE_SINKING = 7,         /* sinking after release */
    DBEGG_MODE_RESPAWN_WAIT = 8,    /* waiting to respawn */
    DBEGG_MODE_CURVE_FOLLOW = 9,    /* following a rom-curve path */
    DBEGG_MODE_CURVE_INIT = 0xA,    /* initialising the curve walker */
    DBEGG_MODE_HELD = 0xB,          /* held; velocity driven from the carry message */
    DBEGG_MODE_GATED_RESPAWN = 0xC, /* respawn gated on the activate game bit */
    DBEGG_MODE_HOMING = 0xD,        /* homing back to its target reposition point */
} DbEggMode;

static const DbEggIntPair sDbEggCurveIds = {1, 0};

int dbegg_setLaunchVelocity(GameObject* obj, f32* v) {
    DbEggState* inner = obj->extra;
    if (inner->mode == DBEGG_MODE_HELD) {
        inner->launchVelX = v[0];
        inner->launchVelY = v[1];
        inner->launchVelZ = v[2];
        return 1;
    }
    return 0;
}

int dbegg_isActive(GameObject* obj) {
    DbEggState* inner = obj->extra;
    return inner->mode != DBEGG_MODE_RELEASED;
}

void dbegg_processMessages(GameObject* obj) {
    DbEggState* eggState;
    DbeggPlacement* config;
    u32 msgType = 0;
    u32 msgFlag = 0;
    u32 msgArg;

    eggState = obj->extra;
    config = (DbeggPlacement*)obj->anim.placementData;

    while (ObjMsg_Pop(obj, &msgType, &msgArg, &msgFlag) != 0) {
        if (msgType == 17) {
            switch (msgFlag) {
            case 18:
                if ((eggState->flags119 & 0x20) == 0) {
                    objFreeObjectType(obj, DBEGG_OBJGROUP);
                }
                ObjHits_DisableObject(obj);
                eggState->mode = DBEGG_MODE_HELD;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                break;
            case 17: {
                struct {
                    s16 rotation[3];
                    u8 pad6[2];
                    f32 scale;
                    f32 vector[3];
                } buf;
                f32 v;
                obj->anim.velocityX = eggState->launchVelX;
                obj->anim.velocityY = eggState->launchVelY;
                obj->anim.velocityZ = -eggState->launchVelZ;
                v = 0.0f;
                buf.vector[0] = v;
                buf.vector[1] = v;
                buf.vector[2] = v;
                buf.scale = 1.0f;
                buf.rotation[2] = 0;
                buf.rotation[1] = 0;
                buf.rotation[0] = *(s16*)msgArg;
                vecRotateZXY(buf.rotation, &obj->anim.velocityX);
            }
            case 16:
                objAddObjectType(obj, DBEGG_OBJGROUP);
            case 20:
                eggState->mode = DBEGG_MODE_FALLING;
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                ObjHits_EnableObject(obj);
                break;
            case 19:
                mainSetBits(config->secondaryGameBit, 1);
                if (config->counterGameBit > 0) {
                    gameBitIncrement(config->counterGameBit);
                }
                Obj_RemoveFromUpdateList(obj);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                objFreeObjectType(obj, DBEGG_OBJGROUP);
                break;
            }
        }
    }
}

void dbegg_setupFromDef(GameObject* obj, u8* state) {
    DbeggPlacement* config;
    f32 surfaceProbeOut;
    DbEggState* egg = (DbEggState*)state;

    config = (DbeggPlacement*)obj->anim.placementData;
    egg->flags119 = 0;
    obj->anim.rotX = config->facingAngleByte << 8;
    obj->anim.rotY = 0;
    obj->anim.rotZ = 0;
    obj->anim.rootMotionScale = config->speedScaleByte / 64.0f;
    obj->anim.rootMotionScale *= obj->anim.modelInstance->rootMotionScaleBase;
    egg->mode = mainGetBit(config->triggerGameBit) != 0 ? DBEGG_MODE_RELEASED : DBEGG_MODE_SETTLED;
    if (egg->mode == DBEGG_MODE_SETTLED) {
        if (dbegg_probeSurface(obj, &surfaceProbeOut, 0.0f, 0.0f, 1) == 0) {
            egg->mode = DBEGG_MODE_DRIFTING;
        }
    }
    if (config->behaviorMode != 0) {
        egg->flags119 |= 1;
        if (config->behaviorMode == 2) {
            egg->flags119 |= 2;
        }
        if (config->behaviorMode == 3) {
            egg->mode = DBEGG_MODE_CURVE_INIT;
        }
        if (config->behaviorMode == 4) {
            egg->flags119 |= 4;
            egg->flags119 &= ~1;
        }
        if (config->behaviorMode == 5) {
            egg->flags119 |= 8;
            egg->flags119 |= 16;
        }
        if (config->behaviorMode == 6) {
            Obj_SetActiveModelIndex(obj, 1);
            egg->flags119 |= 8;
            egg->flags119 |= 16;
        }
        if (config->behaviorMode == 7) {
            egg->flags119 |= 32;
        }
    }
    egg->mode = mainGetBit(config->activateGameBit) != 0 ? DBEGG_MODE_FALLING : DBEGG_MODE_GATED_RESPAWN;
    if (egg->mode == DBEGG_MODE_FALLING) {
        objAddObjectType(obj, DBEGG_OBJGROUP);
    }
    {
        f32 fz = 0.0f;
        obj->anim.velocityX = fz;
        obj->anim.velocityY = fz;
        obj->anim.velocityZ = fz;
        obj->userData2 = 0;
        egg->waterOffset = fz;
    }
}

int dbegg_probeSurface(GameObject* obj, f32* out, f32 offsetX, f32 offsetZ, int flag) {
    f32 water;
    f32 ground;
    f32 bestAbs;
    f32 curAbs;
    f32 dy;
    int hitCount;
    int i;
    TrackGroundHit** hitList;
    TrackGroundHit* hit;

    *out = 0.0f;
    hitCount = trackGetHeight(obj, obj->anim.localPosX + offsetX, obj->anim.localPosY, obj->anim.localPosZ + offsetZ,
                              &hitList, 0, 0);
    if (hitCount != 0) {
        ground = 10000.0f;
        water = ground;
        for (i = 0; i < hitCount; i++) {
            hit = hitList[i];
            dy = hit->height - obj->anim.localPosY;
            if ((s8)hit->surfaceType == 0xe) {
                if (water >= 0.0f) {
                    bestAbs = water;
                } else {
                    bestAbs = -water;
                }
                if (dy >= 0.0f) {
                    curAbs = dy;
                } else {
                    curAbs = -dy;
                }
                if (curAbs < bestAbs) {
                    water = dy;
                }
            } else {
                if (ground >= 0.0f) {
                    bestAbs = ground;
                } else {
                    bestAbs = -ground;
                }
                if (dy >= 0.0f) {
                    curAbs = dy;
                } else {
                    curAbs = -dy;
                }
                if (curAbs < bestAbs) {
                    ground = dy;
                }
            }
        }
        if (flag == 0) {
            if (ground != 10000.0f) {
                *out = ground;
                return 0;
            }
            if (water != 10000.0f) {
                *out = water;
                return 1;
            }
            *out = 1000.0f;
        } else {
            if (water != 10000.0f) {
                if (ground >= 0.0f) {
                    bestAbs = ground;
                } else {
                    bestAbs = -ground;
                }
                if (water >= 0.0f) {
                    curAbs = water;
                } else {
                    curAbs = -water;
                }
                if (curAbs <= bestAbs || water > 0.0f) {
                    *out = water;
                    return 0;
                }
                *out = ground;
                return 1;
            }
            if (ground != 10000.0f) {
                *out = ground;
                return 1;
            }
            *out = 1000.0f;
        }
    }
    return 0;
}

void dbegg_computeFlocking(GameObject* obj, f32* vel) {
    f32 limit;
    f32 force;
    f32 sumX;
    f32 sumZ;
    int count;
    GameObject* sibling;
    int i;

    GameObject** objList;
    sumZ = sumX = 0.0f;
    objList = objGetAllOfType(DBEGG_SIBLING_OBJGROUP, &count);
    for (i = 0, limit = 7.0f; i < count; i++) {
        f32 dy;
        sibling = objList[i];
        dy = sibling->anim.localPosY - obj->anim.localPosY;
        if (dy <= limit && dy >= -7.0f) {
            f32 dx = sibling->anim.localPosX - obj->anim.localPosX;
            f32 dz = sibling->anim.localPosZ - obj->anim.localPosZ;
            f32 dist = sqrtf(dx * dx + dz * dz);
            f32 radius = 1.5f * ((DbeggPlacement*)sibling->anim.placementData)->forceRadiusByte;
            if (dist < radius) {
                force = (radius - dist) / radius;
                force *= (10.0f * sibling->anim.rootMotionScale);
                sumX += force * mathSinf((3.1415927f * sibling->anim.rotX) / 32768.0f);
                sumZ += force * mathCosf((3.1415927f * sibling->anim.rotX) / 32768.0f);
            }
        }
    }
    if (count != 0) {
        f32 weight;
        f32 scale;
        sumX /= count;
        sumZ /= count;
        weight = 0.05f;
        vel[0] = -(weight * sumX - vel[0]);
        vel[2] = -(weight * sumZ - vel[2]);
        vel[0] *= (scale = 0.99f);
        vel[2] *= scale;
        {
            f32 mag = sqrtf(vel[0] * vel[0] + vel[2] * vel[2]);
            if (mag > 1.85f) {
                f32 sc = 1.85f / mag;
                vel[0] *= sc;
                vel[2] *= sc;
            }
        }
    }
}

int dbegg_getExtraSize(void) {
    return sizeof(DbEggState);
}
int dbegg_getObjectTypeId(void) {
    return 0x8;
}

void dbegg_free(GameObject* obj) {
    objFreeObjectType(obj, DBEGG_OBJGROUP);
}

void dbegg_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible) {
    DbEggState* inner = obj->extra;
    if (visible != 0) {
        u32 t = inner->mode;
        if (t != DBEGG_MODE_GATED_RESPAWN && t != DBEGG_MODE_INERT && t != DBEGG_MODE_HELD) {
            objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
        }
    }
}

void dbegg_hitDetect(GameObject* obj) {
    DbEggState* state;
    int hit;
    hit = ObjHits_GetPriorityHit(obj, 0, 0, 0);
    state = obj->extra;
    if (hit == 0x12) {
        if (state->mode != DBEGG_MODE_INERT) {
            Obj_GetPlayerObject();
        }
    }
    if (state->mode != DBEGG_MODE_CURVE_FOLLOW) {
        f32* hitFrom = &obj->anim.previousLocalPosX;
        f32* hitTo = &obj->anim.localPosX;
        f32 hitRadius = 9.0f;
        if (trackGetLineIntersect(hitFrom, hitTo, hitRadius, 1, NULL, obj, 8, -1, 0xff, 0) != 0) {
            obj->anim.velocityX -= 0.95f * obj->anim.velocityX;
            obj->anim.velocityZ -= 0.95f * obj->anim.velocityZ;
        }
    }
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
}

ObjectDescriptor12 gDB_eggObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    dbegg_initialise,
    dbegg_release,
    0,
    (ObjectDescriptorCallback)dbegg_init,
    (ObjectDescriptorCallback)dbegg_update,
    (ObjectDescriptorCallback)dbegg_hitDetect,
    (ObjectDescriptorCallback)dbegg_render,
    (ObjectDescriptorCallback)dbegg_free,
    (ObjectDescriptorCallback)dbegg_getObjectTypeId,
    dbegg_getExtraSize,
    (ObjectDescriptorCallback)dbegg_isActive,
    (ObjectDescriptorCallback)dbegg_setLaunchVelocity,
};

char sAnimGreaterMessage[11] = " GREATER \n\000";

void dbegg_update(GameObject* obj) {
    DbeggPlacement* data = (DbeggPlacement*)obj->anim.placementData;
#define hitState ((ObjHitsPriorityState*)obj->anim.hitReactState)
    GameObject* player;
    DbEggState* egg;
    DbeggPlacement* placement;
    DbEggState* pickupState;
    int i;
    int n;
    GameObject* playerObj;
    f32 v;
    f32 fx;
    f32 fz;
    f32 flockVel[3];
    f32 d[3];
    int curvePair[2];
    f32 surfaceHeight;

    player = Obj_GetPlayerObject();
    egg = obj->extra;
    *(DbEggIntPair*)curvePair = sDbEggCurveIds;
    if (objPosToMapBlockIdx(obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ) != -1) {
        dbegg_processMessages(obj);
        hitState->flags &= ~OBJHITS_PRIORITY_STATE_IMMOVABLE;
        switch (egg->mode) {
        case DBEGG_MODE_FALLING:
            if (obj->userData2 == 0) {
                hitState->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            }
            if (dbegg_probeSurface(obj, &surfaceHeight, 0.0f, 0.0f, 1) == 0) {
                egg->mode = DBEGG_MODE_DRIFTING;
                break;
            }
            v = surfaceHeight;
            v = v >= 0.0f ? v : -v;
            if (v < 0.09f) {
                if (egg->flags119 & 0x10) {
                    egg->mode = DBEGG_MODE_HOMING;
                } else {
                    egg->mode = DBEGG_MODE_SETTLED;
                }
                fz = 0.0f;
                obj->anim.velocityX = 0.0f;
                obj->anim.velocityZ = fz;
                obj->anim.velocityY = fz;
                obj->anim.localPosY += surfaceHeight;
            } else {
                obj->anim.velocityY += -0.3f;
                if (surfaceHeight > 0.0f) {
                    obj->anim.velocityY = 0.65f * -obj->anim.velocityY;
                    obj->anim.velocityX *= 0.9f;
                    obj->anim.velocityZ *= 0.9f;
                    v = obj->anim.velocityY;
                    v = v >= 0.0f ? v : -v;
                    if (v > 0.2f) {
                        Sfx_PlayFromObject(obj, SFXTRIG_id_2df);
                    }
                }
                objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                        obj->anim.velocityZ * timeDelta);
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DBEGG_MODE_SETTLED:
            if (obj->userData2 == 0) {
                hitState->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            }
            obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            break;
        case DBEGG_MODE_DRIFTING:
            if (egg->flags119 & 4) {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                obj->anim.velocityX += (data->base.posX - obj->anim.localPosX) / (fz = 1000.0f);
                obj->anim.velocityY += (data->base.posY - obj->anim.localPosY) / fz;
                obj->anim.velocityZ += (data->base.posZ - obj->anim.localPosZ) / fz;
                if (mainGetBit(0x44d) != 0) {
                    egg->mode = DBEGG_MODE_CURVE_INIT;
                }
            }
            hitState->flags |= OBJHITS_PRIORITY_STATE_IMMOVABLE;
            fz = 0.0f;
            flockVel[0] = 0.0f;
            flockVel[1] = fz;
            flockVel[2] = fz;
            dbegg_computeFlocking(obj, flockVel);
            obj->anim.velocityX += flockVel[0];
            obj->anim.velocityY += flockVel[1];
            obj->anim.velocityZ += flockVel[2];
            if (dbegg_probeSurface(obj, &surfaceHeight, obj->anim.velocityX * timeDelta,
                                   obj->anim.velocityZ * timeDelta, 1) != 0) {
                obj->anim.velocityX = -0.95f * obj->anim.velocityX;
                obj->anim.velocityZ = -0.95f * obj->anim.velocityZ;
                dbegg_probeSurface(obj, &surfaceHeight, obj->anim.velocityX * timeDelta,
                                   obj->anim.velocityZ * timeDelta, 1);
            }
            surfaceHeight += egg->waterOffset;
            if (oneOverTimeDelta) {
                obj->anim.velocityY = surfaceHeight * (0.3f * oneOverTimeDelta);
            } else {
                obj->anim.velocityY = 0.0f;
            }
            randomGetRange(0x64, 0x1388);
            randomGetRange(0x64, 0x1388);
            objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                    obj->anim.velocityZ * timeDelta);
            if (randomGetRange(0, 10) == 0) {
                int nb;
                nb = ((surfaceHeight < 0.05f) >= 0) ? (surfaceHeight < 0.05f) : -(surfaceHeight < 0.05f);
                if (nb != 0) {
                    (*gWaterfxInterface)
                        ->spawnRipple(obj->anim.localPosX, obj->anim.localPosY - egg->waterOffset, obj->anim.localPosZ,
                                      obj->anim.rotX, randomGetRange(1, 10), 1);
                }
            }
            if (mainGetBit(0x426) != 0) {
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                egg->waterOffset -= 0.1f * timeDelta;
                if (egg->waterOffset < -7.0f) {
                    mainSetBits(0x428, mainGetBit(0x428) + 1);
                    egg->mode = DBEGG_MODE_SINKING;
                    fz = 0.0f;
                    obj->anim.velocityY = 0.0f;
                    obj->anim.velocityX = fz;
                    obj->anim.velocityZ = fz;
                    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
            } else if (egg->flags119 & 2) {
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DBEGG_MODE_INERT:
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            break;
        case DBEGG_MODE_PICKUP_PROMPT:
            if (Vec_xzDistance(&obj->anim.worldPosX, &data->base.posX) > 150.0f && (egg->flags119 & 2) == 0) {
                playerObj = Obj_GetPlayerObject();
                pickupState = obj->extra;
                placement = (DbeggPlacement*)obj->anim.placementData;
                objFreeObjectType(obj, DBEGG_OBJGROUP);
                pickupState->mode = DBEGG_MODE_RELEASED;
                mainSetBits(0x3c4, 1);
                mainSetBits(0x86d, 1);
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                mainSetBits(placement->triggerGameBit, 1);
                pickupState->msg11C = -1;
                pickupState->msg11E = 0;
                pickupState->msg120 = 1.0f;
                ObjMsg_SendToObject(playerObj, DBEGG_MSG_IN_RANGE, obj, (int)&pickupState->msg11C);
                obj->userData2 = 0;
            } else if (getButtonsJustPressed(0) & PAD_BUTTON_A) {
                egg->mode = DBEGG_MODE_FALLING;
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
            } else {
                hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
                ObjMsg_SendToObject(player, DBEGG_MSG_PLAYER_GRAB, obj, 0x38000);
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
            break;
        case DBEGG_MODE_HELD:
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            return;
        case DBEGG_MODE_SINKING:
            dbegg_probeSurface(obj, &surfaceHeight, 0.0f, 0.0f, 0);
            v = surfaceHeight;
            v = v >= 0.0f ? v : -v;
            if (v < 0.09f) {
                egg->mode = DBEGG_MODE_RESPAWN_WAIT;
                fz = 0.0f;
                obj->anim.velocityX = 0.0f;
                obj->anim.velocityZ = fz;
            } else {
                obj->anim.velocityY += -0.006f;
                if (surfaceHeight > 0.0f) {
                    obj->anim.velocityY = 0.4f * -obj->anim.velocityY;
                }
                objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                        obj->anim.velocityZ * timeDelta);
            }
            break;
        case DBEGG_MODE_RESPAWN_WAIT:
            if (mainGetBit(0x42a) != 0) {
                dbegg_setupFromDef(obj, (u8*)egg);
            } else if (randomGetRange(0, 10) == 0) {
                (*gPartfxInterface)->spawnObject(obj, DBEGG_PARTFX_RESPAWN_WAIT, NULL, 0, -1, NULL);
            }
            break;
        case DBEGG_MODE_CURVE_INIT:
            if ((*gRomCurveInterface)->initCurve(&egg->curve, obj, 300.0f, curvePair, 2) != 0) {
                egg->mode = DBEGG_MODE_FALLING;
            } else {
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                egg->mode = DBEGG_MODE_CURVE_FOLLOW;
                n = egg->flags119;
                if (n & 4) {
                    egg->flags119 = n & ~4;
                }
            }
            break;
        case DBEGG_MODE_CURVE_FOLLOW:
            if (Curve_AdvanceAlongPath(&egg->curve.curve, 0.6f) != 0 || egg->curve.atSegmentEnd != 0) {
                if ((*gRomCurveInterface)->goNextPoint(&egg->curve) != 0) {
                    egg->mode = DBEGG_MODE_FALLING;
                }
            } else {
                obj->anim.velocityX = egg->curve.posX - obj->anim.localPosX;
                obj->anim.velocityY = egg->curve.posY - obj->anim.localPosY;
                obj->anim.velocityZ = egg->curve.posZ - obj->anim.localPosZ;
                fx = sqrtf(obj->anim.velocityZ * obj->anim.velocityZ +
                           (obj->anim.velocityX * obj->anim.velocityX + obj->anim.velocityY * obj->anim.velocityY));
                if (fx > 4.6f * timeDelta) {
                    Vec3_Normalize(&obj->anim.velocityX);
                    obj->anim.velocityX *= (4.6f * timeDelta);
                    obj->anim.velocityY *= (4.6f * timeDelta);
                    obj->anim.velocityZ *= (4.6f * timeDelta);
                    logPrintf(sAnimGreaterMessage);
                }
                obj->anim.localPosX += obj->anim.velocityX;
                obj->anim.localPosY += obj->anim.velocityY;
                obj->anim.localPosZ += obj->anim.velocityZ;
            }
            break;
        case DBEGG_MODE_GATED_RESPAWN:
            if (mainGetBit(data->activateGameBit) != 0) {
                objAddObjectType(obj, DBEGG_OBJGROUP);
                egg->mode = DBEGG_MODE_FALLING;
            }
            break;
        case DBEGG_MODE_HOMING:
            ObjHits_DisableObject(obj);
            obj->anim.velocityX += (data->base.posX - obj->anim.localPosX) / (fz = 2500.0f);
            obj->anim.velocityY += (data->base.posY - obj->anim.localPosY) / fz;
            obj->anim.velocityZ += (data->base.posZ - obj->anim.localPosZ) / fz;
            d[0] = obj->anim.localPosX - data->base.posX;
            d[1] = obj->anim.localPosY - data->base.posY;
            d[2] = obj->anim.localPosZ - data->base.posZ;
            Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_baddie_eba_smallswipe1);
            fz = *(f32*)((int)d + 8);
            fz = fz >= 0.0f ? fz : -fz;
            fx = *(f32*)((int)d + 0);
            fx = fx >= 0.0f ? fx : -fx;
            if (fx + fz < 6.0f) {
                ObjHits_EnableObject(obj);
                egg->mode = DBEGG_MODE_SETTLED;
                obj->anim.localPosX = data->base.posX;
                obj->anim.localPosY = data->base.posY;
                obj->anim.localPosZ = data->base.posZ;
            } else {
                int n = (int)(PSVECMag(&obj->anim.velocity) / 0.5f);
                for (i = 0; i < n; i++) {
                    (*gPartfxInterface)->spawnObject(obj, DBEGG_PARTFX_HOMING_TRAIL, NULL, 1, -1, NULL);
                }
                objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                        obj->anim.velocityZ * timeDelta);
            }
            break;
        }
        if (egg->flags119 & 8) {
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            ObjHits_DisableObject(obj);
            if (mainGetBit(data->triggerGameBit) != 0) {
                egg->flags119 &= ~9;
                obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
                ObjHits_EnableObject(obj);
            }
        } else if (obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) {
            if (mainGetBit(0x3c4) == 0) {
                if (Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX) < 25.0f) {
                    if ((egg->flags119 & 1) == 0) {
                        DbeggPlacement* placement;
                        DbEggState* pickupState;
                        GameObject* playerObj = Obj_GetPlayerObject();
                        pickupState = obj->extra;
                        placement = (DbeggPlacement*)obj->anim.placementData;
                        objFreeObjectType(obj, DBEGG_OBJGROUP);
                        pickupState->mode = DBEGG_MODE_RELEASED;
                        mainSetBits(0x3c4, 1);
                        mainSetBits(0x86d, 1);
                        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                        mainSetBits(placement->triggerGameBit, 1);
                        pickupState->msg11C = -1;
                        pickupState->msg11E = 0;
                        pickupState->msg120 = 1.0f;
                        ObjMsg_SendToObject(playerObj, DBEGG_MSG_IN_RANGE, obj, (int)&pickupState->msg11C);
                    } else {
                        v = obj->anim.localPosY - player->anim.localPosY;
                        v = v >= 0.0f ? v : -v;
                        if (v < 12.0f) {
                            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                            egg->mode = DBEGG_MODE_PICKUP_PROMPT;
                            hitState->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
                        }
                    }
                }
            }
        }
    }
#undef hitState
}

void dbegg_init(GameObject* obj) {
    ObjModelState* modelState;
    dbegg_setupFromDef(obj, obj->extra);
    ObjMsg_AllocQueue(obj, 8);
    modelState = obj->anim.modelState;
    if (modelState != NULL) {
        modelState->flags |= OBJ_MODEL_STATE_UNREAD_4000 | OBJ_MODEL_STATE_SHADOW_INIT_CALLBACK_RAN;
    }
}

void dbegg_release(void) {
}

void dbegg_initialise(void) {
}
