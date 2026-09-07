/* Controls the spinning ice shards launched during the DIM boss fight. */
#include "dlls/objects/318.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "sys/objects/lifecycle.h"

#define DIM_BOSS_ICE_SMASH_OBJECT_TYPE_BASE       0x400
#define DIM_BOSS_ICE_SMASH_OBJECT_TYPE_BANK_SHIFT 11
#define DIM_BOSS_ICE_SMASH_PARTFX_SPAWN_FLAGS     0x200001
#define DIM_BOSS_ICE_SMASH_PARTFX_TRAIL           1000
#define DIM_BOSS_ICE_SMASH_PATH_INIT_FLAGS        0x40002

u8 gDIMBossIceSmashPathParams[8] = {0x40, 0x80, 0, 0, 0, 0, 0, 0};

u8 gDIMBossIceSmashActivationStarted;

u8 gDIMBossIceSmashPathPoint[0xC] = {0};

void DIMBossIceSmash_initLaunchState(GameObject* obj, DimBossIceSmashState* state,
                                     DimBossIceSmashPlacement* placement) {
    f32 vx, vy, vz;
    f32 spd, len;

    obj->anim.localPosX = state->spawnScaleX * obj->anim.rootMotionScale + placement->base.posX;
    obj->anim.localPosY = state->spawnScaleY * obj->anim.rootMotionScale + placement->base.posY;
    obj->anim.localPosZ = state->spawnScaleZ * obj->anim.rootMotionScale + placement->base.posZ;
    obj->anim.rotX = placement->spawnRotX;
    obj->anim.rotY = placement->spawnRotY;
    obj->anim.rotZ = placement->spawnRotZ;
    if ((placement->flags & DIM_BOSS_ICE_SMASH_PLACEMENT_HOMING) != 0) {
        spd = (f32)placement->velocityX / 100.0f;
        vx = obj->anim.localPosX - (f32)placement->homingTargetX;
        vy = obj->anim.localPosY - (f32)placement->homingTargetY;
        vz = obj->anim.localPosZ - (f32)placement->homingTargetZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (len != 0.0f) {
            vx /= len;
            vy /= len;
            vz /= len;
        }
        obj->anim.velocityX = spd * vx;
        obj->anim.velocityY = spd * vy;
        obj->anim.velocityZ = spd * vz;
    } else {
        obj->anim.velocityX = (f32)placement->velocityX / 100.0f;
        obj->anim.velocityY = (f32)placement->velocityY / 100.0f;
        obj->anim.velocityZ = (f32)placement->velocityZ / 100.0f;
    }
    state->angVelX = (f32)placement->rotVelX;
    state->angVelY = (f32)placement->rotVelY;
    state->angVelZ = (f32)placement->rotVelZ;
    if (obj->anim.velocityX > 0.0f) {
        state->directionFlags |= DIM_BOSS_ICE_SMASH_POSITIVE_VELOCITY_X;
    }
    if (obj->anim.velocityZ > 0.0f) {
        state->directionFlags |= DIM_BOSS_ICE_SMASH_POSITIVE_VELOCITY_Z;
    }
    if (state->angVelX > 0.0f) {
        state->directionFlags |= DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_X;
    }
    if (state->angVelY > 0.0f) {
        state->directionFlags |= DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_Y;
    }
    if (state->angVelZ > 0.0f) {
        state->directionFlags |= DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_Z;
    }
    state->angAccelX = (f32)placement->rotGravityX / 10.0f;
    state->angAccelY = (f32)placement->rotGravityY / 10.0f;
    state->angAccelZ = (f32)placement->rotGravityZ / 10.0f;
    state->accelX = (f32)placement->gravityX / 1000.0f;
    state->accelY = (f32)placement->gravityY / 1000.0f;
    state->accelZ = (f32)placement->gravityZ / 1000.0f;
    state->timer = 0;
}

int DIMBossIceSmash_getExtraSize(void) {
    return sizeof(DimBossIceSmashState);
}

u32 DIMBossIceSmash_getObjectTypeId(GameObject* obj) {
    DimBossIceSmashPlacement* placement = (DimBossIceSmashPlacement*)obj->anim.placementData;

    return (placement->bankIndex << DIM_BOSS_ICE_SMASH_OBJECT_TYPE_BANK_SHIFT) | DIM_BOSS_ICE_SMASH_OBJECT_TYPE_BASE;
}

void DIMBossIceSmash_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void DIMBossIceSmash_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void DIMBossIceSmash_hitDetect(void) {
}

void DIMBossIceSmash_update(GameObject* obj) {
    DimBossIceSmashState* state = obj->extra;
    u8 stateFlags = state->stateFlags;
    DimBossIceSmashPlacement* placement;
    u32 triggerBit;
    int alphaVal;
    s16 cnt;
    int fadeDuration;
    int frameCount;
    f32 nx, nz, ny;
    f32 len, inv, dot;
    f32 fx, fy, fz, ff;
    f32 dx, dy, dz, k;
    int i;
    PartFxSpawnParams spawnParams;

    if ((stateFlags & DIM_BOSS_ICE_SMASH_STATE_FINISHED) != 0) {
        if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0) {
            Obj_FreeObject(obj);
        }
        obj->anim.alpha = 0;
    } else {
        placement = (DimBossIceSmashPlacement*)obj->anim.placementData;
        if ((stateFlags & DIM_BOSS_ICE_SMASH_STATE_ACTIVE) == 0) {
            if (obj->anim.bankIndex == 0) {
                triggerBit = mainGetBit(placement->triggerGameBit);
                if (triggerBit != 0 || placement->triggerGameBit == -1) {
                    state->stateFlags |= DIM_BOSS_ICE_SMASH_STATE_ACTIVE;
                    mainSetBits(placement->activateGameBit, 1);
                    gDIMBossIceSmashActivationStarted = 1;
                }
            } else if (gDIMBossIceSmashActivationStarted != 0) {
                state->stateFlags = stateFlags | DIM_BOSS_ICE_SMASH_STATE_ACTIVE;
            }
            obj->anim.alpha = 0;
        } else {
            obj->anim.alpha = 0xff;
            cnt = (state->timer += framesThisStep);
            if (cnt >= placement->lifetime) {
                state->stateFlags |= DIM_BOSS_ICE_SMASH_STATE_FINISHED;
            }
            frameCount = state->timer;
            if (frameCount > placement->fadeStartFrame &&
                (fadeDuration = placement->lifetime - placement->fadeStartFrame) != 0) {
                alphaVal = (int)(255.0f * (1.0f - (f32)(frameCount - placement->fadeStartFrame) / (f32)fadeDuration));
                if (alphaVal > 0xff) {
                    alphaVal = 0xff;
                } else if (alphaVal < 0) {
                    alphaVal = 0;
                }
                obj->anim.alpha = alphaVal;
            }
            obj->anim.velocityX = timeDelta * state->accelX + obj->anim.velocityX;
            obj->anim.velocityY = timeDelta * state->accelY + obj->anim.velocityY;
            obj->anim.velocityZ = timeDelta * state->accelZ + obj->anim.velocityZ;
            state->angVelX = timeDelta * state->angAccelX + state->angVelX;
            state->angVelY = timeDelta * state->angAccelY + state->angVelY;
            state->angVelZ = timeDelta * state->angAccelZ + state->angVelZ;
            if ((state->directionFlags & DIM_BOSS_ICE_SMASH_POSITIVE_VELOCITY_X) != 0) {
                if (obj->anim.velocityX < 0.0f) {
                    obj->anim.velocityX = 0.0f;
                }
            } else if (obj->anim.velocityX > 0.0f) {
                obj->anim.velocityX = 0.0f;
            }
            if ((state->directionFlags & DIM_BOSS_ICE_SMASH_POSITIVE_VELOCITY_Z) != 0) {
                if (obj->anim.velocityZ < 0.0f) {
                    obj->anim.velocityZ = 0.0f;
                }
            } else if (obj->anim.velocityZ > 0.0f) {
                obj->anim.velocityZ = 0.0f;
            }
            if ((state->directionFlags & DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_X) != 0) {
                if (state->angVelX < 0.0f) {
                    state->angVelX = 0.0f;
                }
            } else if (state->angVelX > 0.0f) {
                state->angVelX = 0.0f;
            }
            if ((state->directionFlags & DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_Y) != 0) {
                if (state->angVelY < 0.0f) {
                    state->angVelY = 0.0f;
                }
            } else if (state->angVelY > 0.0f) {
                state->angVelY = 0.0f;
            }
            if ((state->directionFlags & DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_Z) != 0) {
                if (state->angVelZ < 0.0f) {
                    state->angVelZ = 0.0f;
                }
            } else if (state->angVelZ > 0.0f) {
                state->angVelZ = 0.0f;
            }
            obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
            obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
            obj->anim.rotX = state->angVelX * timeDelta + (f32)obj->anim.rotX;
            obj->anim.rotY = state->angVelY * timeDelta + (f32)obj->anim.rotY;
            obj->anim.rotZ = state->angVelZ * timeDelta + (f32)obj->anim.rotZ;
            if ((placement->flags & DIM_BOSS_ICE_SMASH_PLACEMENT_PATH_CONTROL) != 0) {
                (*gPathControlInterface)->update(obj, &state->path, timeDelta);
                (*gPathControlInterface)->apply(obj, &state->path);
                (*gPathControlInterface)->advance(obj, &state->path, timeDelta);
                if (state->path.surfaceCounter != 0) {
                    nx = -obj->anim.velocityX;
                    ny = -obj->anim.velocityY;
                    nz = -obj->anim.velocityZ;
                    len = sqrtf(nz * nz + (nx * nx + ny * ny));
                    if (len != 0.0f) {
                        inv = 1.0f / len;
                        nx *= inv;
                        ny *= inv;
                        nz *= inv;
                    }
                    fx = state->path.segmentHits.planes[0][0];
                    fy = state->path.segmentHits.planes[0][1];
                    fz = state->path.segmentHits.planes[0][2];
                    dot = 2.0f * (nz * fz + (nx * fx + ny * fy));
                    obj->anim.velocityX = fx * dot;
                    obj->anim.velocityY = fy * dot;
                    obj->anim.velocityZ = fz * dot;
                    obj->anim.velocityX -= nx;
                    obj->anim.velocityY -= ny;
                    obj->anim.velocityZ -= nz;
                    obj->anim.velocityY *= len;
                    obj->anim.velocityY *= 0.75f;
                    obj->anim.velocityX *= len;
                    obj->anim.velocityZ *= len;
                    obj->anim.velocityX *= (ff = 0.9f);
                    obj->anim.velocityZ *= ff;
                }
            }
            if ((placement->flags & DIM_BOSS_ICE_SMASH_PLACEMENT_TRAIL_PARTICLES) != 0 && obj->anim.alpha == 0xff) {
                dx = obj->anim.localPosX - obj->anim.previousLocalPosX;
                dy = obj->anim.localPosY - obj->anim.previousLocalPosY;
                dz = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
                i = 0;
                do {
                    k = i / 2.0f;
                    spawnParams.posX = dx * k + obj->anim.previousLocalPosX;
                    spawnParams.posY = dy * k + obj->anim.previousLocalPosY;
                    spawnParams.posZ = dz * k + obj->anim.previousLocalPosZ;
                    (*gPartfxInterface)
                        ->spawnObject(obj, DIM_BOSS_ICE_SMASH_PARTFX_TRAIL, &spawnParams,
                                      DIM_BOSS_ICE_SMASH_PARTFX_SPAWN_FLAGS, -1, NULL);
                    i++;
                } while (i < 2);
            }
        }
    }
}

void DIMBossIceSmash_init(GameObject* obj, DimBossIceSmashPlacement* placement) {
    DimBossIceSmashState* state;
    f32 fz;
    u8 initState;
    u8 pathParams[8];

    pathParams[0] = 5;
    ((ObjAnimComponent*)obj)->bankIndex = placement->bankIndex;
    state = obj->extra;
    fz = 0.0f;
    state->spawnScaleX = 0.0f;
    state->spawnScaleY = fz;
    state->spawnScaleZ = fz;
    DIMBossIceSmash_initLaunchState(obj, state, placement);
    initState = (mainGetBit(placement->activateGameBit) != 0) ? DIM_BOSS_ICE_SMASH_STATE_FINISHED : 0;
    state->stateFlags = initState;
    gDIMBossIceSmashActivationStarted = 0;
    if ((placement->flags & DIM_BOSS_ICE_SMASH_PLACEMENT_PATH_CONTROL) != 0) {
        (*gPathControlInterface)->init(&state->path, 0, DIM_BOSS_ICE_SMASH_PATH_INIT_FLAGS, 1);
        (*gPathControlInterface)
            ->setup(&state->path, 1, gDIMBossIceSmashPathPoint, gDIMBossIceSmashPathParams, pathParams);
        (*gPathControlInterface)->attachObject(obj, &state->path);
    }
}

void DIMBossIceSmash_release(void) {
}

void DIMBossIceSmash_initialise(void) {
}

ObjectDescriptor10WithPadding gDIMBossIceSmashObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)DIMBossIceSmash_initialise,
        (ObjectDescriptorCallback)DIMBossIceSmash_release,
        0,
        (ObjectDescriptorCallback)DIMBossIceSmash_init,
        (ObjectDescriptorCallback)DIMBossIceSmash_update,
        (ObjectDescriptorCallback)DIMBossIceSmash_hitDetect,
        (ObjectDescriptorCallback)DIMBossIceSmash_render,
        (ObjectDescriptorCallback)DIMBossIceSmash_free,
        (ObjectDescriptorCallback)DIMBossIceSmash_getObjectTypeId,
        DIMBossIceSmash_getExtraSize,
    },
    0,
};
