/*
 * SB_ShipGun (DLL 0x1EC) - one of the two deck cannons on General Scales'
 * galleon in the ShipBattle prologue (SB = the retail "ShipBattle" map).
 * While the player chases the galleon on the Cloudrunner the gun tracks the
 * bird, fires aimed cannonballs (SB_CannonBall) in volleys, takes damage in
 * two stages, then runs an explosion + smoke death sequence (the wreck is
 * then drawn by the SB_ShipGunBroke prop). Both guns are shot out, then the
 * propellers, then both guns again, to bring the galleon down.
 *
 * Lifecycle is a small state machine in state->phase (SBShipGunState +0xA):
 *   0  idle, waiting on the parent Galleon's "wake" condition
 *   2  active: aim at the Cloudrunner, fire timed cannonball volleys, react
 *      to ObjHits damage (two damage thresholds knock the gun toward death)
 *   3  death trigger: spawn explosion (or skip straight to smoke)
 *   4  exploded: emit smoke from the path point each frame
 *   5  smoldering: like 4 but can re-arm if the Galleon re-enters its
 *      fast-fire phase
 * The gun caches the ridden CloudRunner in state->cloudRunner and reads its
 * parent Galleon's phase through the Galleon DLL's interface vtable.
 */
#include "dlls/objects/492_SB_ShipGun.h"

#include "dlls/objects/488_SB_Galleon.h"
#include "dlls/objects/494_SB_CannonBa.h"
#include "dlls/objects/504_WM_Galleon.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/expgfx_interface.h"
#include "main/dll/objfx_api.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/object_transform.h"
#include "main/obj_list.h"
#include "main/obj_path.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/vec_types.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define SB_SHIPGUN_CLOUDRUNNER_ALIAS_OBJECT_TYPE 0x008C
#define SB_SHIPGUN_GALLEON_ALIAS_OBJECT_TYPE     0x008E

#define SB_SHIPGUN_START_HEALTH            2
#define SB_SHIPGUN_WAKE_DELAY              60
#define SB_SHIPGUN_FIRST_DAMAGE_HIT_COUNT  4
#define SB_SHIPGUN_SECOND_DAMAGE_HIT_COUNT 8
#define SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE 3
#define SB_SHIPGUN_VOLLEY_SIZE             3
#define SB_SHIPGUN_FIRE_DELAY_VARIANCE     40
#define SB_SHIPGUN_SLOW_FIRE_DELAY         120
#define SB_SHIPGUN_FAST_FIRE_DELAY         80
#define SB_SHIPGUN_CANNONBALL_LIFETIME     120

#define SB_SHIPGUN_CANNONBALL_COLOR_RED   2
#define SB_SHIPGUN_CANNONBALL_COLOR_GREEN 1
#define SB_SHIPGUN_CANNONBALL_COLOR_BLUE  0xFF
#define SB_SHIPGUN_CANNONBALL_COLOR_ALPHA 0xFF
#define SB_SHIPGUN_CANNONBALL_SETUP_FLAGS 5

#define SB_SHIPGUN_HIT_REACT_TYPE    0x0F
#define SB_SHIPGUN_HIT_REACT_POWER   200
#define SB_SHIPGUN_HIT_SFX           0x36
#define SB_SHIPGUN_SECOND_DAMAGE_SFX 0x3A
#define SB_SHIPGUN_FIRE_SFX          0x3C
#define SB_SHIPGUN_LOOP_SFX_CHANNEL  0x40
#define SB_SHIPGUN_NEAR_RANGE_SFX    0x312

#define SB_SHIPGUN_SMOKE_PARTICLE_ID   0x7AA
#define SB_SHIPGUN_SMOKE_SPAWN_ARG3    0x0C0A
#define SB_SHIPGUN_SMOKE_PARTICLE_MODE 2

int SB_ShipGun_getExtraSize(void) {
    return sizeof(SBShipGunState);
}

void SB_ShipGun_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void SB_ShipGun_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    GameObject* parent;
    SBShipGunState* state;
    s32 isVisible;

    state = obj->extra;
    parent = obj->anim.parent;
    if (parent != NULL) {
        if (parent->anim.romDefNo == WM_GALLEON_OBJECT_ID) {
            return;
        }
    }
    isVisible = visible;
    if (isVisible == 0 || state->health == 0 || state->active == 0) {
        return;
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

enum {
    SB_SHIPGUN_PHASE_IDLE = 0,
    SB_SHIPGUN_PHASE_ACTIVE = 2,
    SB_SHIPGUN_PHASE_DEATH_TRIGGER = 3,
    SB_SHIPGUN_PHASE_EXPLODED = 4,
    SB_SHIPGUN_PHASE_SMOLDERING = 5
};

/* Elevation clamp in binary-angle units. */
#define SB_SHIPGUN_MAX_PITCH 8000

void SB_ShipGun_update(GameObject* obj) {
    s8 phase;
    f32 spawnAdvance;
    GameObject* player;
    GameObject** objects;
    GameObject* cloudRunner;
    GameObject* galleon;
    SBShipGunState* state;
    int galleonStage;
    int hasPriorityHit;
    u32 randDelay;
    GameObject* cannonball;
    int galleonPhase;
    SBShipGunPlacementView* placement;
    ObjPlacement* cannonballSetup;
    PartFxSpawnParams spawnArgs;
    Vec3f offset;
    f32 posX;
    f32 posY;
    f32 posZ;
    int listStart;
    int listCount;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 distance;
    int i;

    player = Obj_GetPlayerObject();
    state = obj->extra;
    placement = (SBShipGunPlacementView*)obj->anim.placementData;
    if (((GameObject*)obj->anim.parent)->anim.romDefNo == WM_GALLEON_OBJECT_ID) {
        ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
        state->active = 0;
    } else {
        if (state->cloudRunner == NULL) {
            /* Find and cache the ridden CloudRunner. */
            objects = ObjList_GetObjects(&listStart, &listCount);
            for (i = listStart; i < listCount; i = i + 1) {
                cloudRunner = objects[i];
                if (cloudRunner->anim.romDefNo == SB_SHIPGUN_CLOUDRUNNER_ALIAS_OBJECT_TYPE) {
                    state->cloudRunner = cloudRunner;
                    i = listCount;
                }
            }
        }
        galleon = obj->anim.parent;
        if (((void*)galleon != NULL) && (galleon->anim.romDefNo == SB_SHIPGUN_GALLEON_ALIAS_OBJECT_TYPE)) {
            galleonStage = SB_GALLEON_VTBL(galleon)->getStage(galleon);
        } else {
            galleonStage = 0;
            state->phase = SB_SHIPGUN_PHASE_EXPLODED;
        }
        state->active = 1;
        phase = state->phase;
        switch (phase) {
        case SB_SHIPGUN_PHASE_IDLE:
            if (((void*)galleon != NULL) && SB_GALLEON_VTBL(galleon)->getPhase(galleon) == 0) {
                if (placement->noWakeDelay == 0) {
                    state->phase = SB_SHIPGUN_PHASE_ACTIVE;
                    state->fireTimer = SB_SHIPGUN_WAKE_DELAY;
                } else {
                    state->phase = SB_SHIPGUN_PHASE_ACTIVE;
                    state->fireTimer = 0;
                }
            }
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            break;
        case SB_SHIPGUN_PHASE_ACTIVE: {
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
            galleonPhase = SB_GALLEON_VTBL(galleon)->getPhase(galleon);
            if ((galleonPhase == 0) && (hasPriorityHit = ObjHits_GetPriorityHit(obj, 0, 0, 0), hasPriorityHit != 0)) {
                Obj_SetModelColorFadeRecursive(obj, SB_SHIPGUN_HIT_REACT_TYPE, SB_SHIPGUN_HIT_REACT_POWER, 0, 0, 1);
                Sfx_PlayFromObject(obj, SB_SHIPGUN_HIT_SFX);
                state->hitCount += 1;
                if (state->hitCount == SB_SHIPGUN_FIRST_DAMAGE_HIT_COUNT) {
                    state->health -= 1;
                    state->phase = SB_SHIPGUN_PHASE_DEATH_TRIGGER;
                    if ((void*)galleon != NULL) {
                        SB_GALLEON_VTBL(galleon)->onPartDestroyed(galleon);
                    }
                } else if (state->hitCount == SB_SHIPGUN_SECOND_DAMAGE_HIT_COUNT) {
                    Sfx_PlayFromObject(obj, SB_SHIPGUN_SECOND_DAMAGE_SFX);
                    state->health -= 1;
                    state->phase = SB_SHIPGUN_PHASE_DEATH_TRIGGER;
                    if ((void*)galleon != NULL) {
                        SB_GALLEON_VTBL(galleon)->onPartDestroyed(galleon);
                    }
                }
            }
            if (((void*)galleon != NULL) && (galleonPhase != 0)) {
                state->phase = SB_SHIPGUN_PHASE_DEATH_TRIGGER;
            }
            deltaX = player->anim.worldPosX - obj->anim.worldPosX;
            deltaZ = player->anim.worldPosZ - obj->anim.worldPosZ;
            state->yawAngle = (s16)(((u32)(u16)getAngle(-deltaZ, deltaX) & 0xFFFF) << 1);
            deltaY = player->anim.worldPosY - obj->anim.worldPosY;
            distance = sqrtf(deltaX * deltaX + deltaZ * deltaZ);
            state->pitchAngle = getAngle(-deltaY, distance);
            if (state->pitchAngle > SB_SHIPGUN_MAX_PITCH) {
                state->pitchAngle = SB_SHIPGUN_MAX_PITCH;
            } else if (state->pitchAngle < -SB_SHIPGUN_MAX_PITCH) {
                state->pitchAngle = -SB_SHIPGUN_MAX_PITCH;
            }
            state->fireTimer -= framesThisStep;
            if ((state->fireTimer < 0) && ((u8)Obj_CanSetupObject() != 0)) {
                Obj_GetWorldPosition(obj, &posX, &posY, &posZ);
                spawnArgs.posX = 0.0f;
                spawnArgs.posY = 0.0f;
                spawnArgs.posZ = 0.0f;
                spawnArgs.scale = 1.0f;
                spawnArgs.rotX = state->yawAngle;
                spawnArgs.rotY = 0;
                spawnArgs.rotZ = 0;
                offset.x = 100.0f;
                offset.y = 135.0f;
                offset.z = 0.0f;
                vecRotateZXY(&spawnArgs.rotX, &offset.x);
                cannonballSetup = Obj_AllocObjectSetup(sizeof(ObjPlacement), SB_CANNONBALL_ALIAS_OBJECT_TYPE);
                cannonballSetup->posX = posX;
                cannonballSetup->posY = posY;
                cannonballSetup->posZ = posZ;
                cannonballSetup->color[0] = SB_SHIPGUN_CANNONBALL_COLOR_RED;
                cannonballSetup->color[1] = SB_SHIPGUN_CANNONBALL_COLOR_GREEN;
                cannonballSetup->color[2] = SB_SHIPGUN_CANNONBALL_COLOR_BLUE;
                cannonballSetup->color[3] = SB_SHIPGUN_CANNONBALL_COLOR_ALPHA;
                cannonball =
                    objSetupObject(cannonballSetup, SB_SHIPGUN_CANNONBALL_SETUP_FLAGS, 0xffffffff, 0xffffffff, 0);
                cloudRunner = state->cloudRunner;
                deltaX = cloudRunner->anim.worldPosX - obj->anim.worldPosX;
                deltaY = cloudRunner->anim.worldPosY - (obj->anim.worldPosY - 25.0f);
                deltaZ = cloudRunner->anim.worldPosZ - obj->anim.worldPosZ;
                posX = sqrtf(deltaZ * deltaZ + (deltaX * deltaX + deltaY * deltaY));
                posX = 10.0f / posX;
                cannonball->anim.velocityX = deltaX * posX;
                cannonball->anim.velocityY = deltaY * posX;
                cannonball->anim.velocityZ = deltaZ * posX;
                spawnAdvance = 8.0f;
                cannonball->anim.localPosX = spawnAdvance * cannonball->anim.velocityX + cannonball->anim.localPosX;
                cannonball->anim.localPosY = spawnAdvance * cannonball->anim.velocityY + cannonball->anim.localPosY;
                cannonball->anim.localPosZ = spawnAdvance * cannonball->anim.velocityZ + cannonball->anim.localPosZ;
                cannonball->anim.rotX = getAngle(cannonball->anim.velocityX, cannonball->anim.velocityZ);
                cannonball->userData1 = SB_SHIPGUN_CANNONBALL_LIFETIME;
                cannonball->userData2 = (int)state->cloudRunner;
                CameraShake_Enable();
                CameraShake_SetOffset(0.1f);
                Sfx_PlayFromObject(obj, SB_SHIPGUN_FIRE_SFX);
                state->volleyCount += 1;
                if (state->volleyCount == SB_SHIPGUN_VOLLEY_SIZE) {
                    if (galleonStage >= SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE) {
                        randDelay = randomGetRange(0, SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                        state->fireTimer = randDelay + SB_SHIPGUN_FAST_FIRE_DELAY;
                    } else {
                        randDelay = randomGetRange(0, SB_SHIPGUN_FIRE_DELAY_VARIANCE);
                        state->fireTimer = randDelay + SB_SHIPGUN_SLOW_FIRE_DELAY;
                    }
                    state->volleyCount = 0;
                } else if (galleonStage >= SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE) {
                    state->fireTimer = SB_SHIPGUN_FAST_FIRE_DELAY;
                } else {
                    state->fireTimer = SB_SHIPGUN_SLOW_FIRE_DELAY;
                }
            }
            break;
        }
        case SB_SHIPGUN_PHASE_DEATH_TRIGGER:
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            if (state->health == 0) {
                spawnExplosion(obj, 100.0f, 1, 1, 1, 0, 1, 1, 0);
                state->phase = SB_SHIPGUN_PHASE_EXPLODED;
            } else {
                state->phase = SB_SHIPGUN_PHASE_SMOLDERING;
            }
            break;
        case SB_SHIPGUN_PHASE_EXPLODED: {
            spawnArgs.scale = 2.0f;
            spawnArgs.arg3 = SB_SHIPGUN_SMOKE_SPAWN_ARG3;
            ObjPath_GetPointWorldPosition(obj, 0, &spawnArgs.posX, &spawnArgs.posY, &spawnArgs.posZ, 0);
            spawnArgs.posX = spawnArgs.posX - obj->anim.worldPosX;
            spawnArgs.posY = spawnArgs.posY - obj->anim.worldPosY;
            spawnArgs.posZ = spawnArgs.posZ - obj->anim.worldPosZ;
            for (i = 0; i < (int)(u32)framesThisStep; i = i + 1) {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, SB_SHIPGUN_SMOKE_PARTICLE_ID, &spawnArgs, SB_SHIPGUN_SMOKE_PARTICLE_MODE,
                                  -1, NULL);
            }
            break;
        }
        case SB_SHIPGUN_PHASE_SMOLDERING:
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            if (((void*)galleon != NULL) && SB_GALLEON_VTBL(galleon)->getPhase(galleon) == 0) {
                if (placement->noWakeDelay == 0) {
                    if (SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE <= galleonStage) {
                        state->phase = SB_SHIPGUN_PHASE_ACTIVE;
                        state->fireTimer = SB_SHIPGUN_WAKE_DELAY;
                    }
                } else if (SB_SHIPGUN_FAST_FIRE_GALLEON_STAGE <= galleonStage) {
                    state->phase = SB_SHIPGUN_PHASE_ACTIVE;
                    state->fireTimer = 0;
                }
            }
            spawnArgs.scale = 2.0f;
            spawnArgs.arg3 = SB_SHIPGUN_SMOKE_SPAWN_ARG3;
            ObjPath_GetPointWorldPosition(obj, 0, &spawnArgs.posX, &spawnArgs.posY, &spawnArgs.posZ, 0);
            spawnArgs.posX = spawnArgs.posX - obj->anim.worldPosX;
            spawnArgs.posY = spawnArgs.posY - obj->anim.worldPosY;
            spawnArgs.posZ = spawnArgs.posZ - obj->anim.worldPosZ;
            for (i = 0; i < (int)(u32)framesThisStep; i = i + 1) {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, SB_SHIPGUN_SMOKE_PARTICLE_ID, &spawnArgs, SB_SHIPGUN_SMOKE_PARTICLE_MODE,
                                  -1, NULL);
            }
            break;
        }
        if (state->health == 0) {
            distance = Vec_distance(&player->anim.worldPosX, &obj->anim.worldPosX);
            if (distance < 200.0f) {
                Sfx_PlayFromObject(obj, SB_SHIPGUN_NEAR_RANGE_SFX);
            } else {
                Sfx_StopObjectChannel(obj, SB_SHIPGUN_LOOP_SFX_CHANNEL);
            }
        }
    }
}

void SB_ShipGun_init(GameObject* obj) {
    SBShipGunState* state;

    state = obj->extra;
    state->active = 0;
    state->health = SB_SHIPGUN_START_HEALTH;
    state->volleyCount = 0;
}

ObjectDescriptor gSB_ShipGunObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)SB_ShipGun_init,
    (ObjectDescriptorCallback)SB_ShipGun_update,
    0,
    (ObjectDescriptorCallback)SB_ShipGun_render,
    (ObjectDescriptorCallback)SB_ShipGun_free,
    0,
    SB_ShipGun_getExtraSize,
};
