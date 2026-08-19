/*
 * DLL 508 / 0x01FC - shared laser-beam hazard behavior.
 */
#include "dlls/objects/508.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "game/objects/object.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0081_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/player_api.h"
#include "main/dll/player_state.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/obj_message.h"
#include "main/resource.h"
#include "main/texture.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define LASERBEAM_MSG_PLAYER_HIT     0x60003
#define LASERBEAM_MSG_PLAYER_BURST   0x60004
#define LASERBEAM_PARTFX_HIT         0x198
#define LASERBEAM_MODGFX_RESOURCE_ID 0x81
#define LASERBEAM_TEXTURE_KIND30     0x3E9
#define LASERBEAM_TEXTURE_KIND1      0x23D
#define LASERBEAM_TEXTURE_DEFAULT    0xD9
#define LASERBEAM_EFFECT_SPAWN_FLAGS 0x10004
#define LASERBEAM_PLAYER_SLIDE_STATE 0x1D7
#define LASERBEAM_HIT_PARTICLE_COUNT 4
#define LASERBEAM_HIT_PARTICLE_MODE  4

int LaserBeam_getExtraSize(void) {
    return sizeof(LaserBeamState);
}

int LaserBeam_getObjectTypeId(void) {
    return 0;
}

void LaserBeam_free(GameObject* obj) {
    LaserBeamState* state;

    state = obj->extra;
    (*gModgfxInterface)->detachSource(obj);
    if (state->beamTexture != NULL) {
        textureFree(state->beamTexture);
        state->beamTexture = NULL;
    }
}

void LaserBeam_render(void) {
}

void LaserBeam_hitDetect(void) {
}

static const f32 gLaserBeamObjPi = 3.1415927f;
static const f32 gLaserBeamObjAngleToRadScale = 32768.0f;

Dll81Interface** gLaserBeamObjModgfxResource;

void LaserBeam_update(GameObject* obj) {
    const LaserBeamPlacementView* placement;
    LaserBeamState* state;
    GameObject* player;
    u8 beamKind;
    int particleIndex;
    int hitSfxId;
    f32 beamRange;
    f32 beamRangeSquared;
    f32 beamDirectionX;
    f32 beamDirectionZ;
    f32 heightThreshold;
    f32 beamPlane;
    f32 heightDelta;
    f32 xDelta;
    f32 zDelta;
    f32 lateralAbs;
    f32 damageDistance;
    f32 pushDistance;
    f32 zero;
    f32 hitStrength;

    placement = (const LaserBeamPlacementView*)obj->anim.placementData;
    state = obj->extra;
    state->cycleTimer -= framesThisStep;
    if (mainGetBit(placement->disableGameBit) == 0) {
        if (state->cycleTimer < 0) {
            if (state->beamBlocked == 0) {
                beamKind = state->beamKind;
                if (beamKind == 3 || beamKind == 30) {
                    state->cycleTimer = state->cyclePeriod;
                } else {
                    if (beamKind == 0 && state->effectHandle != -1) {
                        (*gModgfxInterface)->releaseHandle(&state->effectHandle);
                    }
                    state->cycleTimer = state->cyclePeriod;
                }
                state->beamVolumeScale = 0.0f;
            } else {
                state->cycleTimer = 150;
            }
            state->blastPhase = 0;
        } else if (state->cycleTimer < state->warmupThreshold) {
            if (state->blastPhase == 0) {
                state->blastPhase = 1;
                beamKind = state->beamKind;
                if (beamKind == 1) {
                    if (gLaserBeamObjModgfxResource != NULL) {
                        (*gLaserBeamObjModgfxResource)->spawn(obj, 2, NULL, LASERBEAM_EFFECT_SPAWN_FLAGS, -1, 0);
                    }
                } else if (beamKind != 30 && beamKind != 0) {
                    (*gLaserBeamObjModgfxResource)->spawn(obj, 0, NULL, LASERBEAM_EFFECT_SPAWN_FLAGS, -1, 0);
                }
            }
            if (state->cycleTimer < 0x28) {
                if (state->beamVolumeScale >= 0.0f && state->beamBlocked == 0) {
                    state->beamVolumeScale = -(0.0026f * timeDelta - state->beamVolumeScale);
                }
            } else if (state->cycleTimer < 0x8c) {
                if (state->blastPhase == 1) {
                    state->blastPhase = 2;
                    beamKind = state->beamKind;
                    if (beamKind == 1) {
                        if (gLaserBeamObjModgfxResource != NULL) {
                            (*gLaserBeamObjModgfxResource)
                                ->spawn(obj, 3, NULL, LASERBEAM_EFFECT_SPAWN_FLAGS, -1, 0);
                        }
                    } else if (beamKind == 30) {
                        if (gLaserBeamObjModgfxResource != NULL) {
                            state->effectHandle = (*gLaserBeamObjModgfxResource)
                                                      ->spawn(obj, 30, NULL, LASERBEAM_EFFECT_SPAWN_FLAGS, -1, 0);
                        }
                    } else if (beamKind != 0) {
                        if (gLaserBeamObjModgfxResource != NULL) {
                            (*gLaserBeamObjModgfxResource)
                                ->spawn(obj, 1, NULL, LASERBEAM_EFFECT_SPAWN_FLAGS, -1, 0);
                        }
                    } else if (gLaserBeamObjModgfxResource != NULL && state->effectHandle == -1) {
                        if (state->effectHandle != -1) {
                            (*gModgfxInterface)->releaseHandle(&state->effectHandle);
                        }
                        if (gLaserBeamObjModgfxResource != NULL) {
                            state->effectHandle =
                                (*gLaserBeamObjModgfxResource)
                                    ->spawn(obj, 0, NULL, LASERBEAM_EFFECT_SPAWN_FLAGS, -1, 0);
                        }
                    }
                }
            } else if (state->beamVolumeScale <= 1.0f) {
                state->beamVolumeScale = 0.052f * timeDelta + state->beamVolumeScale;
            }
        }
    } else if (state->beamKind == 0 && state->effectHandle != -1) {
        (*gModgfxInterface)->releaseHandle(&state->effectHandle);
    }
    beamRange = (f32)(int)placement->beamRange;
    beamRangeSquared = beamRange * beamRange;
    beamDirectionX = mathCosf((gLaserBeamObjPi * (f32)(int)obj->anim.rotX) / gLaserBeamObjAngleToRadScale);
    beamDirectionZ = mathSinf((gLaserBeamObjPi * (f32)(int)obj->anim.rotX) / gLaserBeamObjAngleToRadScale);
    beamPlane = -(obj->anim.localPosX * beamDirectionX + obj->anim.localPosZ * beamDirectionZ);
    player = Obj_GetPlayerObject();
    state->damageCooldown = state->damageCooldown - framesThisStep;
    if (state->damageCooldown <= 0) {
        state->damageCooldown = 0;
    } else if (state->beamKind == 0 && state->effectHandle != -1) {
        (*gModgfxInterface)->releaseHandle(&state->effectHandle);
    }
    if ((beamPlane + (beamDirectionX * player->anim.localPosX + beamDirectionZ * player->anim.localPosZ) > 0.0f &&
         state->beamKind != 2) ||
        state->beamKind == 30) {
        state->blockTimer -= framesThisStep;
        if (state->blockTimer < 0) {
            state->blockTimer = 0;
            state->beamBlocked = 0;
        }
    } else {
        state->blockTimer += framesThisStep;
        if (state->blockTimer > 60) {
            state->blockTimer = 60;
            state->beamBlocked = 1;
        }
    }
    if (state->beamBlocked == 0) {
        state->beamState = (u8)(state->blastPhase & 3);
    } else {
        state->beamState = 2;
    }
    if (mainGetBit(placement->disableGameBit) != 0) {
        state->beamState = 0;
    }
    if (state->damageCooldown == 0) {
        state->hitStrength = 0;
    }
    if (player != NULL && state->damageCooldown == 0 && state->beamState == 2) {
        heightThreshold = 5.0f + (f32)state->heightOffset;
        heightDelta = player->anim.localPosY - obj->anim.localPosY;
        if (heightDelta < heightThreshold && heightDelta > -(25.0f + heightThreshold)) {
            xDelta = player->anim.localPosX - obj->anim.localPosX;
            zDelta = player->anim.localPosZ - obj->anim.localPosZ;
            if (xDelta * xDelta + zDelta * zDelta < beamRangeSquared) {
                damageDistance =
                    beamPlane + (beamDirectionX * player->anim.localPosX + beamDirectionZ * player->anim.localPosZ);
                lateralAbs = damageDistance;
                if (damageDistance < 0.0f) {
                    lateralAbs = -damageDistance;
                }
                if (lateralAbs > 63.0f) {
                    lateralAbs = 63.0f;
                }
                hitStrength = 63.0f - lateralAbs;
                hitStrength = 2.0f * hitStrength;
                state->hitStrength = (s16)(int)hitStrength;
                if (!(damageDistance < 70.0f && damageDistance > -70.0f) && state->modgfxAttached == 1) {
                    (*gModgfxInterface)->detachSource(obj);
                    state->modgfxAttached = 0;
                }
                if (damageDistance < heightThreshold && damageDistance > -heightThreshold) {
                    if (objGetAnimState80A(player) == LASERBEAM_PLAYER_SLIDE_STATE && state->beamKind != 1) {
                        mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 1);
                    } else {
                        if (beamPlane + (beamDirectionX * player->anim.previousLocalPosX +
                                         beamDirectionZ * player->anim.previousLocalPosZ) <
                            0.0f) {
                            pushDistance = -20.0f;
                        } else {
                            pushDistance = 20.0f;
                        }
                        Sfx_PlayAtPositionFromObject(obj, player->anim.localPosX, obj->anim.localPosY,
                                                     player->anim.localPosZ, SFXTRIG_wp_fball2_c_1c9);
                        if (((PlayerState*)player->extra)->characterId == 0) {
                            hitSfxId = 31;
                        } else {
                            hitSfxId = 35;
                        }
                        Sfx_PlayFromObject(player, hitSfxId);
                        for (particleIndex = 0; particleIndex < LASERBEAM_HIT_PARTICLE_COUNT; particleIndex++) {
                            (*gPartfxInterface)
                                ->spawnObject(Obj_GetPlayerObject(), LASERBEAM_PARTFX_HIT, NULL,
                                              LASERBEAM_HIT_PARTICLE_MODE, -1, NULL);
                        }
                        state->knockbackTargetX = beamDirectionX * pushDistance + player->anim.localPosX;
                        state->knockbackTargetZ = beamDirectionZ * pushDistance + player->anim.localPosZ;
                        beamKind = state->beamKind;
                        if (beamKind == 0 || beamKind == 1) {
                            ObjMsg_SendToObject(player, LASERBEAM_MSG_PLAYER_HIT, (GameObject*)state->messagePayload,
                                                0);
                        } else if ((u8)(beamKind - 2) <= 1 || beamKind == 30) {
                            ObjMsg_SendToObject(player, LASERBEAM_MSG_PLAYER_BURST, (GameObject*)state->messagePayload,
                                                0);
                        }
                        state->damageCooldown = 2;
                    }
                }
            }
        }
    }
    if (state->beamState == 0) {
        if (state->beamKind == 30 && state->effectHandle != -1) {
            (*gModgfxInterface)->releaseHandle(&state->effectHandle);
        }
        if (state->modgfxAttached == 1) {
            (*gModgfxInterface)->detachSource(obj);
            state->modgfxAttached = 0;
        }
    }
    zero = 0.0f;
    state->beamY = zero;
    state->beamX = zero;
    state->beamZ = zero;
    state->beamY2 = state->beamY;
    state->beamX2 = state->beamX;
    state->beamZ2 = state->beamZ + beamRange;
    state->heightOffset = 8;
    obj->anim.currentMoveProgress = 0.04f * timeDelta + obj->anim.currentMoveProgress;
    if (obj->anim.currentMoveProgress > 1.0f) {
        obj->anim.currentMoveProgress = obj->anim.currentMoveProgress - 1.0f;
    }
}

void LaserBeam_init(GameObject* obj, const LaserBeamPlacementView* placement) {
    LaserBeamState* state;

    state = obj->extra;
    ObjMsg_AllocQueue(obj, 2);
    obj->anim.rotX = (s16)((s32)placement->initialYaw << 8);
    if (placement->cyclePeriod == 0) {
        state->cyclePeriod = (s16)(randomGetRange(-80, 80) + 400);
    } else {
        state->cyclePeriod = placement->cyclePeriod;
    }
    state->cycleTimer = state->cyclePeriod;
    state->blastPhase = 0;
    state->beamVolumeScale = 0.0f;
    state->beamKind = placement->beamKind;
    state->warmupThreshold = 0x118;
    state->effectHandle = -1;
    if (state->beamKind == 30) {
        if ((void*)state->beamTexture == NULL) {
            state->beamTexture = textureLoadAsset(LASERBEAM_TEXTURE_KIND30);
        }
    } else if (state->beamKind == 1) {
        if ((void*)state->beamTexture == NULL) {
            state->beamTexture = textureLoadAsset(LASERBEAM_TEXTURE_KIND1);
        }
    } else if ((void*)state->beamTexture == NULL) {
        state->beamTexture = textureLoadAsset(LASERBEAM_TEXTURE_DEFAULT);
    }
}

void LaserBeam_release(void) {
    Resource_Release(gLaserBeamObjModgfxResource);
    gLaserBeamObjModgfxResource = NULL;
}

void LaserBeam_initialise(void) {
    gLaserBeamObjModgfxResource = Resource_Acquire(LASERBEAM_MODGFX_RESOURCE_ID, 1);
}

ObjectDescriptor gLaserBeamObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    LaserBeam_initialise,
    LaserBeam_release,
    0,
    (ObjectDescriptorCallback)LaserBeam_init,
    (ObjectDescriptorCallback)LaserBeam_update,
    LaserBeam_hitDetect,
    LaserBeam_render,
    (ObjectDescriptorCallback)LaserBeam_free,
    (ObjectDescriptorCallback)LaserBeam_getObjectTypeId,
    LaserBeam_getExtraSize,
};
