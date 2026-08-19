/*
 * DFSH_LaserB (DLL 0x17B) - the shrine's sweeping/pulsing laser-beam
 * hazard: it tracks the player, animates beam geometry and texture,
 * drives SFX channels, and handles proximity damage.
 */
#include "dlls/objects/379_DFSH_LaserB.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_0081_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/obj_message.h"
#include "main/resource.h"
#include "main/texture.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define DFSH_LASER_BEAM_TEXTURE_ID         0x2E
#define DFSH_LASER_BEAM_EFFECT_RESOURCE_ID 0x81
#define DFSH_LASER_BEAM_MSG_PLAYER_HIT     0x60003
#define DFSH_LASER_BEAM_SFX_CHANNEL        0x40
#define DFSH_LASER_BEAM_PLAYER_SLIDE_STATE 0x1D7
#define DFSH_LASER_BEAM_HIT_PARTICLE_ID    0x28B
#define DFSH_LASER_BEAM_HIT_PARTICLE_COUNT 4
#define DFSH_LASER_BEAM_HIT_PARTICLE_MODE  4

Dll81Interface** gDFSHLaserBeamEffectResource;

int dfshLaserBeam_getExtraSize(void) {
    return sizeof(DFSHLaserBeamState);
}

int dfshLaserBeam_getObjectTypeId(void) {
    return 0;
}

void dfshLaserBeam_free(GameObject* obj) {
    DFSHLaserBeamState* state = obj->extra;

    (*gModgfxInterface)->detachSource(obj);
    Resource_Release(gDFSHLaserBeamEffectResource);
    gDFSHLaserBeamEffectResource = NULL;
    if (state->beamTexture != NULL) {
        textureFree(state->beamTexture);
    }
    state->beamTexture = NULL;
}

void dfshLaserBeam_render(void) {
}

void dfshLaserBeam_hitDetect(void) {
}

void dfshLaserBeam_update(GameObject* obj) {
    const DFSHLaserBeamPlacement* placement;
    DFSHLaserBeamState* state;
    GameObject* player;
    f32 beamRange;
    f32 beamRangeSq;
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

    placement = (const DFSHLaserBeamPlacement*)obj->anim.placementData;
    state = obj->extra;

    state->cycleTimer -= framesThisStep;
    if (mainGetBit(placement->disableGameBit) == 0) {
        if (state->cycleTimer < 0) {
            if (state->beamBlocked == 0) {
                state->cycleTimer = 0x190;
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_78);
                state->beamVolumeScale = 0.0f;
            } else {
                state->cycleTimer = 0x113;
            }
            state->blastPhase = 0;
        } else if (state->cycleTimer < state->warmupThreshold) {
            if (state->blastPhase == 0) {
                Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_79);
                if (state->beamBlocked == 0) {
                    Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_77);
                }
                state->blastPhase = 1;
                if (gDFSHLaserBeamEffectResource != NULL) {
                    (*gDFSHLaserBeamEffectResource)->spawn(obj, 10, NULL, 0x10004, -1, 0);
                }
            }
            if (state->cycleTimer < 0x28) {
                Sfx_StopObjectChannel(obj, DFSH_LASER_BEAM_SFX_CHANNEL);
                if ((state->beamVolumeScale >= 0.0f) && (state->beamBlocked == 0)) {
                    state->beamVolumeScale -= 0.0026000000070780516f * timeDelta;
                }
            } else if (state->cycleTimer < 0x8C) {
                if (state->blastPhase == 1) {
                    state->blastPhase = 2;
                    if (gDFSHLaserBeamEffectResource != NULL) {
                        (*gDFSHLaserBeamEffectResource)->spawn(obj, 0xB, NULL, 0x10004, -1, 0);
                    }
                }
            } else if (state->beamVolumeScale <= 1.0f) {
                state->beamVolumeScale += 0.052000001072883606f * timeDelta;
            }
        }
    }

    if (state->beamState != 0) {
        Sfx_SetObjectChannelVolume(obj, DFSH_LASER_BEAM_SFX_CHANNEL, 127.0f * state->beamVolumeScale, 0.5f);
    }

    beamRange = (f32)(int)placement->beamRange;
    beamRangeSq = beamRange * beamRange;
    beamDirectionX = mathCosf((3.1415927f * obj->anim.rotX) / 32768.0f);
    beamDirectionZ = mathSinf((3.1415927f * obj->anim.rotX) / 32768.0f);
    beamPlane = -(obj->anim.localPosX * beamDirectionX + obj->anim.localPosZ * beamDirectionZ);
    player = Obj_GetPlayerObject();

    state->damageCooldown = state->damageCooldown - framesThisStep;
    if (state->damageCooldown < 0) {
        state->damageCooldown = 0;
    }

    damageDistance = beamPlane + (beamDirectionX * player->anim.localPosX + beamDirectionZ * player->anim.localPosZ);
    if ((state->proximityMode == 1) || ((damageDistance > 0.0f) && (state->proximityMode != 0))) {
        state->blockTimer -= framesThisStep;
        if (state->blockTimer < 0) {
            state->blockTimer = 0;
            state->beamBlocked = 0;
        }
    } else {
        state->blockTimer += framesThisStep;
        if (state->blockTimer > 0x3C) {
            state->blockTimer = 0x3C;
            state->beamBlocked = 1;
        }
    }

    if (state->beamBlocked == 0) {
        state->beamState = state->blastPhase & 3;
    } else {
        state->beamState = 1;
    }
    if (mainGetBit(placement->disableGameBit) != 0) {
        state->beamState = 0;
    }

    if (state->damageCooldown == 0) {
        state->hitStrength = 0;
    }
    if (((player != NULL) && (state->damageCooldown == 0)) && (state->beamState != 0)) {
        heightThreshold = 5.0f + (f32)(int)state->heightOffset;
        heightDelta = player->anim.localPosY - obj->anim.localPosY;
        if ((heightDelta < heightThreshold) && (heightDelta > -(25.0f + heightThreshold))) {
            xDelta = player->anim.localPosX - obj->anim.localPosX;
            zDelta = player->anim.localPosZ - obj->anim.localPosZ;
            if ((xDelta * xDelta + zDelta * zDelta) < beamRangeSq) {
                damageDistance =
                    beamPlane + (beamDirectionX * player->anim.localPosX + beamDirectionZ * player->anim.localPosZ);
                lateralAbs = damageDistance;
                if (damageDistance < 0.0f) {
                    lateralAbs = -damageDistance;
                }
                if (lateralAbs > 63.0f) {
                    lateralAbs = 63.0f;
                }
                lateralAbs = 63.0f - lateralAbs;
                state->hitStrength = (s16)(int)(2.0f * lateralAbs);
                if (state->modgfxAttached == 1) {
                    (*gModgfxInterface)->detachSource(obj);
                    state->modgfxAttached = 0;
                }
                if ((damageDistance < heightThreshold) && (damageDistance > -heightThreshold)) {
                    pushDistance = ((beamPlane + (beamDirectionX * player->anim.previousLocalPosX +
                                                  beamDirectionZ * player->anim.previousLocalPosZ)) < 0.0f)
                                       ? -20.0f
                                       : 20.0f;
                    if (objGetAnimState80A(player) != DFSH_LASER_BEAM_PLAYER_SLIDE_STATE) {
                        int i;

                        Sfx_PlayFromObject(obj, SFXTRIG_wp_espk2_c);
                        for (i = 0; i < DFSH_LASER_BEAM_HIT_PARTICLE_COUNT; i++) {
                            (*gPartfxInterface)
                                ->spawnObject(Obj_GetPlayerObject(), DFSH_LASER_BEAM_HIT_PARTICLE_ID, NULL,
                                              DFSH_LASER_BEAM_HIT_PARTICLE_MODE, -1, NULL);
                        }
                        state->knockbackTargetX = beamDirectionX * pushDistance + player->anim.localPosX;
                        state->knockbackTargetZ = beamDirectionZ * pushDistance + player->anim.localPosZ;
                        if ((state->proximityMode == 0) || (state->proximityMode == 1)) {
                            ObjMsg_SendToObject(player, DFSH_LASER_BEAM_MSG_PLAYER_HIT,
                                                (GameObject*)state->messagePayload, 0);
                        }
                        state->damageCooldown = 0x14;
                    } else {
                        mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 1);
                    }
                }
            }
        }
    }

    if ((state->beamState == 0) && (state->modgfxAttached == 1)) {
        (*gModgfxInterface)->detachSource(obj);
        state->modgfxAttached = 0;
    }

    state->beamZ = state->beamX = state->beamY = 0.0f;
    state->beamY2 = state->beamY;
    state->beamX2 = state->beamX;
    state->beamZ2 = state->beamZ + beamRange;
    state->heightOffset = 8;
    obj->anim.currentMoveProgress += 0.04f * timeDelta;
    if (obj->anim.currentMoveProgress > 1.0f) {
        obj->anim.currentMoveProgress -= 1.0f;
    }
}

void dfshLaserBeam_init(GameObject* obj, const DFSHLaserBeamPlacement* placement) {
    DFSHLaserBeamState* state;
    int timer;

    state = obj->extra;
    ObjMsg_AllocQueue(obj, 2);
    obj->anim.rotX = (s16)((s32)placement->initialYaw << 8);
    timer = randomGetRange(-0x50, 0x50);
    state->cycleTimer = (s16)(timer + 0x190);
    state->blastPhase = 0;
    gDFSHLaserBeamEffectResource = Resource_Acquire(DFSH_LASER_BEAM_EFFECT_RESOURCE_ID, 1);
    state->beamVolumeScale = 0.0f;
    state->proximityMode = placement->proximityMode;
    state->warmupThreshold = 0x118;
    if (state->beamTexture == NULL) {
        state->beamTexture = textureLoadAsset(DFSH_LASER_BEAM_TEXTURE_ID);
    }
}

void dfshLaserBeam_release(void) {
}

void dfshLaserBeam_initialise(void) {
}

ObjectDescriptor gDFSHLaserBeamObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfshLaserBeam_initialise,
    (ObjectDescriptorCallback)dfshLaserBeam_release,
    0,
    (ObjectDescriptorCallback)dfshLaserBeam_init,
    (ObjectDescriptorCallback)dfshLaserBeam_update,
    (ObjectDescriptorCallback)dfshLaserBeam_hitDetect,
    (ObjectDescriptorCallback)dfshLaserBeam_render,
    (ObjectDescriptorCallback)dfshLaserBeam_free,
    (ObjectDescriptorCallback)dfshLaserBeam_getObjectTypeId,
    dfshLaserBeam_getExtraSize,
};
