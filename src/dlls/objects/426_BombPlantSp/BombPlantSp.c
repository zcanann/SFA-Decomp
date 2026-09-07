/*
 * BombPlantSp (DLL 0x1AA) - the bomb-spore projectile spawned by BombPlant.
 *
 * A surface hit shortens the fuse. Player contact starts the pickup-message
 * handshake; otherwise the spore detonates when its fuse expires.
 */
#include "dlls/objects/426_BombPlantSp.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/path_control_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gameloop_gamebit_api.h"
#include "main/model_light.h"
#include "main/obj_message.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"

#define BOMB_PLANT_SPORE_MESSAGE_IN_RANGE 0x7000A
#define BOMB_PLANT_SPORE_MESSAGE_DETONATE 0x7000B

#define BOMB_PLANT_SPORE_PATH_CONTACT_MASK 0x11
#define BOMB_PLANT_SPORE_PATH_FLAGS        0x40002
#define BOMB_PLANT_SPORE_PATH_PARAM        5

#define BOMB_PLANT_SPORE_EXPLOSION_PARTICLE_COUNT 10
#define BOMB_PLANT_SPORE_MESSAGE_QUEUE_LENGTH     2

/* Burst spawned per particle on detonation. */
#define BOMB_PLANT_SPORE_PARTFX_EXPLOSION 0x3F3
/* Effect spawned once when the spore is created. */
#define BOMB_PLANT_SPORE_PARTFX_SPAWN 0x3F1

/* Retail OBJECTS.bin remap aliases ignored as friendly/contact objects. */
#define BOMB_PLANT_SPORE_BOMB_PLANT_ALIAS_ID   0x36D
#define BOMB_PLANT_SPORE_GROUND_QUAKE_ALIAS_ID 0x63C

STATIC_ASSERT(sizeof(BombPlantSporeFlags) == 1);


u8 gBombPlantSporePathSetupData[8] = {0x40, 0xA0, 0, 0, 0, 0, 0, 0};
f32 gBombPlantSporePathPointData[3] = {0.0f, 0.0f, 0.0f};

extern f32 gBombPlantSporeLightAttenuationNear;
extern const f32 gBombPlantSporeLightAttenuationFar;

int BombPlantSpore_getExtraSize(void) {
    return sizeof(BombPlantSporeState);
}

void BombPlantSpore_free(GameObject* obj) {
    BombPlantSporeState* state;
    ModelLightStruct* light;

    state = obj->extra;
    (*gExpgfxInterface)->freeSource((u32)obj);
    light = state->light;
    if (light != NULL) {
        ModelLightStruct_free(light);
        state->light = NULL;
    }
}

void BombPlantSpore_startDriftBurst(GameObject* obj, BombPlantSporeState* state) {
    s16 baseAngle;
    BombPlantSporePlacement* placement;
    s32 angleDelta;

    placement = (BombPlantSporePlacement*)obj->anim.placementData;
    baseAngle = placement->behavior.baseAngle;

    state->spinTimer = randomGetRange(0x1E, 0x2D);

    state->driftTimer = state->spinTimer + randomGetRange(0x78, 0xB4);

    state->burstDriftAngle = (s16)(state->currentSpinAngle + randomGetRange(-2000, 2000));
    angleDelta = (s32)state->burstDriftAngle - (u16)baseAngle;
    if (angleDelta > 0x8000) {
        angleDelta -= 0xFFFF;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xFFFF;
    }
    if (angleDelta > placement->behavior.angleSpread) {
        state->burstDriftAngle = (s16)(baseAngle + placement->behavior.angleSpread);
    }
    if (angleDelta < -(s32)placement->behavior.angleSpread) {
        state->burstDriftAngle = (s16)(baseAngle - placement->behavior.angleSpread);
    }

    state->driftSpeedTarget = randomGetRange(900, 0x514) / 1000.0f;
    state->driftSpeed = 0.0f;

    state->driftSin = mathSinf((3.1415927f * (f32)state->burstDriftAngle) / 32768.0f);
    state->driftCos = mathCosf((3.1415927f * (f32)state->burstDriftAngle) / 32768.0f);
}

void BombPlantSpore_updateDrift(GameObject* obj, BombPlantSporeState* state) {
    s16 baseAngle;
    BombPlantSporePlacement* placement;
    s32 angleDelta;

    placement = (BombPlantSporePlacement*)obj->anim.placementData;
    baseAngle = placement->behavior.baseAngle;

    if (randomGetRange(0, 100) < 10 && state->spinChangeTimer <= 0.0f) {
        state->spinAngle = randomGetRange(2000, 4000);
        if (randomGetRange(0, 1) != 0) {
            state->spinAngle = -state->spinAngle;
        }
        state->spinAngle += state->currentSpinAngle;
        angleDelta = (s32)state->spinAngle - (u16)baseAngle;
        if (angleDelta > 0x8000) {
            angleDelta -= 0xFFFF;
        }
        if (angleDelta < -0x8000) {
            angleDelta += 0xFFFF;
        }
        if (angleDelta > placement->behavior.angleSpread) {
            state->spinAngle = (s16)(baseAngle + placement->behavior.angleSpread);
        }
        if (angleDelta < -(s32)placement->behavior.angleSpread) {
            state->spinAngle = (s16)(baseAngle - placement->behavior.angleSpread);
        }
        state->spinChangeTimer = 150.0f;
    }

    if (randomGetRange(0, 100) < 10 && state->spinChangeTimer <= 0.0f) {
        state->driftAmplitudeTarget =
            state->driftAmplitude + randomGetRange(-200, 200) / 1000.0f;
        if (state->driftAmplitudeTarget < 0.5f) {
            state->driftAmplitudeTarget = 0.5f;
        } else if (state->driftAmplitudeTarget > 1.0f) {
            state->driftAmplitudeTarget = 1.0f;
        }
    }

    angleDelta = (s32)state->spinAngle - (u16)state->currentSpinAngle;
    if (angleDelta > 0x8000) {
        angleDelta -= 0xFFFF;
    }
    if (angleDelta < -0x8000) {
        angleDelta += 0xFFFF;
    }
    state->currentSpinAngle += (angleDelta * framesThisStep) >> 4;
    {
        f32 amplitude;
        f32 amplitudeStep = (state->driftAmplitudeTarget - (amplitude = state->driftAmplitude)) *
                            0.006f;
        state->driftAmplitude = amplitudeStep * timeDelta + amplitude;
    }

    state->driftBaseX = state->driftAmplitude *
                        mathSinf((3.1415927f * (f32)state->currentSpinAngle) / 32768.0f);
    state->driftBaseZ = state->driftAmplitude *
                        mathCosf((3.1415927f * (f32)state->currentSpinAngle) / 32768.0f);
}

void BombPlantSpore_update(GameObject* obj) {
    BombPlantSporeState* state;
    s32 particleAlpha;
    s16 hitId;
    GameObject* contactObj;
    int poppedMessage;
    u32 poppedSender;
    GameObject* hitObject;
    GameObject* player;
    int i;
    int j;

    state = obj->extra;
    if (state->flags.waitingForDetonateAck != 0) {
        while (ObjMsg_Pop(obj, (u32*)&poppedMessage, &poppedSender, NULL) != 0) {
            switch (poppedMessage) {
            case BOMB_PLANT_SPORE_MESSAGE_DETONATE:
                gameBitIncrement(GAMEBIT_ITEM_BombSpore_Count);
                Sfx_PlayFromObject(obj, SFXTRIG_sc_gemrun0122);
                (*gExpgfxInterface)->freeSource((u32)obj);
                for (i = 0; i < BOMB_PLANT_SPORE_EXPLOSION_PARTICLE_COUNT; i++) {
                    objfx_spawnDirectionalBurst(obj, 5, 1.0f, 7, 1, 0x3C,
                                                1.5f, NULL, 0);
                    (*gPartfxInterface)->spawnObject(obj, BOMB_PLANT_SPORE_PARTFX_EXPLOSION, NULL, 4, -1, NULL);
                }
                modelLightStruct_setEnabled(state->light, 0, 0.5f);
                state->detonateTimer = 200.0f;
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
                state->flags.waitingForDetonateAck = 0;
                break;
            }
        }
        if (state->flags.waitingForDetonateAck != 0) {
            return;
        }
    }

    {
        f32 zero = 0.0f;
        if (state->detonateTimer != zero) {
            obj->anim.rotX += framesThisStep * 0x40;
            state->detonateTimer -= timeDelta;
            if (state->detonateTimer <= zero) {
                Obj_FreeObject(obj);
            }
            return;
        }
    }

    {
        f32 fuse = state->fuseTimer;
        f32 fuseCap = 120.0f;
        if (fuse < fuseCap) {
            particleAlpha = (s32)(30.0f - 0.25f * fuse);
            objfx_spawnDirectionalBurst(obj, 5, 1.0f, 7, 1, particleAlpha & 0xFF,
                                        (f32)(0.041 * (double)(fuseCap - fuse) +
                                              1.5),
                                        NULL, 0);
        }
    }
    ObjHits_GetPriorityHit(obj, &hitObject, 0, 0);
    contactObj = *(GameObject**)obj->anim.hitReactState;
    if (state->flags.hitSurface == 0) {
        state->driftTimer -= timeDelta;
        if (state->driftTimer < 0.0f) {
            state->driftTimer = 0.0f;
        }
        state->spinChangeTimer -= timeDelta;
        if (state->spinChangeTimer < 0.0f) {
            state->spinChangeTimer = 0.0f;
        }
        obj->anim.rotX += state->yawStep;
        obj->anim.velocityY = -0.009f * timeDelta + obj->anim.velocityY;
        if (obj->anim.velocityY < -0.2f) {
            obj->anim.velocityY = -0.2f;
        }
        if (obj->anim.velocityY > 0.0f) {
            obj->anim.velocityY *= 0.97f;
        }
        if (obj->anim.velocityY < 0.0f) {
            ObjHits_EnableObject(obj);
        }
        BombPlantSpore_updateDrift(obj, state);
        if (randomGetRange(0, 100) < 5 && state->driftTimer <= 0.0f) {
            BombPlantSpore_startDriftBurst(obj, state);
        }
        {
            f32 st = state->spinTimer - timeDelta;
            state->spinTimer = st;
            if (st <= 0.0f) {
                state->driftSin *= 0.97f;
                state->driftCos *= 0.97f;
                state->spinTimer = 0.0f;
            } else {
                f32 driftSpeed;
                f32 driftStep = (state->driftSpeedTarget - (driftSpeed = state->driftSpeed)) *
                                0.01f;
                state->driftSpeed = driftStep * timeDelta + driftSpeed;
            }
        }
        obj->anim.velocityX = state->driftSin * state->driftSpeed + state->driftBaseX;
        obj->anim.velocityZ = state->driftCos * state->driftSpeed + state->driftBaseZ;
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
        (*gPathControlInterface)->update(obj, &state->path, timeDelta);
        (*gPathControlInterface)->apply(obj, &state->path);
        (*gPathControlInterface)->advance(obj, &state->path, timeDelta);
        if (contactObj != NULL && (hitId = contactObj->anim.romDefNo, hitId != BOMB_PLANT_SPORE_BOMB_PLANT_ALIAS_ID) &&
            hitId != BOMB_PLANT_SPORE_OBJECT_ID && hitId != BOMB_PLANT_SPORE_GROUND_QUAKE_ALIAS_ID) {
            Sfx_PlayFromObject(obj, SFXTRIG_sc_eatthefood16);
            state->flags.hitSurface = 1;
            if (state->fuseTimer > 120.0f) {
                state->fuseTimer = 120.0f;
            }
        }
        if (((s8)state->path.surfaceFlags & BOMB_PLANT_SPORE_PATH_CONTACT_MASK) != 0) {
            state->flags.hitSurface = 1;
            if (state->fuseTimer > 120.0f) {
                state->fuseTimer = 120.0f;
            }
        }
    }
    player = Obj_GetPlayerObject();
    if (contactObj == player) {
        state->pickupMsgBitId = GAMEBIT_SawBombSpore;
        ObjMsg_SendToObject(contactObj, BOMB_PLANT_SPORE_MESSAGE_IN_RANGE, obj, (u32)state);
        state->flags.waitingForDetonateAck = 1;
    } else {
        f32 fuse = state->fuseTimer - timeDelta;
        state->fuseTimer = fuse;
        if (fuse <= 0.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_en_majring2);
            (*gExpgfxInterface)->freeSource((u32)obj);
            for (j = 0; j < BOMB_PLANT_SPORE_EXPLOSION_PARTICLE_COUNT; j++) {
                objfx_spawnDirectionalBurst(obj, 5, 1.0f, 7, 1, 0x3C,
                                            1.5f, NULL, 0);
                (*gPartfxInterface)->spawnObject(obj, BOMB_PLANT_SPORE_PARTFX_EXPLOSION, NULL, 4, -1, NULL);
            }
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
            state->detonateTimer = 200.0f;
            obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
        }
    }
}

void BombPlantSpore_init(GameObject* obj, BombPlantSporePlacement* placement) {
    BombPlantSporeState* state;
    ModelLightStruct* light;
    u8 pathParam[8];

    (void)placement;

    state = obj->extra;
    pathParam[0] = BOMB_PLANT_SPORE_PATH_PARAM;
    state->fuseTimer = 1500.0f;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->anim.velocityY = 2.0f;
    ObjHits_DisableObject(obj);
    state->spinAngle = randomGetRange(0, 0xFFFF);

    state->driftAmplitudeTarget = randomGetRange(0, 1000) / 1000.0f;

    (*gPathControlInterface)->init(&state->path, 0, BOMB_PLANT_SPORE_PATH_FLAGS, 1);
    (*gPathControlInterface)
        ->setup(&state->path, 1, gBombPlantSporePathPointData, gBombPlantSporePathSetupData, pathParam);
    (*gPathControlInterface)->attachObject(obj, &state->path);
    (*gPartfxInterface)->spawnObject(obj, BOMB_PLANT_SPORE_PARTFX_SPAWN, NULL, 4, -1, NULL);

    light = objCreateLight(obj, 1);
    if (light != NULL) {
        modelLightStruct_setLightKind(light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(light, 0xFF, 0, 0xFF, 0);
        modelLightStruct_setFieldBC(light, 1);
        modelLightStruct_setDistanceAttenuation(light, gBombPlantSporeLightAttenuationNear,
                                                gBombPlantSporeLightAttenuationFar);
    }
    state->light = light;
    ObjMsg_AllocQueue(obj, BOMB_PLANT_SPORE_MESSAGE_QUEUE_LENGTH);
    state->yawStep = randomGetRange(-0x200, 0x200);
}

ObjectDescriptor10WithPadding gBombPlantSporeObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        0,
        0,
        0,
        (ObjectDescriptorCallback)BombPlantSpore_init,
        (ObjectDescriptorCallback)BombPlantSpore_update,
        0,
        0,
        (ObjectDescriptorCallback)BombPlantSpore_free,
        0,
        BombPlantSpore_getExtraSize,
    },
    0,
};
