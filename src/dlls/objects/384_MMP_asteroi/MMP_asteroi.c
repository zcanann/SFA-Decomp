/*
 * MMP_asteroi (DLL 0x180) - Moon Mountain Pass asteroid re-entry object.
 *
 * Anim events control the asteroid's light, phase, and effect flags. Its
 * update callback drives the vertical wobble, looping sound, and particles.
 */
#include "dlls/objects/384_MMP_asteroi.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/sfx_channel_volume_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera_shake_api.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/lightmap_render_control_api.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/pad_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define MMP_ASTEROID_RE_ANIM_EVENT_LIGHTS_OFF        0
#define MMP_ASTEROID_RE_ANIM_EVENT_START_RISE        1
#define MMP_ASTEROID_RE_ANIM_EVENT_SWITCH_MODEL      2
#define MMP_ASTEROID_RE_ANIM_EVENT_ARM_PERIODIC_FX   3
#define MMP_ASTEROID_RE_ANIM_EVENT_START_CLEAR_TIMER 4

#define MMP_ASTEROID_RE_FX_SMOKE      0x01
#define MMP_ASTEROID_RE_EVENT_FLAG_04 0x04
#define MMP_ASTEROID_RE_FX_DEBRIS     0x08
#define MMP_ASTEROID_RE_FX_EXPLODE    0x10
#define MMP_ASTEROID_RE_FX_IMPACT     0x20
#define MMP_ASTEROID_RE_FX_PERIODIC   0x40
#define MMP_ASTEROID_RE_SEQ_TICK      0x80

#define MMP_ASTEROID_RE_PARTICLE_SMOKE           0x716
#define MMP_ASTEROID_RE_PARTICLE_DEBRIS          0x71A
#define MMP_ASTEROID_RE_PARTICLE_EXPLOSION       0x71B
#define MMP_ASTEROID_RE_PARTICLE_EXPLOSION_CHUNK 0x71C
#define MMP_ASTEROID_RE_PARTICLE_IMPACT          0x71D
#define MMP_ASTEROID_RE_PARTICLE_PERIODIC        0x71E
#define MMP_ASTEROID_RE_PARTICLE_DUST            0x722
#define MMP_ASTEROID_RE_PARTICLE_DUST_CLOUD      0x723
#define MMP_ASTEROID_RE_EXPLOSION_CHUNK_COUNT    0x28

#define MMP_ASTEROID_RE_PHASE_HIDDEN    0
#define MMP_ASTEROID_RE_PHASE_RISING    1
#define MMP_ASTEROID_RE_PHASE_RISEN     2
#define MMP_ASTEROID_RE_PHASE_UNKNOWN_3 3

#define MMP_ASTEROID_RE_PI          3.14159274f
#define MMP_ASTEROID_RE_SFX_CHANNEL 0x40

f32 gMMPAsteroidIntensityHeightTable[4] = {0.0f, 0.0f, 10.0f, 50.0f};
PartFxSpawnParams gMMPAsteroidDustSpawnParams;
int gMMPAsteroidDustHeightParam;

int mmpAsteroidRe_processAnimEvents(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate) {
    MMPAsteroidReState* state = obj->extra;
    int eventIndex;

    animUpdate->movementState = 0;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        u8 eventId = animUpdate->eventIds[eventIndex];

        switch (eventId) {
        case MMP_ASTEROID_RE_ANIM_EVENT_LIGHTS_OFF:
            setDrawLights(0);
            break;
        case MMP_ASTEROID_RE_ANIM_EVENT_START_RISE:
            state->eventFlags = MMP_ASTEROID_RE_FX_SMOKE | MMP_ASTEROID_RE_EVENT_FLAG_04 | MMP_ASTEROID_RE_FX_DEBRIS;
            state->phase = MMP_ASTEROID_RE_PHASE_RISING;
            mainSetBits(GAMEBIT_MMPAsteroidRelated087B, state->phase);
            obj->anim.alpha = 0xFF;
            break;
        case MMP_ASTEROID_RE_ANIM_EVENT_SWITCH_MODEL:
            state->eventFlags = state->eventFlags & ~(MMP_ASTEROID_RE_FX_SMOKE | MMP_ASTEROID_RE_FX_DEBRIS);
            state->eventFlags = state->eventFlags | (MMP_ASTEROID_RE_FX_EXPLODE | MMP_ASTEROID_RE_FX_IMPACT);
            ((ObjAnimComponent*)obj)->bankIndex = 1;
            break;
        case MMP_ASTEROID_RE_ANIM_EVENT_ARM_PERIODIC_FX: {
            int timer;

            state->eventFlags = state->eventFlags & ~MMP_ASTEROID_RE_FX_IMPACT;
            state->eventFlags = state->eventFlags | (MMP_ASTEROID_RE_FX_EXPLODE | MMP_ASTEROID_RE_FX_PERIODIC);
            timer = randomGetRange(10, 60);
            state->periodicFxTimer = timer;
            state->phase = MMP_ASTEROID_RE_PHASE_RISING;
            mainSetBits(GAMEBIT_MMPAsteroidRelated087B, state->phase);
            break;
        }
        case MMP_ASTEROID_RE_ANIM_EVENT_START_CLEAR_TIMER:
            state->gameBitClearTimer = 3600.0f;
            setDrawLights(1);
            break;
        }
    }
    state->eventFlags |= MMP_ASTEROID_RE_SEQ_TICK;
    mmpAsteroidRe_update(obj);
    return 0;
}

int mmpAsteroidRe_getExtraSize(void) {
    return sizeof(MMPAsteroidReState);
}

int mmpAsteroidRe_getObjectTypeId(void) {
    return 0;
}

void mmpAsteroidRe_free(void) {
}

void mmpAsteroidRe_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void mmpAsteroidRe_hitDetect(void) {
}

void mmpAsteroidRe_update(GameObject* obj) {
    MMPAsteroidReState* state = obj->extra;

    if ((state->eventFlags & MMP_ASTEROID_RE_SEQ_TICK) == 0) {
        if (mainGetBit(0xD52) != 0) {
            state->intensity = 1;
        } else {
            state->intensity = mainGetBit(0x88C);
        }
        state->phase = MMP_ASTEROID_RE_PHASE_RISEN;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_lwfl1_c);
        {
            int volume = state->intensity * 0x20 + 0x20;

            if (volume > 0x7F) {
                volume = 0x7F;
            }
            Sfx_SetObjectChannelVolume(obj, MMP_ASTEROID_RE_SFX_CHANNEL, volume, 0.5f);
        }
        if (state->intensity != 0) {
            f32 speed = obj->anim.velocityY;

            if (speed <
                0.1f * ((state->baseY + gMMPAsteroidIntensityHeightTable[state->intensity]) - obj->anim.localPosY)) {
                obj->anim.velocityY = 0.03f * timeDelta + speed;
            } else {
                obj->anim.velocityY = -(0.051f * timeDelta - speed);
            }
            state->bobPhase = 1024.0f * timeDelta + state->bobPhase;
            state->rollPhase = 875.0f * timeDelta + state->rollPhase;
            state->pitchPhase = 512.0f * timeDelta + state->pitchPhase;
            objMove(obj, 0.0f, obj->anim.velocityY * timeDelta, 0.0f);
            obj->anim.localPosY = obj->anim.localPosY + mathSinf((MMP_ASTEROID_RE_PI * state->bobPhase) / 32768.0f);
            if (obj->anim.localPosY < state->baseY) {
                obj->anim.localPosY = state->baseY;
            }
            obj->anim.rotZ =
                (s16)(obj->anim.rotZ + (int)(182.0f * mathSinf((MMP_ASTEROID_RE_PI * state->rollPhase) / 32768.0f)));
            obj->anim.rotY =
                (s16)(obj->anim.rotY + (int)(182.0f * mathSinf((MMP_ASTEROID_RE_PI * state->pitchPhase) / 32768.0f)));
            gMMPAsteroidDustSpawnParams.scale = 1.0f;
            gMMPAsteroidDustSpawnParams.posX = obj->anim.localPosX;
            gMMPAsteroidDustSpawnParams.posY = state->baseY - 55.0f;
            gMMPAsteroidDustSpawnParams.posZ = obj->anim.localPosZ;
            gMMPAsteroidDustHeightParam = (int)(obj->anim.localPosY - state->baseY);
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_DUST, NULL, 2, -1, &gMMPAsteroidDustHeightParam);
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_DUST_CLOUD, &gMMPAsteroidDustSpawnParams, 0x200001,
                              -1, &gMMPAsteroidDustHeightParam);
            (*gPartfxInterface)
                ->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_DUST_CLOUD, &gMMPAsteroidDustSpawnParams, 0x200001,
                              -1, &gMMPAsteroidDustHeightParam);
        }
    }
    if (state->eventFlags != 0) {
        if ((state->eventFlags & MMP_ASTEROID_RE_FX_SMOKE) != 0) {
            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_SMOKE, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_SMOKE, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_SMOKE, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & MMP_ASTEROID_RE_FX_DEBRIS) != 0) {
            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_DEBRIS, NULL, 2, -1, NULL);
        }
        if ((state->eventFlags & MMP_ASTEROID_RE_FX_EXPLODE) != 0) {
            int count;

            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_EXPLOSION, NULL, 1, -1, NULL);
            count = MMP_ASTEROID_RE_EXPLOSION_CHUNK_COUNT;
            do {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_EXPLOSION_CHUNK, NULL, 1, -1, NULL);
                count--;
            } while (count != 0);
            spawnExplosion(obj, 100.0f, 1, 1, 0, 1, 0, 1, 0);
            CameraShake_StartDampened(5.0f, 10.0f, 4.0f);
            {
                f32 rumble = 22.0f;
                doRumble(rumble);
            }
            state->eventFlags &= ~MMP_ASTEROID_RE_FX_EXPLODE;
        }
        if ((state->eventFlags & MMP_ASTEROID_RE_FX_IMPACT) != 0) {
            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_IMPACT, NULL, 1, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_IMPACT, NULL, 1, -1, NULL);
        }
        if ((state->eventFlags & MMP_ASTEROID_RE_FX_PERIODIC) != 0) {
            state->periodicFxTimer -= timeDelta;
            if (state->periodicFxTimer < 0.0f) {
                state->periodicFxTimer = randomGetRange(10, 0x3C);
                (*gPartfxInterface)->spawnObject((void*)obj, MMP_ASTEROID_RE_PARTICLE_PERIODIC, NULL, 1, -1, NULL);
            }
        }
    }
    {
        f32 timer = state->gameBitClearTimer;
        f32 zero = 0.0f;

        if (timer > zero) {
            state->gameBitClearTimer = timer - timeDelta;
            if (state->gameBitClearTimer <= zero) {
                mainSetBits(0x88B, 0);
            }
        }
    }
    state->eventFlags &= ~MMP_ASTEROID_RE_SEQ_TICK;
}

void mmpAsteroidRe_init(GameObject* obj) {
    MMPAsteroidReState* state = obj->extra;

    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->animEventCallback = mmpAsteroidRe_processAnimEvents;
    state->eventFlags = 0;
    state->intensity = mainGetBit(0x88C);
    state->phase = mainGetBit(GAMEBIT_MMPAsteroidRelated087B);
    switch ((s32)state->phase) {
    case MMP_ASTEROID_RE_PHASE_HIDDEN:
        obj->anim.alpha = 0;
        obj->anim.bankIndex = 0;
        break;
    case MMP_ASTEROID_RE_PHASE_RISING:
        obj->anim.alpha = 0xFF;
        state->eventFlags = MMP_ASTEROID_RE_EVENT_FLAG_04;
        obj->anim.bankIndex = 1;
        state->eventFlags |= MMP_ASTEROID_RE_FX_PERIODIC;
        break;
    case MMP_ASTEROID_RE_PHASE_RISEN:
        obj->anim.alpha = 0xFF;
        state->eventFlags = MMP_ASTEROID_RE_EVENT_FLAG_04;
        obj->anim.bankIndex = 1;
        break;
    case MMP_ASTEROID_RE_PHASE_UNKNOWN_3:
        obj->anim.alpha = 0xFF;
        state->eventFlags = MMP_ASTEROID_RE_EVENT_FLAG_04;
        obj->anim.bankIndex = 1;
        break;
    }
    {
        f32 baseY = obj->anim.localPosY;

        state->baseY = baseY;
        state->unknown10 = baseY;
    }
}

void mmpAsteroidRe_release(void) {
}

void mmpAsteroidRe_initialise(void) {
}

ObjectDescriptor gMMPAsteroidReObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmpAsteroidRe_initialise,
    (ObjectDescriptorCallback)mmpAsteroidRe_release,
    0,
    (ObjectDescriptorCallback)mmpAsteroidRe_init,
    (ObjectDescriptorCallback)mmpAsteroidRe_update,
    (ObjectDescriptorCallback)mmpAsteroidRe_hitDetect,
    (ObjectDescriptorCallback)mmpAsteroidRe_render,
    (ObjectDescriptorCallback)mmpAsteroidRe_free,
    (ObjectDescriptorCallback)mmpAsteroidRe_getObjectTypeId,
    mmpAsteroidRe_getExtraSize,
};
