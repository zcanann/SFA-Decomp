/* Collapsing force-field barrier in CloudRunner Fortress. */

#include "dlls/objects/347_CFForceFiel.h"
#include "dolphin/mtx.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/maketex_timer_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

#define CFFORCEFIELD_SILENT_COLLAPSE_MAP_ID   0x47F5E
#define CFFORCEFIELD_COLLAPSE_FRAMES          60
#define CFFORCEFIELD_COLLAPSE_SCALE_PER_FRAME 0.016666668f
#define CFFORCEFIELD_RING_SPIN_STEP           512.0f
#define CFFORCEFIELD_PARTFX_FLAGS             0x200001
#define CFFORCEFIELD_PARTFX_MODEL_NONE        -1

f32 gCfForceFieldRingRadiusScale = 5.0f;
int gCfForceFieldRingJitter = 5;
int gCfForceFieldCollapseSpinStep = 0x200;

CfForceFieldEmitterConfig gCfForceFieldEmitters[CFFORCEFIELD_EMITTER_COUNT] = {
    {0x7A4, 0x7A5, 0x4000, 100, -0x1000, 1850.0f},
    {0x7A2, 0x7A3, 0x4000, 50, 0x1000, 732.0f},
    {0x7A2, 0x7A3, 0x4000, 50, 0x1000, 732.0f},
};

int cfforcefield_getExtraSize(void) {
    return sizeof(CfForceFieldState);
}

int cfforcefield_getObjectTypeId(void) {
    return 0;
}

void cfforcefield_free(void) {
}

void cfforcefield_render(void) {
}

void cfforcefield_hitDetect(void) {
}

void cfforcefield_update(GameObject* obj) {
    f32* phaseSpeedPtr;
    int* angleStepPtr;
    CfForceFieldEmitterConfig* emitter;
    int angle;
    CfForceFieldPlacement* placement;
    CfForceFieldState* state;
    int emitterIndex;
    f32 collapseTimeRemaining;
    int collapseTimerInactive;
    f32 collapseScale;
    f32 zero;
    f32 worldTransform[3][4];
    PartFxSpawnParams particleParams;
    f32 localPosition[3];

    placement = (CfForceFieldPlacement*)obj->anim.placement;
    state = obj->extra;
    zero = 0.0f;
    obj->anim.velocityZ = zero;
    obj->anim.velocityY = zero;
    obj->anim.velocityX = zero;

    if (mainGetBit(placement->activeGameBit) != 0) {
        if (!state->statusFlags.disabled) {
            emitterIndex = placement->effectStyle % CFFORCEFIELD_EMITTER_COUNT;
            collapseTimeRemaining = state->collapseTimer;
            collapseTimerInactive = (collapseTimeRemaining != zero);
            collapseTimerInactive = !collapseTimerInactive;
            if (collapseTimerInactive) {
                collapseScale = 1.0f;
            } else {
                collapseScale = CFFORCEFIELD_COLLAPSE_SCALE_PER_FRAME * collapseTimeRemaining;
            }

            Obj_BuildWorldTransformMatrix(obj, (f32*)worldTransform, 0);
            obj->anim.rotZ = (s16)(CFFORCEFIELD_RING_SPIN_STEP * timeDelta + (f32)obj->anim.rotZ);

            angle = -0x7fff;
            emitter = &gCfForceFieldEmitters[emitterIndex];
            phaseSpeedPtr = &emitter->spiralPhaseSpeed;
            angleStepPtr = &emitter->spiralAngleStep;
            for (; angle < 0x7fff; angle += *angleStepPtr) {
                localPosition[0] = randomGetRange(-gCfForceFieldRingJitter, gCfForceFieldRingJitter) +
                                   10.0f * (collapseScale * gCfForceFieldRingRadiusScale) *
                                       mathCosf(3.1415927f * (f32)(angle + (int)(100.0f * *phaseSpeedPtr)) / 32768.0f);
                localPosition[1] = randomGetRange(-gCfForceFieldRingJitter, gCfForceFieldRingJitter) +
                                   10.0f * (collapseScale * gCfForceFieldRingRadiusScale) *
                                       mathSinf(3.1415927f * (f32)(angle + (int)(100.0f * *phaseSpeedPtr)) / 32768.0f);
                localPosition[2] = 0.0f;
                PSMTXMultVecSR((MtxPtr)worldTransform, (Vec*)localPosition, (Vec*)localPosition);
                particleParams.posX = localPosition[0] + obj->anim.localPosX;
                particleParams.posY = localPosition[1] + obj->anim.localPosY;
                particleParams.posZ = localPosition[2] + obj->anim.localPosZ;
                (*gPartfxInterface)
                    ->spawnObject(obj, emitter->spiralEffectId, &particleParams, CFFORCEFIELD_PARTFX_FLAGS,
                                  CFFORCEFIELD_PARTFX_MODEL_NONE, &obj->anim.velocity);
                (*gPartfxInterface)
                    ->spawnObject(obj, emitter->spiralEffectId, &particleParams, CFFORCEFIELD_PARTFX_FLAGS,
                                  CFFORCEFIELD_PARTFX_MODEL_NONE, &obj->anim.velocity);
                (*gPartfxInterface)
                    ->spawnObject(obj, emitter->spiralEffectId, &particleParams, CFFORCEFIELD_PARTFX_FLAGS,
                                  CFFORCEFIELD_PARTFX_MODEL_NONE, &obj->anim.velocity);
            }

            if (timerIsActive(&state->collapseTimer) != 0) {
                obj->anim.rotY = (s16)((f32)gCfForceFieldCollapseSpinStep * timeDelta + (f32)obj->anim.rotY);
                if (timerCountDown(&state->collapseTimer) != 0) {
                    state->statusFlags.disabled = 1;
                    obj->anim.rotY = 0;
                }
            } else if (mainGetBit(placement->collapseGameBit) != 0) {
                s16toFloat(&state->collapseTimer, CFFORCEFIELD_COLLAPSE_FRAMES);
                Sfx_PlayFromObject(obj, SFXTRIG_en_littletink22);
                if (((CfForceFieldPlacement*)obj->anim.placement)->base.ident != CFFORCEFIELD_SILENT_COLLAPSE_MAP_ID) {
                    Sfx_PlayFromObject(obj, SFXTRIG_sc_menuups16k_409);
                }
            }
        } else {
            state->statusFlags.disabled = mainGetBit(placement->collapseGameBit);
        }
    }
}

void cfforcefield_init(GameObject* obj, CfForceFieldPlacement* placement) {
    register CfForceFieldState* state = obj->extra;
    {
        s8 rotXByte = placement->rotXByte;
        s16 rotX = rotXByte << 8;
        obj->anim.rotX = rotX;
    }
    state->statusFlags.disabled = mainGetBit(placement->collapseGameBit);
    storeZeroToFloatParam(&state->collapseTimer);
}

void cfforcefield_release(void) {
}

void cfforcefield_initialise(void) {
}

ObjectDescriptor gCFForceFieldObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)cfforcefield_initialise,
    (ObjectDescriptorCallback)cfforcefield_release,
    0,
    (ObjectDescriptorCallback)cfforcefield_init,
    (ObjectDescriptorCallback)cfforcefield_update,
    (ObjectDescriptorCallback)cfforcefield_hitDetect,
    (ObjectDescriptorCallback)cfforcefield_render,
    (ObjectDescriptorCallback)cfforcefield_free,
    (ObjectDescriptorCallback)cfforcefield_getObjectTypeId,
    cfforcefield_getExtraSize,
};
