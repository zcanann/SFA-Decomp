/*
 * DLL 0x19B (generated slot 411).
 *
 * This is a dynamically used Krazoa Test 1 controller. Retail OBJECTS.bin and
 * the root romlists do not associate the descriptor with a named object, so
 * the unit retains a numbered namespace.
 */
#include "dlls/objects/411.h"

#include "main/debug.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/dll_006A_modgfx.h"
#include "main/dll/dll_0083_modgfx.h"
#include "main/dll/dll_0084_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/render_envfx_api.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/dll/player_api.h"
#include "main/obj_message.h"

#define DLL19B_TARGET_OBJGROUP 0xE

#define DLL19B_ENVFX_A 0xC3
#define DLL19B_ENVFX_B 0x14

#define DLL19B_BRIGHTNESS_CHANNEL_A 2
#define DLL19B_BRIGHTNESS_CHANNEL_B 3
#define DLL19B_BRIGHTNESS_A_MIN     12
#define DLL19B_BRIGHTNESS_B_MIN     1
#define DLL19B_BRIGHTNESS_B_NEAR    30
#define DLL19B_BRIGHTNESS_MAX       70
#define DLL19B_BRIGHTNESS_EVENT     100
#define DLL19B_BRIGHTNESS_FADE_RATE (-3)
#define DLL19B_BRIGHTNESS_RISE_RATE 1

#define DLL19B_NEAREST_DISTANCE_INITIAL 1000.0f
#define DLL19B_NEAREST_DISTANCE_MAX     300.0f
#define DLL19B_NEAREST_DISTANCE_MIN     100.0f
#define DLL19B_DISTANCE_BLEND_SPAN      200.0f
#define DLL19B_RENDER_SCALE             1.0f

#define DLL19B_MESSAGE_FADE           0x30005
#define DLL19B_MESSAGE_LIGHT          0x30006
#define DLL19B_MESSAGE_LIGHT_RATE     0x10
#define DLL19B_MESSAGE_QUEUE_CAPACITY 4

#define DLL19B_RESOURCE_EFFECT_A    0x83
#define DLL19B_RESOURCE_EFFECT_B    0x84
#define DLL19B_RESOURCE_PARTICLE    0x6A
#define DLL19B_PARTICLE_SPAWN_FLAGS 0x402

#define DLL19B_SEQUENCE_START   0
#define DLL19B_SEQUENCE_RESOLVE 1
#define DLL19B_SEQUENCE_TIMEOUT 2

#define DLL19B_DEFAULT_ACTIVATION_DISTANCE 10
#define DLL19B_WAIT_EVENT_TIMER            160
#define DLL19B_RESOLVE_TIMER               200
#define DLL19B_INITIAL_DISPLAY_TIMER       200
#define DLL19B_UNKNOWN10_INITIAL           200
#define DLL19B_RESET_DELAY                 400
#define DLL19B_TIMEOUT_DELAY               10
#define DLL19B_COUNTDOWN_START             4000

typedef enum Dll19BAnimEvent {
    DLL19B_ANIM_EVENT_ENVFX_A = 1,
    DLL19B_ANIM_EVENT_ENVFX_OVERRIDE = 2,
    DLL19B_ANIM_EVENT_PENDING = 3,
    DLL19B_ANIM_EVENT_COMPLETE = 4,
    DLL19B_ANIM_EVENT_RESET = 5,
    DLL19B_ANIM_EVENT_GAMEBIT_01D2_SET = 6,
    DLL19B_ANIM_EVENT_GAMEBIT_01D2_CLEAR = 7,
    DLL19B_ANIM_EVENT_GAMEBIT_0127_SET = 8,
    DLL19B_ANIM_EVENT_GAMEBIT_0128_SET = 9,
    DLL19B_ANIM_EVENT_BRIGHTNESS = 11,
} Dll19BAnimEvent;

/* Engine-owned environment-effect override; this unit consumes its first word. */
u32 gDll19BShaderResult;

ObjectDescriptor gDll19BObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll411_initialise,
    (ObjectDescriptorCallback)dll411_release,
    NULL,
    (ObjectDescriptorCallback)dll411_init,
    (ObjectDescriptorCallback)dll411_update,
    (ObjectDescriptorCallback)dll411_hitDetect,
    (ObjectDescriptorCallback)dll411_render,
    (ObjectDescriptorCallback)dll411_free,
    (ObjectDescriptorCallback)dll411_getObjectTypeId,
    dll411_getExtraSize,
};

int dll411_processAnimEvents(GameObject* obj, int unusedArg, ObjSeqState* animUpdate) {
    Dll19BState* state;
    int eventIndex;

    (void)unusedArg;
    state = obj->extra;
    animUpdate->flags = -1;
    animUpdate->movementState = 0;

    if (state->brightnessBVelocity != 0) {
        state->brightnessB += state->brightnessBVelocity;
        if (state->brightnessB <= DLL19B_BRIGHTNESS_B_MIN && state->brightnessBVelocity <= 0) {
            state->brightnessB = DLL19B_BRIGHTNESS_B_MIN;
            state->brightnessBVelocity = 0;
        } else if (state->brightnessB >= DLL19B_BRIGHTNESS_MAX && state->brightnessBVelocity >= 0) {
            state->brightnessB = DLL19B_BRIGHTNESS_MAX;
            state->brightnessBVelocity = 0;
        }
        gTitleMenuControlInterface->vtable->func11(DLL19B_BRIGHTNESS_CHANNEL_B, (u8)state->brightnessB);
    }

    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++) {
        u8 eventId = animUpdate->eventIds[eventIndex];
        if (eventId != 0) {
            switch (eventId) {
            case DLL19B_ANIM_EVENT_ENVFX_A:
                getEnvfxAct(obj, obj, DLL19B_ENVFX_A, 0);
                break;
            case DLL19B_ANIM_EVENT_ENVFX_OVERRIDE:
                if (gSky2EnvfxActIndices[0] == -1) {
                    getEnvfxAct(obj, obj, DLL19B_ENVFX_B, 0);
                } else {
                    getEnvfxAct(obj, obj, gSky2EnvfxActIndices[0], 0);
                }
                break;
            case DLL19B_ANIM_EVENT_PENDING:
                state->pendingEvent = 1;
                break;
            case DLL19B_ANIM_EVENT_COMPLETE:
                state->phase = DLL19B_PHASE_COMPLETE;
                state->pendingEvent = 2;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                mainSetBits(GAMEBIT_WM_KrazTest1AnimState01D2, 0);
                mainSetBits(GAMEBIT_WM_KrazTest1Related0126, 1);
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_FADE_RATE;
                break;
            case DLL19B_ANIM_EVENT_RESET:
                state->phase = DLL19B_PHASE_RESET;
                state->pendingEvent = 3;
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_FADE_RATE;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                break;
            case DLL19B_ANIM_EVENT_GAMEBIT_01D2_SET:
                mainSetBits(GAMEBIT_WM_KrazTest1AnimState01D2, 1);
                break;
            case DLL19B_ANIM_EVENT_GAMEBIT_01D2_CLEAR:
                mainSetBits(GAMEBIT_WM_KrazTest1AnimState01D2, 0);
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_FADE_RATE;
                break;
            case DLL19B_ANIM_EVENT_GAMEBIT_0128_SET:
                mainSetBits(GAMEBIT_WM_KrazTest1Related0128, 1);
                if (gDll19BShaderResult == 0) {
                    gDll19BShaderResult = shaderReturnZeroStub(1);
                }
                break;
            case DLL19B_ANIM_EVENT_GAMEBIT_0127_SET:
                mainSetBits(GAMEBIT_TestStrengthTexScrollRelated127, 1);
                break;
            case DLL19B_ANIM_EVENT_BRIGHTNESS:
                state->brightnessB = DLL19B_BRIGHTNESS_EVENT;
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2d, 0x50, (u8)state->brightnessB, 0);
                break;
            }
        }
        animUpdate->eventIds[eventIndex] = 0;
    }
    return 0;
}

int dll411_getExtraSize(void) {
    return sizeof(Dll19BState);
}

int dll411_getObjectTypeId(void) {
    return 0;
}

void dll411_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource(obj);
}

void dll411_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, DLL19B_RENDER_SCALE);
    }
}

void dll411_hitDetect(void) {
}

char sDll411CountdownFormat[] = "time %d\n";

void dll411_update(GameObject* obj) {
    Dll19BState* state;
    GameObject* player;
    GameObject* nearestObject;
    Dll19BState* messageState;
    int value;
    f32 positionDelta;
    f32 distance;
    void* messageFlags;
    int messageId;
    GameObject* messageParam;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    distance = DLL19B_NEAREST_DISTANCE_INITIAL;
    messageState = obj->extra;
    messageFlags = 0;
    while (ObjMsg_Pop(obj, (u32*)&messageId, &messageParam, &messageFlags) != 0) {
        switch (messageId) {
        case DLL19B_MESSAGE_FADE:
            messageState->brightnessAVelocity = DLL19B_BRIGHTNESS_FADE_RATE;
            break;
        case DLL19B_MESSAGE_LIGHT:
            messageState->brightnessAVelocity = DLL19B_MESSAGE_LIGHT_RATE;
            break;
        }
    }
    mainSetBits(GAMEBIT_TestStrengthTexScrollRelated127, 1);
    if ((value = state->brightnessAVelocity) != 0) {
        state->brightnessA += (s16)value;
        if (state->brightnessA <= DLL19B_BRIGHTNESS_A_MIN) {
            state->brightnessA = DLL19B_BRIGHTNESS_A_MIN;
            state->brightnessAVelocity = 0;
        } else if (state->brightnessA >= DLL19B_BRIGHTNESS_MAX) {
            state->brightnessA = DLL19B_BRIGHTNESS_MAX;
            state->brightnessAVelocity = 0;
        }
        gTitleMenuControlInterface->vtable->func11(DLL19B_BRIGHTNESS_CHANNEL_A, state->brightnessA & 0xff);
    }
    if ((value = state->brightnessBVelocity) != 0) {
        state->brightnessB += (s16)value;
        if (state->brightnessB <= DLL19B_BRIGHTNESS_B_MIN && state->brightnessBVelocity <= 0) {
            state->brightnessB = DLL19B_BRIGHTNESS_B_MIN;
            state->brightnessBVelocity = 0;
        } else if (state->brightnessB >= DLL19B_BRIGHTNESS_MAX && state->brightnessBVelocity >= 0) {
            state->brightnessB = DLL19B_BRIGHTNESS_MAX;
            state->brightnessBVelocity = 0;
        }
        gTitleMenuControlInterface->vtable->func11(DLL19B_BRIGHTNESS_CHANNEL_B, state->brightnessB & 0xff);
    }
    if (state->timer > 0) {
        state->timer -= framesThisStep;
        if (state->timer <= 0) {
            state->timer = 0;
            if (state->timerDisplayTriggered == 0) {
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2c, 0x50, state->brightnessB, 0);
                state->timerDisplayTriggered = 1;
            }
        }
    } else {
        nearestObject = objGetNearestTypeTo(DLL19B_TARGET_OBJGROUP, player, &distance);
        if (nearestObject != NULL && distance < DLL19B_NEAREST_DISTANCE_MAX && distance > DLL19B_NEAREST_DISTANCE_MIN) {
            positionDelta = nearestObject->anim.localPosZ - player->anim.localPosZ;
            if (positionDelta <= 0.0f) {
                if (positionDelta < 0.0f) {
                    positionDelta *= -1.0f;
                }
                if (state->brightnessB != DLL19B_BRIGHTNESS_B_NEAR) {
                    state->brightnessB = DLL19B_BRIGHTNESS_B_NEAR;
                }
                value = (int)((f32)state->brightnessB *
                              ((positionDelta - DLL19B_NEAREST_DISTANCE_MIN) / DLL19B_DISTANCE_BLEND_SPAN));
                if ((s16)value < 1) {
                    value = 1;
                }
                gTitleMenuControlInterface->vtable->func11(DLL19B_BRIGHTNESS_CHANNEL_B, value & 0xff);
                value = (int)((f32)state->brightnessA *
                              ((DLL19B_DISTANCE_BLEND_SPAN - (positionDelta - DLL19B_NEAREST_DISTANCE_MIN)) /
                               DLL19B_DISTANCE_BLEND_SPAN));
                if ((s16)value < 1) {
                    value = 1;
                }
                gTitleMenuControlInterface->vtable->func11(DLL19B_BRIGHTNESS_CHANNEL_A, value & 0xff);
            }
        }
        switch (state->phase) {
        case DLL19B_PHASE_IDLE:
            if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < state->activationDistance) {
                state->phase = DLL19B_PHASE_WAIT_EVENT;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
                (*gObjectTriggerInterface)->runSequence(DLL19B_SEQUENCE_START, obj, -1);
                {
                    Dll83Interface** res = Resource_Acquire(DLL19B_RESOURCE_EFFECT_A, 1);
                    (*res)->spawn(obj, 1, NULL, 1, -1, NULL);
                    Resource_Release(res);
                }
                {
                    Dll84Interface** res = Resource_Acquire(DLL19B_RESOURCE_EFFECT_B, 1);
                    (*res)->spawn(obj, 0, NULL, 1, -1, NULL);
                    Resource_Release(res);
                }
                mainSetBits(GAMEBIT_WM_KrazTest1Related0126, 0);
                (*gModgfxInterface)->releaseHandle(&state->gfxHandle);
            }
            break;
        case DLL19B_PHASE_WAIT_EVENT:
            if (state->pendingEvent == 1) {
                state->phase = DLL19B_PHASE_COUNTDOWN;
                state->timer = DLL19B_WAIT_EVENT_TIMER;
            }
            break;
        case DLL19B_PHASE_COUNTDOWN:
            if (state->unlockCount == 0 && mainGetBit(GAMEBIT_WM_KrazTest1TorchesActive) == 0) {
                mainSetBits(GAMEBIT_WM_KrazTest1TorchesActive, 1);
            }
            if (mainGetBit(GAMEBIT_WM_KrazTest1TorchPulse) != 0) {
                state->unlockCount += 1;
                mainSetBits(GAMEBIT_WM_KrazTest1TorchPulse, 0);
            }
            state->countdown -= (s16)timeDelta;
            logPrintf(sDll411CountdownFormat, state->countdown);
            if (state->countdown <= 0) {
                mainSetBits(GAMEBIT_WM_KrazTest1TimedOut, 1);
                (*gObjectTriggerInterface)->runSequence(DLL19B_SEQUENCE_TIMEOUT, obj, -1);
                state->timer = DLL19B_TIMEOUT_DELAY;
                state->phase = DLL19B_PHASE_RESET;
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x35, 0x50, state->brightnessB & 0xff, 0);
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_RISE_RATE;
                mainSetBits(GAMEBIT_WM_KrazTest1TorchesActive, 0);
            } else if (state->unlockCount == 1) {
                state->phase = DLL19B_PHASE_RESOLVE;
                state->timer = DLL19B_RESOLVE_TIMER;
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_FADE_RATE;
            }
            break;
        case DLL19B_PHASE_RESOLVE:
            if (mainGetBit(GAMEBIT_WM_KrazTest1Solved) != 0) {
                state->brightnessB = 1;
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2c, 0x50, state->brightnessB & 0xff, 0);
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_RISE_RATE;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                state->phase = DLL19B_PHASE_DONE;
            } else {
                playerCancelSpell(player, -1);
                mainSetBits(GAMEBIT_WM_KrazTest1Related0126, 0);
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2a, 0x50, state->brightnessB & 0xff, 0);
                state->brightnessBVelocity = DLL19B_BRIGHTNESS_RISE_RATE;
                (*gObjectTriggerInterface)->runSequence(DLL19B_SEQUENCE_RESOLVE, obj, -1);
                state->phase = DLL19B_PHASE_COMPLETE;
            }
            break;
        case DLL19B_PHASE_COMPLETE:
            if (mainGetBit(GAMEBIT_WGSH_warpEnabled0FD) == 0) {
                mainSetBits(GAMEBIT_WGSH_warpEnabled0FD, 1);
            }
            mainSetBits(GAMEBIT_WM_KrazTest1AnimState01D2, 0);
            mainSetBits(GAMEBIT_TestStrengthTexScrollRelated127, 0);
            state->phase = DLL19B_PHASE_DONE;
            gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2c, 0x50, state->brightnessB & 0xff, 0);
            break;
        case DLL19B_PHASE_RESET:
            state->phase = DLL19B_PHASE_IDLE;
            state->pendingEvent = 0;
            state->timer = DLL19B_RESET_DELAY;
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
            mainSetBits(GAMEBIT_WM_KrazTest1Related0126, 1);
            mainSetBits(GAMEBIT_TestStrengthTexScrollRelated127, 1);
            {
                Dll6AInterface** handle = Resource_Acquire(DLL19B_RESOURCE_PARTICLE, 1);
                state->gfxHandle = (*handle)->spawn(obj, 2, NULL, DLL19B_PARTICLE_SPAWN_FLAGS, -1, NULL);
                Resource_Release(handle);
            }
            mainSetBits(GAMEBIT_WM_KrazTest1TorchPulse, 0);
            state->unlockCount = 0;
            state->countdown = DLL19B_COUNTDOWN_START;
            mainSetBits(GAMEBIT_WM_KrazTest1TimedOut, 0);
            break;
        }
    }
}

void dll411_init(GameObject* obj, const Dll19BPlacement* placement) {
    register Dll19BState* state;
    Dll6AInterface** particleResource;

    state = obj->extra;
    obj->anim.rotX = 0;
    state->activationDistance = DLL19B_DEFAULT_ACTIVATION_DISTANCE;
    if (placement->activationDistancePacked > 0) {
        state->activationDistance = (s16)(placement->activationDistancePacked >> 8);
    }
    state->phase = DLL19B_PHASE_IDLE;
    state->pendingEvent = 0;
    state->timer = 0;
    state->unlockCount = 0;
    obj->animEventCallback = dll411_processAnimEvents;
    ObjMsg_AllocQueue(obj, DLL19B_MESSAGE_QUEUE_CAPACITY);
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    mainSetBits(GAMEBIT_WM_KrazTest1AnimState01D2, 0);
    mainSetBits(GAMEBIT_WM_KrazTest1Related0126, 1);
    mainSetBits(GAMEBIT_TestStrengthTexScrollRelated127, 1);
    mainSetBits(GAMEBIT_STAFF_ABILITY_FIRE_BLASTER, 1);
    mainSetBits(GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE, 1);
    mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);
    mainSetBits(GAMEBIT_WM_KrazTest1TorchPulse, 0);
    state->brightnessA = DLL19B_BRIGHTNESS_A_MIN;
    state->brightnessB = DLL19B_BRIGHTNESS_B_NEAR;
    state->timer = DLL19B_INITIAL_DISPLAY_TIMER;
    gTitleMenuControlInterface->vtable->onSelectSave(2, 0x2b, 0x50, 1, 0);
    state->brightnessAVelocity = 0;
    state->brightnessBVelocity = 0;
    state->timerDisplayTriggered = 0;
    state->unknown10 = DLL19B_UNKNOWN10_INITIAL;
    state->countdown = DLL19B_COUNTDOWN_START;
    particleResource = Resource_Acquire(DLL19B_RESOURCE_PARTICLE, 1);
    state->gfxHandle = (*particleResource)->spawn(obj, 1, NULL, DLL19B_PARTICLE_SPAWN_FLAGS, -1, NULL);
    Resource_Release(particleResource);
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
}

void dll411_release(void) {
}

void dll411_initialise(void) {
}
