#include "dlls/objects/409.h"

#include "dolphin/pad.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/dll/dll_006A_modgfx.h"
#include "main/dll/dll_0083_modgfx.h"
#include "main/dll/dll_0084_modgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/pad.h"
#include "main/render_envfx_api.h"
#include "main/resource.h"
#include "main/shader_api.h"
#include "main/vecmath_distance_api.h"
#include "sys/objects.h"
#include "main/obj_message.h"
#include "sys/objects/lifecycle.h"

#define DLL199_TARGET_OBJECT_GROUP  0xE
#define DLL199_SPAWNED_OBJECT_GROUP 0x3

#define DLL199_MAP_EVENT_ID     0xB
#define DLL199_MAP_EVENT_ACTION 6

#define DLL199_ENVFX_A 0xC3
#define DLL199_ENVFX_B 0x14

#define DLL199_GAMEBIT_00FD 0xFD
#define DLL199_GAMEBIT_0126 0x126
#define DLL199_GAMEBIT_0127 0x127
#define DLL199_GAMEBIT_0128 0x128
#define DLL199_GAMEBIT_01CD 0x1CD
#define DLL199_GAMEBIT_01CE 0x1CE
#define DLL199_GAMEBIT_01CF 0x1CF
#define DLL199_GAMEBIT_01E7 0x1E7
#define DLL199_GAMEBIT_0594 0x594
#define DLL199_GAMEBIT_05B2 0x5B2
#define DLL199_GAMEBIT_05B5 0x5B5
#define DLL199_GAMEBIT_05B9 0x5B9

#define DLL199_MESSAGE_DECREASE_CHANNEL_2 0x30005
#define DLL199_MESSAGE_INCREASE_CHANNEL_2 0x30006

u32 gDll199Event9Result;

ObjectDescriptor gDll199ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll409_initialise,
    (ObjectDescriptorCallback)dll409_release,
    0,
    (ObjectDescriptorCallback)dll409_init,
    (ObjectDescriptorCallback)dll409_update,
    (ObjectDescriptorCallback)dll409_hitDetect,
    (ObjectDescriptorCallback)dll409_render,
    (ObjectDescriptorCallback)dll409_free,
    (ObjectDescriptorCallback)dll409_getObjectTypeId,
    dll409_getExtraSize,
};

int dll409_processAnimEvents(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    Dll199State* state;
    int i;
    u8 eventId;

    state = obj->extra;
    animUpdate->savedFlags = -1;
    animUpdate->movementState = 0;
    if (state->channel3BrightnessDelta != 0) {
        state->channel3Brightness += state->channel3BrightnessDelta;
        if (state->channel3Brightness <= 1 && state->channel3BrightnessDelta <= 0) {
            state->channel3Brightness = 1;
            state->channel3BrightnessDelta = 0;
        } else if (state->channel3Brightness >= 0x46 && state->channel3BrightnessDelta >= 0) {
            state->channel3Brightness = 0x46;
            state->channel3BrightnessDelta = 0;
        }
        gTitleMenuControlInterface->vtable->func11(3, state->channel3Brightness & 0xFF);
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        eventId = animUpdate->eventIds[i];
        if (eventId != 0) {
            switch (eventId) {
            case 0xB:
                state->phase = 7;
                break;
            case 1:
                getEnvfxAct(obj, obj, DLL199_ENVFX_A, 0);
                break;
            case 2:
                if (gSky2EnvfxActIndices[0] == -1) {
                    getEnvfxAct(obj, obj, DLL199_ENVFX_B, 0);
                } else {
                    getEnvfxAct(obj, obj, gSky2EnvfxActIndices[0], 0);
                }
                break;
            case 3:
                state->sequenceEventState = 1;
                break;
            case 4:
                state->phase = 4;
                state->sequenceEventState = 2;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                mainSetBits(DLL199_GAMEBIT_01CF, 0);
                mainSetBits(DLL199_GAMEBIT_0126, 1);
                state->channel3BrightnessDelta = -3;
                break;
            case 5:
                state->sequenceEventState = 3;
                state->channel3BrightnessDelta = -3;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                break;
            case 6:
                mainSetBits(DLL199_GAMEBIT_01CF, 1);
                break;
            case 7:
                mainSetBits(DLL199_GAMEBIT_01CF, 0);
                state->channel3BrightnessDelta = -3;
                break;
            case 9:
                mainSetBits(DLL199_GAMEBIT_0128, 1);
                if (gDll199Event9Result == 0) {
                    gDll199Event9Result = shaderReturnZeroStub(1);
                }
                break;
            case 8:
                mainSetBits(DLL199_GAMEBIT_0127, 1);
                break;
            case 10:
                state->channel3Brightness = 100;
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2D, 0x50, state->channel3Brightness & 0xFF, 0);
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    switch ((int)state->phase) {
    case 7:
        if ((getButtonsHeld(0) & PAD_BUTTON_A) != 0u) {
            (*gObjectTriggerInterface)->endSequence(animUpdate->slot);
            state->phase = 8;
            state->actionTimer = 0;
        } else if ((getButtonsHeld(0) & PAD_BUTTON_B) != 0u) {
            (*gObjectTriggerInterface)->endSequence(animUpdate->slot);
            state->phase = 7;
            state->actionTimer = 0;
        }
        break;
    }
    return 0;
}

int dll409_getExtraSize(void) {
    return sizeof(Dll199State);
}

int dll409_getObjectTypeId(void) {
    return 0;
}

void dll409_free(GameObject* obj) {
    (*gModgfxInterface)->detachSource(obj);
    gTitleMenuControlInterface->vtable->func11(3, 0);
    gTitleMenuControlInterface->vtable->func11(2, 0);
}

void dll409_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    s32 isVisible = visible;

    if (isVisible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dll409_hitDetect(void) {
}

void dll409_update(GameObject* obj) {
    Dll199State* state;
    GameObject* player;
    GameObject* found;
    f32 dist;
    void* flags;
    u32 msg;
    GameObject* param;
    f32 dz;
    u32 brightness;
    int delta;
    Dll199State* msgState;

    state = obj->extra;
    player = Obj_GetPlayerObject();
    dist = 1000.0f;
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
    msgState = obj->extra;
    flags = 0;
    while (ObjMsg_Pop(obj, &msg, &param, &flags) != 0) {
        switch (msg) {
        case DLL199_MESSAGE_DECREASE_CHANNEL_2:
            msgState->channel2BrightnessDelta = -3;
            break;
        case DLL199_MESSAGE_INCREASE_CHANNEL_2:
            msgState->channel2BrightnessDelta = 0x10;
            break;
        }
    }
    mainSetBits(DLL199_GAMEBIT_0127, 1);
    delta = state->channel2BrightnessDelta;
    if (delta != 0) {
        state->channel2Brightness += (s16)delta;
        if (state->channel2Brightness <= 0xC) {
            state->channel2Brightness = 0xC;
            state->channel2BrightnessDelta = 0;
        } else if (state->channel2Brightness >= 0x46) {
            state->channel2Brightness = 0x46;
            state->channel2BrightnessDelta = 0;
        }
        gTitleMenuControlInterface->vtable->func11(2, state->channel2Brightness & 0xFF);
    }
    delta = state->channel3BrightnessDelta;
    if (delta != 0) {
        state->channel3Brightness += (s16)delta;
        if ((state->channel3Brightness <= 1) && (state->channel3BrightnessDelta <= 0)) {
            state->channel3Brightness = 1;
            state->channel3BrightnessDelta = 0;
        } else if ((state->channel3Brightness >= 0x46) && (state->channel3BrightnessDelta >= 0)) {
            state->channel3Brightness = 0x46;
            state->channel3BrightnessDelta = 0;
        }
        gTitleMenuControlInterface->vtable->func11(3, state->channel3Brightness & 0xFF);
    }
    if (state->actionTimer > 0) {
        state->actionTimer -= framesThisStep;
        if (state->actionTimer <= 0) {
            state->actionTimer = 0;
            if (state->timerActionTriggered == 0) {
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2C, 0x50, state->channel3Brightness, 0);
                state->timerActionTriggered = 1;
            }
        }
    } else {
        found = objGetNearestTypeTo(DLL199_TARGET_OBJECT_GROUP, player, &dist);
        if ((found != 0) && (dist < 300.0f) && (dist > 100.0f)) {
            dz = found->anim.localPosZ - player->anim.localPosZ;
            if (dz <= 0.0f) {
                if (dz < 0.0f) {
                    dz *= -1.0f;
                }
                if (state->channel3Brightness != 0x1E) {
                    state->channel3Brightness = 0x1E;
                }
                brightness = (int)((f32)state->channel3Brightness * ((dz - 100.0f) / 200.0f));
                if ((s16)brightness < 1) {
                    brightness = 1;
                }
                gTitleMenuControlInterface->vtable->func11(3, brightness & 0xFF);
                brightness = (int)((f32)state->channel2Brightness * ((200.0f - (dz - 100.0f)) / 200.0f));
                if ((s16)brightness < 1) {
                    brightness = 1;
                }
                gTitleMenuControlInterface->vtable->func11(2, brightness & 0xFF);
            }
        }
        switch (state->phase) {
        case 0:
            if ((mainGetBit(DLL199_GAMEBIT_05B5) == 0) && (mainGetBit(DLL199_GAMEBIT_0594) != 0)) {
                mainSetBits(DLL199_GAMEBIT_05B5, 1);
            }
            mainSetBits(DLL199_GAMEBIT_05B9, 0);
            if (Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX) < state->activationDistance) {
                state->phase = 1;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
                (*gObjectTriggerInterface)->runSequence(0, obj, 0xffffffff);
                {
                    Dll83Interface** res = Resource_Acquire(0x83, 1);

                    (*res)->spawn(obj, 0, NULL, 1, -1, NULL);
                    Resource_Release(res);
                }
                {
                    Dll84Interface** res = Resource_Acquire(0x84, 1);

                    (*res)->spawn(obj, 0, NULL, 1, -1, NULL);
                    Resource_Release(res);
                }
                mainSetBits(DLL199_GAMEBIT_0126, 0);
                (*gModgfxInterface)->releaseHandle(&state->gfxHandle);
            }
            break;
        case 1:
            if (state->sequenceEventState == 1) {
                state->phase = 2;
                state->actionTimer = 0xA0;
            }
            break;
        case 2:
            if ((state->unlockCount == 0) && (mainGetBit(DLL199_GAMEBIT_01CD) == 0)) {
                mainSetBits(DLL199_GAMEBIT_01CD, 1);
            }
            if (mainGetBit(DLL199_GAMEBIT_05B2) != 0) {
                state->unlockCount += 1;
                state->actionTimer = 100;
                if (state->unlockCount == 1) {
                    (*gObjectTriggerInterface)->runSequence(3, obj, 0xffffffff);
                }
            }
            break;
        case 7:
            (*gObjectTriggerInterface)->runSequence(5, obj, 0xffffffff);
            state->phase = 3;
            state->actionTimer = 0;
            state->channel3BrightnessDelta = -3;
            break;
        case 8:
            (*gObjectTriggerInterface)->runSequence(4, obj, 0xffffffff);
            state->phase = 6;
            state->actionTimer = 0;
            state->channel3BrightnessDelta = -3;
            break;
        case 6:
            gTitleMenuControlInterface->vtable->onSelectSave(3, 0x35, 0x50, state->channel3Brightness & 0xFF, 0);
            state->channel3BrightnessDelta = 1;
            (*gObjectTriggerInterface)->runSequence(2, obj, 0xffffffff);
            dist = 10000.0f;
            found = objGetNearestTypeTo(DLL199_SPAWNED_OBJECT_GROUP, obj, &dist);
            if (found != 0) {
                Obj_FreeObject(found);
            }
            state->phase = 0;
            state->actionTimer = 400;
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
            mainSetBits(DLL199_GAMEBIT_0126, 1);
            mainSetBits(DLL199_GAMEBIT_0127, 1);
            mainSetBits(DLL199_GAMEBIT_05B2, 0);
            mainSetBits(DLL199_GAMEBIT_05B9, 1);
            {
                Dll6AInterface** res = Resource_Acquire(0x6a, 1);

                state->gfxHandle = (*res)->spawn(obj, 0, NULL, 0x402, -1, NULL);
                Resource_Release(res);
            }
            mainSetBits(DLL199_GAMEBIT_01CD, 0);
            state->unlockCount = 0;
            state->sequenceEventState = 0;
            break;
        case 3:
            dist = 10000.0f;
            found = objGetNearestTypeTo(DLL199_SPAWNED_OBJECT_GROUP, obj, &dist);
            if (found != 0) {
                Obj_FreeObject(found);
            }
            if (mainGetBit(DLL199_GAMEBIT_01CE) != 0) {
                state->channel3Brightness = 1;
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2C, 0x50, state->channel3Brightness & 0xFF, 0);
                state->channel3BrightnessDelta = 1;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                state->phase = 5;
            } else {
                mainSetBits(DLL199_GAMEBIT_0126, 0);
                gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2A, 0x50, state->channel3Brightness & 0xFF, 0);
                state->channel3BrightnessDelta = 1;
                (*gObjectTriggerInterface)->runSequence(1, obj, 0xffffffff);
            }
            break;
        case 4:
            if (mainGetBit(DLL199_GAMEBIT_00FD) == 0) {
                mainSetBits(DLL199_GAMEBIT_00FD, 1);
            }
            mainSetBits(DLL199_GAMEBIT_01CF, 0);
            mainSetBits(DLL199_GAMEBIT_0127, 0);
            state->phase = 5;
            gTitleMenuControlInterface->vtable->onSelectSave(3, 0x2C, 0x50, state->channel3Brightness & 0xFF, 0);
            mainSetBits(DLL199_GAMEBIT_01CE, 1);
            (*gMapEventInterface)->setMapAct(DLL199_MAP_EVENT_ID, DLL199_MAP_EVENT_ACTION);
            break;
        }
    }
}

void dll409_init(GameObject* obj, const Dll199Placement* placement) {
    Dll199State* state;
    Dll6AInterface** res;
    s16 id;

    state = obj->extra;
    obj->anim.rotX = 0;
    state->activationDistance = 10;
    if (placement->activationDistancePacked > 0) {
        state->activationDistance = placement->activationDistancePacked >> 8;
    }
    state->phase = 0;
    state->sequenceEventState = 0;
    state->actionTimer = 0;
    state->unlockCount = 0;
    obj->animEventCallback = dll409_processAnimEvents;
    ObjMsg_AllocQueue(obj, 4);
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    mainSetBits(DLL199_GAMEBIT_01CF, 0);
    mainSetBits(DLL199_GAMEBIT_0126, 1);
    mainSetBits(DLL199_GAMEBIT_0127, 1);
    mainSetBits(DLL199_GAMEBIT_01CD, 0);
    mainSetBits(DLL199_GAMEBIT_01E7, 0);
    state->channel2Brightness = 0xC;
    state->channel3Brightness = 0x1E;
    state->actionTimer = 200;
    gTitleMenuControlInterface->vtable->onSelectSave(2, 0x2B, 0x50, 1, 0);
    state->channel2BrightnessDelta = 0;
    state->channel3BrightnessDelta = 0;
    state->timerActionTriggered = 0;
    res = Resource_Acquire(0x6a, 1);
    id = (*res)->spawn(obj, 0, NULL, 0x402, -1, NULL);
    state->gfxHandle = id;
    Resource_Release(res);
}

void dll409_release(void) {
}

void dll409_initialise(void) {
}
