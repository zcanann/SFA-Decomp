#include "main/audio/sfx_limited_object_api.h"
#include "main/dfplightni.h"
#include "main/gamebits_api.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/newclouds.h"
#include "main/frame_timing.h"

#define DFPLIGHTNI_TIMER_MAX 1000.0f
#define DFPLIGHTNI_TIMER_INACTIVE_MAX 1010.0f

#define DFPLIGHTNI_TIMER_ACTIVE_RESET 999.0f
#define DFPLIGHTNI_OFFSET_SCALE 0.1f
#define DFPLIGHTNI_RADIUS_MIN 0.001f
#define DFPLIGHTNI_RADIUS_MAX 5.0f
#define DFPLIGHTNI_TRIGGER_TIME_BASE 400.0f
#define DFPLIGHTNI_RADIUS_NORM_DIVISOR 32767.0f

static inline DfpLightniState* dfplightni_getState(GameObject* obj)
{
    return obj->extra;
}

static inline f64 dfplightni_u32AsDouble(u32 value)
{
    u64 bits = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)(value)));
    return *(f64*)&bits;
}

int DFP_Lightni_getExtraSize(void)
{
    return sizeof(DfpLightniState);
}

void DFP_Lightni_free(GameObject* obj)
{
    DfpLightniState* state;

    if (obj != 0)
    {
        state = dfplightni_getState(obj);
        if (state->effectHandle != 0)
        {
            mm_free(state->effectHandle);
            state->effectHandle = 0;
        }
    }
    return;
}

void DFP_Lightni_render(GameObject* obj)
{
    DfpLightniState* state;
    int eventActive;

    if (obj != 0)
    {
        state = dfplightni_getState(obj);
        if (state->timer >= DFPLIGHTNI_TIMER_MAX)
        {
            eventActive = mainGetBit(DFPLIGHTNI_ZAPPED_PLAYER_GAMEBIT);
            if (state->effectHandle != 0)
            {
                lightningRender(state->effectHandle);
            }
            if (eventActive != 0)
            {
                if (state->timer >= DFPLIGHTNI_TIMER_MAX + (f32)(s32)state->delayFrames)
                {
                    state->timer = 0.0f;
                }
            }
            else if (state->timer >= DFPLIGHTNI_TIMER_INACTIVE_MAX)
            {
                state->timer = 0.0f;
            }
        }
    }
    return;
}

void DFP_Lightni_update(GameObject* obj)
{
    GameObject* playerObj;
    int eventActive;
    u32 eventBlocked;
    DfpLightniState* state;
    f32 radiusX;
    f32 radiusY;
    float* effectStart;
    float* effectEnd;
    float start[3];
    float end[3];

    if (obj != 0)
    {
        state = dfplightni_getState(obj);
        playerObj = Obj_GetPlayerObject();
        if (playerObj != 0)
        {
            state->timer += timeDelta;
            eventActive = mainGetBit(state->eventId);
            if ((eventActive != 0) && (state->timer < DFPLIGHTNI_TIMER_MAX))
            {
                state->timer = DFPLIGHTNI_TIMER_ACTIVE_RESET;
            }
            if ((state->timer > state->triggerTime) && (state->timer < DFPLIGHTNI_TIMER_MAX))
            {
                start[0] = obj->anim.localPosX;
                start[1] = obj->anim.localPosY;
                start[2] = obj->anim.localPosZ;
                if (eventActive != 0)
                {
                    end[0] =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        playerObj->anim.localPosX;
                    end[1] =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN, DFPLIGHTNI_RANDOM_Y_MAX) +
                        playerObj->anim.localPosY;
                    end[2] =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        playerObj->anim.localPosZ;
                }
                else
                {
                    end[0] =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        start[0];
                    end[1] =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN, DFPLIGHTNI_RANDOM_Y_MAX) +
                        obj->anim.localPosY;
                    end[2] =
                        DFPLIGHTNI_OFFSET_SCALE * randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX) +
                        start[2];
                }
                if (state->effectHandle != 0)
                {
                    mm_free(state->effectHandle);
                    state->effectHandle = 0;
                }
                radiusX = state->radiusX;
                radiusY = state->radiusY;
                eventBlocked = mainGetBit(DFPLIGHTNI_PUZZLE_COMPLETE_GAMEBIT);
                if (eventBlocked == 0)
                {
                    f32 clampX;
                    f32 clampY;
                    Sfx_PlayFromObjectLimited(obj, DFPLIGHTNI_SFX_ID, DFPLIGHTNI_SFX_MAX_COUNT);
                    if (eventActive != 0)
                    {
                        clampY = (radiusY < DFPLIGHTNI_RADIUS_MIN)   ? DFPLIGHTNI_RADIUS_MIN
                                 : (radiusY > DFPLIGHTNI_RADIUS_MAX) ? DFPLIGHTNI_RADIUS_MAX
                                                                     : radiusY;
                        effectStart = start;
                        effectEnd = end;
                        clampX = (radiusX < DFPLIGHTNI_RADIUS_MIN)   ? DFPLIGHTNI_RADIUS_MIN
                                 : (radiusX > DFPLIGHTNI_RADIUS_MAX) ? DFPLIGHTNI_RADIUS_MAX
                                                                     : radiusX;
                        state->effectHandle = lightningCreate(
                            (const Vec3f*)effectStart, (const Vec3f*)effectEnd, clampX, clampY,
                            DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES,
                            state->angleIndex * DFPLIGHTNI_ANGLE_STEP & DFPLIGHTNI_EFFECT_ANGLE_MASK, 0);
                    }
                    else
                    {
                        clampY = (radiusY < DFPLIGHTNI_RADIUS_MIN)   ? DFPLIGHTNI_RADIUS_MIN
                                 : (radiusY > DFPLIGHTNI_RADIUS_MAX) ? DFPLIGHTNI_RADIUS_MAX
                                                                     : radiusY;
                        effectStart = start;
                        effectEnd = end;
                        clampX = (radiusX < DFPLIGHTNI_RADIUS_MIN)   ? DFPLIGHTNI_RADIUS_MIN
                                 : (radiusX > DFPLIGHTNI_RADIUS_MAX) ? DFPLIGHTNI_RADIUS_MAX
                                                                     : radiusX;
                        state->effectHandle = lightningCreate(
                            (const Vec3f*)effectStart, (const Vec3f*)effectEnd, clampX, clampY,
                            state->delayFrames,
                            state->angleIndex * DFPLIGHTNI_ANGLE_STEP & DFPLIGHTNI_EFFECT_ANGLE_MASK, 0);
                    }
                }
                state->timer = DFPLIGHTNI_TIMER_MAX;
            }
        }
    }
    return;
}

void DFP_Lightni_init(GameObject* obj, DfpLightniMapData* mapData)
{
    DfpLightniState* state;
    int randomValue;

    if (obj != 0)
    {
        state = dfplightni_getState(obj);
        randomValue = randomGetRange(DFPLIGHTNI_RANDOM_TIMER_MIN, DFPLIGHTNI_RANDOM_TIMER_MAX);
        state->timer = randomValue;
        state->effectHandle = 0;
        if (mapData->radiusX <= 0)
        {
            mapData->radiusX = 1;
        }
        if (mapData->radiusY <= 0)
        {
            mapData->radiusY = 1;
        }
        randomValue = randomGetRange(DFPLIGHTNI_RANDOM_TIMER_MIN, DFPLIGHTNI_RANDOM_TIMER_MAX);
        {
            f32 triggerTime = randomValue;
            triggerTime = DFPLIGHTNI_TRIGGER_TIME_BASE + triggerTime;
            state->triggerTime = triggerTime;
        }
        state->radiusX = ((f32)(s32)mapData->radiusX / DFPLIGHTNI_RADIUS_NORM_DIVISOR) * DFPLIGHTNI_RADIUS_MAX;
        state->radiusY = ((f32)(s32)mapData->radiusY / DFPLIGHTNI_RADIUS_NORM_DIVISOR) * DFPLIGHTNI_RADIUS_MAX;
        state->angleIndex = mapData->angleIndex;
        state->delayFrames = mapData->delayTicks * DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES;
        state->eventId = mapData->eventId;
    }
    return;
}

ObjectDescriptor gDfplightniObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)DFP_Lightni_init,
    (ObjectDescriptorCallback)DFP_Lightni_update,
    0,
    (ObjectDescriptorCallback)DFP_Lightni_render,
    (ObjectDescriptorCallback)DFP_Lightni_free,
    0,
    DFP_Lightni_getExtraSize,
};
