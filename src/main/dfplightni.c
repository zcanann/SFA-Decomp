#include "main/dfplightni.h"
#include "main/gameplay_runtime.h"
#include "main/objhits.h"

extern void lightningRender(void* handle);
extern void* lightningCreate(f32* start, f32* end, f32 radiusX, f32 radiusY, int param_5, int param_6, int param_7);

extern f32 timeDelta;
extern f32 lbl_803E64E0;
extern f32 lbl_803E64E4;
extern f32 lbl_803E64E8;
extern f32 lbl_803E64F8;
extern f32 lbl_803E64FC;
extern f32 lbl_803E6500;
extern const f32 lbl_803E6504;
extern f32 lbl_803E6508;
extern const f32 lbl_803E650C;

static inline DfpLightniState* dfplightni_getState(DfpLightniObject* obj)
{
    return obj->state;
}

static inline f64 dfplightni_u32AsDouble(u32 value)
{
    u64 bits = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)(value)));
    return *(f64*)&bits;
}

int dfplightni_getExtraSize(void)
{
    return sizeof(DfpLightniState);
}

void dfplightni_free(DfpLightniObject* obj)
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

void dfplightni_render(DfpLightniObject* obj)
{
    DfpLightniState* state;
    int eventActive;

    if (obj != 0)
    {
        state = dfplightni_getState(obj);
        if (state->timer >= lbl_803E64E0)
        {
            eventActive = GameBit_Get(DFPLIGHTNI_EVENT_TIMER_GAMEBIT);
            if (state->effectHandle != 0)
            {
                lightningRender(state->effectHandle);
            }
            if (eventActive != 0)
            {
                if (state->timer >= lbl_803E64E0 + (f32)(s32)state->delayFrames
                )
                {
                    state->timer = lbl_803E64E4;
                }
            }
            else if (state->timer >= lbl_803E64E8)
            {
                state->timer = lbl_803E64E4;
            }
        }
    }
    return;
}


void dfplightni_update(DfpLightniObject* obj)
{
    DfpLightniObject* playerObj;
    int eventActive;
    u32 eventBlocked;
    DfpLightniState* state;
    f32 radiusX;
    f32 radiusY;
    float* effectStart;
    float* effectEnd;
    float start[3];
    float end[3];
    int randomZ;
    int randomY;
    int randomX;

    if (obj != 0)
    {
        state = dfplightni_getState(obj);
        playerObj = Obj_GetPlayerObject();
        if (playerObj != 0)
        {
            state->timer += timeDelta;
            eventActive = GameBit_Get(state->eventId);
            if ((eventActive != 0) && (state->timer < lbl_803E64E0))
            {
                state->timer = lbl_803E64F8;
            }
            if ((state->timer > state->triggerTime) && (state->timer < lbl_803E64E0))
            {
                start[0] = obj->position[0];
                start[1] = obj->position[1];
                start[2] = obj->position[2];
                if (eventActive != 0)
                {
                    randomZ = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX);
                    end[0] = randomZ * lbl_803E64FC + playerObj->position[0];
                    randomY = randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN, DFPLIGHTNI_RANDOM_Y_MAX);
                    end[1] = randomY * lbl_803E64FC + playerObj->position[1];
                    randomX = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX);
                    end[2] = randomX * lbl_803E64FC + playerObj->position[2];
                }
                else
                {
                    randomX = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX);
                    end[0] = randomX * lbl_803E64FC + start[0];
                    randomY = randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN, DFPLIGHTNI_RANDOM_Y_MAX);
                    end[1] = randomY * lbl_803E64FC + obj->position[1];
                    randomZ = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN, DFPLIGHTNI_RANDOM_XZ_MAX);
                    end[2] = randomZ * lbl_803E64FC + start[2];
                }
                if (state->effectHandle != 0)
                {
                    mm_free(state->effectHandle);
                    state->effectHandle = 0;
                }
                radiusX = state->radiusX;
                radiusY = state->radiusY;
                eventBlocked = GameBit_Get(DFPLIGHTNI_BLOCKED_GAMEBIT);
                if (eventBlocked == 0)
                {
                    f32 clampX;
                    f32 clampY;
                    Sfx_PlayFromObjectLimited((u32)obj, DFPLIGHTNI_SFX_ID, DFPLIGHTNI_SFX_MAX_COUNT);
                    if (eventActive != 0)
                    {
                        clampY = (radiusY < lbl_803E6500)
                                     ? lbl_803E6500
                                     : (radiusY > lbl_803E6504)
                                     ? lbl_803E6504
                                     : radiusY;
                        effectStart = start;
                        effectEnd = end;
                        clampX = (radiusX < *(f32*)&lbl_803E6500)
                                     ? *(f32*)&lbl_803E6500
                                     : (radiusX > *(f32*)&lbl_803E6504)
                                     ? *(f32*)&lbl_803E6504
                                     : radiusX;
                        state->effectHandle =
                            lightningCreate(effectStart, effectEnd, clampX, clampY,
                                            DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES,
                                            state->angleIndex * DFPLIGHTNI_ANGLE_STEP &
                                            DFPLIGHTNI_EFFECT_ANGLE_MASK, 0);
                    }
                    else
                    {
                        clampY = (radiusY < lbl_803E6500)
                                     ? lbl_803E6500
                                     : (radiusY > lbl_803E6504)
                                     ? lbl_803E6504
                                     : radiusY;
                        effectStart = start;
                        effectEnd = end;
                        clampX = (radiusX < *(f32*)&lbl_803E6500)
                                     ? *(f32*)&lbl_803E6500
                                     : (radiusX > *(f32*)&lbl_803E6504)
                                     ? *(f32*)&lbl_803E6504
                                     : radiusX;
                        state->effectHandle =
                            lightningCreate(effectStart, effectEnd, clampX, clampY, (u16)state->delayFrames,
                                            state->angleIndex * DFPLIGHTNI_ANGLE_STEP &
                                            DFPLIGHTNI_EFFECT_ANGLE_MASK, 0);
                    }
                }
                state->timer = lbl_803E64E0;
            }
        }
    }
    return;
}


void dfplightni_init(DfpLightniObject* obj, DfpLightniMapData* mapData)
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
            f32 t = randomValue;
            t = lbl_803E6508 + t;
            state->triggerTime = t;
        }
        state->radiusX = ((f32)(s32)mapData->radiusX / lbl_803E650C) * lbl_803E6504;
        state->radiusY = ((f32)(s32)mapData->radiusY / lbl_803E650C) * lbl_803E6504;
        state->angleIndex = mapData->angleIndex;
        state->delayFrames = mapData->delayTicks * DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES;
        state->eventId = mapData->eventId;
    }
    return;
}

int dfppowersl_spawnSeqObjectsOnHit(DfpPowerSlObject* obj)
{
    int i;
    int outObj;

    outObj = 0;
    if (obj == 0)
    {
        return 0;
    }
    i = ObjHits_GetPriorityHit((int)obj, &outObj, 0, 0);
    if (((u32)outObj != 0) && (i != 0))
    {
        i = 1;
        do
        {
            (*gPartfxInterface)->spawnObject(obj, DFPPOWERSL_SPAWN_OBJECT_ID, 0, 1,
                                             0xffffffff, 0);
        }
        while (i++ < DFPPOWERSL_SPAWN_COUNT);
    }
    return 0;
}

ObjectDescriptor gDfplightniObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dfplightni_init,
    (ObjectDescriptorCallback)dfplightni_update,
    0,
    (ObjectDescriptorCallback)dfplightni_render,
    (ObjectDescriptorCallback)dfplightni_free,
    0,
    dfplightni_getExtraSize,
};
