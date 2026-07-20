/* DLL 0x0141 (lightning) - MMP lightning object [0x801978A0-0x80197DA8). */
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/dll_0141_lightning.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/obj_group.h"
#include "main/newclouds.h"
#include "main/objfx.h"
#include "main/obj_placement.h"


int lightning_getExtraSize(void) { return 0x28; }

struct LightningPlacement
{
    ObjPlacement base;
    u32 linkedMapId;
    u8 radiusX;
    u8 radiusY;
    u8 delayBase;
    u8 effectParam;
    u8 flags;
    u8 mode;
    u8 initialDelay;
    u8 repeatDelay;
    s16 enableGameBit;
    u8 pad26[0x28 - 0x26];
};

STATIC_ASSERT(offsetof(LightningPlacement, linkedMapId) == 0x18);
STATIC_ASSERT(offsetof(LightningPlacement, radiusX) == 0x1C);
STATIC_ASSERT(offsetof(LightningPlacement, flags) == 0x20);
STATIC_ASSERT(offsetof(LightningPlacement, initialDelay) == 0x22);
STATIC_ASSERT(offsetof(LightningPlacement, enableGameBit) == 0x24);
STATIC_ASSERT(sizeof(LightningPlacement) == 0x28);

typedef struct LightningFlags
{
    u8 enabled : 1; /* 0x80 */
    u8 noAge : 1; /* 0x40 */
    u8 style : 1; /* 0x20 */
    u8 pad : 5;
} LightningFlags;

typedef struct LightningMode
{
    u8 pad : 4;
    u8 mode : 4; /* 0x0f */
} LightningMode;

/* Per-object extra state for the MMP lightning object
 * (lightning_getExtraSize == 0x28). Shares the carryable header region with
 * MmpMoonrockState but is its own record. */
typedef struct LightningState
{
    LightningEffect* handle; /* 0x00: active lightning effect handle */
    f32 ageTimer;      /* 0x04 */
    f32 radiusX;       /* 0x08 */
    f32 radiusY;       /* 0x0c */
    f32 hitRadius;     /* 0x10 */
    f32 burstRadius;   /* 0x14 */
    f32 countdown;     /* 0x18 */
    u8 delayBase;      /* 0x1c */
    u8 param1D;        /* 0x1d */
    u8 pad1E[2];
    u32 linkedHandle;  /* 0x20 */
    LightningMode modeBits; /* 0x24 */
    LightningFlags flags;   /* 0x25 */
    u8 pad26[2];
} LightningState;

STATIC_ASSERT(sizeof(LightningState) == 0x28);
STATIC_ASSERT(offsetof(LightningState, ageTimer) == 0x04);
STATIC_ASSERT(offsetof(LightningState, radiusX) == 0x08);
STATIC_ASSERT(offsetof(LightningState, radiusY) == 0x0c);
STATIC_ASSERT(offsetof(LightningState, hitRadius) == 0x10);
STATIC_ASSERT(offsetof(LightningState, burstRadius) == 0x14);
STATIC_ASSERT(offsetof(LightningState, countdown) == 0x18);
STATIC_ASSERT(offsetof(LightningState, linkedHandle) == 0x20);
STATIC_ASSERT(offsetof(LightningState, modeBits) == 0x24);
STATIC_ASSERT(offsetof(LightningState, flags) == 0x25);

void lightning_free(GameObject* obj, int mode)
{
    LightningState* state = obj->extra;
    ObjGroup_RemoveObject((int)obj, MMP_LIGHTNING_OBJGROUP);
    if (state->handle != NULL)
    {
        mm_free(state->handle);
    }
}

void lightning_render(GameObject* obj)
{
    LightningState* state = obj->extra;
    if (state->handle != NULL)
    {
        lightningRender(state->handle);
    }
}

void lightning_update(GameObject* obj)
{
    LightningState* state;
    u8* data;
    u32* objects;
    u32* slot;
    int objectCount;
    int objectIndex;
    int spawnLightning;
    LightningEffect* handle;
    u16 delay;
    float* start;

    state = obj->extra;
    data = *(u8**)&obj->anim.placementData;
    if (((LightningPlacement*)data)->enableGameBit != -1)
    {
        if (state->flags.enabled)
        {
            if (mainGetBit(((LightningPlacement*)data)->enableGameBit) == 0)
            {
                state->flags.enabled = 0;
                if (state->handle != 0)
                {
                    mm_free((void*)state->handle);
                    state->handle = 0;
                }
            }
        }
        else if (mainGetBit(((LightningPlacement*)data)->enableGameBit) != 0)
        {
            state->flags.enabled = 1;
        }
    }

    if (state->handle == 0 && state->flags.enabled)
    {
        spawnLightning = 0;
        state->countdown -= timeDelta;
        if (state->countdown <= 0.0f)
        {
            state->countdown += (f32)(s32)((u32)((LightningPlacement*)data)->repeatDelay * 0x3c);
            spawnLightning = 1;
        }
        if (spawnLightning != 0)
        {
            objects = ObjGroup_GetObjects(MMP_LIGHTNING_OBJGROUP, &objectCount);
            objectIndex = 0;
            while (objectIndex < objectCount)
            {
                u32 linkedHandle = *(u32*)(*(u32*)(objects[objectIndex] + 0x4c) + 0x14);
                if (linkedHandle == state->linkedHandle)
                {
                    break;
                }
                objectIndex++;
            }
            if (objectIndex == objectCount)
            {
                state->flags.enabled = 0;
                return;
            }

            delay = (u16)(state->delayBase + randomGetRange(-5, 5));
            start = (float*)((u8*)obj + 0x0c);
            slot = &objects[objectIndex];
            handle = lightningCreate((const Vec3f*)start, (const Vec3f*)(*slot + 0x0c), state->radiusX,
                                             state->radiusY, delay, state->param1D,
                                             (u8)(state->flags.style ? 1 : 0));
            state->handle = handle;
            state->ageTimer = 0.0f;
            if ((state->modeBits.mode & 1) != 0)
            {
                hitDetectFn_80097070(obj, state->hitRadius, 1, 7, 0x1e, NULL);
            }
            data = *(u8**)(*slot + 0xb8);
            if ((((LightningMode*)(data + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070((void*)*slot, ((LightningState*)data)->hitRadius, 1, 7, 0x1e, NULL);
            }
            if ((state->modeBits.mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst(obj, 5, state->burstRadius, 1, 1, 100, 5.0f, NULL, 0);
            }
            if ((((LightningMode*)(data + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst((u8*)*slot, 5, ((LightningState*)data)->burstRadius, 1, 1, 100, 5.0f,
                                            NULL, 0);
            }
        }
    }

    if (state->handle != 0)
    {
        if (state->flags.noAge == 0)
        {
            state->ageTimer += timeDelta;
            state->handle->timer = (u16)(int)(0.5f + state->ageTimer);
        }
        if (state->handle->timer >= state->handle->lifetime)
        {
            mm_free((void*)state->handle);
            state->handle = 0;
        }
    }
}

void lightning_init(GameObject* obj, LightningPlacement* placement)
{
    LightningState* state;
    f32 defaultScale;

    state = obj->extra;
    ObjGroup_AddObject((int)obj, MMP_LIGHTNING_OBJGROUP);
    state->modeBits.mode = placement->mode;
    defaultScale = 1.0f;
    state->hitRadius = defaultScale;
    state->burstRadius = defaultScale;
    state->radiusX = (f32)(u32)
    placement->radiusX;
    state->radiusY = (f32)(u32)
    placement->radiusY;
    state->delayBase = placement->delayBase;
    state->param1D = placement->effectParam;
    state->linkedHandle = placement->linkedMapId;

    state->flags.enabled = (placement->flags & 1) ? 1 : 0;
    state->flags.style = (placement->flags & 2) ? 1 : 0;
    state->flags.noAge = (placement->flags & 4) ? 1 : 0;

    state->countdown = (f32)(s32)((u32)placement->initialDelay * 0x3c);
}
