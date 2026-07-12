/* DLL 0x0141 (lightning) — MMP lightning object [0x801978A0-0x80197DA8). */
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/MMP/MMP_moonrock.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"
#include "main/newclouds.h"


extern u32* ObjGroup_GetObjects(int group, int* countOut);
extern void hitDetectFn_80097070(u8* obj, double radius, int arg3, int arg4, int arg5,
                                 int arg6);
extern void objfx_spawnDirectionalBurst(u8* obj, int idx, double radius, int kind, int mode,
                                        int chance, f32 scale, int origin, int flags);

int lightning_getExtraSize(void) { return 0x28; }

typedef struct LightningPlacement
{
    u8 pad0[0x14 - 0x0];
    u32 unk14;
    u32 unk18;
    u8 pad1C[0x22 - 0x1C];
    u16 unk22;
    s16 enableGameBit;
    u8 pad26[0x28 - 0x26];
} LightningPlacement;

void lightning_free(u8* obj, int p2)
{
    u8* state = ((GameObject*)obj)->extra;
    void* handle;
    ObjGroup_RemoveObject(obj, MMP_LIGHTNING_OBJGROUP);
    handle = *(void**)state;
    if (handle != NULL)
    {
        mm_free(handle);
    }
}

void lightning_render(u8* obj)
{
    LightningEffect* handle = *(LightningEffect**)(((GameObject*)obj)->extra);
    if (handle != NULL)
    {
        lightningRender(handle);
    }
}

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

void lightning_update(u8* obj)
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

    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
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
            state->countdown += (f32)(s32)((u32)data[0x23] * 0x3c);
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
            start = (float*)(obj + 0x0c);
            slot = &objects[objectIndex];
            handle = lightningCreatePromoted((const Vec3f*)start, (const Vec3f*)(*slot + 0x0c), state->radiusX,
                                             state->radiusY, delay, state->param1D,
                                             (u8)(state->flags.style ? 1 : 0));
            state->handle = handle;
            state->ageTimer = 0.0f;
            if ((state->modeBits.mode & 1) != 0)
            {
                hitDetectFn_80097070(obj, state->hitRadius, 1, 7, 0x1e, 0);
            }
            data = *(u8**)(*slot + 0xb8);
            if ((((LightningMode*)(data + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070((u8*)*slot, ((LightningState*)data)->hitRadius, 1, 7,
                                     0x1e, 0);
            }
            if ((state->modeBits.mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst(obj, 5, state->burstRadius, 1, 1, 100, 5.0f,
                                            0, 0);
            }
            if ((((LightningMode*)(data + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst((u8*)*slot, 5, ((LightningState*)data)->burstRadius,
                                            1, 1, 100, 5.0f, 0, 0);
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

void lightning_init(u8* obj, u8* data)
{
    LightningState* state;
    f32 defaultScale;

    state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, MMP_LIGHTNING_OBJGROUP);
    state->modeBits.mode = data[0x21];
    defaultScale = 1.0f;
    state->hitRadius = defaultScale;
    state->burstRadius = defaultScale;
    state->radiusX = (f32)(u32)
    data[0x1c];
    state->radiusY = (f32)(u32)
    data[0x1d];
    state->delayBase = data[0x1e];
    state->param1D = data[0x1f];
    state->linkedHandle = *(u32*)(data + 0x18);

    state->flags.enabled = (data[0x20] & 1) ? 1 : 0;
    state->flags.style = (data[0x20] & 2) ? 1 : 0;
    state->flags.noAge = (data[0x20] & 4) ? 1 : 0;

    state->countdown = (f32)(s32)((u32)data[0x22] * 0x3c);
}
