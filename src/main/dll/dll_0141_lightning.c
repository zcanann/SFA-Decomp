/* DLL 0x0141 (lightning) — MMP lightning object [0x801978A0-0x80197DA8). */
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/MMP/MMP_moonrock.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"


extern u32* ObjGroup_GetObjects(int group, int* countOut);
extern f32 lbl_803E4088;
extern f32 lbl_803E408C;
extern f32 lbl_803E4090;
extern f32 lbl_803E40A0;
extern void lightningRender(u32 handle);
extern int lightningCreate(float* start, float* end, f32 radiusX, f32 radiusY, int delay,
                           int colorAngle, u8 flags);
extern void hitDetectFn_80097070(u8* obj, double radius, int param_3, int param_4, int param_5,
                                 int param_6);
extern void objfx_spawnDirectionalBurst(u8* obj, int idx, double radius, int kind, int mode,
                                        int chance, double scale, int origin, int flags);

int lightning_getExtraSize(void) { return 0x28; }

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* state encode: ((obj->_X)->_Y << shift) | const. */

/* Drift-recovery: add new fns with v1.0 names. */

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */

/* segment pragma-stack balance (re-split): */

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

/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */

void lightning_render(u8* obj)
{
    u32 handle = *(u32*)(((GameObject*)obj)->extra);
    if (handle != 0)
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
    u32 handle;        /* 0x00: active lightning effect handle (object ptr) */
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
    int handle;
    u16 delay;

    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((LightningPlacement*)data)->enableGameBit != -1)
    {
        if (state->flags.enabled)
        {
            if (GameBit_Get(((LightningPlacement*)data)->enableGameBit) == 0)
            {
                state->flags.enabled = 0;
                if (state->handle != 0)
                {
                    mm_free((void*)state->handle);
                    state->handle = 0;
                }
            }
        }
        else if (GameBit_Get(((LightningPlacement*)data)->enableGameBit) != 0)
        {
            state->flags.enabled = 1;
        }
    }

    if (state->handle == 0 && state->flags.enabled)
    {
        spawnLightning = 0;
        state->countdown -= timeDelta;
        if (state->countdown <= lbl_803E4088)
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
            slot = &objects[objectIndex];
            handle = lightningCreate((float*)(obj + 0x0c), (float*)(*slot + 0x0c),
                                     state->radiusX, state->radiusY,
                                     delay, state->param1D,
                                     (u8)(state->flags.style ? 1 : 0));
            state->handle = handle;
            state->ageTimer = lbl_803E4088;
            if ((state->modeBits.mode & 1) != 0)
            {
                hitDetectFn_80097070(obj, state->hitRadius, 1, 7, 0x1e, 0);
            }
            data = *(u8**)(*slot + 0xb8);
            if ((((LightningMode*)(data + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070((u8*)*slot, *(f32*)(data + 0x10), 1, 7,
                                     0x1e, 0);
            }
            if ((state->modeBits.mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst(obj, 5, state->burstRadius, 1, 1, 100, lbl_803E408C,
                                            0, 0);
            }
            if ((((LightningMode*)(data + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst((u8*)*slot, 5, *(f32*)(data + 0x14),
                                            1, 1, 100, lbl_803E408C, 0, 0);
            }
        }
    }

    if (state->handle != 0)
    {
        if (state->flags.noAge == 0)
        {
            state->ageTimer += timeDelta;
            *(u16*)(state->handle + 0x20) = (u16)(int)(lbl_803E4090 + state->ageTimer);
        }
        if (*(u16*)(state->handle + 0x20) >= *(u16*)(state->handle + 0x22))
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
    defaultScale = lbl_803E40A0;
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

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */
