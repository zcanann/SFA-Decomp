/* DLL 0x0141 (lightning) — MMP lightning object [0x801978A0-0x80197DA8). */
#include "main/dll/MMP/mmp_moonrock_state.h"
#include "main/dll/MMP/MMP_moonrock.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"



extern u64 ObjGroup_RemoveObject();
extern u32 ObjGroup_AddObject();

extern f32 timeDelta;

extern u32* ObjGroup_GetObjects(int group, int* countOut);
extern f32 lbl_803E4088;
extern f32 lbl_803E408C;
extern f32 lbl_803E4090;
extern f32 lbl_803E40A0;

extern void lightningRender(u32 handle);
extern int lightningCreate(float* start, float* end, f32 radiusX, f32 radiusY, int delay,
                           int param_6, u8 param_7);
extern void hitDetectFn_80097070(u8* obj, double radius, int param_3, int param_4, int param_5,
                                 int param_6);
extern void objfx_spawnDirectionalBurst(u8* obj, int param_2, double radius, int param_4, int param_5,
                                        int param_6, double scale, int param_8, int param_9);

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
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} LightningPlacement;

void lightning_free(u8* obj, int p2)
{
    u8* state = ((GameObject*)obj)->extra;
    void* h;
    ObjGroup_RemoveObject(obj, MMP_LIGHTNING_OBJGROUP);
    h = *(void**)state;
    if (h != NULL)
    {
        mm_free(h);
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

void lightning_update(u8* obj)
{
    u8* state;
    u8* data;
    u32* objects;
    u8* otherState;
    int objectCount;
    int objectIndex;
    int spawnLightning;
    int handle;
    u16 delay;

    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((LightningPlacement*)data)->unk24 != -1)
    {
        if (((LightningFlags*)(state + 0x25))->enabled)
        {
            if (GameBit_Get(((LightningPlacement*)data)->unk24) == 0)
            {
                ((LightningFlags*)(state + 0x25))->enabled = 0;
                if (*(u32*)state != 0)
                {
                    mm_free(*(void**)state);
                    *(u32*)state = 0;
                }
            }
        }
        else if (GameBit_Get(((LightningPlacement*)data)->unk24) != 0)
        {
            ((LightningFlags*)(state + 0x25))->enabled = 1;
        }
    }

    if (*(u32*)state == 0 && ((LightningFlags*)(state + 0x25))->enabled)
    {
        spawnLightning = 0;
        ((MmpMoonrockState*)state)->homeX -= timeDelta;
        if (((MmpMoonrockState*)state)->homeX <= lbl_803E4088)
        {
            ((MmpMoonrockState*)state)->homeX += (f32)(s32)((u32)data[0x23] * 0x3c);
            spawnLightning = 1;
        }
        if (spawnLightning != 0)
        {
            objects = ObjGroup_GetObjects(MMP_LIGHTNING_OBJGROUP, &objectCount);
            objectIndex = 0;
            while (objectIndex < objectCount)
            {
                u32 linkedHandle = *(u32*)(*(u32*)(objects[objectIndex] + 0x4c) + 0x14);
                if (linkedHandle == *(u32*)&((MmpMoonrockState*)state)->homeZ)
                {
                    break;
                }
                objectIndex++;
            }
            if (objectIndex == objectCount)
            {
                ((LightningFlags*)(state + 0x25))->enabled = 0;
                return;
            }

            delay = (u16)(state[0x1c] + randomGetRange(-5, 5));
            handle = lightningCreate((float*)(obj + 0x0c), (float*)(objects[objectIndex] + 0x0c),
                                     *(f32*)(state + 0x08), ((MmpMoonrockState*)state)->baseY,
                                     delay, state[0x1d],
                                     (u8)(((LightningFlags*)(state + 0x25))->style ? 1 : 0));
            *(int*)state = handle;
            *(f32*)(state + 0x04) = lbl_803E4088;
            if ((((LightningMode*)(state + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070(obj, ((MmpMoonrockState*)state)->baseY2, 1, 7, 0x1e, 0);
            }
            otherState = *(u8**)(objects[objectIndex] + 0xb8);
            if ((((LightningMode*)(otherState + 0x24))->mode & 1) != 0)
            {
                hitDetectFn_80097070((u8*)objects[objectIndex], *(f32*)(otherState + 0x10), 1, 7,
                                     0x1e, 0);
            }
            if ((((LightningMode*)(state + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst(obj, 5, ((MmpMoonrockState*)state)->respawnTimer, 1, 1, 100, lbl_803E408C,
                                            0, 0);
            }
            if ((((LightningMode*)(otherState + 0x24))->mode & 2) != 0)
            {
                objfx_spawnDirectionalBurst((u8*)objects[objectIndex], 5, *(f32*)(otherState + 0x14),
                                            1, 1, 100, lbl_803E408C, 0, 0);
            }
        }
    }

    if (*(u32*)state != 0)
    {
        if (((LightningFlags*)(state + 0x25))->noAge == 0)
        {
            *(f32*)(state + 0x04) += timeDelta;
            *(u16*)(*(u32*)state + 0x20) = (u16)(int)(lbl_803E4090 + *(f32*)(state + 0x04));
        }
        if (*(u16*)(*(u32*)state + 0x20) >= *(u16*)(*(u32*)state + 0x22))
        {
            mm_free(*(void**)state);
            *(u32*)state = 0;
        }
    }
}

void lightning_init(u8* obj, u8* data)
{
    u8* state;
    f32 defaultScale;

    state = ((GameObject*)obj)->extra;
    ObjGroup_AddObject(obj, MMP_LIGHTNING_OBJGROUP);
    ((LightningMode*)(state + 0x24))->mode = data[0x21];
    defaultScale = lbl_803E40A0;
    ((MmpMoonrockState*)state)->baseY2 = defaultScale;
    ((MmpMoonrockState*)state)->respawnTimer = defaultScale;
    *(f32*)(state + 0x08) = (f32)(u32)
    data[0x1c];
    ((MmpMoonrockState*)state)->baseY = (f32)(u32)
    data[0x1d];
    state[0x1c] = data[0x1e];
    state[0x1d] = data[0x1f];
    *(u32*)&((MmpMoonrockState*)state)->homeZ = *(u32*)(data + 0x18);

    ((LightningFlags*)(state + 0x25))->enabled = (data[0x20] & 1) ? 1 : 0;
    ((LightningFlags*)(state + 0x25))->style = (data[0x20] & 2) ? 1 : 0;
    ((LightningFlags*)(state + 0x25))->noAge = (data[0x20] & 4) ? 1 : 0;

    ((MmpMoonrockState*)state)->homeX = (f32)(s32)((u32)data[0x22] * 0x3c);
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
