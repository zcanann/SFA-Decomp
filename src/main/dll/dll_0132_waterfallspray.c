/* DLL 0x132 — waterfall spray / XYZ animator / SFX player objects [801978A0-801978A8) */
#include "main/dll/MMP/MMP_asteroid.h"

extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);


extern u8 framesThisStep;
extern f32 sqrtf(f32);

#include "main/dll/MMP/MMP_moonrock.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"

typedef struct WaterFallSprayState
{
    u32 unk0;
    u32 unk4;
} WaterFallSprayState;

extern u8* Obj_GetPlayerObject(void);
extern f32 sqrtf(f32 value);

/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */

extern f32 lbl_803E40BC;

void WaterFallSpray_free(u8* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

typedef struct WaterFallSprayPartfxArgs
{
    u32 pad0;
    u32 pad1;
    u32 pad2;
    f32 xOffset;
    f32 yOffset;
    f32 zOffset;
} WaterFallSprayPartfxArgs;

#define WATERFALLSPRAY_SPAWN_PARTICLE(obj, id, args) \
    (*gPartfxInterface)->spawnObject( \
        (obj), (id), (args), 4, -1, 0)

void WaterFallSpray_update(int* objParam)
{
    extern void Sfx_KeepAliveLoopedObjectSound(u8* obj, int sfxId); /* #57 */
    u8* obj;
    u32* state;
    u8* data;
    u8* player;
    GameObject* playerObj;
    WaterFallSprayPartfxArgs partfxArgs;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    int cooldown;
    s16 i;

    obj = (u8*)objParam;
    state = ((GameObject*)obj)->extra;
    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    playerObj = (GameObject*)player;
    if (player != NULL)
    {
        if (*(s16*)(data + 0x18) != -1)
        {
            i = GameBit_Get(*(s16*)(data + 0x18));
        }
        else
        {
            i = 1;
        }
        if (i != 0)
        {
            if ((data[0x23] & 0x10) == 0)
            {
                Sfx_KeepAliveLoopedObjectSound(obj, state[0] & 0xffff);
                Sfx_KeepAliveLoopedObjectSound(obj, state[1] & 0xffff);
            }

            cooldown = ((GameObject*)obj)->unkF4;
            if (cooldown <= 0)
            {
                dx = ((GameObject*)obj)->anim.worldPosX - playerObj->anim.worldPosX;
                dy = ((GameObject*)obj)->anim.worldPosY - playerObj->anim.worldPosY;
                dz = ((GameObject*)obj)->anim.worldPosZ - playerObj->anim.worldPosZ;
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (((distance <= (f32)(s32)((u32)data[0x20] << 4)) || (data[0x20] == 0)) &&
                    ((((GameObject*)obj)->objectFlags & 0x800) != 0))
                {
                    for (i = 0; i < data[0x24]; i++)
                    {
                        partfxArgs.xOffset = (f32)(s32)
                        randomGetRange(-data[0x1d], data[0x1d]);
                        partfxArgs.yOffset = (f32)(s32)
                        randomGetRange(-data[0x1f], data[0x1f]);
                        partfxArgs.zOffset = (f32)(s32)
                        randomGetRange(-data[0x1e], data[0x1e]);
                        if ((data[0x23] & 1) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x320, &partfxArgs);
                        }
                        if ((data[0x23] & 2) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x321, &partfxArgs);
                        }
                        if ((data[0x23] & 4) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x322, &partfxArgs);
                        }
                        if ((data[0x23] & 8) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x351, &partfxArgs);
                        }
                    }
                }
                *(u32*)&((GameObject*)obj)->unkF4 = -(u32)data[0x24];
            }
            else if (cooldown > 0)
            {
                *(u32*)&((GameObject*)obj)->unkF4 = cooldown - (u32)framesThisStep;
            }
        }
    }
}

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */
void WaterFallSpray_init(u8* obj, u8* data)
{
    u8* sub = ((GameObject*)obj)->extra;
    s16 a, b, c;
    int v;
    a = (s16)((s32)(s8)data[0x1a] << 8);
    ((GameObject*)obj)->anim.rotZ = a;
    b = (s16)((s32)(s8)data[0x1b] << 8);
    ((GameObject*)obj)->anim.rotY = b;
    c = (s16)((s32)(s8)data[0x1c] << 8);
    ((GameObject*)obj)->anim.rotX = c;
    *(u32*)&((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)WaterFallSpray_SeqFn;
    v = *(int*)((char*)(*(u8**)&((GameObject*)obj)->anim.placementData) + 0x14);
    if (v < WATERFALLSPRAY_ALT_SFX_DEF_END)
    {
        if (v >= WATERFALLSPRAY_ALT_SFX_DEF_MIN)
        {
            ((WaterFallSprayState*)sub)->unk0 = WATERFALLSPRAY_ALT_SFX_A;
            ((WaterFallSprayState*)sub)->unk4 = WATERFALLSPRAY_ALT_SFX_B;
            return;
        }
    }
    ((WaterFallSprayState*)sub)->unk0 = WATERFALLSPRAY_DEFAULT_SFX_A;
    ((WaterFallSprayState*)sub)->unk4 = WATERFALLSPRAY_DEFAULT_SFX_B;
}

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on (s8)data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */

void sfxplayerObj_init(u8* obj, u8* data);

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */

void WaterFallSpray_render(void)
{
}

int WaterFallSpray_getExtraSize(void) { return 0x8; }
int sfxplayerObj_getExtraSize(void);

int WaterFallSpray_SeqFn(int* obj)
{
    WaterFallSpray_update(obj);
    return 0;
}
