/* DLL 0x132 - waterfall spray / XYZ animator / SFX player objects [801978A0-801978A8) */
#include "main/dll/MMP/MMP_asteroid.h"

#include "main/dll/MMP/MMP_moonrock.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

#define WATERFALLSPRAY_OBJFLAG_RENDERED 0x800

typedef struct WaterFallSprayState
{
    u32 sfxIdA;
    u32 sfxIdB;
} WaterFallSprayState;

/* Placement/def record the map loader hands to the waterfall-spray init/update.
 * Shares the ObjPlacement head (pos at 0x8/0xc/0x10, mapId at 0x14). */
typedef struct WaterFallSprayPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;       /* 0x14: selects the alternate SFX-id pair */
    s16 gameBit;     /* 0x18: gating GameBit_Get (-1 = always on) */
    s8 rotZSeed;     /* 0x1a: <<8 -> anim.rotZ */
    s8 rotYSeed;     /* 0x1b: <<8 -> anim.rotY */
    s8 rotXSeed;     /* 0x1c: <<8 -> anim.rotX */
    u8 randX;        /* 0x1d: +/- spawn offset range, X */
    u8 randZ;        /* 0x1e: +/- spawn offset range, Z */
    u8 randY;        /* 0x1f: +/- spawn offset range, Y */
    u8 distance;     /* 0x20: trigger radius (<<4) */
    u8 pad21[0x23 - 0x21];
    u8 flags;        /* 0x23: spawn/keepalive flags */
    u8 count;        /* 0x24: particles spawned per trigger */
} WaterFallSprayPlacement;

STATIC_ASSERT(offsetof(WaterFallSprayPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WaterFallSprayPlacement, count) == 0x24);



/* lightning_render: deref obj->_b8->_0 (effect handle); if non-null call
 * lightningRender(handle). */


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
    WaterFallSprayState* state;
    WaterFallSprayPlacement* data;
    u8* obj;
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
    data = *(WaterFallSprayPlacement**)&((GameObject*)obj)->anim.placementData;
    playerObj = (GameObject*)Obj_GetPlayerObject();
    if (playerObj != NULL)
    {
        if (data->gameBit != -1)
        {
            i = GameBit_Get(data->gameBit);
        }
        else
        {
            i = 1;
        }
        if (i != 0)
        {
            if ((data->flags & 0x10) == 0)
            {
                Sfx_KeepAliveLoopedObjectSound(obj, state->sfxIdA & 0xffff);
                Sfx_KeepAliveLoopedObjectSound(obj, state->sfxIdB & 0xffff);
            }

            cooldown = ((GameObject*)obj)->unkF4;
            if (cooldown <= 0)
            {
                dx = ((GameObject*)obj)->anim.worldPosX - playerObj->anim.worldPosX;
                dy = ((GameObject*)obj)->anim.worldPosY - playerObj->anim.worldPosY;
                dz = ((GameObject*)obj)->anim.worldPosZ - playerObj->anim.worldPosZ;
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (((distance <= (f32)(s32)((u32)data->distance << 4)) || (data->distance == 0)) &&
                    ((((GameObject*)obj)->objectFlags & WATERFALLSPRAY_OBJFLAG_RENDERED) != 0))
                {
                    for (i = 0; i < data->count; i++)
                    {
                        partfxArgs.xOffset = (f32)(s32)
                        randomGetRange(-data->randX, data->randX);
                        partfxArgs.yOffset = (f32)(s32)
                        randomGetRange(-data->randY, data->randY);
                        partfxArgs.zOffset = (f32)(s32)
                        randomGetRange(-data->randZ, data->randZ);
                        if ((data->flags & 1) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x320, &partfxArgs);
                        }
                        if ((data->flags & 2) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x321, &partfxArgs);
                        }
                        if ((data->flags & 4) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x322, &partfxArgs);
                        }
                        if ((data->flags & 8) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x351, &partfxArgs);
                        }
                    }
                }
                *(u32*)&((GameObject*)obj)->unkF4 = -data->count;
            }
            else if (cooldown > 0)
            {
                *(u32*)&((GameObject*)obj)->unkF4 = cooldown - framesThisStep;
            }
        }
    }
}

/* WaterFallSpray_init: stash 3 signed-byte<<8 fields at obj+0..+4, clear
 * obj+0xf4, install WaterFallSpray_SeqFn as the think routine at obj+0xbc, then
 * pick one of two SFX-id pairs based on the range of obj->_4c->_14. */
void WaterFallSpray_init(u8* obj, u8* dataRaw)
{
    WaterFallSprayPlacement* data = (WaterFallSprayPlacement*)dataRaw;
    u8* sub = ((GameObject*)obj)->extra;
    s16 a, b, c;
    int mapId;
    a = (s16)((s32)data->rotZSeed << 8);
    ((GameObject*)obj)->anim.rotZ = a;
    b = (s16)((s32)data->rotYSeed << 8);
    ((GameObject*)obj)->anim.rotY = b;
    c = (s16)((s32)data->rotXSeed << 8);
    ((GameObject*)obj)->anim.rotX = c;
    *(u32*)&((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->animEventCallback = WaterFallSpray_SeqFn;
    mapId = (*(WaterFallSprayPlacement**)&((GameObject*)obj)->anim.placementData)->mapId;
    switch (mapId)
    {
    case WATERFALLSPRAY_ALT_SFX_DEF_MIN:
    case WATERFALLSPRAY_ALT_SFX_DEF_END - 1:
        ((WaterFallSprayState*)sub)->sfxIdA = WATERFALLSPRAY_ALT_SFX_A;
        ((WaterFallSprayState*)sub)->sfxIdB = WATERFALLSPRAY_ALT_SFX_B;
        return;
    default:
        ((WaterFallSprayState*)sub)->sfxIdA = WATERFALLSPRAY_DEFAULT_SFX_A;
        ((WaterFallSprayState*)sub)->sfxIdB = WATERFALLSPRAY_DEFAULT_SFX_B;
    }
}

/* sfxplayerObj_init: prime obj->_b0 with SFXPLAYER_OBJECT_FLAGS, then dispatch
 * on data->_1d: gamebit mode stores GameBit_Get(data->_18) at sub[0] if the
 * event id is positive; random-delay mode computes randomGetRange(data->_1e, data->_1f)
 * scaled by lbl_803E40BC as f32; cases 1 and >=3 are no-ops. */

/* sfxplayerObj_free: bit-0 of obj->_b8->_4 gates teardown. When set, clear
 * it and stop two sfx loops (data->_1a and data->_22). Mode depends on
 * data->_1d: 1 → Sfx_RemoveLoopedObjectSound, else Sfx_StopFromObject. */

void WaterFallSpray_render(void)
{
}

int WaterFallSpray_getExtraSize(void) { return 0x8; }

int WaterFallSpray_SeqFn(int* obj)
{
    WaterFallSpray_update(obj);
    return 0;
}
