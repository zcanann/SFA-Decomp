/* DLL 0x132 - waterfall spray / XYZ animator / SFX player objects [801978A0-801978A8) */
#include "main/dll/partfx_interface.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/object_api.h"
#include "main/audio/sfx_keep_alive_api.h"

#include "main/dll/dll_0132_waterfallspray.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"

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
    s32 mapId;   /* 0x14: selects the alternate SFX-id pair */
    s16 gameBit; /* 0x18: gating mainGetBit (-1 = always on) */
    s8 rotZSeed; /* 0x1a: <<8 -> anim.rotZ */
    s8 rotYSeed; /* 0x1b: <<8 -> anim.rotY */
    s8 rotXSeed; /* 0x1c: <<8 -> anim.rotX */
    u8 randX;    /* 0x1d: +/- spawn offset range, X */
    u8 randZ;    /* 0x1e: +/- spawn offset range, Z */
    u8 randY;    /* 0x1f: +/- spawn offset range, Y */
    u8 distance; /* 0x20: trigger radius (<<4) */
    u8 pad21[0x23 - 0x21];
    u8 flags; /* 0x23: spawn/keepalive flags */
    u8 count; /* 0x24: particles spawned per trigger */
} WaterFallSprayPlacement;

STATIC_ASSERT(offsetof(WaterFallSprayPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WaterFallSprayPlacement, count) == 0x24);

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

#define WATERFALLSPRAY_SPAWN_PARTICLE(obj, id, args) (*gPartfxInterface)->spawnObject((obj), (id), (args), 4, -1, 0)

void WaterFallSpray_update(int* objParam)
{
    WaterFallSprayState* state;
    WaterFallSprayPlacement* data[1];
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
    data[0] = *(WaterFallSprayPlacement**)&((GameObject*)obj)->anim.placementData;
    playerObj = (GameObject*)Obj_GetPlayerObject();
    if (playerObj != NULL)
    {
        if (data[0]->gameBit != -1)
        {
            i = mainGetBit(data[0]->gameBit);
        }
        else
        {
            i = 1;
        }
        if (i != 0)
        {
            if ((data[0]->flags & 0x10) == 0)
            {
                Sfx_KeepAliveLoopedObjectSoundPtrIntLegacy(obj, state->sfxIdA & 0xffff);
                Sfx_KeepAliveLoopedObjectSoundPtrIntLegacy(obj, state->sfxIdB & 0xffff);
            }

            cooldown = ((GameObject*)obj)->unkF4;
            if (cooldown <= 0)
            {
                dx = ((GameObject*)obj)->anim.worldPosX - playerObj->anim.worldPosX;
                dy = ((GameObject*)obj)->anim.worldPosY - playerObj->anim.worldPosY;
                dz = ((GameObject*)obj)->anim.worldPosZ - playerObj->anim.worldPosZ;
                distance = sqrtf(dz * dz + (dx * dx + dy * dy));
                if (((distance <= (f32)(s32)((u32)data[0]->distance << 4)) || (data[0]->distance == 0)) &&
                    ((((GameObject*)obj)->objectFlags & WATERFALLSPRAY_OBJFLAG_RENDERED) != 0))
                {
                    for (i = 0; i < data[0]->count; i++)
                    {
                        partfxArgs.xOffset = (f32)(s32)randomGetRange(-data[0]->randX, data[0]->randX);
                        partfxArgs.yOffset = (f32)(s32)randomGetRange(-data[0]->randY, data[0]->randY);
                        partfxArgs.zOffset = (f32)(s32)randomGetRange(-data[0]->randZ, data[0]->randZ);
                        if ((data[0]->flags & 1) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x320, &partfxArgs);
                        }
                        if ((data[0]->flags & 2) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x321, &partfxArgs);
                        }
                        if ((data[0]->flags & 4) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x322, &partfxArgs);
                        }
                        if ((data[0]->flags & 8) != 0)
                        {
                            WATERFALLSPRAY_SPAWN_PARTICLE(obj, 0x351, &partfxArgs);
                        }
                    }
                }
                *(u32*)&((GameObject*)obj)->unkF4 = -data[0]->count;
            }
            else if (cooldown > 0)
            {
                *(u32*)&((GameObject*)obj)->unkF4 = cooldown - framesThisStep;
            }
        }
    }
}

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

void WaterFallSpray_render(void)
{
}

int WaterFallSpray_getExtraSize(void)
{
    return 0x8;
}

int WaterFallSpray_SeqFn(int* obj)
{
    WaterFallSpray_update(obj);
    return 0;
}
