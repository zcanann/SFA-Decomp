/*
 * dll_00A3 (dlla3func0) - bone-particle effect spawner.
 *
 * dll_A3_func03 builds a 14-command GfxCmd list on the stack from a data
 * blob (lbl_80312F98: per-command texture offsets, half-words and the
 * spawnEffect parameter bytes), scales the effect by the low byte of
 * `variant` (or a default when zero), then optionally biases the spawn
 * position either by the source object's world position (when flag bit 0
 * is set and a source object is supplied) or by the PartFxSpawnParams at
 * posSource, and submits the list through gModgfxInterface->spawnEffect.
 *
 * func00/func01 are the standard empty DLL entry stubs.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_00A3_dlla3func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLLA3_EFFECT_ID 0x5e0

extern u8 lbl_80312F98[];

void dll_A3_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    GfxCmd* e = buf.entries;
    u8* base = (u8*)(int)lbl_80312F98;
    u32 variantByte = (u8)variant;
    int ctx;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = &base[404];
    e[1].mode = 2;
    e[1].x = 0.95f;
    e[1].y = 0.4f;
    e[1].z = 0.95f;
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &base[372];
    e[2].mode = 2;
    e[2].x = 0.95f;
    e[2].y = 0.4f;
    e[2].z = 0.95f;
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = &base[372];
    e[3].mode = 4;
    e[3].x = 255.0f;
    e[3].y = 0.0f;
    e[3].z = 0.0f;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &base[388];
    e[4].mode = 4;
    e[4].x = 255.0f;
    e[4].y = 0.0f;
    e[4].z = 0.0f;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x100;
    e[5].x = 0.0f;
    e[5].y = 0.0f;
    e[5].z = 10.0f;
    e[6].layer = 2;
    e[6].flags = 0x3a;
    e[6].tex = NULL;
    e[6].mode = 0x1800000;
    e[6].x = 0.0f;
    e[6].y = 0.0f;
    e[6].z = 5.0f;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x100;
    e[7].x = 0.0f;
    e[7].y = 0.0f;
    e[7].z = 10.0f;
    e[8].layer = 3;
    e[8].flags = 0x3a;
    e[8].tex = NULL;
    e[8].mode = 0x1800000;
    e[8].x = 0.0f;
    e[8].y = 0.0f;
    e[8].z = 5.0f;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = &base[432];
    e[9].mode = 0x100;
    e[9].x = 0.0f;
    e[9].y = 0.0f;
    e[9].z = 10.0f;
    e[10].layer = 4;
    e[10].flags = 2;
    e[10].tex = NULL;
    e[10].mode = 0x2000;
    e[10].x = 0.0f;
    e[10].y = 0.0f;
    e[10].z = 0.0f;
    e[11].layer = 5;
    e[11].flags = 7;
    e[11].tex = &base[372];
    e[11].mode = 4;
    e[11].x = 0.0f;
    e[11].y = 0.0f;
    e[11].z = 0.0f;
    e[12].layer = 5;
    e[12].flags = 7;
    e[12].tex = &base[388];
    e[12].mode = 4;
    e[12].x = 0.0f;
    e[12].y = 0.0f;
    e[12].z = 0.0f;
    e[13].layer = 5;
    e[13].flags = 0x15;
    e[13].tex = &base[432];
    e[13].mode = 0x100;
    e[13].x = 0.0f;
    e[13].y = 0.0f;
    e[13].z = 10.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    if (variantByte != 0)
    {
        buf.scale = 0.1f * variantByte;
    }
    else
    {
        buf.scale = 1.0f;
    }
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 14;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0400c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)buf.ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80312F98, 0x18, &base[212], DLLA3_EFFECT_ID, 0);
}

void dll_A3_func01_nop(void)
{
}

void dll_A3_func00_nop(void)
{
}
