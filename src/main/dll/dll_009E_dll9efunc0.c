/*
 * dll9efunc0 (DLL 0x9E) - one of the per-effect pickup/modgfx spawners.
 *
 * dll_9E_func03 builds a fixed list of 14 modgfx draw commands (GfxCmd
 * entries[], one mode/blend + xyz per command, texture sub-tables taken
 * from the lbl_80318260 data blob) plus the surrounding spawn header
 * (colour, position, scale, the seven s16 params at base+0x1f8..+0x204),
 * then hands the whole packet to (*gModgfxInterface)->spawnEffect.
 *
 * The spawn flag word starts at 0xC0100C0 and ORs in the caller's flags;
 * bit 0 means "anchor to a world position": from sourceObj+0x18 when a
 * source object was passed, otherwise from posSource+0xc.
 *
 * func00/func01 are the empty DLL entry-table slots for this object.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/pickup.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL9E_EFFECT_ID 0x46c


/* lbl_80318260: shared texture + halfword table. Home TU unknown. */
extern u8 lbl_80318260[];

void dll_9E_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80318260;
    GfxCmd* e = buf.entries;
    u32 spawnFlags;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[0x1b0];
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[0x1b0];
    e[1].mode = 2;
    e[1].x = 1.0f;
    e[1].y = 20.0f;
    e[1].z = 1.0f;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = 0.0f;
    e[2].y = -300.0f;
    e[2].z = 0.0f;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = &base[0x1b0];
    e[3].mode = 2;
    e[3].x = 1.5f;
    e[3].y = 1.5f;
    e[3].z = 1.5f;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &base[0x174];
    e[4].mode = 4;
    e[4].x = 155.0f;
    e[4].y = 0.0f;
    e[4].z = 0.0f;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[0x1b0];
    e[5].mode = 0x4000;
    e[5].x = 2.0f;
    e[5].y = 0.0f;
    e[5].z = 0.0f;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x400000;
    e[6].x = 0.0f;
    e[6].y = 0.0f;
    e[6].z = 0.0f;
    e[7].layer = 2;
    e[7].flags = 0x7a;
    e[7].tex = NULL;
    e[7].mode = 0x10000;
    e[7].x = 0.0f;
    e[7].y = 0.0f;
    e[7].z = 0.0f;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &base[0x1b0];
    e[8].mode = 8;
    e[8].x = 255.0f;
    e[8].y = 125.0f;
    e[8].z = 0.0f;
    e[9].layer = 2;
    e[9].flags = 0x15;
    e[9].tex = &base[0x1b0];
    e[9].mode = 0x4000;
    e[9].x = 2.0f;
    e[9].y = 0.0f;
    e[9].z = 0.0f;
    e[10].layer = 2;
    e[10].flags = 0;
    e[10].tex = NULL;
    e[10].mode = 0x400000;
    e[10].x = 0.0f;
    e[10].y = 600.0f;
    e[10].z = 0.0f;
    e[11].layer = 3;
    e[11].flags = 0x15;
    e[11].tex = &base[0x1b0];
    e[11].mode = 0x4000;
    e[11].x = 2.0f;
    e[11].y = 0.0f;
    e[11].z = 0.0f;
    e[12].layer = 3;
    e[12].flags = 0;
    e[12].tex = NULL;
    e[12].mode = 0x400000;
    e[12].x = 0.0f;
    e[12].y = 600.0f;
    e[12].z = 0.0f;
    e[13].layer = 3;
    e[13].flags = 7;
    e[13].tex = &base[0x174];
    e[13].mode = 4;
    e[13].x = 0.0f;
    e[13].y = 0.0f;
    e[13].z = 0.0f;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 4.0f;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 336) - e;
    buf.hw[0] = *(s16*)&base[0x1f8];
    buf.hw[1] = *(s16*)&base[0x1fa];
    buf.hw[2] = *(s16*)&base[0x1fc];
    buf.hw[3] = *(s16*)&base[0x1fe];
    buf.hw[4] = *(s16*)&base[0x200];
    buf.hw[5] = *(s16*)&base[0x202];
    buf.hw[6] = *(s16*)&base[0x204];
    buf.cmds = e;
    spawnFlags = 0xc0100c0;
    buf.flags = spawnFlags;
    spawnFlags |= flags;
    buf.flags = spawnFlags;
    if (spawnFlags & 1)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] += ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80318260, 0x18, &base[0xd4], DLL9E_EFFECT_ID, 0);
}

void dll_9E_func01_nop(void)
{
}

void dll_9E_func00_nop(void)
{
}
