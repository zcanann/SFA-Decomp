/*
 * dll80func0 (DLL 0x80) - a foodbag-family modgfx effect builder.
 *
 * dll_80_func03 fills a stack FbBuf with a fixed list of FbCmd draw
 * entries (textures taken from the `lbl_80315468` texture data array) and hands it
 * to ModgfxInterface::spawnEffect. The `variant` arg only swaps the
 * second entry's offsets/scale (4.2/20 vs 0.42/2); the
 * low bit of the merged flag word selects whether the effect position is
 * read from the source object (+0x18..) or the posSource transform
 * (+0xc..). The two trailing _nop entry points are the DLL's empty
 * func00/func01 slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/dll/dll_0080_dll80func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL80_EFFECT_ID 0x156

extern u8 lbl_80315468[];

void dll_80_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = lbl_80315468;
    FbCmd* e = buf.entries;
    FbCmd* p;

    e[0].layer = 0;
    e[0].flags = 9;
    e[0].tex = base + 0x8c;
    e[0].mode = 0x80;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 16383.0f;
    if (variant == 1)
    {
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = base + 0xa0;
        e[1].mode = 2;
        e[1].x = 4.2f;
        e[1].y = 4.2f;
        e[1].z = 20.0f;
        p = e + 2;
    }
    else
    {
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = base + 0xa0;
        e[1].mode = 2;
        e[1].x = 0.42f;
        e[1].y = 0.42f;
        e[1].z = 2.0f;
        p = e + 2;
    }
    p[0].layer = 1;
    p[0].flags = 8;
    p[0].tex = base + 0x8c;
    p[0].mode = 2;
    p[0].x = 2.0f;
    p[0].y = 2.0f;
    p[0].z = 1.0f;
    p[1].layer = 1;
    p[1].flags = 9;
    p[1].tex = base + 0x8c;
    p[1].mode = 0x100;
    p[1].x = -900.0f;
    p[1].y = 0.0f;
    p[1].z = 0.0f;
    p[2].layer = 1;
    p[2].flags = 9;
    p[2].tex = base + 0x8c;
    p[2].mode = 4;
    p[2].x = 0.0f;
    p[2].y = 0.0f;
    p[2].z = 0.0f;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0x20;
    buf.count = &p[3] - e;
    buf.hw[0] = *(s16*)(base + 0xb0);
    buf.hw[1] = *(s16*)(base + 0xb2);
    buf.hw[2] = *(s16*)(base + 0xb4);
    buf.hw[3] = *(s16*)(base + 0xb6);
    buf.hw[4] = *(s16*)(base + 0xb8);
    buf.hw[5] = *(s16*)(base + 0xba);
    buf.hw[6] = *(s16*)(base + 0xbc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000010;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
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
    buf.v58 = 0;
    (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base, 8, base + 0x5c, DLL80_EFFECT_ID, 0);
}

void dll_80_func01_nop(void)
{
}

void dll_80_func00_nop(void)
{
}
