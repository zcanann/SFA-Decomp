/*
 * dll80func0 (DLL 0x80) - a foodbag-family modgfx effect builder.
 *
 * dll_80_func03 fills a stack FbBuf with a fixed list of FbCmd draw
 * entries (textures taken from the `lbl_80315468` texture data array) and hands it
 * to ModgfxInterface::spawnEffect. The `variant` arg only swaps the
 * second entry's offsets/scale (lbl_803E0E60/64 vs lbl_803E0E68/6C); the
 * low bit of the merged flag word selects whether the effect position is
 * read from the source object (+0x18..) or the posSource transform
 * (+0xc..). The two trailing _nop entry points are the DLL's empty
 * func00/func01 slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315468[];
extern f32 lbl_803E0E58;
extern f32 lbl_803E0E5C;
extern f32 lbl_803E0E60;
extern f32 lbl_803E0E64;
extern f32 lbl_803E0E68;
extern f32 lbl_803E0E6C;
extern f32 lbl_803E0E70;
extern f32 lbl_803E0E74;

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
    e[0].x = lbl_803E0E58;
    e[0].y = lbl_803E0E58;
    e[0].z = lbl_803E0E5C;
    if (variant == 1)
    {
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = base + 0xa0;
        e[1].mode = 2;
        e[1].x = lbl_803E0E60;
        e[1].y = lbl_803E0E60;
        e[1].z = lbl_803E0E64;
        p = e + 2;
    }
    else
    {
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = base + 0xa0;
        e[1].mode = 2;
        e[1].x = lbl_803E0E68;
        e[1].y = lbl_803E0E68;
        e[1].z = lbl_803E0E6C;
        p = e + 2;
    }
    p[0].layer = 1;
    p[0].flags = 8;
    p[0].tex = base + 0x8c;
    p[0].mode = 2;
    p[0].x = lbl_803E0E6C;
    p[0].y = lbl_803E0E6C;
    p[0].z = lbl_803E0E70;
    p[1].layer = 1;
    p[1].flags = 9;
    p[1].tex = base + 0x8c;
    p[1].mode = 0x100;
    p[1].x = lbl_803E0E74;
    p[1].y = lbl_803E0E58;
    p[1].z = lbl_803E0E58;
    p[2].layer = 1;
    p[2].flags = 9;
    p[2].tex = base + 0x8c;
    p[2].mode = 4;
    p[2].x = lbl_803E0E58;
    p[2].y = lbl_803E0E58;
    p[2].z = lbl_803E0E58;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0E58;
    buf.pos[1] = lbl_803E0E58;
    buf.pos[2] = lbl_803E0E58;
    buf.col[0] = lbl_803E0E58;
    buf.col[1] = lbl_803E0E58;
    buf.col[2] = lbl_803E0E58;
    buf.scale = lbl_803E0E70;
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
            buf.pos[0] = lbl_803E0E58 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0E58 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0E58 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0E58 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0E58 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0E58 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    buf.v58 = 0;
    (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base, 8, base + 0x5c, 0x156, 0);
}


void dll_80_func01_nop(void)
{
}

void dll_80_func00_nop(void)
{
}
