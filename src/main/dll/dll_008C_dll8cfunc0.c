/*
 * dll_008C (foodbag effect 0x8C) - builds a fixed 14-entry modgfx command
 * list (FbBuf/FbCmd) and spawns it through gModgfxInterface->spawnEffect.
 *
 * dll_8C_func03 is the effect's func03 spawn entry (one of the dll_NN_func03
 * family declared in foodbag.h). Each FbCmd row sets a layer, render flags,
 * a texture pointer into the per-effect asset blob (lbl_80316950 + offset),
 * a draw mode and an x/y/z triple. Rows 1, 2, 5, 7 and 9 read live values
 * from posSource (the s16 vector/scale packet) when supplied, else fall back
 * to the lbl_803E10xx default constants. buf.flags ORs in the caller flags;
 * bit 0 means "use a world position" - taken from sourceObj+0x18 when there
 * is a source object, otherwise from posSource+0xC.
 *
 * func00/func01 are the descriptor's empty init/free slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316950[]; /* per-effect texture/asset blob */
extern f32 lbl_803E10B0;
extern f32 lbl_803E10B4;
extern f32 lbl_803E10B8;
extern f32 lbl_803E10BC;
extern f32 lbl_803E10C0;
extern f32 lbl_803E10C4;
extern f32 lbl_803E10C8;
extern f32 lbl_803E10CC;
extern f32 lbl_803E10D0;
extern f32 lbl_803E10D4;

void dll_8C_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = lbl_80316950;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E10B0;
    e[0].y = lbl_803E10B0;
    e[0].z = lbl_803E10B0;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = base + 0x194;
    e[1].mode = 2;
    if ((u32)posSource != 0)
    {
        e[1].x = lbl_803E10B4 * (lbl_803E10B8 * (f32) * (s16*)(posSource + 4));
        e[1].y = lbl_803E10B4 * (lbl_803E10BC * (f32) * (s16*)(posSource + 0));
        e[1].z = lbl_803E10B4 * (lbl_803E10B8 * (f32) * (s16*)(posSource + 4));
    }
    else
    {
        e[1].x = lbl_803E10B8;
        e[1].y = lbl_803E10BC;
        e[1].z = lbl_803E10B8;
    }
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = base + 0x174;
    e[2].mode = 2;
    if ((u32)posSource != 0)
    {
        e[2].x = lbl_803E10B4 * (lbl_803E10B8 * (f32) * (s16*)(posSource + 4));
        e[2].y = lbl_803E10B4 * (lbl_803E10C0 * (f32) * (s16*)(posSource + 0));
        e[2].z = lbl_803E10B4 * (lbl_803E10B8 * (f32) * (s16*)(posSource + 4));
    }
    else
    {
        e[2].x = lbl_803E10B8;
        e[2].y = lbl_803E10BC;
        e[2].z = lbl_803E10B8;
    }
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = base + 0x174;
    e[3].mode = 4;
    e[3].x = lbl_803E10C4;
    e[3].y = lbl_803E10B0;
    e[3].z = lbl_803E10B0;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = base + 0x184;
    e[4].mode = 4;
    e[4].x = lbl_803E10C4;
    e[4].y = lbl_803E10B0;
    e[4].z = lbl_803E10B0;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 0x100;
    e[5].x = lbl_803E10B0;
    e[5].y = lbl_803E10B0;
    if ((u32)posSource != 0)
    {
        e[5].z = (f32) * (s16*)(posSource + 2);
    }
    else
    {
        e[5].z = lbl_803E10C8;
    }
    e[6].layer = 2;
    e[6].flags = 0x3a;
    e[6].tex = NULL;
    e[6].mode = 0x1800000;
    e[6].x = lbl_803E10CC;
    e[6].y = lbl_803E10B0;
    e[6].z = lbl_803E10D0;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = base + 0x1b0;
    e[7].mode = 0x100;
    e[7].x = lbl_803E10B0;
    e[7].y = lbl_803E10B0;
    if ((u32)posSource != 0)
    {
        e[7].z = (f32) * (s16*)(posSource + 2);
    }
    else
    {
        e[7].z = lbl_803E10C8;
    }
    e[8].layer = 3;
    e[8].flags = 0x3b8;
    e[8].tex = NULL;
    e[8].mode = 0x1800000;
    e[8].x = lbl_803E10CC;
    e[8].y = lbl_803E10B0;
    e[8].z = lbl_803E10D0;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = base + 0x1b0;
    e[9].mode = 0x100;
    e[9].x = lbl_803E10B0;
    e[9].y = lbl_803E10B0;
    if ((u32)posSource != 0)
    {
        e[9].z = (f32) * (s16*)(posSource + 2);
    }
    else
    {
        e[9].z = lbl_803E10C8;
    }
    e[10].layer = 4;
    e[10].flags = 0;
    e[10].tex = NULL;
    e[10].mode = 0x1000;
    e[10].x = lbl_803E10D4;
    e[10].y = lbl_803E10B0;
    e[10].z = lbl_803E10B0;
    e[11].layer = 5;
    e[11].flags = 7;
    e[11].tex = base + 0x174;
    e[11].mode = 4;
    e[11].x = lbl_803E10B0;
    e[11].y = lbl_803E10B0;
    e[11].z = lbl_803E10B0;
    e[12].layer = 5;
    e[12].flags = 7;
    e[12].tex = base + 0x184;
    e[12].mode = 4;
    e[12].x = lbl_803E10B0;
    e[12].y = lbl_803E10B0;
    e[12].z = lbl_803E10B0;
    e[13].layer = 5;
    e[13].flags = 0x15;
    e[13].tex = base + 0x1b0;
    e[13].mode = 0x100;
    e[13].x = lbl_803E10B0;
    e[13].y = lbl_803E10B0;
    e[13].z = lbl_803E10C8;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E10B0;
    buf.pos[1] = lbl_803E10B0;
    buf.pos[2] = lbl_803E10B0;
    buf.col[0] = lbl_803E10B0;
    buf.col[1] = lbl_803E10B0;
    buf.col[2] = lbl_803E10B0;
    buf.scale = lbl_803E10CC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 0xe;
    buf.hw[0] = *(s16*)(base + 0x1dc);
    buf.hw[1] = *(s16*)(base + 0x1de);
    buf.hw[2] = *(s16*)(base + 0x1e0);
    buf.hw[3] = *(s16*)(base + 0x1e2);
    buf.hw[4] = *(s16*)(base + 0x1e4);
    buf.hw[5] = *(s16*)(base + 0x1e6);
    buf.hw[6] = *(s16*)(base + 0x1e8);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0400c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E10B0 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E10B0 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E10B0 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E10B0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E10B0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E10B0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, base, 0x18, base + 0xd4, 0x5e0, 0);
}

void dll_8C_func01_nop(void)
{
}

void dll_8C_func00_nop(void)
{
}
