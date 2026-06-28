/*
 * dll83func0 (DLL 0x83) - a foodbag-family modgfx effect builder.
 * dll_83_func03 fills a 20-entry FbCmd draw list (textures sourced from
 * gFoodbagEffectTexData, layers 0..4) plus the FbBuf header, then spawns the effect
 * through gModgfxInterface. When flags bit 0 is set the effect position is
 * offset by the source object's (sourceObj+0x18) or, when absent, the
 * posSource (posSource+0xc) world position. func00 and func01 are empty
 * no-op slots; func03 is the main entry point.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E0ED8;
extern f32 lbl_803E0EDC;
extern f32 lbl_803E0EE0;
extern f32 lbl_803E0EE4;
extern f32 lbl_803E0EE8;
extern f32 lbl_803E0EEC;
extern f32 lbl_803E0EF0;
extern f32 lbl_803E0EF4;
extern f32 lbl_803E0EF8;
extern f32 lbl_803E0EFC;
extern f32 lbl_803E0F00;
extern f32 lbl_803E0F04;
extern f32 lbl_803E0F08;
extern f32 lbl_803E0F0C;
extern f32 lbl_803E0F10;
extern f32 lbl_803E0F14;
extern f32 lbl_803E0F18;
extern u8 gFoodbagEffectTexData[];

void dll_83_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)gFoodbagEffectTexData;
    int* base32 = (int*)base;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x9;
    e[0].tex = base + 0x1c8;
    e[0].mode = 0x2;
    e[0].x = lbl_803E0ED8;
    e[0].y = lbl_803E0EDC;
    e[0].z = lbl_803E0ED8;
    e[1].layer = 0;
    e[1].flags = 0x9;
    e[1].tex = base + 0x1dc;
    e[1].mode = 0x2;
    e[1].x = lbl_803E0EE0;
    e[1].y = lbl_803E0EDC;
    e[1].z = lbl_803E0EE0;
    e[2].layer = 0;
    e[2].flags = 0x9;
    e[2].tex = base + 0x1f0;
    e[2].mode = 0x2;
    e[2].x = lbl_803E0EE0;
    e[2].y = lbl_803E0EDC;
    e[2].z = lbl_803E0EE0;
    e[3].layer = 0;
    e[3].flags = 0x9;
    e[3].tex = base + 0x204;
    e[3].mode = 0x2;
    e[3].x = lbl_803E0EE0;
    e[3].y = lbl_803E0EDC;
    e[3].z = lbl_803E0EE0;
    e[4].layer = 0;
    e[4].flags = 0x24;
    e[4].tex = base + 0x260;
    e[4].mode = 0x4;
    e[4].x = lbl_803E0EE4;
    e[4].y = lbl_803E0EE4;
    e[4].z = lbl_803E0EE4;
    e[5].layer = 0;
    e[5].flags = 0x0;
    e[5].tex = NULL;
    e[5].mode = 0x400000;
    e[5].x = lbl_803E0EE8;
    e[5].y = lbl_803E0EEC;
    e[5].z = lbl_803E0EF0;
    e[6].layer = 1;
    e[6].flags = 0x24;
    e[6].tex = base + 0x260;
    e[6].mode = 0x2;
    e[6].x = lbl_803E0EF4;
    e[6].y = lbl_803E0EF8;
    e[6].z = lbl_803E0EF4;
    e[7].layer = 1;
    e[7].flags = 0x24;
    e[7].tex = base + 0x260;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0EE4;
    e[7].y = lbl_803E0EE4;
    e[7].z = lbl_803E0EE4;
    e[8].layer = 1;
    e[8].flags = 0x24;
    e[8].tex = base + 0x260;
    e[8].mode = 0x100;
    e[8].x = lbl_803E0EE4;
    e[8].y = lbl_803E0EE4;
    e[8].z = lbl_803E0EFC;
    e[9].layer = 2;
    e[9].flags = 0x12;
    e[9].tex = base + 0x2a8;
    e[9].mode = 0x4;
    e[9].x = lbl_803E0F00;
    e[9].y = lbl_803E0EE4;
    e[9].z = lbl_803E0EE4;
    e[10].layer = 2;
    e[10].flags = 0x24;
    e[10].tex = base + 0x260;
    e[10].mode = 0x2;
    e[10].x = lbl_803E0F04;
    e[10].y = lbl_803E0F04;
    e[10].z = lbl_803E0F04;
    e[11].layer = 2;
    e[11].flags = 0x24;
    e[11].tex = base + 0x260;
    e[11].mode = 0x4000;
    e[11].x = lbl_803E0EE4;
    e[11].y = lbl_803E0EE4;
    e[11].z = lbl_803E0EE4;
    e[12].layer = 2;
    e[12].flags = 0x0;
    e[12].tex = NULL;
    e[12].mode = 0x400000;
    e[12].x = lbl_803E0F08;
    e[12].y = lbl_803E0F0C;
    e[12].z = lbl_803E0F10;
    e[13].layer = 2;
    e[13].flags = 0x24;
    e[13].tex = base + 0x260;
    e[13].mode = 0x100;
    e[13].x = lbl_803E0EE4;
    e[13].y = lbl_803E0EE4;
    e[13].z = lbl_803E0EFC;
    e[14].layer = 3;
    e[14].flags = 0x24;
    e[14].tex = base + 0x260;
    e[14].mode = 0x100;
    e[14].x = lbl_803E0EE4;
    e[14].y = lbl_803E0EE4;
    e[14].z = lbl_803E0EFC;
    e[15].layer = 3;
    e[15].flags = 0x24;
    e[15].tex = base + 0x260;
    e[15].mode = 0x4000;
    e[15].x = lbl_803E0EE4;
    e[15].y = lbl_803E0EE4;
    e[15].z = lbl_803E0EE4;
    e[16].layer = 4;
    e[16].flags = 0x24;
    e[16].tex = base + 0x260;
    e[16].mode = 0x4000;
    e[16].x = lbl_803E0EE4;
    e[16].y = lbl_803E0EE4;
    e[16].z = lbl_803E0EE4;
    e[17].layer = 4;
    e[17].flags = 0x24;
    e[17].tex = base + 0x260;
    e[17].mode = 0x100;
    e[17].x = lbl_803E0EE4;
    e[17].y = lbl_803E0EE4;
    e[17].z = lbl_803E0F00;
    e[18].layer = 4;
    e[18].flags = 0x12;
    e[18].tex = base + 0x2a8;
    e[18].mode = 0x4;
    e[18].x = lbl_803E0EE4;
    e[18].y = lbl_803E0EE4;
    e[18].z = lbl_803E0EE4;
    e[19].layer = 4;
    e[19].flags = 0x24;
    e[19].tex = base + 0x260;
    e[19].mode = 0x2;
    e[19].x = lbl_803E0F14;
    e[19].y = lbl_803E0F18;
    e[19].z = lbl_803E0F14;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0EE4;
    buf.pos[1] = lbl_803E0EE4;
    buf.pos[2] = lbl_803E0EE4;
    buf.col[0] = lbl_803E0EE4;
    buf.col[1] = lbl_803E0EE4;
    buf.col[2] = lbl_803E0EE4;
    buf.scale = lbl_803E0F18;
    buf.v40 = 3;
    buf.v3c = 9;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x4000484;
    buf.count = (FbCmd*)((u8*)e + 0x1e0) - e;
    buf.hw[0] = *(s16*)(base + 0x2cc);
    buf.hw[1] = *(s16*)(base + 0x2ce);
    buf.hw[2] = *(s16*)(base + 0x2d0);
    buf.hw[3] = *(s16*)(base + 0x2d2);
    buf.hw[4] = *(s16*)(base + 0x2d4);
    buf.hw[5] = *(s16*)(base + 0x2d6);
    buf.hw[6] = *(s16*)(base + 0x2d8);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0EE4 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0EE4 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0EE4 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0EE4 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0EE4 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0EE4 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x24, (u8*)(int)gFoodbagEffectTexData, 0x10, base + 0x168, base32[variant + 0xb7],
                                     0);
}

void dll_83_func01_nop(void)
{
}

void dll_83_func00_nop(void)
{
}
