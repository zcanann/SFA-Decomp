/*
 * dll88func0 (DLL 0x88) - one of the foodbag "func03" model-effect
 * spawners (siblings 0x7C..0x90). dll_88_func03 fills a stack FbBuf
 * command list (9 FbCmd model layers built from the lbl_80316240 asset
 * block) plus the per-effect color/position/scale/flags header, folds
 * the caller's flags in, and when bit 0 is set offsets the spawn
 * position from either the source object (+0x18..0x20) or an explicit
 * position source (+0xC..0x14). The list is handed to the modgfx
 * interface's spawnEffect. func00/func01 are nops.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316240[];
extern f32 lbl_803E1010;
extern f32 lbl_803E1014;
extern f32 lbl_803E1018;
extern f32 lbl_803E101C;
extern f32 lbl_803E1020;
extern f32 lbl_803E1024;

void dll_88_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316240;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x19;
    e[0].tex = base + 0x1bc;
    e[0].mode = 2;
    e[0].x = lbl_803E1010;
    e[0].y = lbl_803E1010;
    e[0].z = lbl_803E1010;
    e[1].layer = 0;
    e[1].flags = 0x19;
    e[1].tex = base + 0x1bc;
    e[1].mode = 0x80;
    e[1].x = lbl_803E1014;
    e[1].y = lbl_803E1014;
    e[1].z = lbl_803E1014;
    e[2].layer = 0;
    e[2].flags = 0x7a;
    e[2].tex = 0;
    e[2].mode = 0x10000;
    e[2].x = lbl_803E1014;
    e[2].y = lbl_803E1014;
    e[2].z = lbl_803E1014;
    e[3].layer = 0;
    e[3].flags = 0x19;
    e[3].tex = base + 0x1bc;
    e[3].mode = 4;
    e[3].x = lbl_803E1014;
    e[3].y = lbl_803E1014;
    e[3].z = lbl_803E1014;
    e[4].layer = 1;
    e[4].flags = 0x19;
    e[4].tex = base + 0x1bc;
    e[4].mode = 4;
    e[4].x = lbl_803E1018;
    e[4].y = lbl_803E1014;
    e[4].z = lbl_803E1014;
    e[5].layer = 1;
    e[5].flags = 0x19;
    e[5].tex = base + 0x1bc;
    e[5].mode = 2;
    e[5].x = lbl_803E101C;
    e[5].y = lbl_803E101C;
    e[5].z = lbl_803E1020;
    e[6].layer = 2;
    e[6].flags = 0x19;
    e[6].tex = base + 0x1bc;
    e[6].mode = 2;
    e[6].x = lbl_803E1024;
    e[6].y = lbl_803E1024;
    e[6].z = lbl_803E1020;
    e[7].layer = 3;
    e[7].flags = 0x19;
    e[7].tex = base + 0x1bc;
    e[7].mode = 2;
    e[7].x = lbl_803E1024;
    e[7].y = lbl_803E1024;
    e[7].z = lbl_803E1020;
    e[8].layer = 3;
    e[8].flags = 0x19;
    e[8].tex = base + 0x1bc;
    e[8].mode = 4;
    e[8].x = lbl_803E1014;
    e[8].y = lbl_803E1014;
    e[8].z = lbl_803E1014;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1014;
    buf.pos[1] = lbl_803E1014;
    buf.pos[2] = lbl_803E1014;
    buf.col[0] = lbl_803E1014;
    buf.col[1] = lbl_803E1014;
    buf.col[2] = lbl_803E1014;
    buf.scale = lbl_803E1020;
    buf.v40 = 1;
    buf.v3c = 25;
    buf.v59 = 0x19;
    buf.v5a = 0xff;
    buf.v5b = 16;
    buf.flags = 0x4000480;
    buf.count = (FbCmd*)((u8*)e + 216) - e;
    buf.hw[0] = *(s16*)(base + 0x1f0);
    buf.hw[1] = *(s16*)(base + 0x1f2);
    buf.hw[2] = *(s16*)(base + 0x1f4);
    buf.hw[3] = *(s16*)(base + 0x1f6);
    buf.hw[4] = *(s16*)(base + 0x1f8);
    buf.hw[5] = *(s16*)(base + 0x1fa);
    buf.hw[6] = *(s16*)(base + 0x1fc);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1014 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E1014 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E1014 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E1014 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1014 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1014 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x19, (u8*)(int)lbl_80316240, 0x20, base + 0xfc, 0x205, 0);
}


void dll_88_func01_nop(void)
{
}

void dll_88_func00_nop(void)
{
}
