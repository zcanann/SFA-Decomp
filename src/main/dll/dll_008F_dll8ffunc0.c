#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316C90[];
extern f32 lbl_803E1178;
extern f32 lbl_803E117C;
extern f32 lbl_803E1180;
extern f32 lbl_803E1184;
extern f32 lbl_803E1188;
extern f32 lbl_803E118C;
extern f32 lbl_803E1190;
extern f32 lbl_803E1194;
extern f32 lbl_803E1198;
extern f32 lbl_803E119C;

void dll_8F_func03(int sourceObj, int variant, int posSource, uint flags)
{
    typedef struct
    {
        FbCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        FbCmd entries[32];
    } FbBuf8F;
    FbBuf8F buf;
    u8* base = (u8*)(int)lbl_80316C90;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 18;
    e[0].tex = base + 0x128;
    e[0].mode = 4;
    e[0].x = lbl_803E1178;
    e[0].y = lbl_803E1178;
    e[0].z = lbl_803E1178;
    e[1].layer = 0;
    e[1].flags = 18;
    e[1].tex = base + 0x128;
    e[1].mode = 2;
    e[1].x = lbl_803E117C;
    e[1].y = lbl_803E1180;
    e[1].z = lbl_803E117C;
    e[2].layer = 0;
    e[2].flags = 18;
    e[2].tex = base + 0x128;
    e[2].mode = 256;
    e[2].x = lbl_803E1178;
    e[2].y = lbl_803E1178;
    e[2].z = lbl_803E1184;
    e[3].layer = 1;
    e[3].flags = 18;
    e[3].tex = base + 0x128;
    e[3].mode = 4;
    e[3].x = lbl_803E1188;
    e[3].y = lbl_803E1178;
    e[3].z = lbl_803E1178;
    e[4].layer = 1;
    e[4].flags = 18;
    e[4].tex = base + 0x128;
    e[4].mode = 2;
    e[4].x = lbl_803E118C;
    e[4].y = lbl_803E1190;
    e[4].z = lbl_803E118C;
    e[5].layer = 1;
    e[5].flags = 18;
    e[5].tex = base + 0x128;
    e[5].mode = 256;
    e[5].x = lbl_803E1178;
    e[5].y = lbl_803E1178;
    e[5].z = lbl_803E1184;
    e[6].layer = 2;
    e[6].flags = 18;
    e[6].tex = base + 0x128;
    e[6].mode = 256;
    e[6].x = lbl_803E1178;
    e[6].y = lbl_803E1178;
    e[6].z = lbl_803E1184;
    e[7].layer = 3;
    e[7].flags = 18;
    e[7].tex = base + 0x128;
    e[7].mode = 4;
    e[7].x = lbl_803E1178;
    e[7].y = lbl_803E1178;
    e[7].z = lbl_803E1178;
    e[8].layer = 3;
    e[8].flags = 18;
    e[8].tex = base + 0x128;
    e[8].mode = 2;
    e[8].x = lbl_803E1194;
    e[8].y = lbl_803E1198;
    e[8].z = lbl_803E1194;
    e[9].layer = 3;
    e[9].flags = 18;
    e[9].tex = base + 0x128;
    e[9].mode = 256;
    e[9].x = lbl_803E1178;
    e[9].y = lbl_803E1178;
    e[9].z = lbl_803E1184;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E1178;
    buf.pos[1] = lbl_803E1178;
    buf.pos[2] = lbl_803E1178;
    buf.col[0] = lbl_803E1178;
    buf.col[1] = lbl_803E1178;
    buf.col[2] = lbl_803E1178;
    buf.scale = lbl_803E119C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 18;
    buf.v5a = 0;
    buf.v5b = 16;
    buf.flags = 0x4000000;
    buf.count = (FbCmd*)((u8*)e + 240) - e;
    buf.hw[0] = *(s16*)(base + 0x160);
    buf.hw[1] = *(s16*)(base + 0x162);
    buf.hw[2] = *(s16*)(base + 0x164);
    buf.hw[3] = *(s16*)(base + 0x166);
    buf.hw[4] = *(s16*)(base + 0x168);
    buf.hw[5] = *(s16*)(base + 0x16a);
    buf.hw[6] = *(s16*)(base + 0x16c);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1178 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E1178 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E1178 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E1178 + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E1178 + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E1178 + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 18, (u8*)(int)lbl_80316C90, 16, base + 0xb4, 0x2e, 0);
}


void dll_8F_func01_nop(void)
{
}

void dll_8F_func00_nop(void)
{
}

void dll_90_func01_nop(void);
