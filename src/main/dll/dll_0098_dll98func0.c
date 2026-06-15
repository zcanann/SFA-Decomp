#include "main/effect_interfaces.h"
#include "main/dll/savegame.h"

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u32 randomGetRange(int min, int max);

extern f32 lbl_803E1318;
extern f32 lbl_803E131C;
extern f32 lbl_803E1320;
extern f32 lbl_803E1324;
extern f32 lbl_803E1328;
extern f32 lbl_803E132C;
extern f32 lbl_803E1330;
extern f32 lbl_803E1334;
extern f32 lbl_803E1338;
extern f32 lbl_803E133C;
extern u8 lbl_803178B0[];

void dll_98_func01_nop(void)
{
}

void dll_98_func00_nop(void)
{
}

void dll_99_func01_nop(void);

/* Stubs to align function set with v1.0 asm. The dll_xx_func03 stubs follow
 * the same large-struct + vtable-call pattern as foodbag's func03s; matching
 * bodies needs proper struct recovery as follow-up. */

typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04 */
    u8 pad0[0x18]; /* +0x08 */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 v3c; /* +0x3c */
    u32 v40; /* +0x40 */
    s16 v44; /* +0x44 */
    s16 hw[7]; /* +0x46 */
    u32 flags; /* +0x54 */
    u8 v58, v59, v5a, v5b, v5c; /* +0x58..+0x5c */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

void dll_98_func03(int sourceObj, int variant, int posSource, uint flags, int arg5, int extraArgs)
{
    GfxBuf buf;
    u8* base = (u8*)(int)lbl_803178B0;
    GfxCmd* e;

    *(s16*)(base + 0x216) = randomGetRange(0, 0x1e) + 0x1e;
    *(s16*)(base + 0x218) = *(s16*)(base + 0x216);
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x12;
    e[0].tex = base + 0x1dc;
    e[0].mode = 4;
    e[0].x = lbl_803E1318;
    e[0].y = lbl_803E1318;
    e[0].z = lbl_803E1318;
    e[1].layer = 0;
    e[1].flags = 0x12;
    e[1].tex = base + 0x1dc;
    e[1].mode = 2;
    e[1].z = e[1].x = lbl_803E131C;
    e[1].y = lbl_803E1320;
    e[2].layer = 1;
    e[2].flags = 0x12;
    e[2].tex = base + 0x1dc;
    e[2].mode = 4;
    e[2].x = lbl_803E1324;
    e[2].y = lbl_803E1318;
    e[2].z = lbl_803E1318;
    e[3].layer = 1;
    e[3].flags = 0x12;
    e[3].tex = base + 0x1dc;
    e[3].mode = 0x400000;
    e[3].x = lbl_803E1318;
    if ((uint)extraArgs != 0)
    {
        e[3].y = lbl_803E1328;
    }
    else
    {
        e[3].y = lbl_803E132C;
    }
    e[3].z = lbl_803E1318;
    e[4].layer = 1;
    e[4].flags = 0x12;
    e[4].tex = base + 0x1dc;
    e[4].mode = 0x4000;
    e[4].x = lbl_803E1318;
    if ((uint)extraArgs != 0)
    {
        e[4].y = lbl_803E1330;
    }
    else
    {
        e[4].y = lbl_803E1334;
    }
    e[4].z = lbl_803E1318;
    e[5].layer = 2;
    e[5].flags = 0x12;
    e[5].tex = base + 0x1dc;
    e[5].mode = 4;
    e[5].x = lbl_803E1318;
    e[5].y = lbl_803E1318;
    e[5].z = lbl_803E1318;
    e[6].layer = 2;
    e[6].flags = 0x12;
    e[6].tex = base + 0x1dc;
    e[6].mode = 0x400000;
    e[6].x = lbl_803E1318;
    if ((uint)extraArgs != 0)
    {
        e[6].y = lbl_803E1328;
    }
    else
    {
        e[6].y = lbl_803E132C;
    }
    e[6].z = lbl_803E1318;
    e[7].layer = 2;
    e[7].flags = 0x12;
    e[7].tex = base + 0x1dc;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1318;
    if ((uint)extraArgs != 0)
    {
        e[7].y = lbl_803E1330;
    }
    else
    {
        e[7].y = lbl_803E1334;
    }
    e[7].z = lbl_803E1318;
    e[8].layer = 2;
    e[8].flags = 0x12;
    e[8].tex = base + 0x1dc;
    e[8].mode = 2;
    e[8].x = lbl_803E1330;
    e[8].y = lbl_803E1330;
    e[8].z = lbl_803E1330;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E1318;
    if ((uint)extraArgs != 0)
    {
        buf.pos[1] = lbl_803E1338;
    }
    else
    {
        buf.pos[1] = lbl_803E133C;
    }
    buf.pos[2] = lbl_803E1318;
    buf.col[0] = lbl_803E1318;
    buf.col[1] = lbl_803E1318;
    buf.col[2] = lbl_803E1318;
    buf.scale = lbl_803E1330;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x4080400;
    buf.count = (GfxCmd*)((u8*)e + 0xd8) - e;
    buf.hw[0] = *(s16*)(base + 0x214);
    buf.hw[1] = *(s16*)(base + 0x216);
    buf.hw[2] = *(s16*)(base + 0x218);
    buf.hw[3] = *(s16*)(base + 0x21a);
    buf.hw[4] = *(s16*)(base + 0x21c);
    buf.hw[5] = *(s16*)(base + 0x21e);
    buf.hw[6] = *(s16*)(base + 0x220);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = lbl_803E1318 + *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] += *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E1318 + *(f32*)(posSource + 0x14);
        }
    }
    {
        int v;
        if (variant == 0)
        {
            v = 0x3e9;
        }
        else if (variant == 1)
        {
            v = 0x3f0;
        }
        else
        {
            v = 0x3f3;
        }
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, (uint)extraArgs != 0 ? base + 0xb4 : (u8*)(int)lbl_803178B0, 0x10, base + 0x168, v,
                                         0);
    }
}

void dll_99_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* extraArgs );
