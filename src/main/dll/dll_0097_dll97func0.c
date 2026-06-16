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

extern u8 lbl_803DB948[8];
extern f32 lbl_803E12F0;
extern f32 lbl_803E12F8;
extern u8 lbl_80317810[];
extern f32 lbl_803E12E8;
extern f32 lbl_803E12EC;
extern f32 lbl_803E12F4;
extern f32 lbl_803E12FC;
extern f32 lbl_803E1300;
extern f32 lbl_803E1304;
extern f32 lbl_803E1308;
extern f32 lbl_803E130C;
extern f32 lbl_803E1310;

void dll_97_func01_nop(void)
{
}

void dll_97_func00_nop(void)
{
}

void dll_98_func01_nop(void);

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

void dll_97_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* extraArgs
)
{
    GfxBuf buf;
    GfxCmd* e;
    u8* base = lbl_80317810;
    f32 s = lbl_803E12E8;
    if (extraArgs != (f32*)0)
    {
        s = *extraArgs;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x60;
    e[0].mode = 4;
    e[0].x = lbl_803E12EC;
    e[0].y = lbl_803E12EC;
    e[0].z = lbl_803E12EC;
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = lbl_803DB948;
    e[1].mode = 4;
    if (variant == 1)
    {
        e[1].x = lbl_803E12F0;
    }
    else
    {
        e[1].x = lbl_803E12F4;
    }
    e[1].y = lbl_803E12EC;
    e[1].z = lbl_803E12EC;
    e[2].layer = 0;
    e[2].flags = 6;
    e[2].tex = base + 0x54;
    e[2].mode = 2;
    if (variant == 1)
    {
        e[2].z = e[2].y = e[2].x = lbl_803E12F8 * s;
    }
    else
    {
        e[2].z = e[2].y = e[2].x = lbl_803E12FC * s;
    }
    e[3].layer = 1;
    e[3].flags = 6;
    e[3].tex = base + 0x54;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1300;
    e[3].y = lbl_803E12E8;
    e[3].z = lbl_803E12EC;
    e[4].layer = 1;
    e[4].flags = 6;
    e[4].tex = base + 0x54;
    e[4].mode = 2;
    e[4].x = lbl_803E1304;
    e[4].y = lbl_803E1304;
    e[4].z = lbl_803E1308;
    e[5].layer = 2;
    e[5].flags = 6;
    e[5].tex = base + 0x54;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1300;
    e[5].y = lbl_803E12E8;
    e[5].z = lbl_803E12EC;
    e[6].layer = 2;
    e[6].flags = 6;
    e[6].tex = base + 0x54;
    e[6].mode = 2;
    e[6].x = lbl_803E130C;
    e[6].y = lbl_803E130C;
    e[6].z = lbl_803E12E8;
    e[7].layer = 3;
    e[7].flags = 6;
    e[7].tex = base + 0x54;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1300;
    e[7].y = lbl_803E12E8;
    e[7].z = lbl_803E12EC;
    e[8].layer = 3;
    e[8].flags = 1;
    e[8].tex = lbl_803DB948;
    e[8].mode = 4;
    e[8].x = lbl_803E12EC;
    e[8].y = lbl_803E12EC;
    e[8].z = lbl_803E12EC;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E12EC;
    buf.pos[1] = lbl_803E12EC;
    buf.pos[2] = lbl_803E12EC;
    buf.col[0] = lbl_803E12EC;
    buf.col[1] = lbl_803E12EC;
    buf.col[2] = lbl_803E12EC;
    buf.scale = lbl_803E1310;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 6;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (GfxCmd*)((u8*)e + 0xd8) - e;
    buf.hw[0] = *(s16*)(base + 0x6c);
    buf.hw[1] = *(s16*)(base + 0x6e);
    buf.hw[2] = *(s16*)(base + 0x70);
    buf.hw[3] = *(s16*)(base + 0x72);
    buf.hw[4] = *(s16*)(base + 0x74);
    buf.hw[5] = *(s16*)(base + 0x76);
    buf.hw[6] = *(s16*)(base + 0x78);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000410;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0 && (uint)posSource != 0)
        {
            buf.pos[0] = lbl_803E12EC + (*(f32*)(sourceObj + 0x18) + *(f32*)(posSource + 0xc));
            buf.pos[1] = lbl_803E12EC + (*(f32*)(sourceObj + 0x1c) + *(f32*)(posSource + 0x10));
            buf.pos[2] = lbl_803E12EC + (*(f32*)(sourceObj + 0x20) + *(f32*)(posSource + 0x14));
        }
        else if ((uint)sourceObj != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else if ((uint)posSource != 0)
        {
            buf.pos[0] += *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(posSource + 0x10);
            buf.pos[2] += *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, base, 4, base + 0x3c, 0x3c, 0);
}

void dll_98_func03(int sourceObj, int variant, int posSource, uint flags, int arg5, int extraArgs);
