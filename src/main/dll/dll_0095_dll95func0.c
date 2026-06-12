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

/* Trivial 4b 0-arg blr leaves. */

void dll_95_func01_nop(void)
{
}

void dll_95_func00_nop(void)
{
}

void dll_96_func01_nop(void);

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

extern u8 lbl_80317528[];
extern u8 lbl_803DB940[8];
extern f32 lbl_803E1298;
extern f32 lbl_803E129C;
extern f32 lbl_803E12A0;
extern f32 lbl_803E12A4;
extern f32 lbl_803E12A8;
extern f32 lbl_803E12AC;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;

void dll_95_func03(int sourceObj, int variant, int posSource)
{
    GfxBuf buf;
    u8* base = lbl_80317528;
    GfxCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = base + 0x80;
    e[0].mode = 2;
    e[0].x = lbl_803E1298;
    e[0].y = lbl_803E129C;
    e[0].z = lbl_803E1298;
    e[1].layer = 0;
    e[1].flags = 4;
    e[1].tex = lbl_803DB940;
    e[1].mode = 8;
    e[1].x = lbl_803E12A0;
    e[1].y = lbl_803E12A0;
    e[1].z = lbl_803E12A4;
    e[2].layer = 0;
    e[2].flags = 4;
    e[2].tex = base + 0x80;
    e[2].mode = 8;
    e[2].x = lbl_803E12A0;
    e[2].y = lbl_803E12A8;
    e[2].z = lbl_803E12A4;
    e[3].layer = 0;
    e[3].flags = 0;
    e[3].tex = (void*)0;
    e[3].mode = 0x400000;
    e[3].x = lbl_803E12A4;
    e[3].y = lbl_803E12AC;
    e[3].z = lbl_803E12A4;
    e[4].layer = 1;
    e[4].flags = 8;
    e[4].tex = base + 0x80;
    e[4].mode = 2;
    e[4].x = lbl_803E12B0;
    e[4].y = lbl_803E12B0;
    e[4].z = lbl_803E12B0;
    e[5].layer = 1;
    e[5].flags = 0;
    e[5].tex = (void*)0;
    e[5].mode = 0x400000;
    e[5].x = lbl_803E12A4;
    e[5].y = lbl_803E12B4;
    e[5].z = lbl_803E12A4;
    e[6].layer = 2;
    e[6].flags = 8;
    e[6].tex = base + 0x80;
    e[6].mode = 4;
    e[6].x = lbl_803E12A4;
    e[6].y = lbl_803E12A4;
    e[6].z = lbl_803E12A4;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E12A4;
    buf.pos[1] = lbl_803E12A4;
    buf.pos[2] = lbl_803E12A4;
    buf.col[0] = lbl_803E12A4;
    buf.col[1] = lbl_803E12A4;
    buf.col[2] = lbl_803E12A4;
    buf.scale = lbl_803E12B8;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 8;
    buf.v5a = 0;
    buf.v5b = 0x3c;
    buf.count = (GfxCmd*)((u8*)e + 0xa8) - e;
    buf.hw[0] = *(s16*)(base + 0x90);
    buf.hw[1] = *(s16*)(base + 0x92);
    buf.hw[2] = *(s16*)(base + 0x94);
    buf.hw[3] = *(s16*)(base + 0x96);
    buf.hw[4] = *(s16*)(base + 0x98);
    buf.hw[5] = *(s16*)(base + 0x9a);
    buf.hw[6] = *(s16*)(base + 0x9c);
    buf.cmds = e;
    buf.flags = 0x4002400;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0 && (uint)posSource != 0)
        {
            buf.pos[0] = lbl_803E12A4 + (*(f32*)(sourceObj + 0x18) + *(f32*)(posSource + 0xc));
            buf.pos[1] = lbl_803E12A4 + (*(f32*)(sourceObj + 0x1c) + *(f32*)(posSource + 0x10));
            buf.pos[2] = lbl_803E12A4 + (*(f32*)(sourceObj + 0x20) + *(f32*)(posSource + 0x14));
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, base, 8, base + 0x50, 0x46, 0);
}

int dll_96_func03(int sourceObj, int variant, int posSource, uint flags);
