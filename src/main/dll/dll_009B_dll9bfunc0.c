/*
 * dll9bfunc0 (DLL 0x9B) - one of the screenfx scene builders (sibling of
 * DLL 0x9A/0x9C). dll_9B_func03 fills a fixed 14-entry GfxCmd list plus the
 * surrounding GfxBuf header describing a multi-state screen effect (texture/
 * model ids, per-part placement offsets and a 7-entry anim table read out of
 * the lbl_80317BD8 resource blob), then hands it to ModgfxInterface
 * spawnEffect (effect 0x15, asset 0x156). When header flag bit 0 is set the
 * base position is offset by either the target object's transform (target,
 * +0x18) or the passed parameter packet (parent, +0x0C). func00/func01 are
 * the DLL's nop lifecycle slots.
 */
#include "main/effect_interfaces.h"

typedef struct GfxCmd
{
    u32 mode;    /* 0x00 */
    f32 x, y, z; /* 0x04 */
    void* tex;   /* 0x10 */
    u16 flags;   /* 0x14 */
    u8 layer;    /* 0x16 */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80317BD8[];

extern f32 lbl_803E13A0;
extern f32 lbl_803E13A4;
extern f32 lbl_803E13A8;
extern f32 lbl_803E13AC;
extern f32 lbl_803E13B0;
extern f32 lbl_803E13B4;
extern f32 lbl_803E13B8;
extern f32 lbl_803E13BC;
extern f32 lbl_803E13C0;
extern f32 lbl_803E13C4;

void dll_9B_func03(int target, int variant, int parent, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 c7;
        u32 c2;
        s16 b;
        s16 anim[7];
        u32 flags;
        u8 v0, v1, v2, v3, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_80317BD8;
    GfxCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E13A0;
    e[0].y = lbl_803E13A0;
    e[0].z = lbl_803E13A0;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 2;
    e[1].x = lbl_803E13A4;
    e[1].y = lbl_803E13A8;
    e[1].z = lbl_803E13A4;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = 0;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E13A0;
    e[2].y = lbl_803E13AC;
    e[2].z = lbl_803E13A0;
    e[3].layer = 0;
    e[3].flags = 0x124;
    e[3].tex = 0;
    e[3].mode = 0x20000;
    e[3].x = lbl_803E13A0;
    e[3].y = lbl_803E13A0;
    e[3].z = lbl_803E13A0;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = base + 0x1b0;
    e[4].mode = 2;
    e[4].x = lbl_803E13B0;
    e[4].y = lbl_803E13B4;
    e[4].z = lbl_803E13B0;
    e[5].layer = 1;
    e[5].flags = 0xe;
    e[5].tex = base + 0x1dc;
    e[5].mode = 4;
    e[5].x = lbl_803E13B8;
    e[5].y = lbl_803E13A0;
    e[5].z = lbl_803E13A0;
    e[6].layer = 1;
    e[6].flags = 0x15;
    e[6].tex = base + 0x1b0;
    e[6].mode = 0x4000;
    e[6].x = lbl_803E13A8;
    e[6].y = lbl_803E13BC;
    e[6].z = lbl_803E13A0;
    e[7].layer = 1;
    e[7].flags = 0;
    e[7].tex = 0;
    e[7].mode = 0x400000;
    e[7].x = lbl_803E13A0;
    e[7].y = lbl_803E13C0;
    e[7].z = lbl_803E13A0;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = base + 0x1b0;
    e[8].mode = 0x4000;
    e[8].x = lbl_803E13A8;
    e[8].y = lbl_803E13BC;
    e[8].z = lbl_803E13A0;
    e[9].layer = 3;
    e[9].flags = 0x124;
    e[9].tex = 0;
    e[9].mode = 0x20000;
    e[9].x = lbl_803E13A0;
    e[9].y = lbl_803E13A0;
    e[9].z = lbl_803E13A0;
    e[10].layer = 3;
    e[10].flags = 0xe;
    e[10].tex = base + 0x1dc;
    e[10].mode = 4;
    e[10].x = lbl_803E13A0;
    e[10].y = lbl_803E13A0;
    e[10].z = lbl_803E13A0;
    e[11].layer = 3;
    e[11].flags = 0x15;
    e[11].tex = base + 0x1b0;
    e[11].mode = 0x4000;
    e[11].x = lbl_803E13A8;
    e[11].y = lbl_803E13BC;
    e[11].z = lbl_803E13A0;
    e[12].layer = 3;
    e[12].flags = 0x15;
    e[12].tex = base + 0x1b0;
    e[12].mode = 2;
    e[12].x = lbl_803E13A4;
    e[12].y = lbl_803E13C4;
    e[12].z = lbl_803E13A4;
    e[13].layer = 3;
    e[13].flags = 0;
    e[13].tex = 0;
    e[13].mode = 0x400000;
    e[13].x = lbl_803E13A0;
    e[13].y = lbl_803E13AC;
    e[13].z = lbl_803E13A0;

    buf.v0 = 0;
    buf.ctx = target;
    buf.b = variant;
    buf.pos[0] = lbl_803E13A0;
    buf.pos[1] = lbl_803E13A0;
    buf.pos[2] = lbl_803E13A0;
    buf.col[0] = lbl_803E13A0;
    buf.col[1] = lbl_803E13A0;
    buf.col[2] = lbl_803E13A0;
    buf.scale = lbl_803E13C4;
    buf.c2 = 2;
    buf.c7 = 7;
    buf.v1 = 0xe;
    buf.v2 = 0;
    buf.v3 = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 0x150) - e;
    buf.anim[0] = *(s16*)(base + 0x1f8);
    buf.anim[1] = *(s16*)(base + 0x1fa);
    buf.anim[2] = *(s16*)(base + 0x1fc);
    buf.anim[3] = *(s16*)(base + 0x1fe);
    buf.anim[4] = *(s16*)(base + 0x200);
    buf.anim[5] = *(s16*)(base + 0x202);
    buf.anim[6] = *(s16*)(base + 0x204);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc010480;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)target != 0)
        {
            buf.pos[0] = lbl_803E13A0 + *(f32*)(target + 0x18);
            buf.pos[1] = lbl_803E13A0 + *(f32*)(target + 0x1c);
            buf.pos[2] = lbl_803E13A0 + *(f32*)(target + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E13A0 + *(f32*)(parent + 0xc);
            buf.pos[1] = lbl_803E13A0 + *(f32*)(parent + 0x10);
            buf.pos[2] = lbl_803E13A0 + *(f32*)(parent + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80317BD8, 0x18, base + 0xd4, 0x156, 0);
}

void dll_9B_func01_nop(void)
{
}

void dll_9B_func00_nop(void)
{
}
