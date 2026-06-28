/*
 * dll_0093 (dll93func0) - mod-gfx effect spawner for DLL 0x93.
 *
 * func00/func01 are empty stub entry points (kept to align this DLL's
 * exported function set with the v1.0 asm). func03 builds a six-entry
 * GfxCmd display list on the stack from the resource blob at
 * lbl_80317260, fills out the surrounding GfxBuf parameters, optionally
 * offsets the effect position by the source/posSource object's world
 * position (when the caller-supplied flag bit 0 is set), then hands the
 * buffer to the mod-gfx interface's spawnEffect.
 */
#include "main/effect_interfaces.h"
#include "ghidra_import.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80317260[];
extern f32 lbl_803E1240;
extern f32 lbl_803E1244;
extern f32 lbl_803E1248;
extern f32 lbl_803E124C;
extern f32 lbl_803E1250;
extern f32 lbl_803E1254;
extern f32 lbl_803E1258;

void dll_93_func01_nop(void)
{
}

void dll_93_func00_nop(void)
{
}

typedef struct GfxCmd
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

typedef struct GfxBuf
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04 */
    u8 pad0[0x18]; /* +0x08 */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 v3c; /* +0x3c */
    u32 v40; /* +0x40 */
    s16 variant; /* +0x44 */
    s16 hw[7]; /* +0x46 */
    u32 flags; /* +0x54 */
    u8 v58; /* +0x58 */
    u8 v59; /* +0x59 */
    u8 v5a; /* +0x5a */
    u8 priority; /* +0x5b */
    u8 v5c; /* +0x5c */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

void dll_93_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    GfxBuf buf;
    u8* base = (u8*)(int)lbl_80317260;
    GfxCmd* e = buf.entries;
    f32 rval;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E1240;
    e[0].y = lbl_803E1240;
    e[0].z = lbl_803E1240;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 2;
    rval = lbl_803E1248 * (f32)(int)randomGetRange(0, 10) + lbl_803E1244;
    e[1].x = rval;
    e[1].y = lbl_803E124C;
    e[1].z = rval;
    e[2].layer = 1;
    e[2].flags = 0x15;
    e[2].tex = base + 0x1b0;
    e[2].mode = 4;
    e[2].x = lbl_803E1250;
    e[2].y = lbl_803E1240;
    e[2].z = lbl_803E1240;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = base + 0x1b0;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1254;
    e[3].y = lbl_803E1240;
    e[3].z = lbl_803E1240;
    e[4].layer = 2;
    e[4].flags = 0x15;
    e[4].tex = base + 0x1b0;
    e[4].mode = 4;
    e[4].x = lbl_803E1240;
    e[4].y = lbl_803E1240;
    e[4].z = lbl_803E1240;
    e[5].layer = 2;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1254;
    e[5].y = lbl_803E1240;
    e[5].z = lbl_803E1240;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.variant = variant;
    buf.pos[0] = lbl_803E1240;
    buf.pos[1] = lbl_803E1240;
    buf.pos[2] = lbl_803E1240;
    buf.col[0] = lbl_803E1240;
    buf.col[1] = lbl_803E1240;
    buf.col[2] = lbl_803E1240;
    buf.scale = lbl_803E1258;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.priority = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 0x90) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1240 + *(f32*)(sourceObj + 0xc);
            buf.pos[1] = lbl_803E1240 + *(f32*)(sourceObj + 0x10);
            buf.pos[2] = lbl_803E1240 + *(f32*)(sourceObj + 0x14);
        }
        else
        {
            buf.pos[0] = lbl_803E1240 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1240 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1240 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80317260, 0x18, base + 0xd4, 0x89, 0);
}
