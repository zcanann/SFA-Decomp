/*
 * dll92func0 (DLL 0x92) - entry-point table for DLL 0x92.
 *
 * func00/func01 are no-op slots. func03 builds a modgfx effect: a stack
 * GfxBuf holding a fixed list of GfxCmd entries (textures from
 * lbl_803171C0 / lbl_803DB930, modes, per-entry positions and a shared
 * scale), then hands it to gModgfxInterface->spawnEffect.
 *
 * `variant` selects between two sets of x/scale constants (lbl_803E1218
 * vs lbl_803E121C, lbl_803E1220 vs lbl_803E1224). When flags bit 0 is
 * set the effect origin is offset by the source object's world position
 * (sourceObj +0x18..+0x20) and/or the position source (posSource
 * +0x0c..+0x14). extraArgs, when non-NULL, overrides the base scale.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "ghidra_import.h"

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_803171C0[];
extern u8 lbl_803DB930[8];
extern f32 lbl_803E1210;
extern f32 lbl_803E1214;
extern f32 lbl_803E1218;
extern f32 lbl_803E121C;
extern f32 lbl_803E1220;
extern f32 lbl_803E1224;
extern f32 lbl_803E1228;
extern f32 lbl_803E122C;
extern f32 lbl_803E1230;
extern f32 lbl_803E1234;
extern f32 lbl_803E1238;

void dll_92_func01_nop(void)
{
}

void dll_92_func00_nop(void)
{
}

typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04 */
    u8 pad0[0x18]; /* +0x08 */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 unk_3c; /* +0x3c */
    u32 unk_40; /* +0x40 */
    s16 unk_44; /* +0x44 */
    s16 hw[7]; /* +0x46 */
    u32 flags; /* +0x54 */
    u8 unk_58, unk_59, unk_5a, unk_5b; /* +0x58..+0x5b */
    u8 unk_5c; /* +0x5c - not written */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

#pragma inline_max_size(2000)
static inline void dll_92_func03Body(u8* base, int sourceObj, int variant, int posSource, u32 flags, u32 arg5, f32* extraArgs)
{
    GfxBuf buf;
    GfxCmd* e;
    f32 s = lbl_803E1210;
    if (extraArgs != NULL)
    {
        s = *extraArgs;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x60;
    e[0].mode = 4;
    e[0].x = lbl_803E1214;
    e[0].y = lbl_803E1214;
    e[0].z = lbl_803E1214;
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = lbl_803DB930;
    e[1].mode = 4;
    if (variant == 1)
    {
        e[1].x = lbl_803E1218;
    }
    else
    {
        e[1].x = lbl_803E121C;
    }
    e[1].y = lbl_803E1214;
    e[1].z = lbl_803E1214;
    e[2].layer = 0;
    e[2].flags = 6;
    e[2].tex = base + 0x54;
    e[2].mode = 2;
    if (variant == 1)
    {
        e[2].z = e[2].y = e[2].x = lbl_803E1220 * s;
    }
    else
    {
        e[2].z = e[2].y = e[2].x = lbl_803E1224 * s;
    }
    e[3].layer = 1;
    e[3].flags = 6;
    e[3].tex = base + 0x54;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1228;
    e[3].y = lbl_803E1210;
    e[3].z = lbl_803E1214;
    e[4].layer = 1;
    e[4].flags = 6;
    e[4].tex = base + 0x54;
    e[4].mode = 2;
    e[4].x = lbl_803E122C;
    e[4].y = lbl_803E122C;
    e[4].z = lbl_803E1230;
    e[5].layer = 2;
    e[5].flags = 6;
    e[5].tex = base + 0x54;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1228;
    e[5].y = lbl_803E1210;
    e[5].z = lbl_803E1214;
    e[6].layer = 2;
    e[6].flags = 6;
    e[6].tex = base + 0x54;
    e[6].mode = 2;
    e[6].x = lbl_803E1234;
    e[6].y = lbl_803E1234;
    e[6].z = lbl_803E1210;
    e[7].layer = 3;
    e[7].flags = 6;
    e[7].tex = base + 0x54;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1228;
    e[7].y = lbl_803E1210;
    e[7].z = lbl_803E1214;
    e[8].layer = 3;
    e[8].flags = 1;
    e[8].tex = lbl_803DB930;
    e[8].mode = 4;
    e[8].x = lbl_803E1214;
    e[8].y = lbl_803E1214;
    e[8].z = lbl_803E1214;
    buf.unk_58 = 0;
    buf.ctx = sourceObj;
    buf.unk_44 = variant;
    buf.pos[0] = lbl_803E1214;
    buf.pos[1] = lbl_803E1214;
    buf.pos[2] = lbl_803E1214;
    buf.col[0] = lbl_803E1214;
    buf.col[1] = lbl_803E1214;
    buf.col[2] = lbl_803E1214;
    buf.scale = lbl_803E1238;
    buf.unk_40 = 1;
    buf.unk_3c = 0;
    buf.unk_59 = 6;
    buf.unk_5a = 0;
    buf.unk_5b = 0;
    buf.count = (GfxCmd*)((u8*)e + 0xd8) - e;
    buf.hw[0] = *(s16*)(base + 0x6c);
    buf.hw[1] = *(s16*)(base + 0x6e);
    buf.hw[2] = *(s16*)(base + 0x70);
    buf.hw[3] = *(s16*)(base + 0x72);
    buf.hw[4] = *(s16*)(base + 0x74);
    buf.hw[5] = *(s16*)(base + 0x76);
    buf.hw[6] = *(s16*)(base + 0x78);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000400;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0 && (u32)posSource != 0)
        {
            buf.pos[0] = lbl_803E1214 + (((GameObject*)(sourceObj))->anim.worldPosX + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] = lbl_803E1214 + (((GameObject*)(sourceObj))->anim.worldPosY + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] = lbl_803E1214 + (((GameObject*)(sourceObj))->anim.worldPosZ + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if ((u32)sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, base, 4, base + 0x3c, 0x3c, 0);    base++;
}

void dll_92_func03(int sourceObj, int variant, int posSource, u32 flags, u32 arg5, f32* extraArgs)
{
    dll_92_func03Body((u8*)(int)lbl_803171C0, sourceObj, variant, posSource, flags, arg5, extraArgs);
}
#pragma inline_max_size reset

