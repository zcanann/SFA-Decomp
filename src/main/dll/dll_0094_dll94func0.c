/*
 * dll94func0 (DLL 0x94) - a one-shot modgfx effect spawner.
 *
 * dll_94_func03 builds a fixed nine-command GfxBuf on the stack (a small
 * layered effect that varies between two presets selected by `variant`),
 * derives its world position from the source/position objects when the
 * positioning flag is set, then hands the whole buffer to the modgfx
 * interface's spawnEffect. The four *_nop entry points and the dll_95
 * forward decl exist to align this object's function set with the v1.0
 * asm. Sibling of dll_0093 (same GfxCmd/GfxBuf layout and func03 shape).
 */
#include "main/effect_interfaces.h"
#include "main/dll/savegame.h"

/* GfxCmd/GfxBuf are duplicated from dll_0093; should be unified in a shared header. */
typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_803DB938[8]; /* texture/resource handle */
extern f32 lbl_803E1270;
extern f32 lbl_803E1278;
extern u8 lbl_80317488[];
extern f32 lbl_803E1268;
extern f32 lbl_803E126C; /* 0.0f */
extern f32 lbl_803E1274;
extern f32 lbl_803E127C;
extern f32 lbl_803E1280;
extern f32 lbl_803E1284;
extern f32 lbl_803E1288;
extern f32 lbl_803E128C;
extern f32 lbl_803E1290;

void dll_94_func01_nop(void)
{
}

void dll_94_func00_nop(void)
{
}

void dll_95_func01_nop(void); /* forward decl to align function set with v1.0 asm; defined in dll_0095 */

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
    u8 v58, v59, v5a, v5b; /* +0x58..+0x5b */
    u8 pad5c[1]; /* +0x5c layout-only; never written by dll_93/94 */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

void dll_94_func03(int sourceObj, int variant, int posSource, u32 flags, int arg5,
                   f32* extraArgs)
{
    GfxBuf buf;
    GfxCmd* e;
    u8* base = lbl_80317488;
    f32 s = lbl_803E1268;
    if (extraArgs != NULL)
    {
        s = *extraArgs;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x60;
    e[0].mode = 4;
    e[0].x = lbl_803E126C;
    e[0].y = lbl_803E126C;
    e[0].z = lbl_803E126C;
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = lbl_803DB938;
    e[1].mode = 4;
    if (variant == 1)
    {
        e[1].x = lbl_803E1270;
    }
    else
    {
        e[1].x = lbl_803E1274;
    }
    e[1].y = lbl_803E126C;
    e[1].z = lbl_803E126C;
    e[2].layer = 0;
    e[2].flags = 6;
    e[2].tex = base + 0x54;
    e[2].mode = 2;
    if (variant == 1)
    {
        e[2].z = e[2].y = e[2].x = lbl_803E1278 * s;
    }
    else
    {
        e[2].z = e[2].y = e[2].x = lbl_803E127C * s;
    }
    e[3].layer = 1;
    e[3].flags = 6;
    e[3].tex = base + 0x54;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1280;
    e[3].y = lbl_803E1268;
    e[3].z = lbl_803E126C;
    e[4].layer = 1;
    e[4].flags = 6;
    e[4].tex = base + 0x54;
    e[4].mode = 2;
    e[4].x = lbl_803E1284;
    e[4].y = lbl_803E1284;
    e[4].z = lbl_803E1288;
    e[5].layer = 2;
    e[5].flags = 6;
    e[5].tex = base + 0x54;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1280;
    e[5].y = lbl_803E1268;
    e[5].z = lbl_803E126C;
    e[6].layer = 2;
    e[6].flags = 6;
    e[6].tex = base + 0x54;
    e[6].mode = 2;
    e[6].x = lbl_803E128C;
    e[6].y = lbl_803E128C;
    e[6].z = lbl_803E1268;
    e[7].layer = 3;
    e[7].flags = 6;
    e[7].tex = base + 0x54;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1280;
    e[7].y = lbl_803E1268;
    e[7].z = lbl_803E126C;
    e[8].layer = 3;
    e[8].flags = 1;
    e[8].tex = lbl_803DB938;
    e[8].mode = 4;
    e[8].x = lbl_803E126C;
    e[8].y = lbl_803E126C;
    e[8].z = lbl_803E126C;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E126C;
    buf.pos[1] = lbl_803E126C;
    buf.pos[2] = lbl_803E126C;
    buf.col[0] = lbl_803E126C;
    buf.col[1] = lbl_803E126C;
    buf.col[2] = lbl_803E126C;
    buf.scale = lbl_803E1290;
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
        if ((u32)sourceObj != 0 && (u32)posSource != 0)
        {
            buf.pos[0] = lbl_803E126C + (*(f32*)(sourceObj + 0x18) + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] = lbl_803E126C + (*(f32*)(sourceObj + 0x1c) + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] = lbl_803E126C + (*(f32*)(sourceObj + 0x20) + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if ((u32)sourceObj != 0)
        {
            buf.pos[0] += *(f32*)(sourceObj + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, base, 4, base + 0x3c, 0x3c, 0);
}
