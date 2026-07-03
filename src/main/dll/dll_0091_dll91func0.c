/*
 * DLL 0x91 - func0 object. Holds the "func00"/"func01" no-op slots plus
 * dll_91_func03, which assembles a fixed 19-entry modgfx command list (one
 * GfxCmd per sub-effect: per-layer texture, draw mode, and a position scale
 * triple) into a stack GfxBuf, optionally biases the spawn position by the
 * source object's world position (flags bit 0), then hands the buffer to
 * (*gModgfxInterface)->spawnEffect. The texture pointers index a shared
 * resource blob (gDll91Func0ResourceBlob); the position/scale constants live in a
 * shared float pool (lbl_803E11D8..lbl_803E1208).
 */
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

extern u8 gDll91Func0ResourceBlob[];
extern u8 gDll91Func0Tex[8];
extern f32 lbl_803E11D8;
extern f32 lbl_803E11DC;
extern f32 lbl_803E11E0;
extern f32 lbl_803E11E4;
extern f32 lbl_803E11E8;
extern f32 lbl_803E11EC;
extern f32 lbl_803E11F0;
extern f32 lbl_803E11F4;
extern f32 lbl_803E11F8;
extern f32 lbl_803E11FC;
extern f32 lbl_803E1200;
extern f32 lbl_803E1204;
extern f32 lbl_803E1208;

void dll_91_func01_nop(void)
{
}

void dll_91_func00_nop(void)
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
    u32 v3c; /* +0x3c */
    u32 v40; /* +0x40 */
    s16 v44; /* +0x44 */
    s16 params[7]; /* +0x46: 7 consecutive s16s read from base+0x194..0x1a0 */
    u32 flags; /* +0x54 */
    u8 v58, v59, v5a, v5b; /* +0x58..+0x5b */
    u8 pad2; /* +0x5c: never written by dll_91_func03 */
    s8 count; /* +0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

void dll_91_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    GfxBuf buf;
    u8* base = (u8*)(int)gDll91Func0ResourceBlob;
    GfxCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x12;
    e[0].tex = base + 0x150;
    e[0].mode = 4;
    e[0].x = lbl_803E11D8;
    e[0].y = lbl_803E11D8;
    e[0].z = lbl_803E11D8;
    e[1].layer = 0;
    e[1].flags = 9;
    e[1].tex = base + 0x114;
    e[1].mode = 8;
    e[1].x = lbl_803E11D8;
    e[1].y = lbl_803E11D8;
    e[1].z = lbl_803E11DC;
    e[2].layer = 0;
    e[2].flags = 9;
    e[2].tex = base + 0x128;
    e[2].mode = 2;
    e[2].x = lbl_803E11E0;
    e[2].y = lbl_803E11E4;
    e[2].z = lbl_803E11E0;
    e[3].layer = 0;
    e[3].flags = 0x12;
    e[3].tex = base + 0x150;
    e[3].mode = 2;
    e[3].x = lbl_803E11E8;
    e[3].y = lbl_803E11EC;
    e[3].z = lbl_803E11E8;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = base + 0x128;
    e[4].mode = 8;
    e[4].x = lbl_803E11DC;
    e[4].y = lbl_803E11D8;
    e[4].z = lbl_803E11DC;
    e[5].layer = 1;
    e[5].flags = 0x12;
    e[5].tex = base + 0x150;
    e[5].mode = 4;
    e[5].x = lbl_803E11DC;
    e[5].y = lbl_803E11D8;
    e[5].z = lbl_803E11D8;
    e[6].layer = 1;
    e[6].flags = 9;
    e[6].tex = base + 0x128;
    e[6].mode = 2;
    e[6].x = lbl_803E11F0;
    e[6].y = lbl_803E11F4;
    e[6].z = lbl_803E11F0;
    e[7].layer = 2;
    e[7].flags = 0;
    e[7].tex = NULL;
    e[7].mode = 0x20;
    e[7].x = lbl_803E11D8;
    e[7].y = lbl_803E11D8;
    e[7].z = lbl_803E11D8;
    e[8].layer = 3;
    e[8].flags = 9;
    e[8].tex = base + 0x114;
    e[8].mode = 8;
    e[8].x = lbl_803E11DC;
    e[8].y = lbl_803E11F8;
    e[8].z = lbl_803E11D8;
    e[9].layer = 3;
    e[9].flags = 0x12;
    e[9].tex = base + 0x150;
    e[9].mode = 0x100;
    e[9].x = lbl_803E11D8;
    e[9].y = lbl_803E11D8;
    e[9].z = lbl_803E11FC;
    e[10].layer = 3;
    e[10].flags = 5;
    e[10].tex = base + 0x188;
    e[10].mode = 2;
    e[10].x = lbl_803E1200;
    e[10].y = lbl_803E11F0;
    e[10].z = lbl_803E1200;
    e[11].layer = 3;
    e[11].flags = 4;
    e[11].tex = gDll91Func0Tex;
    e[11].mode = 2;
    e[11].x = lbl_803E1204;
    e[11].y = lbl_803E11F0;
    e[11].z = lbl_803E1204;
    e[12].layer = 4;
    e[12].flags = 9;
    e[12].tex = base + 0x114;
    e[12].mode = 8;
    e[12].x = lbl_803E11DC;
    e[12].y = lbl_803E11D8;
    e[12].z = lbl_803E11DC;
    e[13].layer = 4;
    e[13].flags = 0x12;
    e[13].tex = base + 0x150;
    e[13].mode = 0x100;
    e[13].x = lbl_803E11D8;
    e[13].y = lbl_803E11D8;
    e[13].z = lbl_803E11FC;
    e[14].layer = 4;
    e[14].flags = 5;
    e[14].tex = base + 0x188;
    e[14].mode = 2;
    e[14].x = lbl_803E1204;
    e[14].y = lbl_803E11F0;
    e[14].z = lbl_803E1204;
    e[15].layer = 4;
    e[15].flags = 4;
    e[15].tex = gDll91Func0Tex;
    e[15].mode = 2;
    e[15].x = lbl_803E1200;
    e[15].y = lbl_803E11F0;
    e[15].z = lbl_803E1200;
    e[16].layer = 5;
    e[16].flags = 2;
    e[16].tex = NULL;
    e[16].mode = 0x1000;
    e[16].x = lbl_803E11F0;
    e[16].y = lbl_803E11D8;
    e[16].z = lbl_803E11D8;
    e[17].layer = 6;
    e[17].flags = 0x12;
    e[17].tex = base + 0x150;
    e[17].mode = 4;
    e[17].x = lbl_803E11D8;
    e[17].y = lbl_803E11D8;
    e[17].z = lbl_803E11D8;
    e[18].layer = 6;
    e[18].flags = 0x12;
    e[18].tex = base + 0x150;
    e[18].mode = 2;
    e[18].x = lbl_803E1208;
    e[18].y = lbl_803E11F0;
    e[18].z = lbl_803E1208;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E11D8;
    buf.pos[1] = lbl_803E11D8;
    buf.pos[2] = lbl_803E11D8;
    buf.col[0] = lbl_803E11D8;
    buf.col[1] = lbl_803E11D8;
    buf.col[2] = lbl_803E11D8;
    buf.scale = lbl_803E11F0;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0xc;
    buf.flags = 0x1000082;
    buf.count = (GfxCmd*)((u8*)e + 0x1c8) - e;
    buf.params[0] = *(s16*)(base + 0x194);
    buf.params[1] = *(s16*)(base + 0x196);
    buf.params[2] = *(s16*)(base + 0x198);
    buf.params[3] = *(s16*)(base + 0x19a);
    buf.params[4] = *(s16*)(base + 0x19c);
    buf.params[5] = *(s16*)(base + 0x19e);
    buf.params[6] = *(s16*)(base + 0x1a0);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E11D8 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E11D8 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E11D8 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E11D8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E11D8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E11D8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, (u8*)(int)gDll91Func0ResourceBlob, 0x10, base + 0xb4, 0x45, 0);
}

u8 gDll91Func0ResourceBlob[420] = {
    3, 232, 0, 0, 0, 0, 0, 0, 0, 0, 2, 195, 0, 0, 253, 61,
    0, 15, 0, 0, 0, 0, 0, 0, 252, 24, 0, 31, 0, 0, 253, 61,
    0, 0, 253, 61, 0, 47, 0, 0, 252, 24, 0, 0, 0, 0, 0, 63,
    0, 0, 253, 61, 0, 0, 2, 195, 0, 79, 0, 0, 0, 0, 0, 0,
    3, 232, 0, 95, 0, 0, 2, 195, 0, 0, 2, 195, 0, 111, 0, 0,
    3, 232, 0, 0, 0, 0, 0, 127, 0, 0, 3, 232, 7, 208, 0, 0,
    0, 0, 0, 31, 2, 195, 7, 208, 253, 61, 0, 15, 0, 31, 0, 0,
    7, 208, 252, 24, 0, 31, 0, 31, 253, 61, 7, 208, 253, 61, 0, 47,
    0, 31, 252, 24, 7, 208, 0, 0, 0, 63, 0, 31, 253, 61, 7, 208,
    2, 195, 0, 79, 0, 31, 0, 0, 7, 208, 3, 232, 0, 95, 0, 31,
    2, 195, 7, 208, 2, 195, 0, 111, 0, 31, 3, 232, 7, 208, 0, 0,
    0, 127, 0, 31, 0, 0, 0, 1, 0, 10, 0, 0, 0, 10, 0, 9,
    0, 1, 0, 2, 0, 11, 0, 1, 0, 11, 0, 10, 0, 2, 0, 3,
    0, 12, 0, 2, 0, 12, 0, 11, 0, 3, 0, 4, 0, 13, 0, 3,
    0, 13, 0, 12, 0, 4, 0, 5, 0, 14, 0, 4, 0, 14, 0, 13,
    0, 5, 0, 6, 0, 15, 0, 5, 0, 15, 0, 14, 0, 6, 0, 7,
    0, 16, 0, 6, 0, 16, 0, 15, 0, 7, 0, 8, 0, 17, 0, 7,
    0, 17, 0, 16, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
    0, 6, 0, 7, 0, 8, 0, 0, 0, 9, 0, 10, 0, 11, 0, 12,
    0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 0, 0, 18, 0, 19,
    0, 20, 0, 21, 0, 22, 0, 23, 0, 24, 0, 25, 0, 26, 0, 0,
    0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7,
    0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15,
    0, 16, 0, 17, 0, 0, 0, 2, 0, 4, 0, 6, 0, 8, 0, 10,
    0, 12, 0, 14, 0, 16, 0, 0, 0, 9, 0, 11, 0, 13, 0, 15,
    0, 17, 0, 0, 0, 0, 0, 45, 0, 0, 0, 18, 0, 18, 0, 0,
    0, 30, 0, 0,
};
