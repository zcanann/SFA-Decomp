/*
 * dll_009D (dll9dfunc0) - pickup/effect glow spawner.
 *
 * dll_9D_func03 builds a 13-entry gfx command list on the stack (a
 * GfxBuf), seeds each layer's blend mode / texture-table offset / scale
 * triple from the f32 constant pool (lbl_803E13F8..lbl_803E1414) and a
 * shared texture/halfword table (lbl_80318038), then hands the buffer to
 * gModgfxInterface->spawnEffect to render the effect. When the caller
 * sets flag bit 0, the effect is positioned either from the source
 * object (offset 0x18..0x20) or from posSource (offset 0xc..0x14).
 *
 * dll_9D_func00_nop / dll_9D_func01_nop are the DLL's empty entry-point
 * thunks.
 */
#include "main/effect_interfaces.h"
#include "main/dll/pickup.h"

/* lbl_80318038: shared texture + halfword table; lbl_803E13F8..1414:
   gfx-constant pool. Home TU unknown. */
extern u8 lbl_80318038[];
extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E13F8;
extern f32 lbl_803E13FC;
extern f32 lbl_803E1400;
extern f32 lbl_803E1404;
extern f32 lbl_803E1408;
extern f32 lbl_803E140C;
extern f32 lbl_803E1410;
extern f32 lbl_803E1414;

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

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

void dll_9D_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    GfxBuf buf;
    u8* tab = (u8*)(int)lbl_80318038;
    GfxCmd* e = buf.entries;
    u32 effectFlags;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &tab[432];
    e[0].mode = 4;
    e[0].x = lbl_803E13F8;
    e[0].y = lbl_803E13F8;
    e[0].z = lbl_803E13F8;
    e[1].layer = 0;
    e[1].flags = 7;
    e[1].tex = &tab[356];
    e[1].mode = 2;
    e[1].x = lbl_803E13FC;
    e[1].y = lbl_803E1400;
    e[1].z = lbl_803E13FC;
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &tab[372];
    e[2].mode = 2;
    e[2].x = lbl_803E1400;
    e[2].y = lbl_803E1400;
    e[2].z = lbl_803E1400;
    e[3].layer = 0;
    e[3].flags = 7;
    e[3].tex = &tab[388];
    e[3].mode = 2;
    e[3].x = lbl_803E13FC;
    e[3].y = lbl_803E1400;
    e[3].z = lbl_803E13FC;
    e[4].layer = 0;
    e[4].flags = 0;
    e[4].tex = NULL;
    e[4].mode = 0x400000;
    e[4].x = lbl_803E13F8;
    e[4].y = lbl_803E1404;
    e[4].z = lbl_803E13F8;
    e[5].layer = 1;
    e[5].flags = 7;
    e[5].tex = &tab[372];
    e[5].mode = 4;
    e[5].x = lbl_803E1408;
    e[5].y = lbl_803E13F8;
    e[5].z = lbl_803E13F8;
    e[6].layer = 1;
    e[6].flags = 0x15;
    e[6].tex = &tab[432];
    e[6].mode = 0x4000;
    e[6].x = lbl_803E13F8;
    e[6].y = lbl_803E13F8;
    e[6].z = lbl_803E13F8;
    e[7].layer = 1;
    e[7].flags = 0;
    e[7].tex = NULL;
    e[7].mode = 0x400000;
    e[7].x = lbl_803E13F8;
    e[7].y = lbl_803E140C;
    e[7].z = lbl_803E13F8;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &tab[432];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E13F8;
    e[8].y = lbl_803E13F8;
    e[8].z = lbl_803E13F8;
    e[9].layer = 2;
    e[9].flags = 0;
    e[9].tex = NULL;
    e[9].mode = 0x400000;
    e[9].x = lbl_803E13F8;
    e[9].y = lbl_803E1410;
    e[9].z = lbl_803E13F8;
    e[10].layer = 3;
    e[10].flags = 0x15;
    e[10].tex = &tab[432];
    e[10].mode = 0x4000;
    e[10].x = lbl_803E13F8;
    e[10].y = lbl_803E13F8;
    e[10].z = lbl_803E13F8;
    e[11].layer = 3;
    e[11].flags = 0;
    e[11].tex = NULL;
    e[11].mode = 0x400000;
    e[11].x = lbl_803E13F8;
    e[11].y = lbl_803E140C;
    e[11].z = lbl_803E13F8;
    e[12].layer = 3;
    e[12].flags = 7;
    e[12].tex = &tab[372];
    e[12].mode = 4;
    e[12].x = lbl_803E13F8;
    e[12].y = lbl_803E13F8;
    e[12].z = lbl_803E13F8;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E13F8;
    buf.pos[1] = lbl_803E13F8;
    buf.pos[2] = lbl_803E13F8;
    buf.col[0] = lbl_803E13F8;
    buf.col[1] = lbl_803E13F8;
    buf.col[2] = lbl_803E13F8;
    buf.scale = lbl_803E1414;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 0x138) - e; /* 13 entries */
    buf.hw[0] = *(s16*)&tab[504];
    buf.hw[1] = *(s16*)&tab[506];
    buf.hw[2] = *(s16*)&tab[508];
    buf.hw[3] = *(s16*)&tab[510];
    buf.hw[4] = *(s16*)&tab[512];
    buf.hw[5] = *(s16*)&tab[514];
    buf.hw[6] = *(s16*)&tab[516];
    buf.cmds = e;
    buf.flags = 0xc0100c0;
    buf.flags |= flags;
    effectFlags = buf.flags;
    if (effectFlags & 1)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E13F8 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E13F8 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E13F8 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E13F8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E13F8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E13F8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80318038, 0x18, &tab[212], 0x46c, 0);
}


void dll_9D_func01_nop(void)
{
}

void dll_9D_func00_nop(void)
{
}
