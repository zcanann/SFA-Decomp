/*
 * DLL 0x68 (dll68func0) - a thin gameplay-effect DLL.
 *
 * Real exports (per the DLL's .text):
 *   dll_68_func00_nop / dll_68_func01_nop - empty entry-point stubs.
 *   dll_68_func03 - builds an 11-command Modgfx effect command list on the
 *     stack (textures/half-words sourced from lbl_803135C8, colours/positions
 *     from the lbl_803E09xx float pool) and submits it via
 *     gModgfxInterface->spawnEffect. When the caller's flags bit 0 is set the
 *     effect is positioned from the source object (offset 0x18..0x20) or, if
 *     none, from the PartFxSpawnParams pos fields.
 */
#include "main/effect_interfaces.h"
#include "main/dll/gameplay.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_803135C8[];
extern f32 lbl_803E09E0;
extern f32 lbl_803E09E4;
extern f32 lbl_803E09E8;
extern f32 lbl_803E09EC;
extern f32 lbl_803E09F0;
extern f32 lbl_803E09F4;
extern f32 lbl_803E09F8;

void dll_68_func01_nop(void)
{
}

void dll_68_func00_nop(void)
{
}

void dll_68_func03(int sourceObj, int variant, int posSource, uint flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 spawnFlags;
        u8 v58, v59, v5a, v5b, pad5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_803135C8;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x15;
    buf.entries[0].tex = &base[432];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E09E0;
    buf.entries[0].y = lbl_803E09E0;
    buf.entries[0].z = lbl_803E09E0;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x15;
    buf.entries[1].tex = &base[432];
    buf.entries[1].mode = 2;
    buf.entries[1].x = lbl_803E09E4;
    buf.entries[1].y = lbl_803E09E8;
    buf.entries[1].z = lbl_803E09E4;
    buf.entries[2].layer = 1;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[356];
    buf.entries[2].mode = 2;
    buf.entries[2].x = lbl_803E09E8;
    buf.entries[2].y = lbl_803E09EC;
    buf.entries[2].z = lbl_803E09E8;
    buf.entries[3].layer = 1;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[372];
    buf.entries[3].mode = 4;
    buf.entries[3].x = lbl_803E09F0;
    buf.entries[3].y = lbl_803E09E0;
    buf.entries[3].z = lbl_803E09E0;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 0x15;
    buf.entries[4].tex = &base[432];
    buf.entries[4].mode = 0x4000;
    buf.entries[4].x = lbl_803E09E0;
    buf.entries[4].y = lbl_803E09F4;
    buf.entries[4].z = lbl_803E09E0;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 0;
    buf.entries[5].tex = NULL;
    buf.entries[5].mode = 0x100;
    buf.entries[5].x = lbl_803E09E0;
    buf.entries[5].y = lbl_803E09E0;
    buf.entries[5].z = lbl_803E09F8;
    buf.entries[6].layer = 2;
    buf.entries[6].flags = 0x15;
    buf.entries[6].tex = &base[432];
    buf.entries[6].mode = 0x4000;
    buf.entries[6].x = lbl_803E09E0;
    buf.entries[6].y = lbl_803E09F4;
    buf.entries[6].z = lbl_803E09E0;
    buf.entries[7].layer = 2;
    buf.entries[7].flags = 0;
    buf.entries[7].tex = NULL;
    buf.entries[7].mode = 0x100;
    buf.entries[7].x = lbl_803E09E0;
    buf.entries[7].y = lbl_803E09E0;
    buf.entries[7].z = lbl_803E09F8;
    buf.entries[8].layer = 3;
    buf.entries[8].flags = 7;
    buf.entries[8].tex = &base[372];
    buf.entries[8].mode = 4;
    buf.entries[8].x = lbl_803E09E0;
    buf.entries[8].y = lbl_803E09E0;
    buf.entries[8].z = lbl_803E09E0;
    buf.entries[9].layer = 3;
    buf.entries[9].flags = 0x15;
    buf.entries[9].tex = &base[432];
    buf.entries[9].mode = 0x4000;
    buf.entries[9].x = lbl_803E09E0;
    buf.entries[9].y = lbl_803E09F4;
    buf.entries[9].z = lbl_803E09E0;
    buf.entries[10].layer = 3;
    buf.entries[10].flags = 0;
    buf.entries[10].tex = NULL;
    buf.entries[10].mode = 0x100;
    buf.entries[10].x = lbl_803E09E0;
    buf.entries[10].y = lbl_803E09E0;
    buf.entries[10].z = lbl_803E09F8;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E09F8;
    buf.pos[1] = lbl_803E09F8;
    buf.pos[2] = lbl_803E09F8;
    buf.col[0] = lbl_803E09E0;
    buf.col[1] = lbl_803E09E0;
    buf.col[2] = lbl_803E09E0;
    buf.scale = lbl_803E09EC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 11;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.spawnFlags = 0xc0100c0;
    buf.spawnFlags |= flags;
    if ((buf.spawnFlags & 1) != 0)
    {
        if ((void*)sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E09F8 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E09F8 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E09F8 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E09F8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E09F8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E09F8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803135C8, 0x18, &base[212], 0x41, 0);
}
