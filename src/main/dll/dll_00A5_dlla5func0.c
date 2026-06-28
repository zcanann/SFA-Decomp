/*
 * dlla5func0 (DLL 0xA5) - a modgfx effect spawner (sibling of DLL 0xA6/0xA8).
 *
 * dll_A5_func03 builds a fixed 13-entry GfxCmd command buffer on the stack
 * (mode/layer/flags plus three coordinate words per primitive, several
 * textured from the asset table at lbl_80318D48), fills a per-effect header
 * (colour, position, scale, and hardware-state words copied from the same
 * table), then hands it to gModgfxInterface->spawnEffect. When flag bit 0 is
 * set the effect position is taken from the source object's world position,
 * or, when no source object is given, from the spawn-param packet
 * (posSource + 0xc..0x14). func00/func01 are the DLL's unused entry stubs.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern u8 lbl_80318D48[];
extern f32 lbl_803E1508;
extern f32 lbl_803E150C;
extern f32 lbl_803E1510;
extern f32 lbl_803E1514;
extern f32 lbl_803E1518;
extern f32 lbl_803E151C;
extern f32 lbl_803E1520;
extern f32 lbl_803E1524;
extern u8 lbl_803DB970;
extern u8 lbl_803DB978;

void dll_A5_func03(short* sourceObj, int variant, u8* posSource, u32 flags)
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
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c; /* v5c never written here; required for layout */
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* tab = (u8*)(int)lbl_80318D48;
    GfxCmd* e = buf.entries;
    u32 fl;

    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = &tab[0x68];
    e[0].mode = 4;
    e[0].x = lbl_803E1508;
    e[0].y = lbl_803E1508;
    e[0].z = lbl_803E1508;
    e[1].layer = 0;
    e[1].flags = 4;
    e[1].tex = &lbl_803DB970;
    e[1].mode = 2;
    e[1].x = lbl_803E150C;
    e[1].y = lbl_803E150C;
    e[1].z = lbl_803E1510;
    e[2].layer = 0;
    e[2].flags = 4;
    e[2].tex = &lbl_803DB978;
    e[2].mode = 2;
    e[2].x = lbl_803E1514;
    e[2].y = lbl_803E1514;
    e[2].z = lbl_803E1510;
    e[3].layer = 0;
    e[3].flags = 0;
    e[3].tex = NULL;
    e[3].mode = 0x80;
    e[3].x = lbl_803E1508;
    e[3].y = lbl_803E1508;
    e[3].z = (f32) * sourceObj;
    e[4].layer = 0;
    e[4].flags = 0x7a;
    e[4].tex = NULL;
    e[4].mode = 0x10000;
    e[4].x = lbl_803E1508;
    e[4].y = lbl_803E1508;
    e[4].z = lbl_803E1508;
    e[5].layer = 1;
    e[5].flags = 8;
    e[5].tex = &tab[0x68];
    e[5].mode = 4;
    e[5].x = lbl_803E1518;
    e[5].y = lbl_803E1508;
    e[5].z = lbl_803E1508;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x400000;
    e[6].x = lbl_803E1508;
    e[6].y = lbl_803E1508;
    e[6].z = lbl_803E150C;
    e[7].layer = 1;
    e[7].flags = 8;
    e[7].tex = &tab[0x68];
    e[7].mode = 2;
    e[7].x = lbl_803E150C;
    e[7].y = lbl_803E150C;
    e[7].z = lbl_803E151C;
    e[8].layer = 1;
    e[8].flags = 0x3a1;
    e[8].tex = NULL;
    e[8].mode = 0x1800000;
    e[8].x = lbl_803E150C;
    e[8].y = lbl_803E1508;
    e[8].z = lbl_803E1520;
    e[9].layer = 2;
    e[9].flags = 0x7a;
    e[9].tex = NULL;
    e[9].mode = 0x10000;
    e[9].x = lbl_803E1508;
    e[9].y = lbl_803E1508;
    e[9].z = lbl_803E1508;
    e[10].layer = 2;
    e[10].flags = 8;
    e[10].tex = &tab[0x68];
    e[10].mode = 4;
    e[10].x = lbl_803E1508;
    e[10].y = lbl_803E1508;
    e[10].z = lbl_803E1508;
    e[11].layer = 2;
    e[11].flags = 0;
    e[11].tex = NULL;
    e[11].mode = 0x400000;
    e[11].x = lbl_803E1508;
    e[11].y = lbl_803E1508;
    e[11].z = lbl_803E1524;
    e[12].layer = 2;
    e[12].flags = 0x3a0;
    e[12].tex = NULL;
    e[12].mode = 0x800000;
    e[12].x = lbl_803E150C;
    e[12].y = lbl_803E1508;
    e[12].z = lbl_803E1508;

    buf.v58 = variant;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1508;
    buf.pos[1] = lbl_803E1508;
    buf.pos[2] = lbl_803E1508;
    buf.col[0] = lbl_803E1508;
    buf.col[1] = lbl_803E1508;
    buf.col[2] = lbl_803E1508;
    buf.scale = lbl_803E150C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 8;
    buf.v5a = 0;
    buf.v5b = 0x3c;
    buf.count = (GfxCmd*)((u8*)e + 0x138) - e;
    buf.hw[0] = *(s16*)&tab[0x78];
    buf.hw[1] = *(s16*)&tab[0x7a];
    buf.hw[2] = *(s16*)&tab[0x7c];
    buf.hw[3] = *(s16*)&tab[0x7e];
    buf.hw[4] = *(s16*)&tab[0x80];
    buf.hw[5] = *(s16*)&tab[0x82];
    buf.hw[6] = *(s16*)&tab[0x84];
    buf.cmds = e;
    buf.flags = 0x4040000;
    buf.flags |= (flags | 0x80);
    fl = buf.flags;
    if (fl & 1)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1508 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = lbl_803E1508 + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = lbl_803E1508 + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E1508 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1508 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1508 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, (u8*)(int)lbl_80318D48, 4, &tab[0x50], 0x5e0, 0);
}

void dll_A5_func01_nop(void)
{
}

void dll_A5_func00_nop(void)
{
}
