/*
 * dll70func0 (DLL 0x70) - particle/gfx spawn helper for a DLL object.
 *
 * The unit owns three entry points:
 *   dll_70_func00_nop / dll_70_func01_nop - empty stubs.
 *   dll_70_func03 - builds a 27-command graphics command list (GfxCmd[])
 *     on the stack from a layout table (gDll70Func03GfxLayoutTable) and a set of shared
 *     float constants, then submits it via gModgfxInterface->spawnEffect.
 *     Bit 0 of the spawn-context flags word (buf.flags) enables
 *     world-position override: a non-null sourceObj uses the GameObject
 *     world position, a null one uses posSource as a PartFxSpawnParams packet.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 gDll70Func03GfxLayoutTable[];
extern int lbl_803DB8D0; /* symbols.txt size:0x8; only &lbl is taken so width is inert */
extern f32 lbl_803E0AF8;
extern f32 lbl_803E0AFC;
extern f32 lbl_803E0B00;
extern f32 lbl_803E0B04;
extern f32 lbl_803E0B08;
extern f32 lbl_803E0B0C;
extern f32 lbl_803E0B10;
extern f32 lbl_803E0B14;
extern f32 lbl_803E0B18;
extern f32 lbl_803E0B1C;
extern f32 lbl_803E0B20;
extern f32 lbl_803E0B24;
extern f32 lbl_803E0B28;
extern f32 lbl_803E0B2C;
extern f32 lbl_803E0B30;

void dll_70_func01_nop(void)
{
}

void dll_70_func00_nop(void)
{
}

void dll_70_func03(int sourceObj, int variant, int posSource, u32 flags)
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
        s16 effectType;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)gDll70Func03GfxLayoutTable;
    GfxCmd* e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x12;
    e[0].tex = &base[336];
    e[0].mode = 4;
    e[0].x = lbl_803E0AF8;
    e[0].y = lbl_803E0AF8;
    e[0].z = lbl_803E0AF8;
    e[1].layer = 0;
    e[1].flags = 9;
    e[1].tex = &base[276];
    e[1].mode = 8;
    e[1].x = lbl_803E0AFC;
    e[1].y = lbl_803E0AFC;
    e[1].z = lbl_803E0AF8;
    e[2].layer = 0;
    e[2].flags = 9;
    e[2].tex = &base[296];
    e[2].mode = 2;
    e[2].x = lbl_803E0B00;
    e[2].y = lbl_803E0B04;
    e[2].z = lbl_803E0B00;
    e[3].layer = 0;
    e[3].flags = 0x12;
    e[3].tex = &base[336];
    e[3].mode = 2;
    e[3].x = lbl_803E0B08;
    e[3].y = lbl_803E0B00;
    e[3].z = lbl_803E0B08;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = &base[296];
    e[4].mode = 8;
    e[4].x = lbl_803E0B0C;
    e[4].y = lbl_803E0AF8;
    e[4].z = lbl_803E0AF8;
    e[5].layer = 0;
    e[5].flags = 1;
    e[5].tex = NULL;
    e[5].mode = 0x8000;
    e[5].x = lbl_803E0AFC;
    e[5].y = lbl_803E0B10;
    e[5].z = lbl_803E0AF8;
    e[6].layer = 0;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x80000;
    e[6].x = lbl_803E0AF8;
    e[6].y = lbl_803E0B14;
    e[6].z = lbl_803E0AF8;
    e[7].layer = 1;
    e[7].flags = 0x12;
    e[7].tex = &base[336];
    e[7].mode = 4;
    e[7].x = lbl_803E0AFC;
    e[7].y = lbl_803E0AF8;
    e[7].z = lbl_803E0AF8;
    e[8].layer = 1;
    e[8].flags = 9;
    e[8].tex = &base[296];
    e[8].mode = 2;
    e[8].x = lbl_803E0B00;
    e[8].y = lbl_803E0B18;
    e[8].z = lbl_803E0B00;
    e[9].layer = 1;
    e[9].flags = 0x7a;
    e[9].tex = NULL;
    e[9].mode = 0x10000;
    e[9].x = lbl_803E0AF8;
    e[9].y = lbl_803E0AF8;
    e[9].z = lbl_803E0AF8;
    e[10].layer = 1;
    e[10].flags = 0;
    e[10].tex = NULL;
    e[10].mode = 0x80000;
    e[10].x = lbl_803E0AF8;
    e[10].y = lbl_803E0B14;
    e[10].z = lbl_803E0AF8;
    e[11].layer = 2;
    e[11].flags = 0x9d;
    e[11].tex = NULL;
    e[11].mode = 0x20000;
    e[11].x = lbl_803E0AF8;
    e[11].y = lbl_803E0AF8;
    e[11].z = lbl_803E0AF8;
    e[12].layer = 3;
    e[12].flags = 9;
    e[12].tex = &base[276];
    e[12].mode = 8;
    e[12].x = lbl_803E0AFC;
    e[12].y = lbl_803E0B1C;
    e[12].z = lbl_803E0AF8;
    e[13].layer = 3;
    e[13].flags = 0x12;
    e[13].tex = &base[336];
    e[13].mode = 0x100;
    e[13].x = lbl_803E0AF8;
    e[13].y = lbl_803E0AF8;
    e[13].z = lbl_803E0B20;
    e[14].layer = 3;
    e[14].flags = 5;
    e[14].tex = &base[392];
    e[14].mode = 2;
    e[14].x = lbl_803E0B24;
    e[14].y = lbl_803E0B00;
    e[14].z = lbl_803E0B24;
    e[15].layer = 3;
    e[15].flags = 4;
    e[15].tex = &lbl_803DB8D0;
    e[15].mode = 2;
    e[15].x = lbl_803E0B28;
    e[15].y = lbl_803E0B00;
    e[15].z = lbl_803E0B28;
    e[16].layer = 3;
    e[16].flags = 0;
    e[16].tex = NULL;
    e[16].mode = 0x80000;
    e[16].x = lbl_803E0AF8;
    e[16].y = lbl_803E0B2C;
    e[16].z = lbl_803E0AF8;
    e[17].layer = 4;
    e[17].flags = 9;
    e[17].tex = &base[276];
    e[17].mode = 8;
    e[17].x = lbl_803E0AFC;
    e[17].y = lbl_803E0AFC;
    e[17].z = lbl_803E0AF8;
    e[18].layer = 4;
    e[18].flags = 0x12;
    e[18].tex = &base[336];
    e[18].mode = 0x100;
    e[18].x = lbl_803E0AF8;
    e[18].y = lbl_803E0AF8;
    e[18].z = lbl_803E0B20;
    e[19].layer = 4;
    e[19].flags = 5;
    e[19].tex = &base[392];
    e[19].mode = 2;
    e[19].x = lbl_803E0B28;
    e[19].y = lbl_803E0B00;
    e[19].z = lbl_803E0B28;
    e[20].layer = 4;
    e[20].flags = 4;
    e[20].tex = &lbl_803DB8D0;
    e[20].mode = 2;
    e[20].x = lbl_803E0B24;
    e[20].y = lbl_803E0B00;
    e[20].z = lbl_803E0B24;
    e[21].layer = 5;
    e[21].flags = 2;
    e[21].tex = NULL;
    e[21].mode = 0x1000;
    e[21].x = lbl_803E0B00;
    e[21].y = lbl_803E0AF8;
    e[21].z = lbl_803E0AF8;
    e[22].layer = 6;
    e[22].flags = 0x9d;
    e[22].tex = NULL;
    e[22].mode = 0x20000;
    e[22].x = lbl_803E0AF8;
    e[22].y = lbl_803E0AF8;
    e[22].z = lbl_803E0AF8;
    e[23].layer = 6;
    e[23].flags = 0x9b;
    e[23].tex = NULL;
    e[23].mode = 0x10000;
    e[23].x = lbl_803E0AF8;
    e[23].y = lbl_803E0AF8;
    e[23].z = lbl_803E0AF8;
    e[24].layer = 6;
    e[24].flags = 0x12;
    e[24].tex = &base[336];
    e[24].mode = 4;
    e[24].x = lbl_803E0AF8;
    e[24].y = lbl_803E0AF8;
    e[24].z = lbl_803E0AF8;
    e[25].layer = 6;
    e[25].flags = 0x12;
    e[25].tex = &base[336];
    e[25].mode = 2;
    e[25].x = lbl_803E0B30;
    e[25].y = lbl_803E0B00;
    e[25].z = lbl_803E0B30;
    e[26].layer = 6;
    e[26].flags = 0;
    e[26].tex = NULL;
    e[26].mode = 0x80000;
    e[26].x = lbl_803E0AF8;
    e[26].y = lbl_803E0B2C;
    e[26].z = lbl_803E0AF8;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.effectType = variant;
    buf.pos[0] = lbl_803E0AF8;
    buf.pos[1] = lbl_803E0AF8;
    buf.pos[2] = lbl_803E0AF8;
    buf.col[0] = lbl_803E0AF8;
    buf.col[1] = lbl_803E0AF8;
    buf.col[2] = lbl_803E0AF8;
    buf.scale = lbl_803E0B00;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0xc;
    buf.flags = 0x1000082;
    buf.count = 27;
    buf.hw[0] = *(s16*)&base[404];
    buf.hw[1] = *(s16*)&base[406];
    buf.hw[2] = *(s16*)&base[408];
    buf.hw[3] = *(s16*)&base[410];
    buf.hw[4] = *(s16*)&base[412];
    buf.hw[5] = *(s16*)&base[414];
    buf.hw[6] = *(s16*)&base[416];
    buf.cmds = (GfxCmd*)((u8*)&buf.col[0] + 0x40);
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E0AF8 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0AF8 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0AF8 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0AF8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0AF8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0AF8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, (u8*)(int)gDll70Func03GfxLayoutTable, 0x10, &base[180], 0x45, 0);
}

u8 gDll70Func03GfxLayoutTable[420] = {
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
