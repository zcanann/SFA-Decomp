/*
 * dll70func0 (DLL 0x70) - particle/gfx spawn helper for a DLL object.
 *
 * The unit owns three entry points:
 *   dll_70_func00_nop / dll_70_func01_nop - empty stubs.
 *   dll_70_func03 - builds a 27-command graphics command list (GfxCmd[])
 *     on the stack from a layout table (lbl_80313E98) and a set of shared
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

extern u8 lbl_80313E98[];
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

void dll_70_func03(int sourceObj, int variant, int posSource, uint flags)
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
    u8* base = (u8*)(int)lbl_80313E98;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x12;
    buf.entries[0].tex = &base[336];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E0AF8;
    buf.entries[0].y = lbl_803E0AF8;
    buf.entries[0].z = lbl_803E0AF8;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 9;
    buf.entries[1].tex = &base[276];
    buf.entries[1].mode = 8;
    buf.entries[1].x = lbl_803E0AFC;
    buf.entries[1].y = lbl_803E0AFC;
    buf.entries[1].z = lbl_803E0AF8;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 9;
    buf.entries[2].tex = &base[296];
    buf.entries[2].mode = 2;
    buf.entries[2].x = lbl_803E0B00;
    buf.entries[2].y = lbl_803E0B04;
    buf.entries[2].z = lbl_803E0B00;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x12;
    buf.entries[3].tex = &base[336];
    buf.entries[3].mode = 2;
    buf.entries[3].x = lbl_803E0B08;
    buf.entries[3].y = lbl_803E0B00;
    buf.entries[3].z = lbl_803E0B08;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 9;
    buf.entries[4].tex = &base[296];
    buf.entries[4].mode = 8;
    buf.entries[4].x = lbl_803E0B0C;
    buf.entries[4].y = lbl_803E0AF8;
    buf.entries[4].z = lbl_803E0AF8;
    buf.entries[5].layer = 0;
    buf.entries[5].flags = 1;
    buf.entries[5].tex = NULL;
    buf.entries[5].mode = 0x8000;
    buf.entries[5].x = lbl_803E0AFC;
    buf.entries[5].y = lbl_803E0B10;
    buf.entries[5].z = lbl_803E0AF8;
    buf.entries[6].layer = 0;
    buf.entries[6].flags = 0;
    buf.entries[6].tex = NULL;
    buf.entries[6].mode = 0x80000;
    buf.entries[6].x = lbl_803E0AF8;
    buf.entries[6].y = lbl_803E0B14;
    buf.entries[6].z = lbl_803E0AF8;
    buf.entries[7].layer = 1;
    buf.entries[7].flags = 0x12;
    buf.entries[7].tex = &base[336];
    buf.entries[7].mode = 4;
    buf.entries[7].x = lbl_803E0AFC;
    buf.entries[7].y = lbl_803E0AF8;
    buf.entries[7].z = lbl_803E0AF8;
    buf.entries[8].layer = 1;
    buf.entries[8].flags = 9;
    buf.entries[8].tex = &base[296];
    buf.entries[8].mode = 2;
    buf.entries[8].x = lbl_803E0B00;
    buf.entries[8].y = lbl_803E0B18;
    buf.entries[8].z = lbl_803E0B00;
    buf.entries[9].layer = 1;
    buf.entries[9].flags = 0x7a;
    buf.entries[9].tex = NULL;
    buf.entries[9].mode = 0x10000;
    buf.entries[9].x = lbl_803E0AF8;
    buf.entries[9].y = lbl_803E0AF8;
    buf.entries[9].z = lbl_803E0AF8;
    buf.entries[10].layer = 1;
    buf.entries[10].flags = 0;
    buf.entries[10].tex = NULL;
    buf.entries[10].mode = 0x80000;
    buf.entries[10].x = lbl_803E0AF8;
    buf.entries[10].y = lbl_803E0B14;
    buf.entries[10].z = lbl_803E0AF8;
    buf.entries[11].layer = 2;
    buf.entries[11].flags = 0x9d;
    buf.entries[11].tex = NULL;
    buf.entries[11].mode = 0x20000;
    buf.entries[11].x = lbl_803E0AF8;
    buf.entries[11].y = lbl_803E0AF8;
    buf.entries[11].z = lbl_803E0AF8;
    buf.entries[12].layer = 3;
    buf.entries[12].flags = 9;
    buf.entries[12].tex = &base[276];
    buf.entries[12].mode = 8;
    buf.entries[12].x = lbl_803E0AFC;
    buf.entries[12].y = lbl_803E0B1C;
    buf.entries[12].z = lbl_803E0AF8;
    buf.entries[13].layer = 3;
    buf.entries[13].flags = 0x12;
    buf.entries[13].tex = &base[336];
    buf.entries[13].mode = 0x100;
    buf.entries[13].x = lbl_803E0AF8;
    buf.entries[13].y = lbl_803E0AF8;
    buf.entries[13].z = lbl_803E0B20;
    buf.entries[14].layer = 3;
    buf.entries[14].flags = 5;
    buf.entries[14].tex = &base[392];
    buf.entries[14].mode = 2;
    buf.entries[14].x = lbl_803E0B24;
    buf.entries[14].y = lbl_803E0B00;
    buf.entries[14].z = lbl_803E0B24;
    buf.entries[15].layer = 3;
    buf.entries[15].flags = 4;
    buf.entries[15].tex = &lbl_803DB8D0;
    buf.entries[15].mode = 2;
    buf.entries[15].x = lbl_803E0B28;
    buf.entries[15].y = lbl_803E0B00;
    buf.entries[15].z = lbl_803E0B28;
    buf.entries[16].layer = 3;
    buf.entries[16].flags = 0;
    buf.entries[16].tex = NULL;
    buf.entries[16].mode = 0x80000;
    buf.entries[16].x = lbl_803E0AF8;
    buf.entries[16].y = lbl_803E0B2C;
    buf.entries[16].z = lbl_803E0AF8;
    buf.entries[17].layer = 4;
    buf.entries[17].flags = 9;
    buf.entries[17].tex = &base[276];
    buf.entries[17].mode = 8;
    buf.entries[17].x = lbl_803E0AFC;
    buf.entries[17].y = lbl_803E0AFC;
    buf.entries[17].z = lbl_803E0AF8;
    buf.entries[18].layer = 4;
    buf.entries[18].flags = 0x12;
    buf.entries[18].tex = &base[336];
    buf.entries[18].mode = 0x100;
    buf.entries[18].x = lbl_803E0AF8;
    buf.entries[18].y = lbl_803E0AF8;
    buf.entries[18].z = lbl_803E0B20;
    buf.entries[19].layer = 4;
    buf.entries[19].flags = 5;
    buf.entries[19].tex = &base[392];
    buf.entries[19].mode = 2;
    buf.entries[19].x = lbl_803E0B28;
    buf.entries[19].y = lbl_803E0B00;
    buf.entries[19].z = lbl_803E0B28;
    buf.entries[20].layer = 4;
    buf.entries[20].flags = 4;
    buf.entries[20].tex = NULL;
    buf.entries[20].mode = 2;
    buf.entries[20].x = lbl_803E0B24;
    buf.entries[20].y = lbl_803E0B00;
    buf.entries[20].z = lbl_803E0B24;
    buf.entries[21].layer = 5;
    buf.entries[21].flags = 2;
    buf.entries[21].tex = NULL;
    buf.entries[21].mode = 0x1000;
    buf.entries[21].x = lbl_803E0B00;
    buf.entries[21].y = lbl_803E0AF8;
    buf.entries[21].z = lbl_803E0AF8;
    buf.entries[22].layer = 6;
    buf.entries[22].flags = 0x9d;
    buf.entries[22].tex = NULL;
    buf.entries[22].mode = 0x20000;
    buf.entries[22].x = lbl_803E0AF8;
    buf.entries[22].y = lbl_803E0AF8;
    buf.entries[22].z = lbl_803E0AF8;
    buf.entries[23].layer = 6;
    buf.entries[23].flags = 0x9b;
    buf.entries[23].tex = NULL;
    buf.entries[23].mode = 0x10000;
    buf.entries[23].x = lbl_803E0AF8;
    buf.entries[23].y = lbl_803E0AF8;
    buf.entries[23].z = lbl_803E0AF8;
    buf.entries[24].layer = 6;
    buf.entries[24].flags = 0x12;
    buf.entries[24].tex = &base[336];
    buf.entries[24].mode = 4;
    buf.entries[24].x = lbl_803E0AF8;
    buf.entries[24].y = lbl_803E0AF8;
    buf.entries[24].z = lbl_803E0AF8;
    buf.entries[25].layer = 6;
    buf.entries[25].flags = 0x12;
    buf.entries[25].tex = &base[336];
    buf.entries[25].mode = 2;
    buf.entries[25].x = lbl_803E0B30;
    buf.entries[25].y = lbl_803E0B00;
    buf.entries[25].z = lbl_803E0B30;
    buf.entries[26].layer = 6;
    buf.entries[26].flags = 0;
    buf.entries[26].tex = NULL;
    buf.entries[26].mode = 0x80000;
    buf.entries[26].x = lbl_803E0AF8;
    buf.entries[26].y = lbl_803E0B2C;
    buf.entries[26].z = lbl_803E0AF8;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.effectType = variant;
    buf.pos[0] = lbl_803E0B30;
    buf.pos[1] = lbl_803E0B30;
    buf.pos[2] = lbl_803E0B30;
    buf.col[0] = lbl_803E0AF8;
    buf.col[1] = lbl_803E0AF8;
    buf.col[2] = lbl_803E0AF8;
    buf.scale = lbl_803E0B00;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0xc;
    buf.count = 27;
    buf.hw[0] = *(s16*)&base[404];
    buf.hw[1] = *(s16*)&base[406];
    buf.hw[2] = *(s16*)&base[408];
    buf.hw[3] = *(s16*)&base[410];
    buf.hw[4] = *(s16*)&base[412];
    buf.hw[5] = *(s16*)&base[414];
    buf.hw[6] = *(s16*)&base[416];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x1000082;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)sourceObj == NULL)
        {
            buf.pos[0] = lbl_803E0B30 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0B30 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0B30 + ((PartFxSpawnParams*)posSource)->posZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0B30 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0B30 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0B30 + *(f32*)(sourceObj + 0x20);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, (u8*)(int)lbl_80313E98, 0x10, &base[180], 0x45, 0);
}
