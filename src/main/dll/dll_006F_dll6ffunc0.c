/*
 * dll6ffunc0 (DLL 0x6F, foodbag family, func03 slot): dll_6F_func03 builds a
 * 32-entry modgfx command list (the spirit/aura particle effect) and submits
 * it via gModgfxInterface->spawnEffect. func00/func01 are the DLL's empty
 * entry-point slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_006F_dll6ffunc0.h"

u8 gDll6FGfxCmdTexture[8] = {0, 0, 0, 6, 0, 0x0C, 0, 0x12};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL6F_EFFECT_ID 0x48


extern u8 gDll6FGfxCmdResourceTable[];

void dll_6F_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)gDll6FGfxCmdResourceTable;
    int ctx;
    f32 originOffset = 0.0f;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x18;
    buf.entries[0].tex = &base[336];
    buf.entries[0].mode = 2;
    buf.entries[0].x = 3.0f;
    buf.entries[0].y = 16.0f;
    buf.entries[0].z = 3.0f;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x18;
    buf.entries[1].tex = &base[336];
    buf.entries[1].mode = 4;
    buf.entries[1].x = originOffset;
    buf.entries[1].y = originOffset;
    buf.entries[1].z = originOffset;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 0x18;
    buf.entries[2].tex = &base[336];
    buf.entries[2].mode = 8;
    buf.entries[2].x = 255.0f;
    buf.entries[2].y = 255.0f;
    buf.entries[2].z = originOffset;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x18;
    buf.entries[3].tex = &base[336];
    buf.entries[3].mode = 8;
    buf.entries[3].x = 255.0f;
    buf.entries[3].y = 255.0f;
    buf.entries[3].z = originOffset;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 8;
    buf.entries[4].tex = &base[384];
    buf.entries[4].mode = 8;
    buf.entries[4].x = 255.0f;
    buf.entries[4].y = 155.0f;
    buf.entries[4].z = originOffset;
    buf.entries[5].layer = 0;
    buf.entries[5].flags = 0xc;
    buf.entries[5].tex = &base[400];
    buf.entries[5].mode = 8;
    buf.entries[5].x = 235.0f;
    buf.entries[5].y = originOffset;
    buf.entries[5].z = originOffset;
    buf.entries[6].layer = 0;
    buf.entries[6].flags = 0x7a;
    buf.entries[6].tex = 0;
    buf.entries[6].mode = 0x10000;
    buf.entries[6].x = originOffset;
    buf.entries[6].y = originOffset;
    buf.entries[6].z = originOffset;
    buf.entries[7].layer = 0;
    buf.entries[7].flags = 0x14;
    buf.entries[7].tex = 0;
    buf.entries[7].mode = 0x800000;
    buf.entries[7].x = 1.0f;
    buf.entries[7].y = originOffset;
    buf.entries[7].z = originOffset;
    buf.entries[8].layer = 0;
    buf.entries[8].flags = 0x11;
    buf.entries[8].tex = 0;
    buf.entries[8].mode = 0x800000;
    buf.entries[8].x = 40.0f;
    buf.entries[8].y = originOffset;
    buf.entries[8].z = originOffset;
    buf.entries[9].layer = 0;
    buf.entries[9].flags = 1;
    buf.entries[9].tex = 0;
    buf.entries[9].mode = 0x2008000;
    buf.entries[9].x = 255.0f;
    buf.entries[9].y = 155.0f;
    buf.entries[9].z = originOffset;
    buf.entries[10].layer = 0;
    buf.entries[10].flags = 0;
    buf.entries[10].tex = 0;
    buf.entries[10].mode = 0x80000;
    buf.entries[10].x = originOffset;
    buf.entries[10].y = 10.0f;
    buf.entries[10].z = originOffset;
    buf.entries[11].layer = 0;
    buf.entries[11].flags = 0;
    buf.entries[11].tex = 0;
    buf.entries[11].mode = 0x100;
    buf.entries[11].x = originOffset;
    buf.entries[11].y = originOffset;
    buf.entries[11].z = 200.0f;
    buf.entries[12].layer = 1;
    buf.entries[12].flags = 4;
    buf.entries[12].tex = gDll6FGfxCmdTexture;
    buf.entries[12].mode = 4;
    buf.entries[12].x = 85.0f;
    buf.entries[12].y = originOffset;
    buf.entries[12].z = originOffset;
    buf.entries[13].layer = 1;
    buf.entries[13].flags = 8;
    buf.entries[13].tex = &base[384];
    buf.entries[13].mode = 4;
    buf.entries[13].x = 25.0f;
    buf.entries[13].y = originOffset;
    buf.entries[13].z = originOffset;
    buf.entries[14].layer = 1;
    buf.entries[14].flags = 0x18;
    buf.entries[14].tex = &base[336];
    buf.entries[14].mode = 0x4000;
    buf.entries[14].x = originOffset;
    buf.entries[14].y = -0.6f;
    buf.entries[14].z = originOffset;
    buf.entries[15].layer = 1;
    buf.entries[15].flags = 0x7a;
    buf.entries[15].tex = 0;
    buf.entries[15].mode = 0x10000;
    buf.entries[15].x = 1.0f;
    buf.entries[15].y = originOffset;
    buf.entries[15].z = originOffset;
    buf.entries[16].layer = 1;
    buf.entries[16].flags = 0;
    buf.entries[16].tex = 0;
    buf.entries[16].mode = 0x100;
    buf.entries[16].x = originOffset;
    buf.entries[16].y = originOffset;
    buf.entries[16].z = 200.0f;
    buf.entries[17].layer = 2;
    buf.entries[17].flags = 4;
    buf.entries[17].tex = gDll6FGfxCmdTexture;
    buf.entries[17].mode = 4;
    buf.entries[17].x = originOffset;
    buf.entries[17].y = originOffset;
    buf.entries[17].z = originOffset;
    buf.entries[18].layer = 2;
    buf.entries[18].flags = 8;
    buf.entries[18].tex = &base[384];
    buf.entries[18].mode = 4;
    buf.entries[18].x = 155.0f;
    buf.entries[18].y = originOffset;
    buf.entries[18].z = originOffset;
    buf.entries[19].layer = 2;
    buf.entries[19].flags = 0x18;
    buf.entries[19].tex = &base[336];
    buf.entries[19].mode = 0x4000;
    buf.entries[19].x = originOffset;
    buf.entries[19].y = -0.6f;
    buf.entries[19].z = originOffset;
    buf.entries[20].layer = 2;
    buf.entries[20].flags = 0;
    buf.entries[20].tex = 0;
    buf.entries[20].mode = 0x80000;
    buf.entries[20].x = originOffset;
    buf.entries[20].y = 30.0f;
    buf.entries[20].z = originOffset;
    buf.entries[21].layer = 2;
    buf.entries[21].flags = 0;
    buf.entries[21].tex = 0;
    buf.entries[21].mode = 0x100;
    buf.entries[21].x = originOffset;
    buf.entries[21].y = originOffset;
    buf.entries[21].z = 200.0f;
    buf.entries[22].layer = 3;
    buf.entries[22].flags = 8;
    buf.entries[22].tex = &base[384];
    buf.entries[22].mode = 4;
    buf.entries[22].x = originOffset;
    buf.entries[22].y = originOffset;
    buf.entries[22].z = originOffset;
    buf.entries[23].layer = 3;
    buf.entries[23].flags = 0xc;
    buf.entries[23].tex = &base[400];
    buf.entries[23].mode = 4;
    buf.entries[23].x = 115.0f;
    buf.entries[23].y = originOffset;
    buf.entries[23].z = originOffset;
    buf.entries[24].layer = 3;
    buf.entries[24].flags = 0x18;
    buf.entries[24].tex = &base[336];
    buf.entries[24].mode = 0x4000;
    buf.entries[24].x = originOffset;
    buf.entries[24].y = -0.6f;
    buf.entries[24].z = originOffset;
    buf.entries[25].layer = 3;
    buf.entries[25].flags = 0;
    buf.entries[25].tex = 0;
    buf.entries[25].mode = 0x100;
    buf.entries[25].x = originOffset;
    buf.entries[25].y = originOffset;
    buf.entries[25].z = 200.0f;
    buf.entries[26].layer = 4;
    buf.entries[26].flags = 0xc;
    buf.entries[26].tex = &base[400];
    buf.entries[26].mode = 4;
    buf.entries[26].x = originOffset;
    buf.entries[26].y = originOffset;
    buf.entries[26].z = originOffset;
    buf.entries[27].layer = 4;
    buf.entries[27].flags = 0x18;
    buf.entries[27].tex = &base[336];
    buf.entries[27].mode = 0x4000;
    buf.entries[27].x = originOffset;
    buf.entries[27].y = -0.6f;
    buf.entries[27].z = originOffset;
    buf.entries[28].layer = 4;
    buf.entries[28].flags = 0;
    buf.entries[28].tex = 0;
    buf.entries[28].mode = 0x2008000;
    buf.entries[28].x = 255.0f;
    buf.entries[28].y = 155.0f;
    buf.entries[28].z = originOffset;
    buf.entries[29].layer = 4;
    buf.entries[29].flags = 0;
    buf.entries[29].tex = 0;
    buf.entries[29].mode = 0x100;
    buf.entries[29].x = originOffset;
    buf.entries[29].y = originOffset;
    buf.entries[29].z = 200.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = originOffset;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x18;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x4000084;
    buf.count = 0x14;
    buf.hw[0] = *(s16*)&base[424];
    buf.hw[1] = *(s16*)&base[426];
    buf.hw[2] = *(s16*)&base[428];
    buf.hw[3] = *(s16*)&base[430];
    buf.hw[4] = *(s16*)&base[432];
    buf.hw[5] = *(s16*)&base[434];
    buf.hw[6] = *(s16*)&base[436];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = originOffset + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = originOffset + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = originOffset + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)
        ->spawnEffect(&buf, 0, 0x18, (u8*)(int)gDll6FGfxCmdResourceTable, 0x10, &base[240], DLL6F_EFFECT_ID, 0);
}

void dll_6F_func01_nop(void)
{
}

void dll_6F_func00_nop(void)
{
}

u8 gDll6FGfxCmdResourceTable[440] = {
    0,   0,   0,  0,  0,   0,   0,   15, 0,  0,   1,   77,  0,  40, 0,   0,   0,  0,  0,  11,  0,   235, 0,  40, 255,
    21,  0,   31, 0,  11,  3,   232, 0,  0,  0,   0,   0,   0,  0,  31,  3,   85, 0,  0,  254, 159, 0,   15, 0,  31,
    2,   195, 0,  0,  253, 61,  0,   31, 0,  31,  0,   0,   0,  0,  0,   0,   0,  15, 0,  0,   0,   0,   0,  40, 254,
    179, 0,   0,  0,  11,  255, 22,  0,  40, 255, 21,  0,   31, 0,  11,  0,   0,  0,  0,  252, 24,  0,   0,  0,  31,
    254, 160, 0,  0,  252, 171, 0,   15, 0,  31,  253, 62,  0,  0,  253, 61,  0,  31, 0,  31,  0,   0,   0,  0,  0,
    0,   0,   15, 0,  0,   254, 179, 0,  40, 0,   0,   0,   0,  0,  11,  255, 21, 0,  40, 0,   234, 0,   31, 0,  11,
    252, 24,  0,  0,  0,   0,   0,   0,  0,  31,  252, 171, 0,  0,  1,   96,  0,  15, 0,  31,  253, 61,  0,  0,  2,
    194, 0,   31, 0,  31,  0,   0,   0,  0,  0,   0,   0,   15, 0,  0,   0,   0,  0,  40, 1,   77,  0,   0,  0,  11,
    0,   234, 0,  40, 0,   235, 0,   31, 0,  11,  0,   0,   0,  0,  3,   232, 0,  0,  0,  31,  1,   96,  0,  0,  3,
    85,  0,   15, 0,  31,  2,   194, 0,  0,  2,   195, 0,   31, 0,  31,  0,   0,  0,  2,  0,   1,   0,   1,  0,  4,
    0,   3,   0,  1,  0,   2,   0,   4,  0,  2,   0,   5,   0,  4,  0,   6,   0,  8,  0,  7,   0,   7,   0,  10, 0,
    9,   0,   7,  0,  8,   0,   10,  0,  8,  0,   11,  0,   10, 0,  12,  0,   14, 0,  13, 0,   13,  0,   16, 0,  15,
    0,   13,  0,  14, 0,   16,  0,   14, 0,  17,  0,   16,  0,  18, 0,   19,  0,  20, 0,  19,  0,   22,  0,  21, 0,
    19,  0,   20, 0,  22,  0,   20,  0,  23, 0,   22,  0,   0,  0,  1,   0,   2,  0,  3,  0,   4,   0,   5,  0,  6,
    0,   7,   0,  8,  0,   9,   0,   10, 0,  11,  0,   12,  0,  13, 0,   14,  0,  15, 0,  16,  0,   17,  0,  18, 0,
    19,  0,   20, 0,  21,  0,   22,  0,  23, 0,   1,   0,   2,  0,  7,   0,   8,  0,  13, 0,   14,  0,   19, 0,  20,
    0,   3,   0,  4,  0,   5,   0,   9,  0,  10,  0,   11,  0,  15, 0,   16,  0,  17, 0,  21,  0,   22,  0,  23, 0,
    0,   0,   24, 0,  24,  0,   24,  0,  24, 0,   0,   0,   0,  0,  0,
};

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80313E78[8] = {(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000,
                         dll_6F_func00_nop, dll_6F_func01_nop, (void*)0x00000000, dll_6F_func03};
