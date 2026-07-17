/*
 * DLL 0x5D (dll5dfunc0) - one of the per-map gameplay overlay DLLs.
 *
 * The only real entry points are dll_5D_func03 (builds a stacked modgfx
 * command list and spawns effect 0x20b through gModgfxInterface) plus two
 * empty no-op callback slots. The remaining symbols Ghidra pulled in here
 * (the save/preview gameplay code at 0x800e....) are drift duplicates that
 * belong to the main DOL, not to this DLL, and have been dropped.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_005D_dll5dfunc0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL5D_EFFECT_ID 0x20b


u8 lbl_80312130[492] = {
    0,   0,   0,   0,   3,   232, 0,   0,   0,   0,   3,   98,  0,   0,   1,   244, 0,   11,  0,   0,   3,   98,  0,
    0,   254, 12,  0,   22,  0,   0,   0,   0,   0,   0,   252, 24,  0,   32,  0,   0,   252, 158, 0,   0,   254, 12,
    0,   42,  0,   0,   252, 158, 0,   0,   1,   244, 0,   52,  0,   0,   0,   0,   0,   0,   3,   232, 0,   63,  0,
    0,   0,   0,   11,  184, 3,   232, 0,   0,   0,   31,  3,   98,  11,  184, 1,   244, 0,   11,  0,   31,  3,   98,
    11,  184, 254, 12,  0,   22,  0,   31,  0,   0,   11,  184, 252, 24,  0,   32,  0,   31,  252, 158, 11,  184, 254,
    12,  0,   42,  0,   31,  252, 158, 11,  184, 1,   244, 0,   52,  0,   31,  0,   0,   11,  184, 3,   232, 0,   63,
    0,   31,  0,   0,   23,  112, 3,   232, 0,   0,   0,   63,  3,   98,  23,  112, 1,   244, 0,   11,  0,   63,  3,
    98,  23,  112, 254, 12,  0,   22,  0,   63,  0,   0,   23,  112, 252, 24,  0,   32,  0,   63,  252, 158, 23,  112,
    254, 12,  0,   42,  0,   63,  252, 158, 23,  112, 1,   244, 0,   52,  0,   63,  0,   0,   23,  112, 3,   232, 0,
    63,  0,   63,  0,   0,   0,   0,   0,   1,   0,   8,   0,   0,   0,   8,   0,   7,   0,   1,   0,   2,   0,   9,
    0,   1,   0,   9,   0,   8,   0,   2,   0,   3,   0,   10,  0,   2,   0,   10,  0,   9,   0,   3,   0,   4,   0,
    11,  0,   3,   0,   11,  0,   10,  0,   4,   0,   5,   0,   12,  0,   4,   0,   12,  0,   11,  0,   5,   0,   6,
    0,   13,  0,   5,   0,   13,  0,   12,  0,   7,   0,   8,   0,   15,  0,   7,   0,   15,  0,   14,  0,   8,   0,
    9,   0,   16,  0,   8,   0,   16,  0,   15,  0,   9,   0,   10,  0,   17,  0,   9,   0,   17,  0,   16,  0,   10,
    0,   11,  0,   18,  0,   10,  0,   18,  0,   17,  0,   11,  0,   12,  0,   19,  0,   11,  0,   19,  0,   18,  0,
    12,  0,   13,  0,   20,  0,   12,  0,   20,  0,   19,  0,   0,   0,   1,   0,   2,   0,   3,   0,   4,   0,   5,
    0,   6,   0,   0,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,  0,   0,   0,   14,  0,
    15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   1,   0,   2,   0,   3,   0,   4,
    0,   5,   0,   6,   0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   1,   0,
    2,   0,   3,   0,   4,   0,   5,   0,   6,   0,   7,   0,   8,   0,   9,   0,   10,  0,   11,  0,   12,  0,   13,
    0,   14,  0,   15,  0,   16,  0,   17,  0,   18,  0,   19,  0,   20,  0,   0,   0,   0,   0,   30,  0,   80,  0,
    30,  0,   0,   0,   0,   0,   0,   0,   0};
extern f32 lbl_803E0790;
extern f32 lbl_803E0794;
extern f32 lbl_803E0798;
extern f32 lbl_803E079C;
extern f32 lbl_803E07A0;
extern f32 lbl_803E07A4;
extern f32 lbl_803E07A8;
extern f32 lbl_803E07AC;
extern f32 lbl_803E07B0;
extern f32 lbl_803E07B4;
extern f32 lbl_803E07B8;
extern f32 lbl_803E07BC;

void dll_5D_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80312130;
    GfxCmd* e = buf.entries;
    int ctx;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = lbl_803E0790;
    e[0].y = lbl_803E0790;
    e[0].z = lbl_803E0790;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = lbl_803E0794;
    e[1].y = lbl_803E0798;
    e[1].z = lbl_803E0794;
    e[2].layer = 0;
    e[2].flags = 0x15;
    e[2].tex = &base[432];
    e[2].mode = 0x400000;
    e[2].x = lbl_803E0790;
    e[2].y = lbl_803E079C;
    e[2].z = lbl_803E0790;
    e[3].layer = 1;
    e[3].flags = 7;
    e[3].tex = &base[372];
    e[3].mode = 4;
    e[3].x = lbl_803E07A0;
    e[3].y = lbl_803E0790;
    e[3].z = lbl_803E0790;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = &base[432];
    e[4].mode = 0x4000;
    e[4].x = lbl_803E07A4;
    e[4].y = lbl_803E07A8;
    e[4].z = lbl_803E0790;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[432];
    e[5].mode = 0x400000;
    e[5].x = lbl_803E0790;
    e[5].y = lbl_803E07AC;
    e[5].z = lbl_803E0790;
    e[6].layer = 2;
    e[6].flags = 0x15;
    e[6].tex = &base[432];
    e[6].mode = 0x4000;
    e[6].x = lbl_803E07A8;
    e[6].y = lbl_803E07A4;
    e[6].z = lbl_803E0790;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &base[432];
    e[7].mode = 0x400000;
    e[7].x = lbl_803E0790;
    e[7].y = lbl_803E07B0;
    e[7].z = lbl_803E0790;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 2;
    e[8].x = lbl_803E07B4;
    e[8].y = lbl_803E0798;
    e[8].z = lbl_803E07B4;
    e[9].layer = 3;
    e[9].flags = 7;
    e[9].tex = &base[372];
    e[9].mode = 4;
    e[9].x = lbl_803E0790;
    e[9].y = lbl_803E0790;
    e[9].z = lbl_803E0790;
    e[10].layer = 3;
    e[10].flags = 0x15;
    e[10].tex = &base[432];
    e[10].mode = 0x4000;
    e[10].x = lbl_803E07A8;
    e[10].y = lbl_803E07A4;
    e[10].z = lbl_803E0790;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0790;
    buf.pos[1] = lbl_803E07B8;
    buf.pos[2] = lbl_803E0790;
    buf.col[0] = lbl_803E0790;
    buf.col[1] = lbl_803E0790;
    buf.col[2] = lbl_803E0790;
    buf.scale = lbl_803E07BC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 11) - buf.entries;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = buf.entries;
    buf.flags = 0xc000040;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0790 + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E07B8 + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0790 + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0790 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E07B8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0790 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80312130, 0x18, &base[212], DLL5D_EFFECT_ID, 0);
}

void dll_5D_func01_nop(void)
{
}

void dll_5D_func00_nop(void)
{
}
void* lbl_8031231C[9] = {(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_5D_func00_nop,
                         dll_5D_func01_nop, (void*)0x00000000, dll_5D_func03,     (void*)0x00000000};
