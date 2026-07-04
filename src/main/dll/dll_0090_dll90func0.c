/*
 * dll90func0 (DLL 0x90) - one of the foodbag effect-spawner DLLs.
 *
 * dll_90_func03 builds a fixed 21-entry FbCmd display list on the stack
 * (textures resolved as offsets into the gDll90EffectResourceBlock resource block, all
 * coordinates pulled from the lbl_803E11A0.. float pool) plus the
 * surrounding FbBuf header, then hands it to the modgfx interface's
 * spawnEffect. When the low flag bit is set the effect is anchored to a
 * world position: from sourceObj+0x18 if a source object was given,
 * otherwise from posSource+0xc.
 *
 * func00/func01 are nops in this DLL.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 gDll90EffectResourceBlock[];
extern u8 lbl_803DB920;
extern f32 lbl_803E11A0;
extern f32 lbl_803E11A4;
extern f32 lbl_803E11A8;
extern f32 lbl_803E11AC;
extern f32 lbl_803E11B0;
extern f32 lbl_803E11B4;
extern f32 lbl_803E11B8;
extern f32 lbl_803E11BC;
extern f32 lbl_803E11C0;
extern f32 lbl_803E11C4;
extern f32 lbl_803E11C8;
extern f32 lbl_803E11CC;
extern f32 lbl_803E11D0;
extern f32 lbl_803E11D4;

void dll_90_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)gDll90EffectResourceBlock;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x12;
    e[0].tex = base + 0x150;
    e[0].mode = 0x4;
    e[0].x = lbl_803E11A0;
    e[0].y = lbl_803E11A0;
    e[0].z = lbl_803E11A0;
    e[1].layer = 0;
    e[1].flags = 0x9;
    e[1].tex = base + 0x114;
    e[1].mode = 0x8;
    e[1].x = lbl_803E11A4;
    e[1].y = lbl_803E11A4;
    e[1].z = lbl_803E11A0;
    e[2].layer = 0;
    e[2].flags = 0x9;
    e[2].tex = base + 0x128;
    e[2].mode = 0x2;
    e[2].x = lbl_803E11A8;
    e[2].y = lbl_803E11AC;
    e[2].z = lbl_803E11A8;
    e[3].layer = 0;
    e[3].flags = 0x12;
    e[3].tex = base + 0x150;
    e[3].mode = 0x2;
    e[3].x = lbl_803E11B0;
    e[3].y = lbl_803E11B4;
    e[3].z = lbl_803E11B0;
    e[4].layer = 0;
    e[4].flags = 0x9;
    e[4].tex = base + 0x128;
    e[4].mode = 0x8;
    e[4].x = lbl_803E11B8;
    e[4].y = lbl_803E11A0;
    e[4].z = lbl_803E11A0;
    e[5].layer = 1;
    e[5].flags = 0x12;
    e[5].tex = base + 0x150;
    e[5].mode = 0x4;
    e[5].x = lbl_803E11A4;
    e[5].y = lbl_803E11A0;
    e[5].z = lbl_803E11A0;
    e[6].layer = 1;
    e[6].flags = 0x9;
    e[6].tex = base + 0x128;
    e[6].mode = 0x2;
    e[6].x = lbl_803E11A8;
    e[6].y = lbl_803E11BC;
    e[6].z = lbl_803E11A8;
    e[7].layer = 1;
    e[7].flags = 0x7a;
    e[7].tex = 0;
    e[7].mode = 0x10000;
    e[7].x = lbl_803E11A0;
    e[7].y = lbl_803E11A0;
    e[7].z = lbl_803E11A0;
    e[8].layer = 1;
    e[8].flags = 0x0;
    e[8].tex = 0;
    e[8].mode = 0x80000;
    e[8].x = lbl_803E11A0;
    e[8].y = lbl_803E11C0;
    e[8].z = lbl_803E11A0;
    e[9].layer = 2;
    e[9].flags = 0x9d;
    e[9].tex = 0;
    e[9].mode = 0x20000;
    e[9].x = lbl_803E11A0;
    e[9].y = lbl_803E11A0;
    e[9].z = lbl_803E11A0;
    e[10].layer = 3;
    e[10].flags = 0x9;
    e[10].tex = base + 0x114;
    e[10].mode = 0x8;
    e[10].x = lbl_803E11A4;
    e[10].y = lbl_803E11C4;
    e[10].z = lbl_803E11A0;
    e[11].layer = 3;
    e[11].flags = 0x12;
    e[11].tex = base + 0x150;
    e[11].mode = 0x100;
    e[11].x = lbl_803E11A0;
    e[11].y = lbl_803E11A0;
    e[11].z = lbl_803E11C8;
    e[12].layer = 3;
    e[12].flags = 0x5;
    e[12].tex = base + 0x188;
    e[12].mode = 0x2;
    e[12].x = lbl_803E11CC;
    e[12].y = lbl_803E11A8;
    e[12].z = lbl_803E11CC;
    e[13].layer = 3;
    e[13].flags = 0x4;
    e[13].tex = &lbl_803DB920;
    e[13].mode = 0x2;
    e[13].x = lbl_803E11D0;
    e[13].y = lbl_803E11A8;
    e[13].z = lbl_803E11D0;
    e[14].layer = 4;
    e[14].flags = 0x9;
    e[14].tex = base + 0x114;
    e[14].mode = 0x8;
    e[14].x = lbl_803E11A4;
    e[14].y = lbl_803E11A4;
    e[14].z = lbl_803E11A0;
    e[15].layer = 4;
    e[15].flags = 0x12;
    e[15].tex = base + 0x150;
    e[15].mode = 0x100;
    e[15].x = lbl_803E11A0;
    e[15].y = lbl_803E11A0;
    e[15].z = lbl_803E11C8;
    e[16].layer = 4;
    e[16].flags = 0x5;
    e[16].tex = base + 0x188;
    e[16].mode = 0x2;
    e[16].x = lbl_803E11D0;
    e[16].y = lbl_803E11A8;
    e[16].z = lbl_803E11D0;
    e[17].layer = 4;
    e[17].flags = 0x4;
    e[17].tex = &lbl_803DB920;
    e[17].mode = 0x2;
    e[17].x = lbl_803E11CC;
    e[17].y = lbl_803E11A8;
    e[17].z = lbl_803E11CC;
    e[18].layer = 5;
    e[18].flags = 0x1;
    e[18].tex = 0;
    e[18].mode = 0x1000;
    e[18].x = lbl_803E11A8;
    e[18].y = lbl_803E11A0;
    e[18].z = lbl_803E11A0;
    e[19].layer = 6;
    e[19].flags = 0x12;
    e[19].tex = base + 0x150;
    e[19].mode = 0x4;
    e[19].x = lbl_803E11A0;
    e[19].y = lbl_803E11A0;
    e[19].z = lbl_803E11A0;
    e[20].layer = 6;
    e[20].flags = 0x12;
    e[20].tex = base + 0x150;
    e[20].mode = 0x2;
    e[20].x = lbl_803E11D4;
    e[20].y = lbl_803E11A8;
    e[20].z = lbl_803E11D4;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E11A0;
    buf.pos[1] = lbl_803E11A0;
    buf.pos[2] = lbl_803E11A0;
    buf.col[0] = lbl_803E11A0;
    buf.col[1] = lbl_803E11A0;
    buf.col[2] = lbl_803E11A0;
    buf.scale = lbl_803E11A8;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0xc;
    buf.flags = 0x1000082;
    buf.count = (FbCmd*)((u8*)e + 0x1f8) - e;
    buf.hw[0] = *(s16*)(base + 0x194);
    buf.hw[1] = *(s16*)(base + 0x196);
    buf.hw[2] = *(s16*)(base + 0x198);
    buf.hw[3] = *(s16*)(base + 0x19a);
    buf.hw[4] = *(s16*)(base + 0x19c);
    buf.hw[5] = *(s16*)(base + 0x19e);
    buf.hw[6] = *(s16*)(base + 0x1a0);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E11A0 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E11A0 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E11A0 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E11A0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E11A0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E11A0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, (u8*)(int)gDll90EffectResourceBlock, 0x10, base + 0xb4, 0x45, 0);
}

void dll_90_func01_nop(void)
{
}

void dll_90_func00_nop(void)
{
}

u8 gDll90EffectResourceBlock[420] = {
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

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80316FD4[9] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_90_func00_nop, dll_90_func01_nop, (void*)0x00000000, dll_90_func03, (void*)0x00000000 };
