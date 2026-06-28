/*
 * dll89func0 (DLL 0x89) - one entry of the foodbag/modgfx spawn-effect
 * family (dll_7C..dll_90 in foodbag.h). dll_89_func03 fills a stack
 * FbBuf command list with ten FbCmd layers (texture/mode/xyz from the
 * lbl_803E10xx float pool and the lbl_80316460 resource block) and hands
 * it to gModgfxInterface->spawnEffect (effect 0x1fd). When flag bit 0 is
 * requested the effect is positioned from sourceObj's transform (+0x18)
 * or, when none, from posSource (+0xc). The two _nop entries are empty
 * vtable slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316460[];
extern u8 lbl_803DB908;
extern f32 lbl_803E1028;
extern f32 lbl_803E102C;
extern f32 lbl_803E1030;
extern f32 lbl_803E1034;
extern f32 lbl_803E1038;
extern f32 lbl_803E103C;
extern f32 lbl_803E1040;
extern f32 lbl_803E1044;
extern f32 lbl_803E1048;

void dll_89_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316460;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 10;
    e[0].tex = base + 0x1ac;
    e[0].mode = 2;
    e[0].x = lbl_803E1028;
    e[0].y = lbl_803E102C;
    e[0].z = lbl_803E1028;
    e[1].layer = 0;
    e[1].flags = 10;
    e[1].tex = base + 0x1ac;
    e[1].mode = 4;
    e[1].x = lbl_803E1030;
    e[1].y = lbl_803E1030;
    e[1].z = lbl_803E1030;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E1034;
    e[2].y = lbl_803E1038;
    e[2].z = lbl_803E103C;
    e[3].layer = 1;
    e[3].flags = 10;
    e[3].tex = base + 0x1ac;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1040;
    e[3].y = lbl_803E1040;
    e[3].z = lbl_803E1030;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = base + 0x198;
    e[4].mode = 2;
    e[4].x = lbl_803E1044;
    e[4].y = lbl_803E102C;
    e[4].z = lbl_803E1044;
    e[5].layer = 2;
    e[5].flags = 1;
    e[5].tex = &lbl_803DB908;
    e[5].mode = 4;
    e[5].x = lbl_803E1048;
    e[5].y = lbl_803E1030;
    e[5].z = lbl_803E1030;
    e[6].layer = 2;
    e[6].flags = 10;
    e[6].tex = base + 0x1ac;
    e[6].mode = 0x4000;
    e[6].x = lbl_803E1040;
    e[6].y = lbl_803E1040;
    e[6].z = lbl_803E1030;
    e[7].layer = 3;
    e[7].flags = 10;
    e[7].tex = base + 0x1ac;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1040;
    e[7].y = lbl_803E1040;
    e[7].z = lbl_803E1030;
    e[8].layer = 4;
    e[8].flags = 10;
    e[8].tex = base + 0x1ac;
    e[8].mode = 0x4000;
    e[8].x = lbl_803E1040;
    e[8].y = lbl_803E1040;
    e[8].z = lbl_803E1030;
    e[9].layer = 4;
    e[9].flags = 10;
    e[9].tex = base + 0x1ac;
    e[9].mode = 4;
    e[9].x = lbl_803E1030;
    e[9].y = lbl_803E1030;
    e[9].z = lbl_803E1030;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1030;
    buf.pos[1] = lbl_803E1030;
    buf.pos[2] = lbl_803E1030;
    buf.col[0] = lbl_803E1030;
    buf.col[1] = lbl_803E1030;
    buf.col[2] = lbl_803E1030;
    buf.scale = lbl_803E1030;
    buf.v40 = 1;
    buf.v3c = 10;
    buf.v59 = 10;
    buf.v5a = 0;
    buf.v5b = 16;
    buf.flags = 0x4000494;
    buf.count = (FbCmd*)((u8*)e + 240) - e;
    buf.hw[0] = *(s16*)(base + 0x1c0);
    buf.hw[1] = *(s16*)(base + 0x1c2);
    buf.hw[2] = *(s16*)(base + 0x1c4);
    buf.hw[3] = *(s16*)(base + 0x1c6);
    buf.hw[4] = *(s16*)(base + 0x1c8);
    buf.hw[5] = *(s16*)(base + 0x1ca);
    buf.hw[6] = *(s16*)(base + 0x1cc);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1030 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E1030 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E1030 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E1030 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1030 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1030 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 10, (u8*)(int)lbl_80316460, 8, base + 0x168, 0x1fd, 0);
}


void dll_89_func01_nop(void)
{
}

void dll_89_func00_nop(void)
{
}

