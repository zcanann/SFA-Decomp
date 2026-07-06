/*
 * dll7dfunc0 (DLL 0x7D) - one entry in the foodbag effect-DLL family
 * (DLLs 0x7C..0x90). dll_7D_func03 builds a 10-entry FbBuf model-graphics
 * command list from sub-textures of the global texture blob lbl_80315030,
 * scales the second sprite by an optional caller scale (arg6), positions
 * the effect from either the source object (flags bit 0 set, sourceObj
 * non-null) or a separate position source, then spawns it through
 * gModgfxInterface->spawnEffect. lbl_803DD4B0 is a 0..4 rotating slot
 * counter advanced per spawn. The trailing func01/func00 nops are this
 * DLL's empty lifecycle stubs; the next DLL's nop is forward-declared per
 * the family convention.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315030[];
extern int lbl_803DD4B0;
extern f32 lbl_803E0DD8;
extern f32 lbl_803E0DDC;
extern f32 lbl_803E0DE0;
extern f32 lbl_803E0DE4;
extern f32 lbl_803E0DE8;
extern f32 lbl_803E0DEC;
extern f32 lbl_803E0DF0;
extern f32 lbl_803E0DF4;
extern f32 lbl_803E0DF8;

int dll_7D_func03(int sourceObj, int variant, int posSource, u32 flags, u32 arg5,
                  f32* arg6)
{
    int ret;
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315030;
    f32 scale = lbl_803E0DD8;
    FbCmd* entry;
    if (arg6 != NULL)
    {
        scale = *arg6;
    }
    entry = buf.entries;
    entry[0].layer = 0;
    entry[0].flags = 0x15;
    entry[0].tex = base + 0x1b0;
    entry[0].mode = 4;
    entry[0].x = lbl_803E0DDC;
    entry[0].y = lbl_803E0DDC;
    entry[0].z = lbl_803E0DDC;
    entry[1].layer = 0;
    entry[1].flags = 0x15;
    entry[1].tex = base + 0x1b0;
    entry[1].mode = 2;
    entry[1].y = entry[1].x = lbl_803E0DE0 * scale;
    entry[1].z = lbl_803E0DE4 * scale;
    entry[2].layer = 1;
    entry[2].flags = 7;
    entry[2].tex = base + 0x184;
    entry[2].mode = 2;
    entry[2].x = lbl_803E0DE8;
    entry[2].y = lbl_803E0DE8;
    entry[2].z = lbl_803E0DD8;
    entry[3].layer = 2;
    entry[3].flags = 7;
    entry[3].tex = base + 0x164;
    entry[3].mode = 4;
    entry[3].x = lbl_803E0DEC;
    entry[3].y = lbl_803E0DDC;
    entry[3].z = lbl_803E0DDC;
    entry[4].layer = 2;
    entry[4].flags = 7;
    entry[4].tex = base + 0x174;
    entry[4].mode = 4;
    entry[4].x = lbl_803E0DEC;
    entry[4].y = lbl_803E0DDC;
    entry[4].z = lbl_803E0DDC;
    entry[5].layer = 2;
    entry[5].flags = 7;
    entry[5].tex = base + 0x174;
    entry[5].mode = 2;
    entry[5].x = lbl_803E0DF0;
    entry[5].y = lbl_803E0DF0;
    entry[5].z = lbl_803E0DD8;
    entry[6].layer = 2;
    entry[6].flags = 0x15;
    entry[6].tex = base + 0x1b0;
    entry[6].mode = 0x4000;
    entry[6].x = lbl_803E0DF4;
    entry[6].y = lbl_803E0DF8;
    entry[6].z = lbl_803E0DDC;
    entry[7].layer = 3;
    entry[7].flags = 0x15;
    entry[7].tex = base + 0x1b0;
    entry[7].mode = 0x4000;
    entry[7].x = lbl_803E0DF4;
    entry[7].y = lbl_803E0DF8;
    entry[7].z = lbl_803E0DDC;
    entry[8].layer = 3;
    entry[8].flags = 7;
    entry[8].tex = base + 0x164;
    entry[8].mode = 4;
    entry[8].x = lbl_803E0DDC;
    entry[8].y = lbl_803E0DDC;
    entry[8].z = lbl_803E0DDC;
    entry[9].layer = 3;
    entry[9].flags = 7;
    entry[9].tex = base + 0x174;
    entry[9].mode = 4;
    entry[9].x = lbl_803E0DDC;
    entry[9].y = lbl_803E0DDC;
    entry[9].z = lbl_803E0DDC;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0DDC;
    buf.pos[1] = lbl_803E0DDC;
    buf.pos[2] = lbl_803E0DDC;
    buf.col[0] = lbl_803E0DDC;
    buf.col[1] = lbl_803E0DDC;
    buf.col[2] = lbl_803E0DDC;
    buf.scale = lbl_803E0DD8;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)entry + 0xf0) - entry;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = entry;
    buf.flags = 0xc010080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0DDC + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E0DDC + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E0DDC + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0DDC + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0DDC + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0DDC + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315030, 0x18, base + 0xd4, 0x89, 0);
    lbl_803DD4B0 += 1;
    if (lbl_803DD4B0 == 5)
    {
        lbl_803DD4B0 = 0;
    }
    return ret;
}

void dll_7D_func01_nop(void)
{
}

void dll_7D_func00_nop(void)
{
}
