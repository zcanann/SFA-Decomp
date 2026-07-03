/*
 * dll8afunc0 (DLL 0x8A) - one of the foodbag modgfx effect spawners
 * (dll_NN_func03 family, see foodbag.h). func03 builds a single-command
 * FbBuf from the effect's resource table (lbl_80316650) and hands it to
 * the modgfx interface to spawn a bone particle effect; flag bit 0 sources
 * the spawn position either from sourceObj (offsets 0x18/0x1c/0x20) or, when
 * sourceObj is null, from posSource (offsets 0xc/0x10/0x14). func00/func01
 * are unused stub slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316650[]; /* effect resource table: tex blob + halfword params */
extern f32 lbl_803E1050;
extern f32 lbl_803E1054;
extern f32 lbl_803E1058;

void dll_8A_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316650;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = base + 0x98;
    e[0].mode = 2;
    e[0].x = lbl_803E1050;
    e[0].y = lbl_803E1050;
    e[0].z = lbl_803E1050;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1054;
    buf.pos[1] = lbl_803E1054;
    buf.pos[2] = lbl_803E1054;
    buf.col[0] = lbl_803E1054;
    buf.col[1] = lbl_803E1054;
    buf.col[2] = lbl_803E1054;
    buf.scale = lbl_803E1058;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 8;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x2000492;
    buf.count = (FbCmd*)((u8*)e + 0x18) - e;
    buf.hw[0] = *(s16*)(base + 0xa8);
    buf.hw[1] = *(s16*)(base + 0xaa);
    buf.hw[2] = *(s16*)(base + 0xac);
    buf.hw[3] = *(s16*)(base + 0xae);
    buf.hw[4] = *(s16*)(base + 0xb0);
    buf.hw[5] = *(s16*)(base + 0xb2);
    buf.hw[6] = *(s16*)(base + 0xb4);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1054 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E1054 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E1054 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E1054 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1054 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1054 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, (u8*)(int)lbl_80316650, 0xc, base + 0x50, 0x1fd, 0);
}

void dll_8A_func01_nop(void)
{
}

void dll_8A_func00_nop(void)
{
}
