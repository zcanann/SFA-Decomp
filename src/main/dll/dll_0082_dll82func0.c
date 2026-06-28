/*
 * dll82func0 (DLL 0x82) - a foodbag-family modgfx effect builder.
 * dll_82_func03 is the effect spawn; func00/func01 are the DLL's empty slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315770[];
extern f32 lbl_803E0EB0;
extern f32 lbl_803E0EB4;
extern f32 lbl_803E0EB8;
extern f32 lbl_803E0EBC;
extern f32 lbl_803E0EC0;
extern f32 lbl_803E0EC4;
extern f32 lbl_803E0EC8;
extern f32 lbl_803E0ECC;
extern f32 lbl_803E0ED0;

void dll_82_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315770;
    FbCmd* e;
    if (variant == 1 || variant == 4)
    {
        *(s16*)(base + 0x1fc) = 0x50;
    }
    if (variant == 2)
    {
        *(s16*)(base + 0x1fc) = 0x6e;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 0x4;
    e[0].x = lbl_803E0EB0;
    e[0].y = lbl_803E0EB0;
    e[0].z = lbl_803E0EB0;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 0x2;
    e[1].x = lbl_803E0EB4;
    e[1].y = lbl_803E0EB8;
    e[1].z = lbl_803E0EB4;
    e[2].layer = 1;
    e[2].flags = 0x15;
    e[2].tex = base + 0x1b0;
    e[2].mode = 0x2;
    e[2].x = lbl_803E0EBC;
    e[2].y = lbl_803E0EC0;
    e[2].z = lbl_803E0EBC;
    e[3].layer = 1;
    e[3].flags = 0x7;
    e[3].tex = base + 0x164;
    e[3].mode = 0x4;
    e[3].x = lbl_803E0EC4;
    e[3].y = lbl_803E0EB0;
    e[3].z = lbl_803E0EB0;
    e[4].layer = 1;
    e[4].flags = 0x7;
    e[4].tex = base + 0x174;
    e[4].mode = 0x4;
    e[4].x = lbl_803E0EC8;
    e[4].y = lbl_803E0EB0;
    e[4].z = lbl_803E0EB0;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 0x4000;
    e[5].x = lbl_803E0ECC;
    e[5].y = lbl_803E0ED0;
    e[5].z = lbl_803E0EB0;
    e[6].layer = 2;
    e[6].flags = 0x1e;
    e[6].tex = NULL;
    e[6].mode = 0x20000;
    e[6].x = lbl_803E0EBC;
    e[6].y = lbl_803E0EB0;
    e[6].z = lbl_803E0EB0;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = base + 0x1b0;
    e[7].mode = 0x2;
    e[7].x = lbl_803E0ED0;
    e[7].y = lbl_803E0EBC;
    e[7].z = lbl_803E0ED0;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = base + 0x1b0;
    e[8].mode = 0x4000;
    e[8].x = lbl_803E0ECC;
    e[8].y = lbl_803E0ED0;
    e[8].z = lbl_803E0EB0;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = base + 0x1b0;
    e[9].mode = 0x2;
    e[9].x = lbl_803E0ED0;
    e[9].y = lbl_803E0EBC;
    e[9].z = lbl_803E0ED0;
    e[10].layer = 3;
    e[10].flags = 0x15;
    e[10].tex = base + 0x1b0;
    e[10].mode = 0x4000;
    e[10].x = lbl_803E0ECC;
    e[10].y = lbl_803E0ED0;
    e[10].z = lbl_803E0EB0;
    e[11].layer = 3;
    e[11].flags = 0x7;
    e[11].tex = base + 0x164;
    e[11].mode = 0x4;
    e[11].x = lbl_803E0EB0;
    e[11].y = lbl_803E0EB0;
    e[11].z = lbl_803E0EB0;
    e[12].layer = 3;
    e[12].flags = 0x7;
    e[12].tex = base + 0x174;
    e[12].mode = 0x4;
    e[12].x = lbl_803E0EB0;
    e[12].y = lbl_803E0EB0;
    e[12].z = lbl_803E0EB0;
    e[13].layer = 3;
    e[13].flags = 0x1e;
    e[13].tex = NULL;
    e[13].mode = 0x20000;
    e[13].x = lbl_803E0EBC;
    e[13].y = lbl_803E0EB0;
    e[13].z = lbl_803E0EB0;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0EB0;
    buf.pos[1] = lbl_803E0EB0;
    buf.pos[2] = lbl_803E0EB0;
    buf.col[0] = lbl_803E0EB0;
    buf.col[1] = lbl_803E0EB0;
    buf.col[2] = lbl_803E0EB0;
    buf.scale = lbl_803E0EBC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)e + 0x150) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = e;
    buf.flags = 0xc010480;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0EB0 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0EB0 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0EB0 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0EB0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0EB0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0EB0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 3 || variant == 4)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315770, 0x18, base + 0xd4, 0xd9, 0);
    }
    else
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315770, 0x18, base + 0xd4, 0x2e, 0);
    }
}


void dll_82_func01_nop(void)
{
}

void dll_82_func00_nop(void)
{
}

void dll_83_func01_nop(void);
