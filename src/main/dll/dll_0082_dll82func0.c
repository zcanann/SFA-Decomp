/*
 * dll82func0 (DLL 0x82) - a foodbag-family modgfx effect builder.
 * dll_82_func03 is the effect spawn; func00/func01 are the DLL's empty slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

/* spawnEffect effect ids per variant (textureAssetId arg). */
#define DLL82_EFFECT_ID_VARIANT3_4 0xd9
#define DLL82_EFFECT_ID_DEFAULT    0x2e

extern u8 lbl_80315770[];

void dll_82_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315770;
    FbCmd* e;
    f32 originOffset = 0.0f;
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
    e[0].x = originOffset;
    e[0].y = originOffset;
    e[0].z = originOffset;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 0x2;
    e[1].x = 0.85f;
    e[1].y = 0.08f;
    e[1].z = 0.85f;
    e[2].layer = 1;
    e[2].flags = 0x15;
    e[2].tex = base + 0x1b0;
    e[2].mode = 0x2;
    e[2].x = 1.0f;
    e[2].y = 10.0f;
    e[2].z = 1.0f;
    e[3].layer = 1;
    e[3].flags = 0x7;
    e[3].tex = base + 0x164;
    e[3].mode = 0x4;
    e[3].x = 255.0f;
    e[3].y = originOffset;
    e[3].z = originOffset;
    e[4].layer = 1;
    e[4].flags = 0x7;
    e[4].tex = base + 0x174;
    e[4].mode = 0x4;
    e[4].x = 55.0f;
    e[4].y = originOffset;
    e[4].z = originOffset;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = base + 0x1b0;
    e[5].mode = 0x4000;
    e[5].x = 4.0f;
    e[5].y = 2.0f;
    e[5].z = originOffset;
    e[6].layer = 2;
    e[6].flags = 0x1e;
    e[6].tex = NULL;
    e[6].mode = 0x20000;
    e[6].x = 1.0f;
    e[6].y = originOffset;
    e[6].z = originOffset;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = base + 0x1b0;
    e[7].mode = 0x2;
    e[7].x = 2.0f;
    e[7].y = 1.0f;
    e[7].z = 2.0f;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = base + 0x1b0;
    e[8].mode = 0x4000;
    e[8].x = 4.0f;
    e[8].y = 2.0f;
    e[8].z = originOffset;
    e[9].layer = 3;
    e[9].flags = 0x15;
    e[9].tex = base + 0x1b0;
    e[9].mode = 0x2;
    e[9].x = 2.0f;
    e[9].y = 1.0f;
    e[9].z = 2.0f;
    e[10].layer = 3;
    e[10].flags = 0x15;
    e[10].tex = base + 0x1b0;
    e[10].mode = 0x4000;
    e[10].x = 4.0f;
    e[10].y = 2.0f;
    e[10].z = originOffset;
    e[11].layer = 3;
    e[11].flags = 0x7;
    e[11].tex = base + 0x164;
    e[11].mode = 0x4;
    e[11].x = originOffset;
    e[11].y = originOffset;
    e[11].z = originOffset;
    e[12].layer = 3;
    e[12].flags = 0x7;
    e[12].tex = base + 0x174;
    e[12].mode = 0x4;
    e[12].x = originOffset;
    e[12].y = originOffset;
    e[12].z = originOffset;
    e[13].layer = 3;
    e[13].flags = 0x1e;
    e[13].tex = NULL;
    e[13].mode = 0x20000;
    e[13].x = 1.0f;
    e[13].y = originOffset;
    e[13].z = originOffset;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = originOffset;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
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
            buf.pos[0] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = originOffset + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 3 || variant == 4)
    {
        (*gModgfxInterface)
            ->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315770, 0x18, base + 0xd4, DLL82_EFFECT_ID_VARIANT3_4, 0);
    }
    else
    {
        (*gModgfxInterface)
            ->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315770, 0x18, base + 0xd4, DLL82_EFFECT_ID_DEFAULT, 0);
    }
}

void dll_82_func01_nop(void)
{
}

void dll_82_func00_nop(void)
{
}
