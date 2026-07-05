/*
 * dll81func0 (DLL 0x81) - a foodbag-family modgfx effect builder.
 *
 * dll_81_func03 fills a stack FbBuf with a list of FbCmd draw entries
 * (textures taken from the lbl_80315548 texture data array) and hands it to
 * ModgfxInterface::spawnEffect. The `variant` arg selects which optional
 * entries get appended and which spawnEffect effect id is used (0x3e9 for
 * variant 0x1e, 0x23d for variants 2/3, 0x2e for variants 10..13 and 0xe,
 * 0xd9 otherwise); the low bit of the merged flag word selects whether the
 * effect position is read from the source object (+0x18..) or the posSource
 * transform (+0xc..). The two trailing _nop entry points are the DLL's empty
 * func00/func01 slots.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315548[];
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;
extern f32 lbl_803E0E90;
extern f32 lbl_803E0E94;
extern f32 lbl_803E0E98;
extern f32 lbl_803E0E9C;
extern f32 lbl_803E0EA0;
extern f32 lbl_803E0EA4;
extern f32 lbl_803E0EA8;

void dll_81_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315548;
    f32 sy = lbl_803E0E78;
    FbCmd* p;
    FbCmd* e;
    if (variant == 0 || variant == 2 || variant == 0x1e)
    {
        *(s16*)(base + 0x1fa) = 0xc;
    }
    else if (variant == 1 || variant == 3)
    {
        sy *= lbl_803E0E7C;
        *(s16*)(base + 0x1fa) = 4;
        *(s16*)(base + 0x200) = 0x32;
    }
    e = buf.entries;
    p = &e[1];
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E0E80;
    e[0].y = lbl_803E0E80;
    e[0].z = lbl_803E0E80;
    if (variant == 0 || variant == 2)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E84;
        p->y = lbl_803E0E84;
        p->z = lbl_803E0E88;
        p++;
    }
    else if (variant == 0xe)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E8C;
        p->y = lbl_803E0E8C;
        p->z = lbl_803E0E90;
        p++;
    }
    else if (variant == 0x1e)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E94;
        p->y = lbl_803E0E94;
        p->z = lbl_803E0E88;
        p++;
    }
    else
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E84;
        p->y = lbl_803E0E84;
        p->z = lbl_803E0E98;
        p++;
    }
    p[0].layer = 0;
    p[0].flags = 0x77;
    p[0].tex = NULL;
    p[0].mode = 0x10000;
    p[0].x = lbl_803E0E80;
    p[0].y = lbl_803E0E80;
    p[0].z = lbl_803E0E80;
    p[1].layer = 0;
    p[1].flags = 0x79;
    p[1].tex = NULL;
    p[1].mode = 0x10000;
    p[1].x = lbl_803E0E80;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    p[2].layer = 1;
    p[2].flags = 0x15;
    p[2].tex = base + 0x1b0;
    p[2].mode = 4;
    p[2].x = lbl_803E0E9C;
    p[2].y = lbl_803E0E80;
    p[2].z = lbl_803E0E80;
    p += 3;
    if (variant == 0 || variant == 2)
    {
        p->layer = 1;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0EA0;
        p->y = lbl_803E0EA0;
        p->z = lbl_803E0EA4;
        p++;
    }
    else if (variant == 0x1e)
    {
        p->layer = 1;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0EA0;
        p->y = lbl_803E0EA0;
        p->z = lbl_803E0EA8;
        p++;
    }
    p[0].layer = 1;
    p[0].flags = 0x15;
    p[0].tex = base + 0x1b0;
    p[0].mode = 0x4000;
    p[0].x = lbl_803E0EA0;
    p[0].y = sy;
    p[0].z = lbl_803E0E80;
    p[1].layer = 2;
    p[1].flags = 0x15;
    p[1].tex = base + 0x1b0;
    p[1].mode = 4;
    p[1].x = lbl_803E0E9C;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    p[2].layer = 2;
    p[2].flags = 0x15;
    p[2].tex = base + 0x1b0;
    p[2].mode = 0x4000;
    p[2].x = lbl_803E0EA0;
    p[2].y = sy;
    p[2].z = lbl_803E0E80;
    p[3].layer = 3;
    p[3].flags = 0x15;
    p[3].tex = base + 0x1b0;
    p[3].mode = 0x4000;
    p[3].x = lbl_803E0EA0;
    p[3].y = sy;
    p[3].z = lbl_803E0E80;
    p[4].layer = 4;
    p[4].flags = 0x15;
    p[4].tex = base + 0x1b0;
    p[4].mode = 0x4000;
    p[4].x = lbl_803E0EA0;
    p[4].y = sy;
    p[4].z = lbl_803E0E80;
    p += 5;
    if (variant == 0 || variant == 0x1e)
    {
        p->layer = 4;
        p->flags = 2;
        p->tex = NULL;
        p->mode = 0x2000;
        p->x = lbl_803E0E80;
        p->y = lbl_803E0E80;
        p->z = lbl_803E0E80;
        p++;
    }
    p[0].layer = 5;
    p[0].flags = 0x15;
    p[0].tex = base + 0x1b0;
    p[0].mode = 0x4000;
    p[0].x = lbl_803E0EA0;
    p[0].y = sy;
    p[0].z = lbl_803E0E80;
    p[1].layer = 5;
    p[1].flags = 0x15;
    p[1].tex = base + 0x1b0;
    p[1].mode = 4;
    p[1].x = lbl_803E0E80;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    p += 2;
    if (variant == 1 || variant == 3)
    {
        p->layer = 5;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0EA0;
        p->y = lbl_803E0EA0;
        p->z = lbl_803E0E88;
        p++;
    }
    p[0].layer = 5;
    p[0].flags = 0x78;
    p[0].tex = NULL;
    p[0].mode = 0x10000;
    p[0].x = lbl_803E0E80;
    p[0].y = lbl_803E0E80;
    p[0].z = lbl_803E0E80;
    p[1].layer = 5;
    *(s16*)&p[1].flags = -1;
    p[1].tex = NULL;
    p[1].mode = 0x10000;
    p[1].x = lbl_803E0E80;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0E80;
    buf.pos[1] = lbl_803E0E80;
    buf.pos[2] = lbl_803E0E80;
    buf.col[0] = lbl_803E0E80;
    buf.col[1] = lbl_803E0E80;
    buf.col[2] = lbl_803E0E80;
    buf.scale = lbl_803E0EA0;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)p + 0x30) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0E80 + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E0E80 + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E0E80 + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0E80 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0E80 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0E80 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0x1e)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0x3e9, 0);
    }
    else if (variant == 2 || variant == 3)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0x23d, 0);
    }
    else if ((u32)(variant - 10) <= 3 || variant == 0xe)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0x2e, 0);
    }
    else
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0xd9, 0);
    }
}

void dll_81_func01_nop(void)
{
}

void dll_81_func00_nop(void)
{
}
