/*
 * dll7ffunc0 (DLL 0x7F) - one of the foodbag effect DLLs (siblings 0x7C..0x90).
 * dll_7F_func03 builds a FbBuf command list of textured billboard quads from
 * the resource blob at lbl_80315328 and the per-effect float table
 * lbl_803E0E20..lbl_803E0E54, then hands it to the modgfx system via
 * (*gModgfxInterface)->spawnEffect. The `variant` arg (0/1/2) selects which
 * quads are emitted; `flags` is OR'd into the buffer's flags, and bit 0 makes
 * the effect track the source object's (or posSource's) world position.
 * dll_7F_func00_nop/func01_nop are the DLL's empty init/free export slots.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315328[];
extern u8 lbl_803DB8E8;
extern f32 lbl_803E0E20;
extern f32 lbl_803E0E24;
extern f32 lbl_803E0E28;
extern f32 lbl_803E0E2C;
extern f32 lbl_803E0E30;
extern f32 lbl_803E0E34;
extern f32 lbl_803E0E38;
extern f32 lbl_803E0E3C;
extern f32 lbl_803E0E40;
extern f32 lbl_803E0E44;
extern f32 lbl_803E0E48;
extern f32 lbl_803E0E4C;
extern f32 lbl_803E0E50;
extern f32 lbl_803E0E54;

void dll_7F_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = lbl_80315328;
    FbCmd* p;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x8c;
    e[0].tex = NULL;
    e[0].mode = 0x20000000;
    e[0].x = lbl_803E0E20;
    e[0].y = lbl_803E0E24;
    e[0].z = lbl_803E0E28;
    p = &e[1];
    if (variant != 2)
    {
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0xe8;
        p->mode = 0x80;
        p->x = lbl_803E0E2C;
        p->y = lbl_803E0E2C;
        p->z = lbl_803E0E30;
        p++;
    }
    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0xfc;
        p->mode = 2;
        p->x = lbl_803E0E34;
        p->y = lbl_803E0E34;
        p->z = lbl_803E0E38;
        p++;
    }
    else
    {
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0xfc;
        p->mode = 2;
        p->x = lbl_803E0E3C;
        p->y = lbl_803E0E3C;
        p->z = lbl_803E0E40;
        p++;
    }
    if (variant == 0)
    {
        p->layer = 1;
        p->flags = 8;
        p->tex = base + 0xe8;
        p->mode = 2;
        p->x = lbl_803E0E44;
        p->y = lbl_803E0E44;
        p->z = lbl_803E0E44;
        p++;
    }
    else
    {
        p->layer = 1;
        p->flags = 8;
        p->tex = base + 0xe8;
        p->mode = 2;
        p->x = lbl_803E0E44;
        p->y = lbl_803E0E44;
        p->z = lbl_803E0E44;
        p++;
    }
    if (variant == 0)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0xe8;
        p->mode = 0x100;
        p->x = lbl_803E0E48;
        p->y = lbl_803E0E2C;
        p->z = lbl_803E0E2C;
        p++;
        p->layer = 1;
        p->flags = 1;
        p->tex = &lbl_803DB8E8;
        p->mode = 0x4000;
        p->x = lbl_803E0E4C;
        p->y = lbl_803E0E4C;
        p->z = lbl_803E0E2C;
    }
    else if (variant == 1)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0xe8;
        p->mode = 0x100;
        p->x = lbl_803E0E50;
        p->y = lbl_803E0E2C;
        p->z = lbl_803E0E2C;
        p++;
    }
    if (variant == 0)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0xe8;
        p->mode = 0x100;
        p->x = lbl_803E0E48;
        p->y = lbl_803E0E2C;
        p->z = lbl_803E0E2C;
        p++;
        p->layer = 2;
        p->flags = 1;
        p->tex = &lbl_803DB8E8;
        p->mode = 0x4000;
        p->x = lbl_803E0E4C;
        p->y = lbl_803E0E4C;
        p->z = lbl_803E0E2C;
    }
    else if (variant == 1)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0xe8;
        p->mode = 0x100;
        p->x = lbl_803E0E50;
        p->y = lbl_803E0E2C;
        p->z = lbl_803E0E2C;
        p++;
    }
    p->layer = 2;
    p->flags = 9;
    p->tex = base + 0xe8;
    p->mode = 4;
    p->x = lbl_803E0E2C;
    p->y = lbl_803E0E2C;
    p->z = lbl_803E0E2C;
    p++;
    p->layer = 3;
    p->flags = 0;
    p->tex = NULL;
    p->mode = 0x20000000;
    p->x = lbl_803E0E20;
    p->y = lbl_803E0E24;
    p->z = lbl_803E0E28;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0E2C;
    buf.pos[1] = lbl_803E0E2C;
    buf.pos[2] = lbl_803E0E2C;
    buf.col[0] = lbl_803E0E2C;
    buf.col[1] = lbl_803E0E2C;
    buf.col[2] = lbl_803E0E2C;
    buf.scale = lbl_803E0E54;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0x20;
    buf.count = (FbCmd*)((u8*)p + 0x18) - e;
    buf.hw[0] = *(s16*)(base + 0x10c);
    buf.hw[1] = *(s16*)(base + 0x10e);
    buf.hw[2] = *(s16*)(base + 0x110);
    buf.hw[3] = *(s16*)(base + 0x112);
    buf.hw[4] = *(s16*)(base + 0x114);
    buf.hw[5] = *(s16*)(base + 0x116);
    buf.hw[6] = *(s16*)(base + 0x118);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0E2C + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E0E2C + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E0E2C + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0E2C + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0E2C + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0E2C + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0)
    {
        buf.v58 = 0;
        (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base, 8, base + 0xb8, 0x156, 0);
    }
    else
    {
        buf.v58 = 0;
        (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base + 0x5c, 8, base + 0xb8, 0x8a, 0);
    }
}

void dll_7F_func01_nop(void)
{
}

void dll_7F_func00_nop(void)
{
}
