#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

extern u32 randomGetRange(int min, int max);

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316B60[];
extern f32 lbl_803E10E0;
extern f32 lbl_803E10E4;
extern f32 lbl_803E10E8;
extern f32 lbl_803E10EC;
extern f32 lbl_803E10F0;
extern f32 lbl_803E10F4;
extern f32 lbl_803E10F8;
extern f32 lbl_803E10FC;
extern f32 lbl_803E1100;
extern f32 lbl_803E1104;
extern f32 lbl_803E1108;
extern f32 lbl_803E110C;
extern f32 lbl_803E1110;
extern f32 lbl_803E1114;
extern f32 lbl_803E1118;
extern f32 lbl_803E111C;
extern f32 lbl_803E1120;
extern f32 lbl_803E1124;
extern f32 lbl_803E1128;

int dll_8D_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    FbCmd* p;
    u8* base = lbl_80316B60;
    int ret = 0;
    f32 q;

    p = buf.entries;

    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 0x8c;
        p->tex = (void*)0;
        p->mode = 0x20000000;
        p->x = lbl_803E10E0;
        p->y = lbl_803E10E4;
        p->z = lbl_803E10E8;
        p++;
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x80;
        if ((uint)posSource != 0)
        {
            p->x = *(f32*)(posSource + 0xc);
            p->y = *(f32*)(posSource + 0x10);
            p->z = *(f32*)(posSource + 0x14);
            p++;
        }
        else
        {
            p->x = lbl_803E10EC;
            p->y = lbl_803E10F0;
            p->z = lbl_803E10EC;
            p++;
        }
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0x8c;
        p->mode = 2;
        p->x = lbl_803E10F4;
        p->y = lbl_803E10F4;
        p->z = lbl_803E10F8;
        p++;
    }
    else if (variant == 1)
    {
        *(s16*)(base + 0xb2) = 0x50;
        *(s16*)(base + 0xb4) = 0x50;
        p->layer = 0;
        p->flags = 2;
        p->tex = (void*)0;
        p->mode = 0x1800000;
        p->x = lbl_803E10FC;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
        p->layer = 0;
        p->flags = 0x69;
        p->tex = (void*)0;
        p->mode = 0x1800000;
        p->x = lbl_803E10FC;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0x8c;
        p->mode = 2;
        q = lbl_803E1100 * (f32)(int)
        randomGetRange(0, 0xc);
        p->y = p->x = lbl_803E1104 + q;
        p->z = lbl_803E1108 + q;
        p++;
        p->layer = 0;
        p->flags = 0x8c;
        p->tex = (void*)0;
        p->mode = 0x20000000;
        p->x = lbl_803E10E0;
        p->y = lbl_803E110C;
        p->z = lbl_803E1110;
        p++;
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x80;
        if ((uint)posSource != 0)
        {
            p->x = *(f32*)(posSource + 0xc);
            p->y = *(f32*)(posSource + 0x10);
            p->z = *(f32*)(posSource + 0x14);
            p++;
        }
        else
        {
            p->x = lbl_803E10EC;
            p->y = lbl_803E10F0;
            p->z = lbl_803E10EC;
            p++;
        }
    }
    else if (variant == 2)
    {
        *(s16*)(base + 0xb2) = 0x50;
        *(s16*)(base + 0xb4) = 0x50;
        p->layer = 0;
        p->flags = 0x1fc;
        p->tex = (void*)0;
        p->mode = 0x1800000;
        p->x = lbl_803E10FC;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
        p->layer = 0;
        p->flags = 8;
        p->tex = base + 0x8c;
        p->mode = 2;
        q = lbl_803E1100 * (f32)(int)
        randomGetRange(0, 0xc);
        p->y = p->x = lbl_803E1114 + q;
        p->z = lbl_803E1118 + q;
        p++;
        p->layer = 0;
        p->flags = 0x8c;
        p->tex = (void*)0;
        p->mode = 0x20000000;
        p->x = lbl_803E10E0;
        p->y = lbl_803E110C;
        p->z = lbl_803E1110;
        p++;
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x80;
        if ((uint)posSource != 0)
        {
            p->x = *(f32*)(posSource + 0xc);
            p->y = *(f32*)(posSource + 0x10);
            p->z = *(f32*)(posSource + 0x14);
            p++;
        }
        else
        {
            p->x = lbl_803E10EC;
            p->y = lbl_803E10F0;
            p->z = lbl_803E10EC;
            p++;
        }
    }
    if (variant == 0)
    {
        p[0].layer = 1;
        p[0].flags = 9;
        p[0].tex = base + 0x8c;
        p[0].mode = 0x4000;
        p[0].x = lbl_803E10EC;
        p[0].y = lbl_803E10EC;
        p[0].z = lbl_803E10EC;
        p[1].layer = 1;
        p[1].flags = 0x68;
        p[1].tex = (void*)0;
        p[1].mode = 0x800000;
        p[1].x = lbl_803E10FC;
        p[1].y = lbl_803E10EC;
        p[1].z = lbl_803E10EC;
        p[2].layer = 1;
        p[2].flags = 8;
        p[2].tex = base + 0x8c;
        p[2].mode = 2;
        p[2].x = lbl_803E111C;
        p[2].y = lbl_803E111C;
        p[2].z = lbl_803E111C;
        p += 3;
    }
    else if (variant == 1)
    {
        p[0].layer = 1;
        p[0].flags = 9;
        p[0].tex = base + 0x8c;
        p[0].mode = 0x4000;
        p[0].x = lbl_803E10EC;
        p[0].y = lbl_803E10EC;
        p[0].z = lbl_803E10EC;
        p[1].layer = 1;
        p[1].flags = 0x8f;
        p[1].tex = (void*)0;
        p[1].mode = 0x1800000;
        p[1].x = lbl_803E1120;
        p[1].y = lbl_803E10EC;
        p[1].z = lbl_803E10EC;
        p += 2;
    }
    else if (variant == 2)
    {
        p[0].layer = 1;
        p[0].flags = 9;
        p[0].tex = base + 0x8c;
        p[0].mode = 0x4000;
        p[0].x = lbl_803E10EC;
        p[0].y = lbl_803E10EC;
        p[0].z = lbl_803E10EC;
        p[1].layer = 1;
        p[1].flags = 0x1fd;
        p[1].tex = (void*)0;
        p[1].mode = 0x1800000;
        p[1].x = lbl_803E1120;
        p[1].y = lbl_803E10EC;
        p[1].z = lbl_803E10EC;
        p += 2;
    }
    if (variant == 0)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = lbl_803E1124;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = lbl_803E1128;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
    }
    else if (variant == 2)
    {
        p->layer = 1;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = lbl_803E1128;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
    }
    if (variant == 0)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = lbl_803E1124;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = lbl_803E1128;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
    }
    else if (variant == 2)
    {
        p->layer = 2;
        p->flags = 9;
        p->tex = base + 0x8c;
        p->mode = 0x100;
        p->x = lbl_803E1128;
        p->y = lbl_803E10EC;
        p->z = lbl_803E10EC;
        p++;
    }
    p->layer = 2;
    p->flags = 9;
    p->tex = base + 0x8c;
    p->mode = 4;
    p->x = lbl_803E10EC;
    p->y = lbl_803E10EC;
    p->z = lbl_803E10EC;
    p++;
    if (variant == 0)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x20000000;
        p->x = lbl_803E10E0;
        p->y = lbl_803E10E4;
        p->z = lbl_803E10E8;
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x20000000;
        p->x = lbl_803E10E0;
        p->y = lbl_803E110C;
        p->z = lbl_803E1110;
        p++;
    }
    else if (variant == 2)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x20000000;
        p->x = lbl_803E10E0;
        p->y = lbl_803E110C;
        p->z = lbl_803E1110;
        p++;
    }
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    if (variant == 0)
    {
        buf.pos[0] = lbl_803E10EC;
        buf.pos[1] = lbl_803E10EC;
        buf.pos[2] = lbl_803E10EC;
    }
    else
    {
        buf.pos[0] = lbl_803E10EC;
        buf.pos[1] = lbl_803E10EC;
        buf.pos[2] = lbl_803E10EC;
    }
    buf.col[0] = lbl_803E10EC;
    buf.col[1] = lbl_803E10EC;
    buf.col[2] = lbl_803E10EC;
    buf.scale = lbl_803E10FC;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = p - buf.entries;
    buf.hw[0] = *(s16*)(base + 0xb0);
    buf.hw[1] = *(s16*)(base + 0xb2);
    buf.hw[2] = *(s16*)(base + 0xb4);
    buf.hw[3] = *(s16*)(base + 0xb6);
    buf.hw[4] = *(s16*)(base + 0xb8);
    buf.hw[5] = *(s16*)(base + 0xba);
    buf.hw[6] = *(s16*)(base + 0xbc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] += *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(posSource + 0x10);
            buf.pos[2] += *(f32*)(posSource + 0x14);
        }
    }
    if (variant == 0)
    {
        buf.v58 = 0;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base, 8, base + 0x5c, 0x156, 0);
    }
    else if (variant == 1)
    {
        buf.v58 = 0;
        buf.flags |= 4;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base, 8, base + 0x5c, 0xc0d, 0);
    }
    else if (variant == 2)
    {
        buf.v58 = 0;
        buf.flags |= 4;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, base, 8, base + 0x5c, 0x23b, 0);
    }
    return ret;
}


void dll_8D_func01_nop(void)
{
}

void dll_8D_func00_nop(void)
{
}

void dll_8E_func01_nop(void);
