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





/*
 * --INFO--
 *
 * Function: dll_7C_func03
 * EN v1.0 Address: 0x800F472C
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: 0x800F49C8
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_7D_func03
 * EN v1.0 Address: 0x800F4C70
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x800F4F0C
 * EN v1.1 Size: 820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_7E_func03
 * EN v1.0 Address: 0x800F4FA4
 * EN v1.0 Size: 820b
 * EN v1.1 Address: 0x800F5240
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_7F_func03
 * EN v1.0 Address: 0x800F52E0
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x800F557C
 * EN v1.1 Size: 1272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_80_func03
 * EN v1.0 Address: 0x800F57D8
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x800F5A74
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_81_func03
 * EN v1.0 Address: 0x800F5A8C
 * EN v1.0 Size: 1724b
 * EN v1.1 Address: 0x800F5D28
 * EN v1.1 Size: 1732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_82_func03
 * EN v1.0 Address: 0x800F6150
 * EN v1.0 Size: 988b
 * EN v1.1 Address: 0x800F63EC
 * EN v1.1 Size: 996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_83_func03
 * EN v1.0 Address: 0x800F6534
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F67D0
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_84_func03
 * EN v1.0 Address: 0x800F6988
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F6C24
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_85_func03
 * EN v1.0 Address: 0x800F6DDC
 * EN v1.0 Size: 1616b
 * EN v1.1 Address: 0x800F7078
 * EN v1.1 Size: 1624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_86_func03
 * EN v1.0 Address: 0x800F7434
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x800F76D0
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_87_func03
 * EN v1.0 Address: 0x800F77BC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F7A58
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_88_func03
 * EN v1.0 Address: 0x800F7AC0
 * EN v1.0 Size: 712b
 * EN v1.1 Address: 0x800F7D5C
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_89_func03
 * EN v1.0 Address: 0x800F7D90
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F802C
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_8A_func03
 * EN v1.0 Address: 0x800F8094
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x800F8330
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_8B_func03
 * EN v1.0 Address: 0x800F8250
 * EN v1.0 Size: 1424b
 * EN v1.1 Address: 0x800F84EC
 * EN v1.1 Size: 1432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_8C_func03
 * EN v1.0 Address: 0x800F87E8
 * EN v1.0 Size: 1400b
 * EN v1.1 Address: 0x800F8A84
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_8D_func03
 * EN v1.0 Address: 0x800F8D68
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800F9004
 * EN v1.1 Size: 2580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int dll_8D_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    FbCmd* p = buf.entries;
    u8* base = lbl_80316B60;
    int ret = 0;
    f32 q;

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

/*
 * --INFO--
 *
 * Function: dll_8E_func03
 * EN v1.0 Address: 0x800F977C
 * EN v1.0 Size: 1780b
 * EN v1.1 Address: 0x800F9A18
 * EN v1.1 Size: 1788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8E_func03(int sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_8F_func03
 * EN v1.0 Address: 0x800F9E78
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x800FA114
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dll_90_func03
 * EN v1.0 Address: 0x800FA16C
 * EN v1.0 Size: 1124b
 * EN v1.1 Address: 0x800FA408
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */


































void dll_8D_func01_nop(void)
{
}

void dll_8D_func00_nop(void)
{
}

void dll_8E_func01_nop(void);





