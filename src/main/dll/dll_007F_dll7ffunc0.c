#include "main/effect_interfaces.h"
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
void dll_7F_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    u8* base = lbl_80315328;
    FbCmd* p;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 0x8c;
    e[0].tex = (void*)0;
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
    p->tex = (void*)0;
    p->mode = 0x20000000;
    p->x = lbl_803E0E20;
    p->y = lbl_803E0E24;
    p->z = lbl_803E0E28;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
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
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0E2C + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0E2C + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0E2C + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0E2C + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E0E2C + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E0E2C + *(f32*)(posSource + 0x14);
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
void dll_80_func03(int sourceObj, int variant, int posSource, uint flags);

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






void dll_7F_func01_nop(void)
{
}

void dll_7F_func00_nop(void)
{
}

void dll_80_func01_nop(void);

































