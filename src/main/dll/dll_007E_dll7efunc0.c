#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"



extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315258[];
extern u8 lbl_803DB8E0;
extern f32 lbl_803E0E00;
extern f32 lbl_803E0E04;
extern f32 lbl_803E0E08;
extern f32 lbl_803E0E0C;
extern f32 lbl_803E0E10;
extern f32 lbl_803E0E14;
extern f32 lbl_803E0E18;
extern f32 lbl_803E0E1C;





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
void dll_7E_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* arg6
)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315258;
    f32 s = lbl_803E0E00;
    FbCmd* e;
    FbCmd* p;
    if (arg6 != (f32*)0)
    {
        s = *arg6;
    }
    if ((uint)posSource != 0)
    {
        s = *(f32*)(posSource + 8);
    }
    e = buf.entries;
    p = &e[2];
    e[0].layer = 0;
    e[0].flags = 5;
    e[0].tex = base + 0x90;
    e[0].mode = 0x4000;
    e[0].x = lbl_803E0E04;
    e[0].y = lbl_803E0E08;
    e[0].z = lbl_803E0E04;
    e[1].layer = 0;
    e[1].flags = 9;
    e[1].tex = base + 0x7c;
    e[1].mode = 4;
    e[1].x = lbl_803E0E04;
    e[1].y = lbl_803E0E04;
    e[1].z = lbl_803E0E04;
    if (variant == 1)
    {
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x7c;
        p->mode = 2;
        p->x = lbl_803E0E0C * s;
        p->y = lbl_803E0E00;
        p->z = lbl_803E0E10;
        p++;
    }
    else
    {
        p->layer = 0;
        p->flags = 9;
        p->tex = base + 0x7c;
        p->mode = 2;
        p->x = lbl_803E0E14 * s;
        p->y = lbl_803E0E00;
        p->z = lbl_803E0E10;
        p++;
    }
    p[0].layer = 1;
    p[0].flags = 3;
    p[0].tex = &lbl_803DB8E0;
    p[0].mode = 4;
    p[0].x = lbl_803E0E18;
    p[0].y = lbl_803E0E04;
    p[0].z = lbl_803E0E04;
    p[1].layer = 1;
    p[1].flags = 5;
    p[1].tex = base + 0x90;
    p[1].mode = 0x4000;
    p[1].x = lbl_803E0E1C;
    p[1].y = lbl_803E0E08;
    p[1].z = lbl_803E0E04;
    p[2].layer = 2;
    p[2].flags = 5;
    p[2].tex = base + 0x90;
    p[2].mode = 0x4000;
    p[2].x = lbl_803E0E1C;
    p[2].y = lbl_803E0E08;
    p[2].z = lbl_803E0E04;
    p[3].layer = 2;
    p[3].flags = 3;
    p[3].tex = &lbl_803DB8E0;
    p[3].mode = 4;
    p[3].x = lbl_803E0E04;
    p[3].y = lbl_803E0E04;
    p[3].z = lbl_803E0E04;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E0E04;
    buf.pos[1] = lbl_803E0E04;
    buf.pos[2] = lbl_803E0E04;
    buf.col[0] = lbl_803E0E04;
    buf.col[1] = lbl_803E0E04;
    buf.col[2] = lbl_803E0E04;
    buf.scale = lbl_803E0E00;
    buf.v40 = 1;
    buf.v3c = 9;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)p + 0x60) - e;
    buf.hw[0] = *(s16*)(base + 0x9c);
    buf.hw[1] = *(s16*)(base + 0x9e);
    buf.hw[2] = *(s16*)(base + 0xa0);
    buf.hw[3] = *(s16*)(base + 0xa2);
    buf.hw[4] = *(s16*)(base + 0xa4);
    buf.hw[5] = *(s16*)(base + 0xa6);
    buf.hw[6] = *(s16*)(base + 0xa8);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4010080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0E04 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0E04 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0E04 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0E04 + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E0E04 + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E0E04 + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_80315258, 5, base + 0x5c, 0x3c, 0);
}

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
void dll_7F_func03(int sourceObj, int variant, int posSource, uint flags);

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




void dll_7E_func01_nop(void)
{
}

void dll_7E_func00_nop(void)
{
}

void dll_7F_func01_nop(void);



































