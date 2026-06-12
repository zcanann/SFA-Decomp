#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"


extern u32 randomGetRange(int min, int max);

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315FA8[];
extern u8 lbl_803DB8F0;
extern u8 lbl_803DB8F4;
extern u8 lbl_803DB8FC;
extern f32 lbl_803E0F70;
extern f32 lbl_803E0F74;
extern f32 lbl_803E0F78;
extern f32 lbl_803E0F7C;
extern f32 lbl_803E0F80;
extern f32 lbl_803E0F84;
extern f32 lbl_803E0F88;
extern f32 lbl_803E0F8C;
extern f32 lbl_803E0F90;
extern f32 lbl_803E0F94;
extern f32 lbl_803E0F98;
extern f32 lbl_803E0F9C;
extern f32 lbl_803E0FA0;





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
void dll_85_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315FA8;
    s16* base16 = (s16*)base;
    FbCmd* p;
    FbCmd* e = buf.entries;
    f32 rv;

    if (variant == 4)
    {
        e[0].layer = 0;
        e[0].flags = 0;
        e[0].tex = (void*)0;
        e[0].mode = 0x400000;
        e[0].x = lbl_803E0F70;
        e[0].y = lbl_803E0F74;
        e[0].z = lbl_803E0F74;
        e[1].layer = 0;
        e[1].flags = 2;
        e[1].tex = &lbl_803DB8FC;
        e[1].mode = 2;
        e[1].x = lbl_803E0F78;
        e[1].y = lbl_803E0F7C;
        e[1].z = lbl_803E0F78;
        e[2].layer = 0;
        e[2].flags = 4;
        e[2].tex = &lbl_803DB8FC;
        e[2].mode = 0x80;
        e[2].x = (f32)(int)
        randomGetRange(-0x7ff8, 0x7ff8);
        e[2].y = lbl_803E0F74;
        e[2].z = lbl_803E0F80;
        p = &e[3];
    }
    else
    {
        e[0].layer = 0;
        e[0].flags = 2;
        e[0].tex = &lbl_803DB8F0;
        e[0].mode = 2;
        e[0].x = lbl_803E0F84 * *(f32*)(sourceObj + 8);
        e[0].y = lbl_803E0F88 * *(f32*)(sourceObj + 8);
        e[0].z = lbl_803E0F8C;
        e[1].layer = 0;
        e[1].flags = 2;
        e[1].tex = &lbl_803DB8FC;
        e[1].mode = 2;
        e[1].x = lbl_803E0F90 * (*(f32*)(sourceObj + 8) / *(f32*)(*(int*)(sourceObj + 0x50) + 4));
        e[1].y = lbl_803E0F88 * (*(f32*)(sourceObj + 8) / *(f32*)(*(int*)(sourceObj + 0x50) + 4));
        e[1].z = lbl_803E0F8C;
        rv = (f32)(int)
        randomGetRange(0, 0xfffe);
        e[2].layer = 0;
        e[2].flags = 0;
        e[2].tex = (void*)0;
        e[2].mode = 0x80;
        e[2].x = rv;
        e[2].y = lbl_803E0F94;
        e[2].z = lbl_803E0F74;
        p = &e[3];
    }
    p[0].layer = 0;
    p[0].flags = 4;
    p[0].tex = &lbl_803DB8F4;
    p[0].mode = 4;
    p[0].x = lbl_803E0F74;
    p[0].y = lbl_803E0F74;
    p[0].z = lbl_803E0F74;
    rv = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[1].layer = 1;
    p[1].flags = 2;
    p[1].tex = &lbl_803DB8F0;
    p[1].mode = 4;
    p[1].x = lbl_803E0F98;
    p[1].y = lbl_803E0F74;
    p[1].z = lbl_803E0F74;
    if (variant == 4)
    {
        p[2].layer = 2;
        p[2].flags = 0;
        p[2].tex = (void*)0;
        p[2].mode = 0x100;
        p[2].x = lbl_803E0F9C;
        p[2].y = lbl_803E0F74;
        p[2].z = lbl_803E0F74;
        p += 3;
    }
    else
    {
        p[2].layer = 1;
        p[2].flags = 0;
        p[2].tex = (void*)0;
        p[2].mode = 0x80;
        p[2].x = rv;
        p[2].y = lbl_803E0F94;
        p[2].z = lbl_803E0F74;
        p += 3;
    }
    rv = (f32)(int)
    randomGetRange(0, 0xfffe);
    if (variant == 4)
    {
        p->layer = 2;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x100;
        p->x = lbl_803E0F9C;
        p->y = lbl_803E0F74;
        p->z = lbl_803E0F74;
        p++;
    }
    else
    {
        p->layer = 2;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x80;
        p->x = rv;
        p->y = lbl_803E0F94;
        p->z = lbl_803E0F74;
        p++;
    }
    if (variant == 4)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x100;
        p->x = lbl_803E0F9C;
        p->y = lbl_803E0F74;
        p->z = lbl_803E0F74;
        p++;
    }
    else
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = (void*)0;
        p->mode = 0x80;
        p->x = rv;
        p->y = lbl_803E0F94;
        p->z = lbl_803E0F74;
        p++;
    }
    p[0].layer = 3;
    p[0].flags = 2;
    p[0].tex = &lbl_803DB8F0;
    p[0].mode = 4;
    p[0].x = lbl_803E0F9C;
    p[0].y = lbl_803E0F74;
    p[0].z = lbl_803E0F74;
    p[1].layer = 3;
    p[1].flags = 4;
    p[1].tex = &lbl_803DB8F4;
    p[1].mode = 2;
    p[1].x = lbl_803E0F7C;
    p[1].y = lbl_803E0FA0;
    p[1].z = lbl_803E0F8C;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E0F74;
    buf.pos[1] = lbl_803E0F74;
    buf.pos[2] = lbl_803E0F74;
    buf.col[0] = lbl_803E0F74;
    buf.col[1] = lbl_803E0F74;
    buf.col[2] = lbl_803E0F74;
    buf.scale = lbl_803E0F8C;
    buf.v40 = 2;
    buf.v3c = 0;
    buf.v59 = 4;
    buf.v5a = 0;
    buf.v5b = 0x20;
    buf.count = (FbCmd*)((u8*)p + 0x30) - e;
    buf.hw[0] = *(s16*)(base + 0x34);
    buf.hw[1] = *(s16*)(base + 0x36);
    buf.hw[2] = *(s16*)(base + 0x38);
    buf.hw[3] = *(s16*)(base + 0x3a);
    buf.hw[4] = *(s16*)(base + 0x3c);
    buf.hw[5] = *(s16*)(base + 0x3e);
    buf.hw[6] = *(s16*)(base + 0x40);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    if (variant == 4)
    {
        buf.flags = 0x4004400;
    }
    else
    {
        buf.flags = 0x4006410;
    }
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)buf.ctx != 0 && (uint)posSource != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18) + *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c) + *(f32*)(posSource + 0x10);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20) + *(f32*)(posSource + 0x14);
        }
        else if ((uint)buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else if ((uint)posSource != 0)
        {
            buf.pos[0] += *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(posSource + 0x10);
            buf.pos[2] += *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 4, (u8*)(int)lbl_80315FA8, 2, base + 0x28,
                                     base16[variant * 2 + (int)randomGetRange(0, 1) + 0x22], 0);
}

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
void dll_86_func03(int sourceObj, int variant, int posSource, uint flags);

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


















void dll_85_func01_nop(void)
{
}

void dll_85_func00_nop(void)
{
}

void dll_86_func01_nop(void);





















