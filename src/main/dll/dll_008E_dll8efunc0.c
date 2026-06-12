#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"


extern u32 randomGetRange(int min, int max);

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316C60[];
extern u8 lbl_80316C40[];
extern u8 lbl_803DB918;
extern u8 lbl_803DB910;
extern f32 lbl_803E1138;
extern f32 lbl_803E113C;
extern f32 lbl_803E1140;
extern f32 lbl_803E1144;
extern f32 lbl_803E1148;
extern f32 lbl_803E114C;
extern f32 lbl_803E1150;
extern f32 lbl_803E1154;
extern f32 lbl_803E1158;
extern f32 lbl_803E115C;
extern f32 lbl_803E1160;
extern f32 lbl_803E1164;
extern f32 lbl_803E1168;
extern f32 lbl_803E116C;





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
void dll_8E_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    FbCmd* p;
    FbCmd* e = buf.entries;
    u8* base;
    f32 rz;
    f32 ry;

    p = e;
    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &lbl_803DB918;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &lbl_803DB918;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->z = (f32)(int)(randomGetRange(0, 0x41) + 0x78);
        p++;
    }
    rz = (f32)(int)
    randomGetRange(0, 0xfffe);
    ry = (f32)(int)
    randomGetRange(-0xbb8, -0x2ee0);
    p[0].layer = 0;
    p[0].flags = 0;
    p[0].tex = (void*)0;
    p[0].mode = 0x80;
    p[0].x = lbl_803E1138;
    p[0].y = ry;
    p[0].z = rz;
    p[1].layer = 0;
    p[1].flags = 3;
    p[1].tex = &lbl_803DB918;
    p[1].mode = 4;
    p[1].x = lbl_803E1138;
    p[1].y = lbl_803E1138;
    p[1].z = lbl_803E1138;
    p[2].layer = 0;
    p[2].flags = 3;
    p[2].tex = &lbl_803DB918;
    p[2].mode = 2;
    p[2].x = lbl_803E113C;
    p[2].y = lbl_803E1144 * (f32)(int)
    randomGetRange(0, 0x32) + lbl_803E1140;
    p[2].z = lbl_803E1144 * (f32)(int)
    randomGetRange(0, 0x14) + lbl_803E1148;
    p[3].layer = 1;
    p[3].flags = 3;
    p[3].tex = &lbl_803DB918;
    p[3].mode = 4;
    if ((int)randomGetRange(0, 0xa) == 0)
    {
        p[3].x = lbl_803E114C + (f32)(int)
        randomGetRange(0, 0x1e);
    }
    else
    {
        p[3].x = lbl_803E1150 + (f32)(int)
        randomGetRange(0, 0xa);
    }
    p[3].y = lbl_803E1138;
    p[3].z = lbl_803E1138;
    p[4].layer = 2;
    p[4].flags = 0;
    p[4].tex = (void*)0;
    p[4].mode = 0x80;
    p[4].x = lbl_803E1138;
    p[4].y = lbl_803E1138;
    p[4].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[5].layer = 1;
    p[5].flags = 3;
    p[5].tex = &lbl_803DB918;
    p[5].mode = 2;
    p[5].x = lbl_803E1154;
    p[5].y = lbl_803E1158;
    p[5].z = lbl_803E115C;
    p[6].layer = 2;
    p[6].flags = 0;
    p[6].tex = (void*)0;
    p[6].mode = 0x80;
    p[6].x = lbl_803E1138;
    p[6].y = lbl_803E1138;
    p[6].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[7].layer = 2;
    p[7].flags = 3;
    p[7].tex = &lbl_803DB918;
    p[7].mode = 4;
    p[7].x = lbl_803E1138;
    p[7].y = lbl_803E1138;
    p[7].z = lbl_803E1138;
    p[8].layer = 2;
    p[8].flags = 3;
    p[8].tex = &lbl_803DB918;
    p[8].mode = 2;
    p[8].x = lbl_803E1160;
    p[8].y = lbl_803E1164;
    p[8].z = lbl_803E1168;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E1138;
    if (variant == 0)
    {
        buf.pos[1] = lbl_803E1138;
    }
    else if (variant == 1)
    {
        buf.pos[1] = lbl_803E116C;
    }
    buf.pos[2] = *(f32*)&lbl_803E1138;
    buf.col[0] = *(f32*)&lbl_803E1138;
    buf.col[1] = *(f32*)&lbl_803E1138;
    buf.col[2] = *(f32*)&lbl_803E1138;
    buf.scale = lbl_803E1164;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 3;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (FbCmd*)((u8*)p + 0xd8) - e;
    base = lbl_80316C60;
    buf.hw[0] = *(s16*)(base + 0);
    buf.hw[1] = *(s16*)(base + 2);
    buf.hw[2] = *(s16*)(base + 4);
    buf.hw[3] = *(s16*)(base + 6);
    buf.hw[4] = *(s16*)(base + 8);
    buf.hw[5] = *(s16*)(base + 0xa);
    buf.hw[6] = *(s16*)(base + 0xc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000410;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)buf.ctx != 0 && (uint)posSource != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18) + *(f32*)(posSource + 0xc);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c) + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E1138 + (*(f32*)(buf.ctx + 0x20) + *(f32*)(posSource + 0x14));
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 3, lbl_80316C40, 1, &lbl_803DB910, 0x26a, 0);
}

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
void dll_8F_func03(int sourceObj, int variant, int posSource, uint flags);

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




































void dll_8E_func01_nop(void)
{
}

void dll_8E_func00_nop(void)
{
}

void dll_8F_func01_nop(void);



