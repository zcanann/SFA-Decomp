#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"



extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316728[];
extern f32 lbl_803E1060;
extern f32 lbl_803E1064;
extern f32 lbl_803E1068;
extern f32 lbl_803E106C;
extern f32 lbl_803E1070;
extern f32 lbl_803E1074;
extern f32 lbl_803E1078;
extern f32 lbl_803E107C;
extern f32 lbl_803E1080;
extern f32 lbl_803E1084;
extern f32 lbl_803E1088;
extern f32 lbl_803E108C;
extern f32 lbl_803E1090;
extern f32 lbl_803E1094;
extern f32 lbl_803E1098;
extern f32 lbl_803E109C;
extern f32 lbl_803E10A0;
extern f32 lbl_803E10A4;





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
void dll_8B_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5,
                   f32* arg6)
{
    FbBuf buf;
    u8* base = lbl_80316728;
    f32 va = lbl_803E1060;
    f32 vb = lbl_803E1064;
    f32 s = lbl_803E1068;
    f32 zoff;
    f32 c74, c78, c7c, c98, c9c, ca0, c94, ca4;
    FbCmd* e;
    FbCmd* p;
    int i;
    if (arg6 != (f32*)0)
    {
        s = *arg6;
    }
    zoff = lbl_803E106C + s;
    e = buf.entries;
    c74 = lbl_803E1074;
    c78 = lbl_803E1078;
    c7c = lbl_803E107C;
    c98 = lbl_803E1098;
    c9c = lbl_803E109C;
    ca0 = lbl_803E10A0;
    c94 = lbl_803E1094;
    ca4 = lbl_803E10A4;
    for (i = 0; i < 2; i++)
    {
        if (i == 1)
        {
            va = lbl_803E1060;
            vb = lbl_803E1070;
        }
        e[0].layer = 0;
        e[0].flags = 0x15;
        e[0].tex = base + 0x1b0;
        e[0].mode = 4;
        e[0].x = c74;
        e[0].y = c74;
        e[0].z = c74;
        e[1].layer = 0;
        e[1].flags = 0x15;
        e[1].tex = base + 0x1b0;
        e[1].mode = 0x80;
        e[1].x = c74;
        e[1].y = (f32) * (s16*)(sourceObj + 2);
        e[1].z = c78 + ((f32) * (s16*)(sourceObj + 0) - c7c);
        p = &e[2];
        if (i == 0)
        {
            p->layer = 0;
            p->flags = 0x15;
            p->tex = base + 0x1b0;
            p->mode = 2;
            if (variant == 4)
            {
                p->x = lbl_803E1080;
                p->y = lbl_803E1080;
                p->z = zoff;
            }
            else
            {
                p->x = lbl_803E1084;
                p->y = lbl_803E1084;
                p->z = zoff;
            }
            p++;
        }
        else
        {
            p->layer = 0;
            p->flags = 0x15;
            p->tex = base + 0x1b0;
            p->mode = 2;
            if (variant == 4)
            {
                p->x = lbl_803E1088;
                p->y = lbl_803E1088;
                p->z = zoff;
            }
            else
            {
                p->x = lbl_803E106C;
                p->y = lbl_803E106C;
                p->z = zoff;
            }
            p++;
        }
        p[0].layer = 0;
        p[0].flags = 0;
        p[0].tex = (void*)0;
        p[0].mode = 0x400000;
        switch (variant)
        {
        case 0:
            p[0].x = c74;
            p[0].y = lbl_803E108C;
            p[0].z = c74;
            break;
        case 1:
            p[0].x = c74;
            p[0].y = lbl_803E1090;
            p[0].z = c74;
            break;
        case 2:
            p[0].x = lbl_803E108C;
            p[0].y = c74;
            p[0].z = c74;
            break;
        case 3:
            p[0].x = lbl_803E1090;
            p[0].y = c74;
            p[0].z = c74;
            break;
        case 4:
            p[0].x = c74;
            p[0].y = c94;
            p[0].z = c74;
            break;
        }
        p[1].layer = 1;
        p[1].flags = 0x15;
        p[1].tex = base + 0x1b0;
        p[1].mode = 4;
        p[1].x = c98;
        p[1].y = c74;
        p[1].z = c74;
        p[2].layer = 1;
        p[2].flags = 0x15;
        p[2].tex = base + 0x1b0;
        p[2].mode = 2;
        p[2].x = c9c;
        p[2].y = c9c;
        p[2].z = ca0;
        p[3].layer = 1;
        p[3].flags = 0x15;
        p[3].tex = base + 0x1b0;
        p[3].mode = 0x4000;
        p[3].x = va;
        p[3].y = vb;
        p[3].z = c74;
        p[4].layer = 2;
        p[4].flags = 0x15;
        p[4].tex = base + 0x1b0;
        p[4].mode = 4;
        p[4].x = c98;
        p[4].y = c74;
        p[4].z = c74;
        p[5].layer = 2;
        p[5].flags = 0x15;
        p[5].tex = base + 0x1b0;
        p[5].mode = 0x4000;
        p[5].x = va;
        p[5].y = vb;
        p[5].z = c74;
        p[6].layer = 3;
        p[6].flags = 0x15;
        p[6].tex = base + 0x1b0;
        p[6].mode = 0x4000;
        p[6].x = va;
        p[6].y = vb;
        p[6].z = c74;
        p[7].layer = 3;
        p[7].flags = 0x15;
        p[7].tex = base + 0x1b0;
        p[7].mode = 4;
        p[7].x = c74;
        p[7].y = c74;
        p[7].z = c74;
        p[8].layer = 3;
        p[8].flags = 0x15;
        p[8].tex = base + 0x1b0;
        p[8].mode = 2;
        p[8].x = c94;
        p[8].y = c94;
        p[8].z = c94;
        buf.v58 = 0;
        buf.ctx = sourceObj;
        buf.v44 = (s16)variant;
        buf.pos[0] = c74;
        buf.pos[1] = c74;
        buf.pos[2] = c74;
        buf.col[0] = c74;
        buf.col[1] = c74;
        buf.col[2] = c74;
        buf.scale = ca4;
        buf.v40 = 2;
        buf.v3c = 7;
        buf.v59 = 0xe;
        buf.v5a = 0;
        buf.v5b = 0x28;
        buf.count = (FbCmd*)((u8*)p + 0xd8) - e;
        buf.hw[0] = *(s16*)(base + 0x1f8);
        buf.hw[1] = *(s16*)(base + 0x1fa);
        buf.hw[2] = *(s16*)(base + 0x1fc);
        buf.hw[3] = *(s16*)(base + 0x1fe);
        buf.hw[4] = *(s16*)(base + 0x200);
        buf.hw[5] = *(s16*)(base + 0x202);
        buf.hw[6] = *(s16*)(base + 0x204);
        buf.cmds = e;
        buf.flags = 0xc0104c0;
        buf.flags |= flags;
        if ((buf.flags & 1) != 0)
        {
            if ((uint)sourceObj != 0)
            {
                buf.pos[0] = c74 + *(f32*)(sourceObj + 0x18);
                buf.pos[1] = c74 + *(f32*)(sourceObj + 0x1c);
                buf.pos[2] = c74 + *(f32*)(sourceObj + 0x20);
            }
            else
            {
                buf.pos[0] = c74 + *(f32*)(posSource + 0xc);
                buf.pos[1] = c74 + *(f32*)(posSource + 0x10);
                buf.pos[2] = c74 + *(f32*)(posSource + 0x14);
            }
        }
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, base, 0x18, base + 0xd4, 0xd9, 0);
    }
}

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
void dll_8C_func03(int sourceObj, int variant, int posSource, uint flags);

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






























void dll_8B_func01_nop(void)
{
}

void dll_8B_func00_nop(void)
{
}

void dll_8C_func01_nop(void);









