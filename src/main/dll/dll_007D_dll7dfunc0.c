#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"



extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315030[];
extern int lbl_803DD4B0;
extern f32 lbl_803E0DD8;
extern f32 lbl_803E0DDC;
extern f32 lbl_803E0DE0;
extern f32 lbl_803E0DE4;
extern f32 lbl_803E0DE8;
extern f32 lbl_803E0DEC;
extern f32 lbl_803E0DF0;
extern f32 lbl_803E0DF4;
extern f32 lbl_803E0DF8;





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
int dll_7D_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5,
                  f32* arg6)
{
    int ret;
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315030;
    f32 s = lbl_803E0DD8;
    FbCmd* e;
    if (arg6 != (f32*)0)
    {
        s = *arg6;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E0DDC;
    e[0].y = lbl_803E0DDC;
    e[0].z = lbl_803E0DDC;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = base + 0x1b0;
    e[1].mode = 2;
    e[1].y = e[1].x = lbl_803E0DE0 * s;
    e[1].z = lbl_803E0DE4 * s;
    e[2].layer = 1;
    e[2].flags = 7;
    e[2].tex = base + 0x184;
    e[2].mode = 2;
    e[2].x = lbl_803E0DE8;
    e[2].y = lbl_803E0DE8;
    e[2].z = lbl_803E0DD8;
    e[3].layer = 2;
    e[3].flags = 7;
    e[3].tex = base + 0x164;
    e[3].mode = 4;
    e[3].x = lbl_803E0DEC;
    e[3].y = lbl_803E0DDC;
    e[3].z = lbl_803E0DDC;
    e[4].layer = 2;
    e[4].flags = 7;
    e[4].tex = base + 0x174;
    e[4].mode = 4;
    e[4].x = lbl_803E0DEC;
    e[4].y = lbl_803E0DDC;
    e[4].z = lbl_803E0DDC;
    e[5].layer = 2;
    e[5].flags = 7;
    e[5].tex = base + 0x174;
    e[5].mode = 2;
    e[5].x = lbl_803E0DF0;
    e[5].y = lbl_803E0DF0;
    e[5].z = lbl_803E0DD8;
    e[6].layer = 2;
    e[6].flags = 0x15;
    e[6].tex = base + 0x1b0;
    e[6].mode = 0x4000;
    e[6].x = lbl_803E0DF4;
    e[6].y = lbl_803E0DF8;
    e[6].z = lbl_803E0DDC;
    e[7].layer = 3;
    e[7].flags = 0x15;
    e[7].tex = base + 0x1b0;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0DF4;
    e[7].y = lbl_803E0DF8;
    e[7].z = lbl_803E0DDC;
    e[8].layer = 3;
    e[8].flags = 7;
    e[8].tex = base + 0x164;
    e[8].mode = 4;
    e[8].x = lbl_803E0DDC;
    e[8].y = lbl_803E0DDC;
    e[8].z = lbl_803E0DDC;
    e[9].layer = 3;
    e[9].flags = 7;
    e[9].tex = base + 0x174;
    e[9].mode = 4;
    e[9].x = lbl_803E0DDC;
    e[9].y = lbl_803E0DDC;
    e[9].z = lbl_803E0DDC;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E0DDC;
    buf.pos[1] = lbl_803E0DDC;
    buf.pos[2] = lbl_803E0DDC;
    buf.col[0] = lbl_803E0DDC;
    buf.col[1] = lbl_803E0DDC;
    buf.col[2] = lbl_803E0DDC;
    buf.scale = lbl_803E0DD8;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)e + 0xf0) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = e;
    buf.flags = 0xc010080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0DDC + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0DDC + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0DDC + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0DDC + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E0DDC + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E0DDC + *(f32*)(posSource + 0x14);
        }
    }
    ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315030, 0x18, base + 0xd4, 0x89, 0);
    lbl_803DD4B0 += 1;
    if (lbl_803DD4B0 == 5)
    {
        lbl_803DD4B0 = 0;
    }
    return ret;
}

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
void dll_7E_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* arg6 );

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


void dll_7D_func01_nop(void)
{
}

void dll_7D_func00_nop(void)
{
}

void dll_7E_func01_nop(void);





































