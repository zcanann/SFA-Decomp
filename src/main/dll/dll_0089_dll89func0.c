#include "main/effect_interfaces.h"
#include "main/dll/foodbag.h"



extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316460[];
extern u8 lbl_803DB908;
extern f32 lbl_803E1028;
extern f32 lbl_803E102C;
extern f32 lbl_803E1030;
extern f32 lbl_803E1034;
extern f32 lbl_803E1038;
extern f32 lbl_803E103C;
extern f32 lbl_803E1040;
extern f32 lbl_803E1044;
extern f32 lbl_803E1048;

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    u16 flags;
    u8 layer;
} FbCmd;


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
void dll_89_func03(int sourceObj, int variant, int posSource, uint flags)
{
    typedef struct
    {
        FbCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 v44;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        FbCmd entries[32];
    } FbBuf89;
    FbBuf89 buf;
    u8* base = (u8*)(int)lbl_80316460;
    FbCmd* e = buf.entries;

    e[0].layer = 0;
    e[0].flags = 10;
    e[0].tex = base + 0x1ac;
    e[0].mode = 2;
    e[0].x = lbl_803E1028;
    e[0].y = lbl_803E102C;
    e[0].z = lbl_803E1028;
    e[1].layer = 0;
    e[1].flags = 10;
    e[1].tex = base + 0x1ac;
    e[1].mode = 4;
    e[1].x = lbl_803E1030;
    e[1].y = lbl_803E1030;
    e[1].z = lbl_803E1030;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = (void*)0;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E1034;
    e[2].y = lbl_803E1038;
    e[2].z = lbl_803E103C;
    e[3].layer = 1;
    e[3].flags = 10;
    e[3].tex = base + 0x1ac;
    e[3].mode = 0x4000;
    e[3].x = lbl_803E1040;
    e[3].y = lbl_803E1040;
    e[3].z = lbl_803E1030;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = base + 0x198;
    e[4].mode = 2;
    e[4].x = lbl_803E1044;
    e[4].y = lbl_803E102C;
    e[4].z = lbl_803E1044;
    e[5].layer = 2;
    e[5].flags = 1;
    e[5].tex = &lbl_803DB908;
    e[5].mode = 4;
    e[5].x = lbl_803E1048;
    e[5].y = lbl_803E1030;
    e[5].z = lbl_803E1030;
    e[6].layer = 2;
    e[6].flags = 10;
    e[6].tex = base + 0x1ac;
    e[6].mode = 0x4000;
    e[6].x = lbl_803E1040;
    e[6].y = lbl_803E1040;
    e[6].z = lbl_803E1030;
    e[7].layer = 3;
    e[7].flags = 10;
    e[7].tex = base + 0x1ac;
    e[7].mode = 0x4000;
    e[7].x = lbl_803E1040;
    e[7].y = lbl_803E1040;
    e[7].z = lbl_803E1030;
    e[8].layer = 4;
    e[8].flags = 10;
    e[8].tex = base + 0x1ac;
    e[8].mode = 0x4000;
    e[8].x = lbl_803E1040;
    e[8].y = lbl_803E1040;
    e[8].z = lbl_803E1030;
    e[9].layer = 4;
    e[9].flags = 10;
    e[9].tex = base + 0x1ac;
    e[9].mode = 4;
    e[9].x = lbl_803E1030;
    e[9].y = lbl_803E1030;
    e[9].z = lbl_803E1030;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E1030;
    buf.pos[1] = lbl_803E1030;
    buf.pos[2] = lbl_803E1030;
    buf.col[0] = lbl_803E1030;
    buf.col[1] = lbl_803E1030;
    buf.col[2] = lbl_803E1030;
    buf.scale = lbl_803E1030;
    buf.v40 = 1;
    buf.v3c = 10;
    buf.v59 = 10;
    buf.v5a = 0;
    buf.v5b = 16;
    buf.flags = 0x4000494;
    buf.count = (FbCmd*)((u8*)e + 240) - e;
    buf.hw[0] = *(s16*)(base + 0x1c0);
    buf.hw[1] = *(s16*)(base + 0x1c2);
    buf.hw[2] = *(s16*)(base + 0x1c4);
    buf.hw[3] = *(s16*)(base + 0x1c6);
    buf.hw[4] = *(s16*)(base + 0x1c8);
    buf.hw[5] = *(s16*)(base + 0x1ca);
    buf.hw[6] = *(s16*)(base + 0x1cc);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E1030 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E1030 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E1030 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E1030 + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E1030 + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E1030 + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 10, (u8*)(int)lbl_80316460, 8, base + 0x168, 0x1fd, 0);
}

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
void dll_8A_func03(int sourceObj, int variant, int posSource, uint flags);

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


























void dll_89_func01_nop(void)
{
}

void dll_89_func00_nop(void)
{
}

void dll_8A_func01_nop(void);













