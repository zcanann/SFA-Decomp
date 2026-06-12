#include "main/effect_interfaces.h"
#include "main/dll/foodbag.h"


extern u32 randomGetRange(int min, int max);

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316020[];
extern f32 lbl_803E0FB0;
extern f32 lbl_803E0FB4;
extern f32 lbl_803E0FB8;
extern f32 lbl_803E0FBC;
extern f32 lbl_803E0FC0;
extern f32 lbl_803E0FC4;
extern f32 lbl_803E0FC8;
extern f32 lbl_803E0FCC;
extern f32 lbl_803E0FD0;
extern f32 lbl_803E0FD4;
extern f32 lbl_803E0FD8;

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    u16 flags;
    u8 layer;
} FbCmd;

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
} FbBuf;

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
void dll_86_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    FbCmd* e;
    u8* base;
    f32 fx = lbl_803E0FB0;
    f32 fy = lbl_803E0FB4;
    int fl = 0x64;
    f32 rx;
    f32 rz;
    if (variant == 0)
    {
        fx = lbl_803E0FB8;
        fy = lbl_803E0FBC;
        fl = 0x410;
    }
    else if (variant == 1)
    {
        fx = lbl_803E0FC0;
        fy = lbl_803E0FC4;
        fl = 0x410;
    }
    else if (variant == 2)
    {
        fx = lbl_803E0FC8;
        fy = lbl_803E0FCC;
        fl = 0x410;
    }
    else if (variant == 3)
    {
        fx = lbl_803E0FC8;
        fy = lbl_803E0FCC;
        fl = 0x410;
    }
    e = buf.entries;
    e[0].layer = 0;
    *(s16*)&e[0].flags = (s16)fl;
    e[0].tex = (void*)0;
    e[0].mode = 0x20000000;
    e[0].x = lbl_803E0FD0;
    e[0].y = fx;
    e[0].z = fy;
    e[1].layer = 1;
    e[1].flags = 0;
    e[1].tex = (void*)0;
    e[1].mode = 0x400000;
    e[1].x = (f32)(int)
    randomGetRange(-0x64, 0x64);
    e[1].y = lbl_803E0FD4;
    e[1].z = (f32)(int)
    randomGetRange(-0x4b0, -0x320);
    rx = e[1].x;
    rz = *(f32*)((int)e + 0x20);
    e[2].layer = 1;
    e[2].flags = 0;
    e[2].tex = (void*)0;
    e[2].mode = 0x40000000;
    e[2].x = rx;
    e[2].y = lbl_803E0FD4;
    e[2].z = rz;
    e[3].layer = 1;
    e[3].flags = 0x65;
    e[3].tex = (void*)0;
    e[3].mode = 0x800000;
    e[3].x = lbl_803E0FD8;
    e[3].y = lbl_803E0FD8;
    e[3].z = lbl_803E0FD4;
    e[4].layer = 2;
    e[4].flags = 0;
    e[4].tex = (void*)0;
    e[4].mode = 0x20000000;
    e[4].x = lbl_803E0FD0;
    e[4].y = fx;
    e[4].z = fy;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    rx = (f32)(int)
    randomGetRange(-0x64, 0x64);
    buf.pos[0] = rx;
    buf.pos[1] = lbl_803E0FD4;
    buf.pos[2] = lbl_803E0FD4;
    buf.col[0] = lbl_803E0FD4;
    buf.col[1] = lbl_803E0FD4;
    buf.col[2] = lbl_803E0FD4;
    buf.scale = lbl_803E0FD8;
    buf.v40 = 0;
    buf.v3c = 0;
    buf.v59 = 0;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (FbCmd*)((u8*)e + 0x78) - e;
    base = lbl_80316020;
    buf.hw[0] = *(s16*)(base + 0);
    buf.hw[1] = *(s16*)(base + 2);
    buf.hw[2] = *(s16*)(base + 4);
    buf.hw[3] = *(s16*)(base + 6);
    buf.hw[4] = *(s16*)(base + 8);
    buf.hw[5] = *(s16*)(base + 0xa);
    buf.hw[6] = *(s16*)(base + 0xc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x10400;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)buf.ctx != 0)
        {
            buf.pos[0] = rx + *(f32*)(buf.ctx + 0x18);
            buf.pos[1] = lbl_803E0FD4 + *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = lbl_803E0FD4 + *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] = rx + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E0FD4 + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E0FD4 + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}

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
void dll_87_func03(int sourceObj, int variant, int posSource, uint flags);

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




















void dll_86_func01_nop(void)
{
}

void dll_86_func00_nop(void)
{
}

void dll_87_func01_nop(void);



















