#include "main/effect_interfaces.h"
#include "main/dll/foodbag.h"



extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80315548[];
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;
extern f32 lbl_803E0E90;
extern f32 lbl_803E0E94;
extern f32 lbl_803E0E98;
extern f32 lbl_803E0E9C;
extern f32 lbl_803E0EA0;
extern f32 lbl_803E0EA4;
extern f32 lbl_803E0EA8;

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
void dll_81_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80315548;
    f32 sy = lbl_803E0E78;
    FbCmd* p;
    FbCmd* e;
    if (variant == 0 || variant == 2 || variant == 0x1e)
    {
        *(s16*)(base + 0x1fa) = 0xc;
    }
    else if (variant == 1 || variant == 3)
    {
        sy *= lbl_803E0E7C;
        *(s16*)(base + 0x1fa) = 4;
        *(s16*)(base + 0x200) = 0x32;
    }
    e = buf.entries;
    p = &e[1];
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E0E80;
    e[0].y = lbl_803E0E80;
    e[0].z = lbl_803E0E80;
    if (variant == 0 || variant == 2)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E84;
        p->y = lbl_803E0E84;
        p->z = lbl_803E0E88;
        p++;
    }
    else if (variant == 0xe)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E8C;
        p->y = lbl_803E0E8C;
        p->z = lbl_803E0E90;
        p++;
    }
    else if (variant == 0x1e)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E94;
        p->y = lbl_803E0E94;
        p->z = lbl_803E0E88;
        p++;
    }
    else
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0E84;
        p->y = lbl_803E0E84;
        p->z = lbl_803E0E98;
        p++;
    }
    p[0].layer = 0;
    p[0].flags = 0x77;
    p[0].tex = (void*)0;
    p[0].mode = 0x10000;
    p[0].x = lbl_803E0E80;
    p[0].y = lbl_803E0E80;
    p[0].z = lbl_803E0E80;
    p[1].layer = 0;
    p[1].flags = 0x79;
    p[1].tex = (void*)0;
    p[1].mode = 0x10000;
    p[1].x = lbl_803E0E80;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    p[2].layer = 1;
    p[2].flags = 0x15;
    p[2].tex = base + 0x1b0;
    p[2].mode = 4;
    p[2].x = lbl_803E0E9C;
    p[2].y = lbl_803E0E80;
    p[2].z = lbl_803E0E80;
    p += 3;
    if (variant == 0 || variant == 2)
    {
        p->layer = 1;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0EA0;
        p->y = lbl_803E0EA0;
        p->z = lbl_803E0EA4;
        p++;
    }
    else if (variant == 0x1e)
    {
        p->layer = 1;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0EA0;
        p->y = lbl_803E0EA0;
        p->z = lbl_803E0EA8;
        p++;
    }
    p[0].layer = 1;
    p[0].flags = 0x15;
    p[0].tex = base + 0x1b0;
    p[0].mode = 0x4000;
    p[0].x = lbl_803E0EA0;
    p[0].y = sy;
    p[0].z = lbl_803E0E80;
    p[1].layer = 2;
    p[1].flags = 0x15;
    p[1].tex = base + 0x1b0;
    p[1].mode = 4;
    p[1].x = lbl_803E0E9C;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    p[2].layer = 2;
    p[2].flags = 0x15;
    p[2].tex = base + 0x1b0;
    p[2].mode = 0x4000;
    p[2].x = lbl_803E0EA0;
    p[2].y = sy;
    p[2].z = lbl_803E0E80;
    p[3].layer = 3;
    p[3].flags = 0x15;
    p[3].tex = base + 0x1b0;
    p[3].mode = 0x4000;
    p[3].x = lbl_803E0EA0;
    p[3].y = sy;
    p[3].z = lbl_803E0E80;
    p[4].layer = 4;
    p[4].flags = 0x15;
    p[4].tex = base + 0x1b0;
    p[4].mode = 0x4000;
    p[4].x = lbl_803E0EA0;
    p[4].y = sy;
    p[4].z = lbl_803E0E80;
    p += 5;
    if (variant == 0 || variant == 0x1e)
    {
        p->layer = 4;
        p->flags = 2;
        p->tex = (void*)0;
        p->mode = 0x2000;
        p->x = lbl_803E0E80;
        p->y = lbl_803E0E80;
        p->z = lbl_803E0E80;
        p++;
    }
    p[0].layer = 5;
    p[0].flags = 0x15;
    p[0].tex = base + 0x1b0;
    p[0].mode = 0x4000;
    p[0].x = lbl_803E0EA0;
    p[0].y = sy;
    p[0].z = lbl_803E0E80;
    p[1].layer = 5;
    p[1].flags = 0x15;
    p[1].tex = base + 0x1b0;
    p[1].mode = 4;
    p[1].x = lbl_803E0E80;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    p += 2;
    if (variant == 1 || variant == 3)
    {
        p->layer = 5;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0EA0;
        p->y = lbl_803E0EA0;
        p->z = lbl_803E0E88;
        p++;
    }
    p[0].layer = 5;
    p[0].flags = 0x78;
    p[0].tex = (void*)0;
    p[0].mode = 0x10000;
    p[0].x = lbl_803E0E80;
    p[0].y = lbl_803E0E80;
    p[0].z = lbl_803E0E80;
    p[1].layer = 5;
    p[1].flags = 0xffff;
    p[1].tex = (void*)0;
    p[1].mode = 0x10000;
    p[1].x = lbl_803E0E80;
    p[1].y = lbl_803E0E80;
    p[1].z = lbl_803E0E80;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E0E80;
    buf.pos[1] = lbl_803E0E80;
    buf.pos[2] = lbl_803E0E80;
    buf.col[0] = lbl_803E0E80;
    buf.col[1] = lbl_803E0E80;
    buf.col[2] = lbl_803E0E80;
    buf.scale = lbl_803E0EA0;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)p + 0x30) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((uint)sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0E80 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E0E80 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E0E80 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0E80 + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E0E80 + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E0E80 + *(f32*)(posSource + 0x14);
        }
    }
    if (variant == 0x1e)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0x3e9, 0);
    }
    else if (variant == 2 || variant == 3)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0x23d, 0);
    }
    else if ((uint)(variant - 10) <= 3 || variant == 0xe)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0x2e, 0);
    }
    else
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80315548, 0x18, base + 0xd4, 0xd9, 0);
    }
}

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
void dll_82_func03(int sourceObj, int variant, int posSource, uint flags);

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










void dll_81_func01_nop(void)
{
}

void dll_81_func00_nop(void)
{
}

void dll_82_func01_nop(void);





























