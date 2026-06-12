#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"



extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80314E08[];
extern f32 lbl_803E0D88;
extern f32 lbl_803E0D8C;
extern f32 lbl_803E0D90;
extern f32 lbl_803E0D94;
extern f32 lbl_803E0D98;
extern f32 lbl_803E0D9C;
extern f32 lbl_803E0DA0;
extern f32 lbl_803E0DA4;
extern f32 lbl_803E0DA8;
extern f32 lbl_803E0DAC;
extern f32 lbl_803E0DB0;
extern f32 lbl_803E0DB4;
extern f32 lbl_803E0DB8;
extern f32 lbl_803E0DBC;
extern f32 lbl_803E0DC0;
extern f32 lbl_803E0DC4;
extern f32 lbl_803E0DC8;
extern f32 lbl_803E0DCC;
extern f32 lbl_803E0DD0;



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
void dll_7C_func03(int sourceObj, int variant, int posSource, uint flags)
{
    FbBuf buf;
    u8* base = lbl_80314E08;
    FbCmd* e = buf.entries;
    FbCmd* p = &e[1];

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = base + 0x1b0;
    e[0].mode = 4;
    e[0].x = lbl_803E0D88;
    e[0].y = lbl_803E0D88;
    e[0].z = lbl_803E0D88;
    if (variant == 0 || variant == 3)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0D8C;
        p->y = lbl_803E0D90;
        p->z = lbl_803E0D8C;
        p++;
    }
    else if (variant == 1 || variant == 2)
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0D94;
        p->y = lbl_803E0D90;
        p->z = lbl_803E0D94;
        p++;
    }
    else
    {
        p->layer = 0;
        p->flags = 0x15;
        p->tex = base + 0x1b0;
        p->mode = 2;
        p->x = lbl_803E0D94;
        p->y = lbl_803E0D90;
        p->z = lbl_803E0D94;
        p++;
    }
    p[0].layer = 0;
    p[0].flags = 0;
    p[0].tex = (void*)0;
    p[0].mode = 0x400000;
    p[0].x = lbl_803E0D88;
    p[0].y = lbl_803E0D98;
    p[0].z = lbl_803E0D88;
    p[1].layer = 1;
    p[1].flags = 0x15;
    p[1].tex = base + 0x1b0;
    p[1].mode = 2;
    p[1].x = lbl_803E0D9C;
    p[1].y = lbl_803E0DA0;
    p[1].z = lbl_803E0D9C;
    p[2].layer = 1;
    p[2].flags = 7;
    p[2].tex = base + 0x164;
    p[2].mode = 4;
    p[2].x = lbl_803E0DA4;
    p[2].y = lbl_803E0D88;
    p[2].z = lbl_803E0D88;
    p[3].layer = 1;
    p[3].flags = 7;
    p[3].tex = base + 0x174;
    p[3].mode = 4;
    p[3].x = lbl_803E0DA8;
    p[3].y = lbl_803E0D88;
    p[3].z = lbl_803E0D88;
    p[4].layer = 1;
    p[4].flags = 0x15;
    p[4].tex = base + 0x1b0;
    p[4].mode = 0x4000;
    p[4].x = lbl_803E0DAC;
    p[4].y = lbl_803E0DB0;
    p[4].z = lbl_803E0D88;
    p[5].layer = 1;
    p[5].flags = 0;
    p[5].tex = (void*)0;
    p[5].mode = 0x400000;
    p[5].x = lbl_803E0D88;
    p[5].y = lbl_803E0DB4;
    p[5].z = lbl_803E0D88;
    p[6].layer = 2;
    p[6].flags = 0x1e;
    p[6].tex = (void*)0;
    p[6].mode = 0x20000;
    p[6].x = lbl_803E0D9C;
    p[6].y = lbl_803E0D88;
    p[6].z = lbl_803E0D88;
    p[7].layer = 2;
    p[7].flags = 0x15;
    p[7].tex = base + 0x1b0;
    p[7].mode = 0x4000;
    p[7].x = lbl_803E0DAC;
    p[7].y = lbl_803E0DB0;
    p[7].z = lbl_803E0D88;
    p[8].layer = 2;
    p[8].flags = 0;
    p[8].tex = (void*)0;
    p[8].mode = 0x400000;
    p[8].x = lbl_803E0D88;
    p[8].y = lbl_803E0DB8;
    p[8].z = lbl_803E0D88;
    p[9].layer = 3;
    p[9].flags = 0x15;
    p[9].tex = base + 0x1b0;
    p[9].mode = 0x4000;
    p[9].x = lbl_803E0DAC;
    p[9].y = lbl_803E0DB0;
    p[9].z = lbl_803E0D88;
    p[10].layer = 3;
    p[10].flags = 7;
    p[10].tex = base + 0x164;
    p[10].mode = 4;
    p[10].x = lbl_803E0D88;
    p[10].y = lbl_803E0D88;
    p[10].z = lbl_803E0D88;
    p[11].layer = 3;
    p[11].flags = 7;
    p[11].tex = base + 0x174;
    p[11].mode = 4;
    p[11].x = lbl_803E0D88;
    p[11].y = lbl_803E0D88;
    p[11].z = lbl_803E0D88;
    p[12].layer = 3;
    p[12].flags = 0x1e;
    p[12].tex = (void*)0;
    p[12].mode = 0x20000;
    p[12].x = lbl_803E0D9C;
    p[12].y = lbl_803E0D88;
    p[12].z = lbl_803E0D88;
    p[13].layer = 3;
    p[13].flags = 0;
    p[13].tex = (void*)0;
    p[13].mode = 0x400000;
    p[13].x = lbl_803E0D88;
    p[13].y = lbl_803E0DB4;
    p[13].z = lbl_803E0D88;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = (s16)variant;
    buf.pos[0] = lbl_803E0D88;
    buf.pos[1] = lbl_803E0D88;
    buf.pos[2] = lbl_803E0D88;
    switch (variant)
    {
    case 0:
        buf.pos[0] = lbl_803E0D88;
        buf.pos[2] = lbl_803E0DBC;
        break;
    case 1:
        buf.pos[0] = lbl_803E0DC0;
        buf.pos[2] = lbl_803E0DC4;
        break;
    case 2:
        buf.pos[0] = lbl_803E0DC8;
        buf.pos[2] = lbl_803E0DC4;
        break;
    case 3:
        buf.pos[0] = lbl_803E0D88;
        buf.pos[2] = lbl_803E0DCC;
        break;
    case 4:
        buf.pos[0] = lbl_803E0DC0;
        buf.pos[2] = lbl_803E0DD0;
        break;
    case 5:
        buf.pos[0] = lbl_803E0DC8;
        buf.pos[2] = lbl_803E0DD0;
        break;
    }
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = lbl_803E0D9C;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0xa;
    buf.count = (FbCmd*)((u8*)p + 0x150) - e;
    buf.hw[0] = *(s16*)(base + 0x1f8);
    buf.hw[1] = *(s16*)(base + 0x1fa);
    buf.hw[2] = *(s16*)(base + 0x1fc);
    buf.hw[3] = *(s16*)(base + 0x1fe);
    buf.hw[4] = *(s16*)(base + 0x200);
    buf.hw[5] = *(s16*)(base + 0x202);
    buf.hw[6] = *(s16*)(base + 0x204);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc010080;
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, base, 0x18, base + 0xd4, 0x2e, 0);
}

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
int dll_7D_func03(int sourceObj, int variant, int posSource, uint flags, undefined4 arg5, f32* arg6);

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
void dll_7C_func01_nop(void)
{
}

void dll_7C_func00_nop(void)
{
}

void dll_7D_func01_nop(void);







































