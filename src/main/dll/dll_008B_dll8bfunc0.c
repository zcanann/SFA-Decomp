/*
 * dll8bfunc0 (DLL 0x8B) - one member of the foodbag/FbBuf cmd-list effect
 * family (siblings dll_007C..dll_0090). dll_8B_func03 builds a stack
 * FbBuf describing a multi-layer billboard effect and hands it to the
 * modgfx interface to spawn.
 *
 * Two passes (i=0/1) emit the command entries; `variant` (0..4) picks one
 * of the layer-0 corner offsets, and entry 1 reads the source object's
 * s16 size words at sourceObj+0 / sourceObj+2. With FbBuf flag bit 0 set,
 * the spawn position is taken from the source object (+0x18..0x20) or,
 * when absent, from posSource (+0xc..0x14).
 *
 * func00_nop / func01_nop are this DLL's empty exported entry slots.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h" /* family cross-sibling header (7C..90 convention); also supplies undefined4 + this DLL's own func03 decl */

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_80316728[];

void dll_8B_func03(int sourceObj, int variant, int posSource, u32 flags, u32 arg5,
                   f32* arg6)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316728;
    void* mbuf = base;
    f32 zero;
    f32 zoff;
    f32 v60 = 2.0f;
    f32 v64 = -1.7f;
    f32 s = 1.0f;
    FbCmd* e;
    FbCmd* p;
    int i;
    if (arg6 != NULL)
    {
        s = *arg6;
    }
    i = 0;
    zoff = 0.01f + s;
    e = buf.entries;
    zero = 0.0f;
    for (; i < 2; i++)
    {
        if (i == 1)
        {
            v60 = 2.0f;
            v64 = -4.2f;
        }
        e[0].layer = 0;
        e[0].flags = 0x15;
        e[0].tex = base + 0x1b0;
        e[0].mode = 4;
        e[0].x = zero;
        e[0].y = zero;
        e[0].z = zero;
        e[1].layer = 0;
        e[1].flags = 0x15;
        e[1].tex = base + 0x1b0;
        e[1].mode = 0x80;
        e[1].x = zero;
        e[1].y = (f32) * (s16*)(sourceObj + 2);
        e[1].z = 16383.0f + ((f32) * (s16*)(sourceObj + 0) - 16128.0f);
        p = &e[2];
        if (i == 0)
        {
            p->layer = 0;
            p->flags = 0x15;
            p->tex = base + 0x1b0;
            p->mode = 2;
            if (variant == 4)
            {
                p->x = 0.0375f;
                p->y = 0.0375f;
                p->z = zoff;
            }
            else
            {
                p->x = 0.0125f;
                p->y = 0.0125f;
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
                p->x = 0.03f;
                p->y = 0.03f;
                p->z = zoff;
            }
            else
            {
                p->x = 0.01f;
                p->y = 0.01f;
                p->z = zoff;
            }
            p++;
        }
        p[0].layer = 0;
        p[0].flags = 0;
        p[0].tex = NULL;
        p[0].mode = 0x400000;
        switch (variant)
        {
        case 0:
            p[0].x = 0.0f;
            p[0].y = 30.0f;
            p[0].z = 0.0f;
            break;
        case 1:
            p[0].x = 0.0f;
            p[0].y = -30.0f;
            p[0].z = 0.0f;
            break;
        case 2:
            p[0].x = 30.0f;
            p[0].y = 0.0f;
            p[0].z = 0.0f;
            break;
        case 3:
            p[0].x = -30.0f;
            p[0].y = 0.0f;
            p[0].z = 0.0f;
            break;
        case 4:
            p[0].x = 0.0f;
            p[0].y = 0.1f;
            p[0].z = 0.0f;
            break;
        }
        p[1].layer = 1;
        p[1].flags = 0x15;
        p[1].tex = base + 0x1b0;
        p[1].mode = 4;
        p[1].x = 255.0f;
        p[1].y = zero;
        p[1].z = zero;
        p[2].layer = 1;
        p[2].flags = 0x15;
        p[2].tex = base + 0x1b0;
        p[2].mode = 2;
        p[2].x = 6.0f;
        p[2].y = 6.0f;
        p[2].z = 300.0f;
        p[3].layer = 1;
        p[3].flags = 0x15;
        p[3].tex = base + 0x1b0;
        p[3].mode = 0x4000;
        p[3].x = v60;
        p[3].y = v64;
        p[3].z = zero;
        p[4].layer = 2;
        p[4].flags = 0x15;
        p[4].tex = base + 0x1b0;
        p[4].mode = 4;
        p[4].x = 255.0f;
        p[4].y = zero;
        p[4].z = zero;
        p[5].layer = 2;
        p[5].flags = 0x15;
        p[5].tex = base + 0x1b0;
        p[5].mode = 0x4000;
        p[5].x = v60;
        p[5].y = v64;
        p[5].z = zero;
        p[6].layer = 3;
        p[6].flags = 0x15;
        p[6].tex = base + 0x1b0;
        p[6].mode = 0x4000;
        p[6].x = v60;
        p[6].y = v64;
        p[6].z = zero;
        p[7].layer = 3;
        p[7].flags = 0x15;
        p[7].tex = base + 0x1b0;
        p[7].mode = 4;
        p[7].x = zero;
        p[7].y = zero;
        p[7].z = zero;
        p[8].layer = 3;
        p[8].flags = 0x15;
        p[8].tex = base + 0x1b0;
        p[8].mode = 2;
        p[8].x = 0.1f;
        p[8].y = 0.1f;
        p[8].z = 0.1f;
        buf.v58 = 0;
        buf.ctx = sourceObj;
        buf.v44 = variant;
        buf.pos[0] = zero;
        buf.pos[1] = zero;
        buf.pos[2] = zero;
        buf.col[0] = zero;
        buf.col[1] = zero;
        buf.col[2] = zero;
        buf.scale = 6.4f;
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
            if ((u32)sourceObj != 0)
            {
                buf.pos[0] = zero + *(f32*)(sourceObj + 0x18);
                buf.pos[1] = zero + *(f32*)(sourceObj + 0x1c);
                buf.pos[2] = zero + *(f32*)(sourceObj + 0x20);
            }
            else
            {
                buf.pos[0] = zero + ((PartFxSpawnParams*)posSource)->posX;
                buf.pos[1] = zero + ((PartFxSpawnParams*)posSource)->posY;
                buf.pos[2] = zero + ((PartFxSpawnParams*)posSource)->posZ;
            }
        }
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, mbuf, 0x18, base + 0xd4, 0xd9, 0);
    }
}

void dll_8B_func01_nop(void)
{
}

void dll_8B_func00_nop(void)
{
}
