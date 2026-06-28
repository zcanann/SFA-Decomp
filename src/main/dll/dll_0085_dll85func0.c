/*
 * dll_0085 (foodbag effect dll 0x85) - func03 builds a ModgfxInterface
 * effect command list (FbBuf) and spawns it. Two layouts are emitted:
 * variant 4 (a self-contained burst, base flags 0x4004400) and the
 * default variant (scaled off the source object's field 8 and a child
 * object at field 0x50, base flags 0x4006410). The caller's `flags` are
 * OR'd in; flag bit 0 adds the source/position-source world offsets to
 * buf.pos before the spawn. Several command slots seed x with a random
 * angle from randomGetRange. The two trailing _nop entry points are the
 * dll's unused func00/func01 slots. Externs (gModgfxInterface, the
 * lbl_803E0Fxx float-constant pool, the lbl_803DB8Fx texture handles and
 * the gFoodbagEffectTemplate effect-template table) live in the foodbag base TU.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;
extern u8 gFoodbagEffectTemplate[];
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

#define FX_VARIANT_BURST 4

void dll_85_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)gFoodbagEffectTemplate;
    s16* tableHw = (s16*)base;
    FbCmd* p;
    FbCmd* e = buf.entries;
    f32 rv;

    if (variant == FX_VARIANT_BURST)
    {
        e[0].layer = 0;
        e[0].flags = 0;
        e[0].tex = NULL;
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
        e[2].tex = NULL;
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
    if (variant == FX_VARIANT_BURST)
    {
        p[2].layer = 2;
        p[2].flags = 0;
        p[2].tex = NULL;
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
        p[2].tex = NULL;
        p[2].mode = 0x80;
        p[2].x = rv;
        p[2].y = lbl_803E0F94;
        p[2].z = lbl_803E0F74;
        p += 3;
    }
    rv = (f32)(int)
    randomGetRange(0, 0xfffe);
    if (variant == FX_VARIANT_BURST)
    {
        p->layer = 2;
        p->flags = 0;
        p->tex = NULL;
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
        p->tex = NULL;
        p->mode = 0x80;
        p->x = rv;
        p->y = lbl_803E0F94;
        p->z = lbl_803E0F74;
        p++;
    }
    if (variant == FX_VARIANT_BURST)
    {
        p->layer = 3;
        p->flags = 0;
        p->tex = NULL;
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
        p->tex = NULL;
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
    buf.v44 = variant;
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
    if (variant == FX_VARIANT_BURST)
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
        if ((u32)buf.ctx != 0 && (u32)posSource != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18) + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c) + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += *(f32*)(buf.ctx + 0x20) + ((PartFxSpawnParams*)posSource)->posZ;
        }
        else if ((u32)buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 4, (u8*)(int)gFoodbagEffectTemplate, 2, base + 0x28,
                                     tableHw[variant * 2 + randomGetRange(0, 1) + 0x22], 0);
}

void dll_85_func01_nop(void)
{
}

void dll_85_func00_nop(void)
{
}

void dll_86_func01_nop(void);
