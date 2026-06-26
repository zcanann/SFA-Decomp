/*
 * dlla7func0 (DLL 0xA7) - a modgfx effect spawner (sibling of DLL 0xA6/0xA8).
 *
 * dll_A7_func03 builds a fixed command buffer of GfxCmd primitives on the
 * stack: a pair of texture/scale commands keyed off the source object's
 * first two fields, a fade command, a variant-gated layer-2 command (skipped
 * when variant == 1), and a tail of fixed layer/mode commands. Three of the
 * commands carry an extraArgs-supplied colour triple (defaults 1/0x30/0x31
 * with flags 0x50). The header copies the hardware-state words from the asset
 * table at lbl_80318E40 (+0x78..0x84) and hands the buffer to
 * gModgfxInterface->spawnEffect. When flag bit 0 is set the effect is
 * positioned from the source object's world position, else from the spawn
 * packet (posSource + 0xc..0x14). func00/func01 are the DLL's unused
 * entry-point stubs.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    s16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern u8 lbl_80318E40[];
extern f32 lbl_803E1570;
extern f32 lbl_803E1574;
extern f32 lbl_803E1578;
extern f32 lbl_803E157C;
extern f32 lbl_803E1580;
extern f32 lbl_803E1584;
extern f32 lbl_803E1588;

void dll_A7_func03(short* sourceObj, int variant, u8* posSource, u32 flags,
                   u32 arg5, /* unused -- passed in r8 by caller */
                   u32* extraArgs)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c; /* 0x3c */
        u32 v40; /* 0x40 */
        s16 variantB; /* 0x44 */
        s16 hw[7];
        u32 flags;
        u8 variantA; /* 0x58 */
        u8 v59; /* 0x59 */
        u8 v5a; /* 0x5a */
        u8 v5b; /* 0x5b */
        u8 v5c; /* 0x5c: reserved (preserves count at 0x5d) */
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* tab = (u8*)(int)lbl_80318E40;
    GfxCmd* e;
    GfxCmd* p;
    u32 argY, argX, argZ;
    int argFlags;
    u32 fl;

    argY = 0x30;
    argZ = 0x31;
    argX = 1;
    argFlags = 0x50;
    e = buf.entries;
    if (extraArgs != 0)
    {
        argX = extraArgs[0];
        argY = extraArgs[1];
        argZ = extraArgs[2];
        argFlags = extraArgs[3];
    }
    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = &tab[0x68];
    e[0].mode = 4;
    e[0].x = lbl_803E1570;
    e[0].y = lbl_803E1570;
    e[0].z = lbl_803E1570;
    e[1].layer = 0;
    e[1].flags = 8;
    e[1].tex = &tab[0x68];
    e[1].mode = 2;
    if (sourceObj != 0)
    {
        e[1].x = lbl_803E1574 * *(f32*)(sourceObj + 4);
        e[1].y = lbl_803E1578 * *(f32*)(sourceObj + 4);
        e[1].z = lbl_803E1574 * *(f32*)(sourceObj + 4);
    }
    else
    {
        e[1].x = lbl_803E1574;
        e[1].y = lbl_803E1578;
        e[1].z = lbl_803E1574;
    }
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x80;
    e[2].x = lbl_803E1570;
    e[2].y = lbl_803E1570;
    if (sourceObj != 0)
    {
        e[2].z = (f32) * sourceObj;
    }
    else
    {
        e[2].z = lbl_803E1570;
    }
    e[3].layer = 1;
    e[3].flags = 8;
    e[3].tex = &tab[0x68];
    e[3].mode = 4;
    e[3].x = lbl_803E157C;
    e[3].y = lbl_803E1570;
    e[3].z = lbl_803E1570;
    e[4].layer = 1;
    e[4].flags = argFlags;
    e[4].tex = NULL;
    e[4].mode = 0x20000000;
    e[4].x = (f32)(int)argX;
    e[4].y = (f32)(int)argY;
    e[4].z = (f32)(int)argZ;
    p = e + 5;
    if (variant != 1)
    {
        p->layer = 2;
        p->flags = 0x3b;
        p->tex = NULL;
        p->mode = 0x1800000;
        p->x = lbl_803E1580;
        p->y = lbl_803E1570;
        p->z = lbl_803E1584;
        p++;
    }
    p[0].layer = 2;
    p[0].flags = 0;
    p[0].tex = NULL;
    p[0].mode = 0x100;
    p[0].x = lbl_803E1570;
    p[0].y = lbl_803E1570;
    p[0].z = lbl_803E1588;
    p[1].layer = 3;
    p[1].flags = 1;
    p[1].tex = NULL;
    p[1].mode = 0x2000;
    p[1].x = lbl_803E1570;
    p[1].y = lbl_803E1570;
    p[1].z = lbl_803E1570;
    p[2].layer = 4;
    p[2].flags = 8;
    p[2].tex = &tab[0x68];
    p[2].mode = 4;
    p[2].x = lbl_803E1570;
    p[2].y = lbl_803E1570;
    p[2].z = lbl_803E1570;
    p[3].layer = 4;
    p[3].flags = 0;
    p[3].tex = NULL;
    p[3].mode = 0x20000000;
    p[3].x = (f32)(int)argX;
    p[3].y = (f32)(int)argY;
    p[3].z = (f32)(int)argZ;

    buf.variantA = variant;
    buf.ctx = (int)sourceObj;
    buf.variantB = variant;
    buf.pos[0] = lbl_803E1570;
    if (posSource != 0)
    {
        buf.pos[1] = *(f32*)(posSource + 0x10);
    }
    else
    {
        buf.pos[1] = lbl_803E1570;
    }
    buf.pos[2] = *(f32*)&lbl_803E1570;
    buf.col[0] = *(f32*)&lbl_803E1570;
    buf.col[1] = *(f32*)&lbl_803E1570;
    buf.col[2] = *(f32*)&lbl_803E1570;
    buf.scale = lbl_803E1580;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 8;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = &p[4] - e;
    buf.hw[0] = *(s16*)&tab[0x78];
    buf.hw[1] = *(s16*)&tab[0x7a];
    buf.hw[2] = *(s16*)&tab[0x7c];
    buf.hw[3] = *(s16*)&tab[0x7e];
    buf.hw[4] = *(s16*)&tab[0x80];
    buf.hw[5] = *(s16*)&tab[0x82];
    buf.hw[6] = *(s16*)&tab[0x84];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4040000;
    buf.flags |= (flags | 0x80);
    fl = buf.flags;
    if (fl & 1)
    {
        GameObject* obj = (GameObject*)buf.ctx;
        if (obj != 0)
        {
            buf.pos[0] = buf.pos[0] + obj->anim.worldPosX;
            buf.pos[1] = buf.pos[1] + obj->anim.worldPosY;
            buf.pos[2] = lbl_803E1570 + obj->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = buf.pos[0] + *(f32*)(posSource + 0xc);
            buf.pos[1] = buf.pos[1] + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E1570 + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, (u8*)(int)lbl_80318E40, 4, &tab[0x50], 0x5e0, 0);
}

void dll_A7_func01_nop(void)
{
}

void dll_A7_func00_nop(void)
{
}
