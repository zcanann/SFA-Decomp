/*
 * dlla6func0 (DLL 0xA6) - a modgfx effect spawner (sibling of DLL 0xA8).
 *
 * dll_A6_func03 builds a stack command buffer of GfxCmd primitives on the
 * stack, with a small variant-0/variant-1 prefix command, then a fixed set
 * of mode/layer commands (several randomised per spawn via randomGetRange),
 * plus a per-effect header (colour, position, scale, hardware-state words
 * copied from the asset table at gDllA6EffectHwWords) and hands it to
 * gModgfxInterface->spawnEffect. When flag bit 0 is set the effect is
 * positioned from the source object's world position and/or the spawn-param
 * packet's position (posSource + 0xc..0x14). func00/func01 are the DLL's
 * unused entry-point stubs.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern u8 lbl_80318DF0[];
extern u8 gDllA6EffectHwWords[];
extern u8 lbl_803DB980;
extern u8 gDllA6EffectTex;
extern f32 lbl_803E1530;
extern f32 lbl_803E1534;
extern f32 lbl_803E1538;
extern f32 lbl_803E153C;
extern f32 lbl_803E1540;
extern f32 lbl_803E1544;
extern f32 lbl_803E1548;
extern f32 lbl_803E154C;
extern f32 lbl_803E1550;
extern f32 lbl_803E1554;
extern f32 lbl_803E1558;
extern f32 lbl_803E155C;
extern f32 lbl_803E1560;
extern f32 lbl_803E1564;

#pragma opt_propagation off
void dll_A6_func03(short* sourceObj, int variant, u8* posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
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
        GfxCmd entries[32];
    } buf;
    GfxCmd* p;
    GfxCmd* e = buf.entries;
    f32 zr;
    f32 yr;
    u32 fl;
    p = e;

    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &gDllA6EffectTex;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p->y = (f32)(int)(randomGetRange(0, 0x14) + 0x87);
        p->z = (f32)(int)(randomGetRange(0, 0x14) + 0x41);
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &gDllA6EffectTex;
        p->mode = 8;
        p->y = p->x = (f32)(int)(randomGetRange(0, 0x5a) + 0x87);
        p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p++;
    }
    zr = (f32)(int)randomGetRange(0, 0xfffe);
    yr = (f32)(int)randomGetRange(-3000, -12000);
    p[0].layer = 0;
    p[0].flags = 0;
    p[0].tex = NULL;
    p[0].mode = 0x80;
    p[0].x = lbl_803E1530;
    p[0].y = yr;
    p[0].z = zr;
    p[1].layer = 0;
    p[1].flags = 3;
    p[1].tex = &gDllA6EffectTex;
    p[1].mode = 4;
    p[1].x = lbl_803E1530;
    p[1].y = lbl_803E1530;
    p[1].z = lbl_803E1530;
    p[2].layer = 0;
    p[2].flags = 3;
    p[2].tex = &gDllA6EffectTex;
    p[2].mode = 2;
    p[2].x = lbl_803E1534;
    p[2].y = lbl_803E153C * (f32)(int)randomGetRange(0, 0x19) + lbl_803E1538;
    p[2].z = lbl_803E153C * (f32)(int)randomGetRange(0, 10) + lbl_803E1540;
    p[3].layer = 1;
    p[3].flags = 3;
    p[3].tex = &gDllA6EffectTex;
    p[3].mode = 4;
    if (randomGetRange(0, 10) == 0)
    {
        p[3].x = lbl_803E1544 + (f32)(int)randomGetRange(0, 0x1e);
    }
    else
    {
        p[3].x = lbl_803E1548 + (f32)(int)randomGetRange(0, 10);
    }
    p[3].y = lbl_803E1530;
    p[3].z = lbl_803E1530;
    p[4].layer = 1;
    p[4].flags = 0;
    p[4].tex = NULL;
    p[4].mode = 0x80;
    p[4].x = lbl_803E1530;
    p[4].y = lbl_803E1530;
    p[4].z = (f32)(int)randomGetRange(0, 0xfffe);
    p[5].layer = 1;
    p[5].flags = 3;
    p[5].tex = &gDllA6EffectTex;
    p[5].mode = 2;
    p[5].x = lbl_803E154C;
    p[5].y = lbl_803E1550;
    p[5].z = lbl_803E1554;
    p[6].layer = 2;
    p[6].flags = 0;
    p[6].tex = NULL;
    p[6].mode = 0x80;
    p[6].x = lbl_803E1530;
    p[6].y = lbl_803E1530;
    p[6].z = (f32)(int)randomGetRange(0, 0xfffe);
    p[7].layer = 2;
    p[7].flags = 3;
    p[7].tex = &gDllA6EffectTex;
    p[7].mode = 4;
    p[7].x = lbl_803E1530;
    p[7].y = lbl_803E1530;
    p[7].z = lbl_803E1530;
    p[8].layer = 2;
    p[8].flags = 3;
    p[8].tex = &gDllA6EffectTex;
    p[8].mode = 2;
    p[8].x = lbl_803E1558;
    p[8].y = lbl_803E155C;
    p[8].z = lbl_803E1560;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1530;
    buf.pos[1] = lbl_803E1530;
    buf.pos[2] = lbl_803E1530;
    buf.col[0] = lbl_803E1530;
    buf.col[1] = lbl_803E1530;
    buf.col[2] = lbl_803E1530;
    buf.scale = lbl_803E1564;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 3;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = &p[9] - e;
    buf.hw[0] = *(s16*)&gDllA6EffectHwWords[0];
    buf.hw[1] = *(s16*)&gDllA6EffectHwWords[2];
    buf.hw[2] = *(s16*)&gDllA6EffectHwWords[4];
    buf.hw[3] = *(s16*)&gDllA6EffectHwWords[6];
    buf.hw[4] = *(s16*)&gDllA6EffectHwWords[8];
    buf.hw[5] = *(s16*)&gDllA6EffectHwWords[10];
    buf.hw[6] = *(s16*)&gDllA6EffectHwWords[12];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    fl = 0x4000400;
    buf.flags = fl;
    fl |= flags;
    buf.flags = fl;
    if (fl & 1)
    {
        if (sourceObj != 0 && posSource != 0)
        {
            buf.pos[0] = lbl_803E1530 + (((GameObject*)sourceObj)->anim.worldPosX + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] = lbl_803E1530 + (((GameObject*)sourceObj)->anim.worldPosY + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] = lbl_803E1530 + (((GameObject*)sourceObj)->anim.worldPosZ + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if (sourceObj != 0)
        {
            buf.pos[0] = buf.pos[0] + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = buf.pos[1] + *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = buf.pos[2] + *(f32*)(buf.ctx + 0x20);
        }
        else if (posSource != 0)
        {
            buf.pos[0] = buf.pos[0] + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = buf.pos[1] + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = buf.pos[2] + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 3, lbl_80318DF0, 1, &lbl_803DB980, 0x26a, 0);
}
#pragma opt_propagation reset

void dll_A6_func01_nop(void)
{
}

void dll_A6_func00_nop(void)
{
}

u8 gDllA6EffectHwWords[] = {0x00, 0x00, 0x00, 0x46, 0x00, 0x46, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
