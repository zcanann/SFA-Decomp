/*
 * dll8efunc0 (DLL 0x8E) - one of the foodbag modgfx effect spawners
 * (dll_NN_func03 family, see foodbag.h). func03 builds a multi-command
 * FbBuf and hands it to the modgfx interface to spawn a randomized
 * particle burst (a flame/spark fan: textured layer-0/1/2 commands plus
 * mode-0x80 emitter markers, the lone &gDll8EEffectTexture texture). variant 0
 * vs 1 selects two different random spawn-box ranges for the lead
 * command; flag bit 0 offsets the burst position from sourceObj
 * (offsets 0x18/0x1c/0x20) and/or posSource (offsets 0xc/0x10/0x14).
 * func00/func01 are unused stub slots; effect params come from the
 * resource tables gDll8EEffectHwParams (the halfword parameter block copied
 * into buf.hw[]) and gDll8EEffectVtxColorTable (the vertex/color table passed to
 * spawnEffect). gDll8EEffectSpawnResource is the lone extra resource handed to
 * spawnEffect alongside the &gDll8EEffectTexture texture.
 */
#include "main/effect_interfaces.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"
#include "main/gameplay_runtime.h"
extern ModgfxInterface** gModgfxInterface;
extern u8 gDll8EEffectHwParams[];
extern u8 gDll8EEffectVtxColorTable[];
extern u8 gDll8EEffectTexture;
extern u8 gDll8EEffectSpawnResource[8];
extern f32 lbl_803E1138;
extern f32 lbl_803E113C;
extern f32 lbl_803E1140;
extern f32 lbl_803E1144;
extern f32 lbl_803E1148;
extern f32 lbl_803E114C;
extern f32 lbl_803E1150;
extern f32 lbl_803E1154;
extern f32 lbl_803E1158;
extern f32 lbl_803E115C;
extern f32 lbl_803E1160;
extern f32 lbl_803E1164;
extern f32 lbl_803E1168;
extern f32 lbl_803E116C;

#pragma opt_propagation off
void dll_8E_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    FbCmd* p;
    FbCmd* e = buf.entries;
    u8* base;
    f32 rz;
    f32 ry;

    p = e;
    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &gDll8EEffectTexture;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &gDll8EEffectTexture;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
        p->z = (f32)(int)(randomGetRange(0, 0x41) + 0x78);
        p++;
    }
    rz = (f32)(int)
    randomGetRange(0, 0xfffe);
    ry = (f32)(int)
    randomGetRange(-0xbb8, -0x2ee0);
    p[0].layer = 0;
    p[0].flags = 0;
    p[0].tex = NULL;
    p[0].mode = 0x80;
    p[0].x = lbl_803E1138;
    p[0].y = ry;
    p[0].z = rz;
    p[1].layer = 0;
    p[1].flags = 3;
    p[1].tex = &gDll8EEffectTexture;
    p[1].mode = 4;
    p[1].x = lbl_803E1138;
    p[1].y = lbl_803E1138;
    p[1].z = lbl_803E1138;
    p[2].layer = 0;
    p[2].flags = 3;
    p[2].tex = &gDll8EEffectTexture;
    p[2].mode = 2;
    p[2].x = lbl_803E113C;
    p[2].y = lbl_803E1144 * (f32)(int)
    randomGetRange(0, 0x32) + lbl_803E1140;
    p[2].z = lbl_803E1144 * (f32)(int)
    randomGetRange(0, 0x14) + lbl_803E1148;
    p[3].layer = 1;
    p[3].flags = 3;
    p[3].tex = &gDll8EEffectTexture;
    p[3].mode = 4;
    if ((int)randomGetRange(0, 0xa) == 0)
    {
        p[3].x = lbl_803E114C + (f32)(int)
        randomGetRange(0, 0x1e);
    }
    else
    {
        p[3].x = lbl_803E1150 + (f32)(int)
        randomGetRange(0, 0xa);
    }
    p[3].y = lbl_803E1138;
    p[3].z = lbl_803E1138;
    p[4].layer = 2;
    p[4].flags = 0;
    p[4].tex = NULL;
    p[4].mode = 0x80;
    p[4].x = lbl_803E1138;
    p[4].y = lbl_803E1138;
    p[4].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[5].layer = 1;
    p[5].flags = 3;
    p[5].tex = &gDll8EEffectTexture;
    p[5].mode = 2;
    p[5].x = lbl_803E1154;
    p[5].y = lbl_803E1158;
    p[5].z = lbl_803E115C;
    p[6].layer = 2;
    p[6].flags = 0;
    p[6].tex = NULL;
    p[6].mode = 0x80;
    p[6].x = lbl_803E1138;
    p[6].y = lbl_803E1138;
    p[6].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[7].layer = 2;
    p[7].flags = 3;
    p[7].tex = &gDll8EEffectTexture;
    p[7].mode = 4;
    p[7].x = lbl_803E1138;
    p[7].y = lbl_803E1138;
    p[7].z = lbl_803E1138;
    p[8].layer = 2;
    p[8].flags = 3;
    p[8].tex = &gDll8EEffectTexture;
    p[8].mode = 2;
    p[8].x = lbl_803E1160;
    p[8].y = lbl_803E1164;
    p[8].z = lbl_803E1168;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = *(f32*)&lbl_803E1138;
    if (variant == 0)
    {
        buf.pos[1] = lbl_803E1138;
    }
    else if (variant == 1)
    {
        buf.pos[1] = lbl_803E116C;
    }
    buf.pos[2] = *(f32*)&lbl_803E1138;
    buf.col[0] = lbl_803E1138;
    buf.col[1] = lbl_803E1138;
    buf.col[2] = *(f32*)&lbl_803E1138;
    buf.scale = lbl_803E1164;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 3;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (FbCmd*)((u8*)p + 0xd8) - e;
    base = gDll8EEffectHwParams;
    buf.hw[0] = *(s16*)(base + 0);
    buf.hw[1] = *(s16*)(base + 2);
    buf.hw[2] = *(s16*)(base + 4);
    buf.hw[3] = *(s16*)(base + 6);
    buf.hw[4] = *(s16*)(base + 8);
    buf.hw[5] = *(s16*)(base + 0xa);
    buf.hw[6] = *(s16*)(base + 0xc);
    buf.cmds = (FbCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000410;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)buf.ctx != 0 && (u32)posSource != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18) + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c) + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1138 + (*(f32*)(buf.ctx + 0x20) + ((PartFxSpawnParams*)posSource)->posZ);
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 3, gDll8EEffectVtxColorTable, 1, &gDll8EEffectSpawnResource, 0x26a, 0);
}
#pragma opt_propagation reset

void dll_8E_func01_nop(void)
{
}

void dll_8E_func00_nop(void)
{
}

void dll_8F_func01_nop(void);
