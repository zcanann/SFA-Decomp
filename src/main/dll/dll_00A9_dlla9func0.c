/*
 * dlla9func0 (DLL 0xA9) - a modgfx pickup/effect spawner.
 *
 * dll_A9_func03 builds a stack command buffer of GfxCmd primitives (two
 * variant layouts selected by extraArgs) plus a per-effect header (colour,
 * position, scale, hardware-state words copied from the asset table at
 * lbl_80319028) and hands it to gModgfxInterface->spawnEffect. When flag bit
 * 0 is set the effect is positioned at the source object's world position
 * (sourceObj + 0x18..0x20) or, lacking a source object, at the spawn-param
 * packet's position (posSource + 0xc..0x14). func00/func01 are the DLL's
 * unused entry-point stubs.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/pickup.h"
#include "main/dll/dll_00A9_dlla9func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLLA9_EFFECT_ID 0x586

extern u8 lbl_80319028[];
__declspec(section ".sdata2") f32 lbl_803E15D0 = -2.0f;
__declspec(section ".sdata2") f32 lbl_803E15D4 = 2.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E15D8 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E15DC = 0.8f;
__declspec(section ".sdata2") f32 lbl_803E15E0 = 0.006f;
__declspec(section ".sdata2") f32 lbl_803E15E4 = 1.5f;
__declspec(section ".sdata2") f32 lbl_803E15E8 = 0.028f;
__declspec(section ".sdata2") f32 lbl_803E15EC = 1.2f;
__declspec(section ".sdata2") f32 lbl_803E15F0 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E15F4 = 130.0f;
__declspec(section ".sdata2") f32 lbl_803E15F8 = 255.0f;
__declspec(section ".sdata2") f32 lbl_803E15FC = 0.01f;

void dll_A9_func03(u8* sourceObj, int variant, u8* posSource, u32 flags, u32 modelId, u8* extraArgs)
{
    ModgfxSpawnPacket buf;
    u8* tab = (u8*)(int)lbl_80319028;
    f32 scaleX;
    GfxCmd* e;
    GfxCmd* p;
    u32 effectFlags;

    if (extraArgs != 0)
    {
        scaleX = lbl_803E15D0;
    }
    else
    {
        scaleX = lbl_803E15D4;
    }
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0xe;
    e[0].tex = &tab[0xf4];
    e[0].mode = 4;
    e[0].x = lbl_803E15D8;
    e[0].y = lbl_803E15D8;
    e[0].z = lbl_803E15D8;
    if (extraArgs != 0)
    {
        e[1].layer = 0;
        e[1].flags = 7;
        e[1].tex = &tab[0xd4];
        e[1].mode = 2;
        e[1].x = lbl_803E15DC;
        e[1].y = lbl_803E15E0;
        e[1].z = lbl_803E15DC;
        e[2].layer = 0;
        e[2].flags = 7;
        e[2].tex = &tab[0xe4];
        e[2].mode = 2;
        e[2].x = lbl_803E15E4;
        e[2].y = lbl_803E15E0;
        e[2].z = lbl_803E15E4;
        p = e + 3;
    }
    else
    {
        e[1].layer = 0;
        e[1].flags = 7;
        e[1].tex = &tab[0xd4];
        e[1].mode = 2;
        e[1].x = lbl_803E15DC;
        e[1].y = lbl_803E15E8;
        e[1].z = lbl_803E15DC;
        e[2].layer = 0;
        e[2].flags = 7;
        e[2].tex = &tab[0xe4];
        e[2].mode = 2;
        e[2].x = lbl_803E15EC;
        e[2].y = lbl_803E15E8;
        e[2].z = lbl_803E15EC;
        p = e + 3;
    }
    p[0].layer = 1;
    p[0].flags = 0xe;
    p[0].tex = &tab[0xf4];
    p[0].mode = 2;
    p[0].x = lbl_803E15F0;
    p[0].y = lbl_803E15F4;
    p[0].z = lbl_803E15F0;
    p[1].layer = 1;
    p[1].flags = 0xe;
    p[1].tex = &tab[0xf4];
    p[1].mode = 4;
    p[1].x = lbl_803E15F8;
    p[1].y = lbl_803E15D8;
    p[1].z = lbl_803E15D8;
    p[2].layer = 1;
    p[2].flags = 0xe;
    p[2].tex = &tab[0xf4];
    p[2].mode = 0x4000;
    p[2].x = scaleX;
    p[2].y = lbl_803E15D8;
    p[2].z = lbl_803E15D8;
    p[3].layer = 2;
    p[3].flags = 0xe;
    p[3].tex = &tab[0xf4];
    p[3].mode = 0x4000;
    p[3].x = scaleX;
    p[3].y = lbl_803E15D8;
    p[3].z = lbl_803E15D8;
    p[4].layer = 3;
    p[4].flags = 1;
    p[4].tex = NULL;
    p[4].mode = 0x2000;
    p[4].x = lbl_803E15D8;
    p[4].y = lbl_803E15D8;
    p[4].z = lbl_803E15D8;
    p[5].layer = 4;
    p[5].flags = 0xe;
    p[5].tex = &tab[0xf4];
    p[5].mode = 4;
    p[5].x = lbl_803E15D8;
    p[5].y = lbl_803E15D8;
    p[5].z = lbl_803E15D8;
    p[6].layer = 4;
    p[6].flags = 0xe;
    p[6].tex = &tab[0xf4];
    p[6].mode = 0x4000;
    p[6].x = scaleX;
    p[6].y = lbl_803E15D8;
    p[6].z = lbl_803E15D8;
    p[7].layer = 4;
    p[7].flags = 0xe;
    p[7].tex = &tab[0xf4];
    p[7].mode = 2;
    p[7].x = lbl_803E15F0;
    p[7].y = lbl_803E15FC;
    p[7].z = lbl_803E15F0;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E15D8;
    buf.pos[1] = lbl_803E15D8;
    buf.pos[2] = lbl_803E15D8;
    buf.col[0] = lbl_803E15D8;
    buf.col[1] = lbl_803E15D8;
    buf.col[2] = lbl_803E15D8;
    buf.scale = lbl_803E15F0;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = &p[8] - e;
    buf.hw[0] = *(s16*)&tab[0x110];
    buf.hw[1] = *(s16*)&tab[0x112];
    buf.hw[2] = *(s16*)&tab[0x114];
    buf.hw[3] = *(s16*)&tab[0x116];
    buf.hw[4] = *(s16*)&tab[0x118];
    buf.hw[5] = *(s16*)&tab[0x11a];
    buf.hw[6] = *(s16*)&tab[0x11c];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    effectFlags = 0xc010040;
    buf.flags = effectFlags;
    effectFlags |= flags;
    buf.flags = effectFlags;
    if (effectFlags & 1)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E15D8 + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E15D8 + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E15D8 + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E15D8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E15D8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E15D8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80319028, 0xc, &tab[0x8c], DLLA9_EFFECT_ID, 0);
}

void dll_A9_func01_nop(void)
{
}

void dll_A9_func00_nop(void)
{
}
