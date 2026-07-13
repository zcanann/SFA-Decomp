/*
 * dll7afunc0 (DLL 0x7A) - a model-fx command-list spawner stub DLL.
 *
 * dll_7A_func03 builds a GfxCmd array on the stack from the shared
 * lbl_80314BD0 resource block and hands it to
 * gModgfxInterface->spawnEffect; the two tiny dll_7A entry stubs are
 * no-ops.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/gameplay_runtime.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_007A_dll7afunc0.h"

/* spawnEffect effect ids per variant (textureAssetId arg). */
#define DLL7A_EFFECT_ID_VARIANT0 0x156
#define DLL7A_EFFECT_ID_VARIANT1 0xc0d

extern u8 lbl_80314BD0[];
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E0D08 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E0D0C = 0.4f;
__declspec(section ".sdata2") f32 lbl_803E0D10 = 0.8f;
__declspec(section ".sdata2") f32 lbl_803E0D14 = -16383.0f;
__declspec(section ".sdata2") f32 lbl_803E0D18 = 2.0f;
__declspec(section ".sdata2") f32 lbl_803E0D1C = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E0D20 = 999.0f;
__declspec(section ".sdata2") f32 lbl_803E0D24 = 94.0f;
__declspec(section ".sdata2") f32 lbl_803E0D28 = 95.0f;
__declspec(section ".sdata2") f32 lbl_803E0D2C = 135.0f;

int dll_7A_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        u8* ctx;
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
    u8* base = (u8*)(int)lbl_80314BD0;
    GfxCmd* entries;
    GfxCmd* e;
    int ret;
    ret = 0;
    entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = 8;
    entries[0].tex = &base[0xa0];
    entries[0].mode = 4;
    entries[0].x = lbl_803E0D08;
    entries[0].y = lbl_803E0D08;
    entries[0].z = lbl_803E0D08;
    entries[1].layer = 0;
    entries[1].flags = 8;
    entries[1].tex = &base[0x8c];
    entries[1].mode = 2;
    entries[1].x = lbl_803E0D0C * (f32)(int)randomGetRange(10, 15);
    entries[1].y = lbl_803E0D0C * (f32)(int)randomGetRange(10, 15);
    entries[1].z = lbl_803E0D10 * (f32)(int)randomGetRange(10, 15);
    entries[2].layer = 0;
    entries[2].flags = 9;
    entries[2].tex = &base[0x8c];
    entries[2].mode = 0x80;
    entries[2].x = lbl_803E0D08;
    entries[2].y = lbl_803E0D08;
    entries[2].z = lbl_803E0D14;
    entries[3].layer = 1;
    entries[3].flags = 0x9c;
    entries[3].tex = 0;
    entries[3].mode = 0x800000;
    entries[3].x = lbl_803E0D18;
    entries[3].y = lbl_803E0D1C;
    entries[3].z = lbl_803E0D08;
    entries[4].layer = 1;
    entries[4].flags = 0;
    entries[4].tex = 0;
    entries[4].mode = 0x400000;
    entries[4].x = (f32)(int)randomGetRange(-2000, 200);
    entries[4].y = (f32)(int)randomGetRange(-200, 200);
    entries[4].z = (f32)(int)randomGetRange(-200, 200);
    entries[5].layer = 1;
    entries[5].flags = 9;
    entries[5].tex = &base[0x8c];
    entries[5].mode = 4;
    entries[5].x = lbl_803E0D08;
    entries[5].y = lbl_803E0D08;
    entries[5].z = lbl_803E0D08;
    e = &entries[6];
    if (variant == 0)
    {
        e->layer = 3;
        e->flags = 0;
        e->tex = 0;
        e->mode = 0x20000000;
        e->x = lbl_803E0D20;
        e->y = lbl_803E0D24;
        e->z = lbl_803E0D28;
        e++;
    }
    buf.ctx = sourceObj;
    buf.v44 = variant;
    if (variant == 0)
    {
        buf.pos[0] = lbl_803E0D08;
        buf.pos[1] = lbl_803E0D08;
        buf.pos[2] = lbl_803E0D08;
    }
    else
    {
        buf.pos[0] = lbl_803E0D08;
        buf.pos[1] = lbl_803E0D2C;
        buf.pos[2] = lbl_803E0D08;
    }
    buf.col[0] = lbl_803E0D08;
    buf.col[1] = lbl_803E0D08;
    buf.col[2] = lbl_803E0D08;
    buf.scale = lbl_803E0D1C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = e - entries;
    buf.hw[0] = *(s16*)&base[0xb0];
    buf.hw[1] = *(s16*)&base[0xb2];
    buf.hw[2] = *(s16*)&base[0xb4];
    buf.hw[3] = *(s16*)&base[0xb6];
    buf.hw[4] = *(s16*)&base[0xb8];
    buf.hw[5] = *(s16*)&base[0xba];
    buf.hw[6] = *(s16*)&base[0xbc];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
        {
            buf.pos[0] += ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0)
    {
        buf.v58 = 0;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_80314BD0, 8, &base[0x5c], DLL7A_EFFECT_ID_VARIANT0, 0);
    }
    else if (variant == 1)
    {
        buf.v58 = 0;
        ret = (*gModgfxInterface)
                  ->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_80314BD0, 8, &base[0x5c], DLL7A_EFFECT_ID_VARIANT1, 0);
    }
    return ret;
}

void dll_7A_func01_nop(void)
{
}

void dll_7A_func00_nop(void)
{
}
