/*
 * dll6dfunc0 (DLL 0x6D) - spirit/aura particle-effect spawner.
 *
 * dll_6D_func03 builds a 6-entry modgfx command list (the spirit/aura
 * particle effect) and submits it via gModgfxInterface->spawnEffect.
 * func00/func01 are the DLL's empty lifecycle hooks. (The Ghidra dump of
 * this TU also carried a large block of mainDol drift duplicates -
 * save-file/cheat/settings helpers from the gameplay.h family, real copies
 * in sibling units - dropped here to match the retail object, which holds
 * only these three functions.)
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_006D_dll6dfunc0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL6D_EFFECT_ID 0x34

u32 lbl_80313AF0[72] = {0x00000000, 0x03e80000, 0x00000362, 0x000001f4, 0x000b0000, 0x03620000, 0xfe0c0016, 0x00000000,
                        0x0000fc18, 0x00200000, 0xfc9e0000, 0xfe0c002a, 0x0000fc9e, 0x000001f4, 0x00350000, 0x00000000,
                        0x03e80040, 0x00000000, 0x177003e8, 0x0000001f, 0x03621770, 0x01f4000b, 0x001f0362, 0x1770fe0c,
                        0x0016001f, 0x00001770, 0xfc180020, 0x001ffc9e, 0x1770fe0c, 0x002a001f, 0xfc9e1770, 0x01f40035,
                        0x001f0000, 0x177003e8, 0x0040001f, 0x00000001, 0x00080000, 0x00080007, 0x00010002, 0x00090001,
                        0x00090008, 0x00020003, 0x000a0002, 0x000a0009, 0x00030004, 0x000b0003, 0x000b000a, 0x00040005,
                        0x000c0004, 0x000c000b, 0x00050006, 0x000d0005, 0x000d000c, 0x00000001, 0x00020003, 0x00040005,
                        0x00060007, 0x00080009, 0x000a000b, 0x000c000d, 0x00000001, 0x00020003, 0x00040005, 0x00060000,
                        0x00070008, 0x0009000a, 0x000b000c, 0x000d0000, 0x00000028, 0x00000000, 0x00000000, 0x00000000};
u32 lbl_80313C10[8] = {
    0x00000000, 0x00000000,        0x00000000, 0x00030000, (u32)dll_6D_func00_nop, (u32)dll_6D_func01_nop,
    0x00000000, (u32)dll_6D_func03};

void dll_6D_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80313AF0;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0xe;
    buf.entries[0].tex = &base[212];
    buf.entries[0].mode = 0x80;
    buf.entries[0].x = 0.0f;
    buf.entries[0].y = -16000.0f;
    buf.entries[0].z = 0.0f;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 7;
    buf.entries[1].tex = &base[256];
    buf.entries[1].mode = 4;
    buf.entries[1].x = 0.0f;
    buf.entries[1].y = 0.0f;
    buf.entries[1].z = 0.0f;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[240];
    buf.entries[2].mode = 2;
    buf.entries[2].x = 0.3f;
    buf.entries[2].y = 0.7f;
    buf.entries[2].z = 0.3f;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[256];
    buf.entries[3].mode = 2;
    buf.entries[3].x = 6.5f;
    buf.entries[3].y = 0.7f;
    buf.entries[3].z = 6.5f;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 0xe;
    buf.entries[4].tex = &base[212];
    buf.entries[4].mode = 0x4000;
    buf.entries[4].x = 0.0f;
    buf.entries[4].y = -3.0f;
    buf.entries[4].z = 0.0f;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[240];
    buf.entries[5].mode = 4;
    buf.entries[5].x = 0.0f;
    buf.entries[5].y = 0.0f;
    buf.entries[5].z = 0.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 6;
    buf.hw[0] = *(s16*)&base[272];
    buf.hw[1] = *(s16*)&base[274];
    buf.hw[2] = *(s16*)&base[276];
    buf.hw[3] = *(s16*)&base[278];
    buf.hw[4] = *(s16*)&base[280];
    buf.hw[5] = *(s16*)&base[282];
    buf.hw[6] = *(s16*)&base[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000004;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80313AF0, 0xc, &base[140], DLL6D_EFFECT_ID, 0);
}

void dll_6D_func01_nop(void)
{
}

void dll_6D_func00_nop(void)
{
}
