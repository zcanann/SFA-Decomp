/*
 * dll87func0 (DLL 0x87) - one of the foodbag/modgfx particle-effect DLLs
 * (the dll_NN_func03 family in foodbag.h). dll_87_func03 builds a ten-layer
 * FbBuf command list, points the FbCmd textures at the shared resource at
 * lbl_80316050 (+0x1ac / +0x198 / lbl_803DB900), copies the seven shared hw
 * words, and submits it via gModgfxInterface->spawnEffect (texture asset
 * 0x1fd, resource base+0x168).
 *
 * flags bit 0 anchors the effect to a source object: when set, the spawn
 * position is offset by the source object's world position (sourceObj+0x18
 * when a context object is given, else posSource+0xc). func00/func01 are the
 * DLL's empty entry/exit stubs.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/fb_cmd.h"
#include "main/dll/foodbag.h"

#pragma explicit_zero_data on
u8 lbl_803DB900[8] = {0};
#pragma explicit_zero_data off

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL87_EFFECT_ID 0x1fd

extern u8 lbl_80316050[];

void dll_87_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    FbBuf buf;
    u8* base = (u8*)(int)lbl_80316050;
    FbCmd* e = buf.entries;
    f32 originOffset = 0.0f;

    e[0].layer = 0;
    e[0].flags = 10;
    e[0].tex = base + 0x1ac;
    e[0].mode = 2;
    e[0].x = 1.1f;
    e[0].y = 1.2f;
    e[0].z = 1.1f;
    e[1].layer = 0;
    e[1].flags = 10;
    e[1].tex = base + 0x1ac;
    e[1].mode = 4;
    e[1].x = originOffset;
    e[1].y = originOffset;
    e[1].z = originOffset;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = 8.0f;
    e[2].y = 72.0f;
    e[2].z = 5.0f;
    e[3].layer = 1;
    e[3].flags = 10;
    e[3].tex = base + 0x1ac;
    e[3].mode = 0x4000;
    e[3].x = 1.0f;
    e[3].y = 1.0f;
    e[3].z = originOffset;
    e[4].layer = 0;
    e[4].flags = 9;
    e[4].tex = base + 0x198;
    e[4].mode = 2;
    e[4].x = 32.1f;
    e[4].y = 1.2f;
    e[4].z = 32.1f;
    e[5].layer = 2;
    e[5].flags = 1;
    e[5].tex = lbl_803DB900;
    e[5].mode = 4;
    e[5].x = 255.0f;
    e[5].y = originOffset;
    e[5].z = originOffset;
    e[6].layer = 2;
    e[6].flags = 10;
    e[6].tex = base + 0x1ac;
    e[6].mode = 0x4000;
    e[6].x = 1.0f;
    e[6].y = 1.0f;
    e[6].z = originOffset;
    e[7].layer = 3;
    e[7].flags = 10;
    e[7].tex = base + 0x1ac;
    e[7].mode = 0x4000;
    e[7].x = 1.0f;
    e[7].y = 1.0f;
    e[7].z = originOffset;
    e[8].layer = 4;
    e[8].flags = 10;
    e[8].tex = base + 0x1ac;
    e[8].mode = 0x4000;
    e[8].x = 1.0f;
    e[8].y = 1.0f;
    e[8].z = originOffset;
    e[9].layer = 4;
    e[9].flags = 10;
    e[9].tex = base + 0x1ac;
    e[9].mode = 4;
    e[9].x = originOffset;
    e[9].y = originOffset;
    e[9].z = originOffset;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = originOffset;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 10;
    buf.v59 = 10;
    buf.v5a = 0;
    buf.v5b = 16;
    buf.flags = 0x4000494;
    buf.count = (FbCmd*)((u8*)e + 240) - e;
    buf.hw[0] = *(s16*)(base + 0x1c0);
    buf.hw[1] = *(s16*)(base + 0x1c2);
    buf.hw[2] = *(s16*)(base + 0x1c4);
    buf.hw[3] = *(s16*)(base + 0x1c6);
    buf.hw[4] = *(s16*)(base + 0x1c8);
    buf.hw[5] = *(s16*)(base + 0x1ca);
    buf.hw[6] = *(s16*)(base + 0x1cc);
    buf.cmds = e;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0)
        {
            buf.pos[0] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = originOffset + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 10, (u8*)(int)lbl_80316050, 8, base + 0x168, DLL87_EFFECT_ID, 0);
}

void dll_87_func01_nop(void)
{
}

void dll_87_func00_nop(void)
{
}
