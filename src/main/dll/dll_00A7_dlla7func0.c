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
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_00A7_dlla7func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLLA7_EFFECT_ID 0x5e0

extern u8 lbl_80318E40[];

void dll_A7_func03(short* sourceObj, int variant, u8* posSource, u32 flags,
                   u32 modelId, /* unused -- passed in r8 by caller */
                   u32* extraArgs)
{
    ModgfxSpawnPacket buf;
    u8* tab = (u8*)(int)lbl_80318E40;
    GfxCmd* p;
    GfxCmd* e;
    u32 argY, argZ, argX;
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
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 8;
    e[1].tex = &tab[0x68];
    e[1].mode = 2;
    if (sourceObj != 0)
    {
        e[1].x = 7.0f * *(f32*)(sourceObj + 4);
        e[1].y = 6.0f * *(f32*)(sourceObj + 4);
        e[1].z = 7.0f * *(f32*)(sourceObj + 4);
    }
    else
    {
        e[1].x = 7.0f;
        e[1].y = 6.0f;
        e[1].z = 7.0f;
    }
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x80;
    e[2].x = 0.0f;
    e[2].y = 0.0f;
    if (sourceObj != 0)
    {
        e[2].z = (f32)*sourceObj;
    }
    else
    {
        e[2].z = 0.0f;
    }
    e[3].layer = 1;
    e[3].flags = 8;
    e[3].tex = &tab[0x68];
    e[3].mode = 4;
    e[3].x = 255.0f;
    e[3].y = 0.0f;
    e[3].z = 0.0f;
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
        p->x = 1.0f;
        p->y = 0.0f;
        p->z = 10.0f;
        p++;
    }
    p[0].layer = 2;
    p[0].flags = 0;
    p[0].tex = NULL;
    p[0].mode = 0x100;
    p[0].x = 0.0f;
    p[0].y = 0.0f;
    p[0].z = 50.0f;
    p[1].layer = 3;
    p[1].flags = 1;
    p[1].tex = NULL;
    p[1].mode = 0x2000;
    p[1].x = 0.0f;
    p[1].y = 0.0f;
    p[1].z = 0.0f;
    p[2].layer = 4;
    p[2].flags = 8;
    p[2].tex = &tab[0x68];
    p[2].mode = 4;
    p[2].x = 0.0f;
    p[2].y = 0.0f;
    p[2].z = 0.0f;
    p[3].layer = 4;
    p[3].flags = 0;
    p[3].tex = NULL;
    p[3].mode = 0x20000000;
    p[3].x = (f32)(int)argX;
    p[3].y = (f32)(int)argY;
    p[3].z = (f32)(int)argZ;

    buf.v58 = variant;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    if (posSource != 0)
    {
        buf.pos[1] = ((PartFxSpawnParams*)posSource)->posY;
    }
    else
    {
        buf.pos[1] = 0.0f;
    }
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
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
            buf.pos[2] += obj->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = buf.pos[0] + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = buf.pos[1] + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, (u8*)(int)lbl_80318E40, 4, &tab[0x50], DLLA7_EFFECT_ID, 0);
}

void dll_A7_func01_nop(void)
{
}

void dll_A7_func00_nop(void)
{
}
