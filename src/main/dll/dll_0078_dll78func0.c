/*
 * dll78func0 (DLL 0x78) - modgfx particle/aura effect builder.
 *
 * One real entry point of note: dll_78_func03 assembles a fixed
 * 12-command modgfx draw list (the spirit/aura particle effect) into a
 * stack command buffer and submits it via gModgfxInterface->spawnEffect.
 * It has two variants selected by posSource: when non-NULL the strength
 * (PartFxSpawnParams.unk4) and world position are taken from the caller's
 * spawn packet; otherwise fixed defaults are used. The flags argument is
 * OR'd into the buffer's command flags; bit 0 offsets the effect position
 * by the source object's transform (or the packet position).
 *
 * dll_78_func01_nop / dll_78_func00_nop are the empty DLL stub entries.
 *
 * The draw-command geometry is fixed; lbl_803149B0 is the shared particle
 * texture set used by each command.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0078_dll78func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL78_EFFECT_ID 0x34

extern u8 lbl_803149B0[];

void dll_78_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxPointerSpawnPacket buf;
    u8* tex = lbl_803149B0;
    GfxCmd* e = buf.entries;
    f32 originOffset = 0.0f;
    e[0].layer = 0;
    e[0].flags = 0xc8;
    e[0].tex = NULL;
    e[0].mode = 0x800000;
    e[0].x = 1.0f;
    e[0].y = originOffset;
    e[0].z = originOffset;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = &tex[212];
    e[1].mode = 0x80;
    e[1].x = originOffset;
    e[1].y = originOffset;
    if (posSource != 0)
    {
        e[1].z = (f32) * (s16*)posSource;
    }
    else
    {
        e[1].z = originOffset;
    }
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &tex[256];
    e[2].mode = 4;
    e[2].x = originOffset;
    e[2].y = originOffset;
    e[2].z = originOffset;
    e[3].layer = 0;
    e[3].flags = 7;
    e[3].tex = &tex[240];
    e[3].mode = 2;
    e[3].x = 0.3f;
    e[3].y = 0.7f;
    e[3].z = 0.3f;
    e[4].layer = 0;
    e[4].flags = 7;
    e[4].tex = &tex[256];
    e[4].mode = 2;
    if (posSource != 0)
    {
        e[4].x = 1.0f;
        e[4].y = 0.5f;
        e[4].z = 1.0f;
    }
    else
    {
        e[4].x = 1.0f;
        e[4].y = 0.5f;
        e[4].z = 1.0f;
    }
    e[5].layer = 1;
    e[5].flags = 7;
    e[5].tex = &tex[256];
    e[5].mode = 2;
    if (posSource != 0)
    {
        e[5].x = 0.01f * (3.5f * (f32)((PartFxSpawnParams*)posSource)->unk4);
        e[5].y = 0.01f * (2.0f * (f32)((PartFxSpawnParams*)posSource)->unk4);
        e[5].z = 0.01f * (3.5f * (f32)((PartFxSpawnParams*)posSource)->unk4);
    }
    else
    {
        e[5].x = 3.5f;
        e[5].y = 2.0f;
        e[5].z = 3.5f;
    }
    e[6].layer = 1;
    e[6].flags = 0x7a;
    e[6].tex = NULL;
    e[6].mode = 0x10000;
    e[6].x = originOffset;
    e[6].y = originOffset;
    e[6].z = originOffset;
    e[7].layer = 1;
    e[7].flags = 0xe;
    e[7].tex = &tex[212];
    e[7].mode = 0x4000;
    e[7].x = originOffset;
    e[7].y = -1.5f;
    e[7].z = originOffset;
    e[8].layer = 1;
    e[8].flags = 7;
    e[8].tex = &tex[240];
    e[8].mode = 4;
    e[8].x = 255.0f;
    e[8].y = originOffset;
    e[8].z = originOffset;
    e[9].layer = 2;
    e[9].flags = 0xe;
    e[9].tex = &tex[212];
    e[9].mode = 2;
    e[9].x = 3.0f;
    e[9].y = 0.1f;
    e[9].z = 3.0f;
    e[10].layer = 2;
    e[10].flags = 0xe;
    e[10].tex = &tex[212];
    e[10].mode = 0x4000;
    e[10].x = originOffset;
    e[10].y = -3.0f;
    e[10].z = originOffset;
    e[11].layer = 2;
    e[11].flags = 7;
    e[11].tex = &tex[240];
    e[11].mode = 4;
    e[11].x = originOffset;
    e[11].y = originOffset;
    e[11].z = originOffset;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    if (posSource != 0)
    {
        buf.pos[0] = ((PartFxSpawnParams*)posSource)->posX;
        buf.pos[1] = ((PartFxSpawnParams*)posSource)->posY;
        buf.pos[2] = ((PartFxSpawnParams*)posSource)->posZ;
    }
    else
    {
        buf.pos[0] = originOffset;
        buf.pos[1] = originOffset;
        buf.pos[2] = originOffset;
    }
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = (e + 11) - buf.entries;
    buf.hw[0] = *(s16*)&tex[272];
    buf.hw[1] = *(s16*)&tex[274];
    buf.hw[2] = *(s16*)&tex[276];
    buf.hw[3] = *(s16*)&tex[278];
    buf.hw[4] = *(s16*)&tex[280];
    buf.hw[5] = *(s16*)&tex[282];
    buf.hw[6] = *(s16*)&tex[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000400;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)buf.ctx)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)buf.ctx)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)buf.ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, &tex[0], 0xc, &tex[140], DLL78_EFFECT_ID, 0);
}

void dll_78_func01_nop(void)
{
}

void dll_78_func00_nop(void)
{
}
