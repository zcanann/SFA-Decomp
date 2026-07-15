/*
 * dll63func0 (DLL 0x63) - save-icon / preview modgfx effect DLL.
 *
 * dll_63_func03 builds a per-object bone-particle command list (GfxCmd
 * entries) and submits it via gModgfxInterface->spawnEffect; variant
 * selects the texture/offset set and posSource supplies an optional
 * scale/position from a PartFxSpawnParams packet.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0063_dll63func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL63_EFFECT_ID 0x40

extern u8 lbl_80312BD8[];

#define DLL63_LARGE_INNER_SIZE 100.0f
#define DLL63_OUTER_SIZE 200.0f
#define DLL63_SMALL_INNER_SIZE 50.0f
#define DLL63_PRIMARY_XZ_SCALE 0.725f
#define DLL63_PRIMARY_Y_SCALE 1.2f
#define DLL63_SECONDARY_XZ_SCALE 0.35f
#define DLL63_LAYER_FIRST_X 70.0f
#define DLL63_LAYER_SECOND_X 12.0f
#define DLL63_LAYER_Z 20.0f
#define DLL63_LAYER_X -0.7f
#define DLL63_EFFECT_Y 4.0f
#define DLL63_FLAG_SCALE 0.1f

#pragma inline_max_size(4000)
static inline void dll_63_func03Body(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxPointerSpawnPacket buf;
    u32 flag;
    int i;
    s16* rec;
    GfxCmd* entries;
    GfxCmd* cmd;
    u8* base = (u8*)(int)lbl_80312BD8;
    if (variant == 1)
    {
        *(s16*)&base[0x112] = 0;
    }
    flag = *(u8*)(*(u8**)&((GameObject*)sourceObj)->anim.placementData + 0x1a);
    if (variant == 2)
    {
        for (i = 0, rec = (s16*)base; i < 14; i++)
        {
            if (rec[0] > 0)
            {
                rec[0] += randomGetRange(0, 800);
            }
            else if (rec[0] < 0)
            {
                rec[0] -= randomGetRange(0, 800);
            }
            if (rec[1] > 0)
            {
                rec[0] += randomGetRange(0, 300);
            }
            else if (rec[1] < 0)
            {
                rec[0] -= randomGetRange(0, 300);
            }
            if (rec[2] > 0)
            {
                rec[0] += randomGetRange(0, 800);
            }
            else if (rec[2] < 0)
            {
                rec[0] -= randomGetRange(0, 800);
            }
            rec += 5;
        }
    }
    entries = buf.entries;
    if (variant == 2)
    {
        entries[0].layer = 0;
        entries[0].flags = 7;
        entries[0].tex = &base[0xf0];
        entries[0].mode = 8;
        entries[0].x = DLL63_LARGE_INNER_SIZE;
        entries[0].y = DLL63_LARGE_INNER_SIZE;
        entries[0].z = DLL63_LARGE_INNER_SIZE;
        entries[1].layer = 0;
        entries[1].flags = 7;
        entries[1].tex = &base[0x100];
        entries[1].mode = 8;
        entries[1].x = DLL63_OUTER_SIZE;
        entries[1].y = DLL63_OUTER_SIZE;
        entries[1].z = DLL63_OUTER_SIZE;
        cmd = &entries[2];
    }
    else
    {
        entries[0].layer = 0;
        entries[0].flags = 7;
        entries[0].tex = &base[0xf0];
        entries[0].mode = 8;
        entries[0].x = DLL63_SMALL_INNER_SIZE;
        entries[0].y = DLL63_SMALL_INNER_SIZE;
        entries[0].z = DLL63_SMALL_INNER_SIZE;
        entries[1].layer = 0;
        entries[1].flags = 7;
        entries[1].tex = &base[0x100];
        entries[1].mode = 8;
        entries[1].x = DLL63_OUTER_SIZE;
        entries[1].y = DLL63_OUTER_SIZE;
        entries[1].z = DLL63_OUTER_SIZE;
        cmd = &entries[2];
    }
    cmd->layer = 0;
    cmd->flags = 0xe;
    cmd->tex = &base[0xd4];
    cmd->mode = 4;
    cmd->x = 0.0f;
    cmd->y = 0.0f;
    cmd->z = 0.0f;
    if (variant != 3 || posSource == 0)
    {
        cmd[1].layer = 0;
        cmd[1].flags = 7;
        cmd[1].tex = &base[0x100];
        cmd[1].mode = 2;
        cmd[1].x = DLL63_PRIMARY_XZ_SCALE;
        cmd[1].y = DLL63_PRIMARY_Y_SCALE;
        cmd[1].z = DLL63_PRIMARY_XZ_SCALE;
        cmd[2].layer = 0;
        cmd[2].flags = 7;
        cmd[2].tex = &base[0xf0];
        cmd[2].mode = 2;
        cmd[2].x = DLL63_SECONDARY_XZ_SCALE;
        cmd[2].y = 1.0f;
        cmd[2].z = DLL63_SECONDARY_XZ_SCALE;
        cmd += 3;
    }
    else
    {
        cmd[1].layer = 0;
        cmd[1].flags = 7;
        cmd[1].tex = &base[0x100];
        cmd[1].mode = 2;
        cmd[1].x = DLL63_PRIMARY_XZ_SCALE * ((PartFxSpawnParams*)posSource)->scale;
        cmd[1].y = DLL63_PRIMARY_Y_SCALE * ((PartFxSpawnParams*)posSource)->scale;
        cmd[1].z = DLL63_PRIMARY_XZ_SCALE * ((PartFxSpawnParams*)posSource)->scale;
        cmd[2].layer = 0;
        cmd[2].flags = 7;
        cmd[2].tex = &base[0xf0];
        cmd[2].mode = 2;
        cmd[2].x = DLL63_SECONDARY_XZ_SCALE * ((PartFxSpawnParams*)posSource)->scale;
        cmd[2].y = ((PartFxSpawnParams*)posSource)->scale;
        cmd[2].z = DLL63_SECONDARY_XZ_SCALE * ((PartFxSpawnParams*)posSource)->scale;
        cmd += 3;
    }
    cmd[0].layer = 1;
    cmd[0].flags = 7;
    cmd[0].tex = &base[0xf0];
    cmd[0].mode = 4;
    cmd[0].x = DLL63_LAYER_FIRST_X;
    cmd[0].y = 0.0f;
    cmd[0].z = 0.0f;
    cmd[1].layer = 1;
    cmd[1].flags = 7;
    cmd[1].tex = &base[0x100];
    cmd[1].mode = 4;
    cmd[1].x = DLL63_LAYER_SECOND_X;
    cmd[1].y = 0.0f;
    cmd[1].z = 0.0f;
    cmd[2].layer = 1;
    cmd[2].flags = 0xe;
    cmd[2].tex = &base[0xd4];
    cmd[2].mode = 0x100;
    cmd[2].x = 0.0f;
    cmd[2].y = 0.0f;
    cmd[2].z = DLL63_LAYER_Z;
    cmd[3].layer = 1;
    cmd[3].flags = 0xe;
    cmd[3].tex = &base[0xd4];
    cmd[3].mode = 0x4000;
    cmd[3].x = DLL63_LAYER_X;
    cmd[3].y = 0.0f;
    cmd[3].z = 0.0f;
    cmd[4].layer = 2;
    cmd[4].flags = 0xe;
    cmd[4].tex = &base[0xd4];
    cmd[4].mode = 0x100;
    cmd[4].x = 0.0f;
    cmd[4].y = 0.0f;
    cmd[4].z = DLL63_LAYER_Z;
    cmd[5].layer = 2;
    cmd[5].flags = 0xe;
    cmd[5].tex = &base[0xd4];
    cmd[5].mode = 0x4000;
    cmd[5].x = DLL63_LAYER_X;
    cmd[5].y = 0.0f;
    cmd[5].z = 0.0f;
    cmd[6].layer = 3;
    cmd[6].flags = 0xe;
    cmd[6].tex = &base[0xd4];
    cmd[6].mode = 0x100;
    cmd[6].x = 0.0f;
    cmd[6].y = 0.0f;
    cmd[6].z = DLL63_LAYER_Z;
    cmd[7].layer = 3;
    cmd[7].flags = 0xe;
    cmd[7].tex = &base[0xd4];
    cmd[7].mode = 0x4000;
    cmd[7].x = DLL63_LAYER_X;
    cmd[7].y = 0.0f;
    cmd[7].z = 0.0f;
    cmd[8].layer = 4;
    cmd[8].flags = 1;
    cmd[8].tex = NULL;
    cmd[8].mode = 0x2000;
    cmd[8].x = 0.0f;
    cmd[8].y = 0.0f;
    cmd[8].z = 0.0f;
    cmd[9].layer = 5;
    cmd[9].flags = 7;
    cmd[9].tex = &base[0xf0];
    cmd[9].mode = 4;
    cmd[9].x = 0.0f;
    cmd[9].y = 0.0f;
    cmd[9].z = 0.0f;
    cmd[10].layer = 5;
    cmd[10].flags = 7;
    cmd[10].tex = &base[0x100];
    cmd[10].mode = 4;
    cmd[10].x = 0.0f;
    cmd[10].y = 0.0f;
    cmd[10].z = 0.0f;
    cmd[11].layer = 5;
    cmd[11].flags = 0xe;
    cmd[11].tex = &base[0xd4];
    cmd[11].mode = 0x100;
    cmd[11].x = 0.0f;
    cmd[11].y = 0.0f;
    cmd[11].z = DLL63_LAYER_Z;
    cmd[12].layer = 5;
    cmd[12].flags = 0xe;
    cmd[12].tex = &base[0xd4];
    cmd[12].mode = 0x4000;
    cmd[12].x = DLL63_LAYER_X;
    cmd[12].y = 0.0f;
    cmd[12].z = 0.0f;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = DLL63_EFFECT_Y;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    if (flag != 0)
    {
        buf.scale = DLL63_FLAG_SCALE * flag;
    }
    else
    {
        buf.scale = 1.0f;
    }
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (cmd + 13) - entries;
    buf.hw[0] = *(s16*)&base[0x110];
    buf.hw[1] = *(s16*)&base[0x112];
    buf.hw[2] = *(s16*)&base[0x114];
    buf.hw[3] = *(s16*)&base[0x116];
    buf.hw[4] = *(s16*)&base[0x118];
    buf.hw[5] = *(s16*)&base[0x11a];
    buf.hw[6] = *(s16*)&base[0x11c];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x40000c0;
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, base, 0xc, &base[0x8c], DLL63_EFFECT_ID, 0);
    base++;
}

void dll_63_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    dll_63_func03Body(sourceObj, variant, posSource, flags);
}
#pragma inline_max_size reset

void dll_63_func01_nop(void)
{
}

void dll_63_func00_nop(void)
{
}
