/*
 * dll64func0 (DLL 0x64) - particle/effect spawner front-end.
 *
 * dll_64_func03 builds a fixed nine-command Modgfx effect description on
 * the stack (the GfxCmd entries[] table, each a textured billboard layer
 * read out of the effect's model-data blob) and submits it through
 * gModgfxInterface->spawnEffect. The overall effect scale tracks the
 * source object's placement byte at offset 0x1a; when bit 0 of the caller
 * flags requests world placement the base position is taken from either
 * the source object (offset 0x18..0x20) or the PartFxSpawnParams packet.
 * func01 and func00 (in binary address order) are the DLL's empty no-op
 * entry-table slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0064_dll64func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL64_EFFECT_ID 0x5e0


extern u8 lbl_80312D18[];

#define DLL64_PRIMARY_COMMAND_XZ 0.75f
#define DLL64_UNIT_SCALE         1.0f
#define DLL64_SECONDARY_XZ       0.45f
#define DLL64_SECONDARY_Y        0.6f
#define DLL64_COMMAND_LENGTH     200.0f
#define DLL64_COMMAND_DEPTH      20.0f
#define DLL64_PLACEMENT_SCALE    0.1f

void dll_64_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxPointerSpawnPacket buf;
    u32 flag;
    u8* base = (u8*)(int)lbl_80312D18;
    if (variant == 1)
    {
        *(s16*)&base[0x112] = 0;
    }
    flag = *(u8*)(*(u8**)&((GameObject*)sourceObj)->anim.placementData + 0x1a);
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 7;
    buf.entries[0].tex = &base[0xf0];
    buf.entries[0].mode = 2;
    buf.entries[0].x = DLL64_PRIMARY_COMMAND_XZ;
    buf.entries[0].y = DLL64_UNIT_SCALE;
    buf.entries[0].z = DLL64_PRIMARY_COMMAND_XZ;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 7;
    buf.entries[1].tex = &base[0x100];
    buf.entries[1].mode = 2;
    buf.entries[1].x = DLL64_SECONDARY_XZ;
    buf.entries[1].y = DLL64_SECONDARY_Y;
    buf.entries[1].z = DLL64_SECONDARY_XZ;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 0xe;
    buf.entries[2].tex = &base[0xd4];
    buf.entries[2].mode = 4;
    buf.entries[2].x = 0.0f;
    buf.entries[2].y = 0.0f;
    buf.entries[2].z = 0.0f;
    buf.entries[3].layer = 1;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[0x100];
    buf.entries[3].mode = 4;
    buf.entries[3].x = DLL64_COMMAND_LENGTH;
    buf.entries[3].y = 0.0f;
    buf.entries[3].z = 0.0f;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 0xe;
    buf.entries[4].tex = &base[0xd4];
    buf.entries[4].mode = 0x100;
    buf.entries[4].x = 0.0f;
    buf.entries[4].y = 0.0f;
    buf.entries[4].z = DLL64_COMMAND_DEPTH;
    buf.entries[5].layer = 2;
    buf.entries[5].flags = 0xe;
    buf.entries[5].tex = &base[0xd4];
    buf.entries[5].mode = 0x100;
    buf.entries[5].x = 0.0f;
    buf.entries[5].y = 0.0f;
    buf.entries[5].z = DLL64_COMMAND_DEPTH;
    buf.entries[6].layer = 3;
    buf.entries[6].flags = 1;
    buf.entries[6].tex = 0;
    buf.entries[6].mode = 0x2000;
    buf.entries[6].x = 0.0f;
    buf.entries[6].y = 0.0f;
    buf.entries[6].z = 0.0f;
    buf.entries[7].layer = 4;
    buf.entries[7].flags = 7;
    buf.entries[7].tex = &base[0x100];
    buf.entries[7].mode = 4;
    buf.entries[7].x = 0.0f;
    buf.entries[7].y = 0.0f;
    buf.entries[7].z = 0.0f;
    buf.entries[8].layer = 4;
    buf.entries[8].flags = 0xe;
    buf.entries[8].tex = &base[0xd4];
    buf.entries[8].mode = 0x100;
    buf.entries[8].x = 0.0f;
    buf.entries[8].y = 0.0f;
    buf.entries[8].z = DLL64_COMMAND_DEPTH;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    if (flag != 0)
    {
        buf.scale = DLL64_PLACEMENT_SCALE * flag;
    }
    else
    {
        buf.scale = DLL64_UNIT_SCALE;
    }
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 9;
    buf.hw[0] = *(s16*)&base[0x110];
    buf.hw[1] = *(s16*)&base[0x112];
    buf.hw[2] = *(s16*)&base[0x114];
    buf.hw[3] = *(s16*)&base[0x116];
    buf.hw[4] = *(s16*)&base[0x118];
    buf.hw[5] = *(s16*)&base[0x11a];
    buf.hw[6] = *(s16*)&base[0x11c];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4040080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80312D18, 0xc, &base[0x8c], DLL64_EFFECT_ID, 0);
}

void dll_64_func01_nop(void)
{
}

void dll_64_func00_nop(void)
{
}
