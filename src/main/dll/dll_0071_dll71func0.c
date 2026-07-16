/*
 * dll71func0 (DLL 0x71) - a one-shot particle-effect spawner.
 *
 * The single real export, dll_71_func03, fills a stacked modgfx command
 * list (14 GfxCmd entries across four render layers, sourced from the
 * effect's float constants and the lbl_80314060 texture/param blob) and
 * hands it to gModgfxInterface->spawnEffect. When flag bit 0 is set the
 * spawn position is taken from the source object (sourceObj+0x18..0x20)
 * or, if none, from the PartFxSpawnParams packet at posSource. The two
 * trailing entry points are the DLL's empty func00/func01 slots.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0071_dll71func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL71_EFFECT_ID 0x154


extern u8 lbl_80314060[];

void dll_71_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80314060;
    GfxCmd* e = buf.entries;
    int ctx;
    f32 originOffset = 0.0f;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = originOffset;
    e[0].y = originOffset;
    e[0].z = originOffset;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = 0.01f;
    e[1].y = 2.0f;
    e[1].z = 0.01f;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = originOffset;
    e[2].y = 100.0f;
    e[2].z = originOffset;
    e[3].layer = 0;
    e[3].flags = 0x124;
    e[3].tex = NULL;
    e[3].mode = 0x20000;
    e[3].x = originOffset;
    e[3].y = originOffset;
    e[3].z = originOffset;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = &base[432];
    e[4].mode = 2;
    e[4].x = 200.0f;
    e[4].y = 1.3f;
    e[4].z = 200.0f;
    e[5].layer = 1;
    e[5].flags = 0xe;
    e[5].tex = &base[476];
    e[5].mode = 4;
    e[5].x = 255.0f;
    e[5].y = originOffset;
    e[5].z = originOffset;
    e[6].layer = 1;
    e[6].flags = 0x15;
    e[6].tex = &base[432];
    e[6].mode = 0x4000;
    e[6].x = 2.0f;
    e[6].y = 2.0f;
    e[6].z = originOffset;
    e[7].layer = 1;
    e[7].flags = 0;
    e[7].tex = NULL;
    e[7].mode = 0x400000;
    e[7].x = originOffset;
    e[7].y = -100.0f;
    e[7].z = originOffset;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 0x4000;
    e[8].x = 2.0f;
    e[8].y = 2.0f;
    e[8].z = originOffset;
    e[9].layer = 3;
    e[9].flags = 0x124;
    e[9].tex = NULL;
    e[9].mode = 0x20000;
    e[9].x = originOffset;
    e[9].y = originOffset;
    e[9].z = originOffset;
    e[10].layer = 3;
    e[10].flags = 0xe;
    e[10].tex = &base[476];
    e[10].mode = 4;
    e[10].x = originOffset;
    e[10].y = originOffset;
    e[10].z = originOffset;
    e[11].layer = 3;
    e[11].flags = 0x15;
    e[11].tex = &base[432];
    e[11].mode = 0x4000;
    e[11].x = 2.0f;
    e[11].y = 2.0f;
    e[11].z = originOffset;
    e[12].layer = 3;
    e[12].flags = 0x15;
    e[12].tex = &base[432];
    e[12].mode = 2;
    e[12].x = 0.01f;
    e[12].y = 1.0f;
    e[12].z = 0.01f;
    e[13].layer = 3;
    e[13].flags = 0;
    e[13].tex = NULL;
    e[13].mode = 0x400000;
    e[13].x = originOffset;
    e[13].y = 100.0f;
    e[13].z = originOffset;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = originOffset;
    buf.pos[1] = originOffset;
    buf.pos[2] = originOffset;
    buf.col[0] = originOffset;
    buf.col[1] = originOffset;
    buf.col[2] = originOffset;
    buf.scale = 1.0f;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 14) - buf.entries;
    buf.hw[0] = *(s16*)&base[504];
    buf.hw[1] = *(s16*)&base[506];
    buf.hw[2] = *(s16*)&base[508];
    buf.hw[3] = *(s16*)&base[510];
    buf.hw[4] = *(s16*)&base[512];
    buf.hw[5] = *(s16*)&base[514];
    buf.hw[6] = *(s16*)&base[516];
    buf.cmds = buf.entries;
    buf.flags = 0xc0100c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = originOffset + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = originOffset + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = originOffset + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = originOffset + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = originOffset + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = originOffset + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80314060, 0x18, &base[212], DLL71_EFFECT_ID, 0);
}

void dll_71_func01_nop(void)
{
}

void dll_71_func00_nop(void)
{
}
