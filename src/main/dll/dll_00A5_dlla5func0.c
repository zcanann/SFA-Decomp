/*
 * dlla5func0 (DLL 0xA5) - a modgfx effect spawner (sibling of DLL 0xA6/0xA8).
 *
 * dll_A5_func03 builds a fixed 13-entry GfxCmd command buffer on the stack
 * (mode/layer/flags plus three coordinate words per primitive, several
 * textured from the asset table at lbl_80318D48), fills a per-effect header
 * (colour, position, scale, and hardware-state words copied from the same
 * table), then hands it to gModgfxInterface->spawnEffect. When flag bit 0 is
 * set the effect position is taken from the source object's world position,
 * or, when no source object is given, from the spawn-param packet
 * (posSource + 0xc..0x14). func00/func01 are the DLL's unused entry stubs.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/dll/dll_00A5_dlla5func0.h"

u8 lbl_803DB970[8] = {0, 0, 0, 1, 0, 2, 0, 3};
u8 lbl_803DB978[8] = {0, 4, 0, 5, 0, 6, 0, 7};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLLA5_EFFECT_ID 0x5e0

extern u8 lbl_80318D48[];

void dll_A5_func03(short* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxSpawnPacket buf;
    u8* tab = (u8*)(int)lbl_80318D48;
    GfxCmd* e = buf.entries;
    u32 fl;

    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = &tab[0x68];
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    e[1].layer = 0;
    e[1].flags = 4;
    e[1].tex = lbl_803DB970;
    e[1].mode = 2;
    e[1].x = 1.0f;
    e[1].y = 1.0f;
    e[1].z = 1.26f;
    e[2].layer = 0;
    e[2].flags = 4;
    e[2].tex = lbl_803DB978;
    e[2].mode = 2;
    e[2].x = 1.9f;
    e[2].y = 1.9f;
    e[2].z = 1.26f;
    e[3].layer = 0;
    e[3].flags = 0;
    e[3].tex = NULL;
    e[3].mode = 0x80;
    e[3].x = 0.0f;
    e[3].y = 0.0f;
    e[3].z = (f32)*sourceObj;
    e[4].layer = 0;
    e[4].flags = 0x7a;
    e[4].tex = NULL;
    e[4].mode = 0x10000;
    e[4].x = 0.0f;
    e[4].y = 0.0f;
    e[4].z = 0.0f;
    e[5].layer = 1;
    e[5].flags = 8;
    e[5].tex = &tab[0x68];
    e[5].mode = 4;
    e[5].x = 255.0f;
    e[5].y = 0.0f;
    e[5].z = 0.0f;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x400000;
    e[6].x = 0.0f;
    e[6].y = 0.0f;
    e[6].z = 1.0f;
    e[7].layer = 1;
    e[7].flags = 8;
    e[7].tex = &tab[0x68];
    e[7].mode = 2;
    e[7].x = 1.0f;
    e[7].y = 1.0f;
    e[7].z = 3.0f;
    e[8].layer = 1;
    e[8].flags = 0x3a1;
    e[8].tex = NULL;
    e[8].mode = 0x1800000;
    e[8].x = 1.0f;
    e[8].y = 0.0f;
    e[8].z = 2.0f;
    e[9].layer = 2;
    e[9].flags = 0x7a;
    e[9].tex = NULL;
    e[9].mode = 0x10000;
    e[9].x = 0.0f;
    e[9].y = 0.0f;
    e[9].z = 0.0f;
    e[10].layer = 2;
    e[10].flags = 8;
    e[10].tex = &tab[0x68];
    e[10].mode = 4;
    e[10].x = 0.0f;
    e[10].y = 0.0f;
    e[10].z = 0.0f;
    e[11].layer = 2;
    e[11].flags = 0;
    e[11].tex = NULL;
    e[11].mode = 0x400000;
    e[11].x = 0.0f;
    e[11].y = 0.0f;
    e[11].z = 25.0f;
    e[12].layer = 2;
    e[12].flags = 0x3a0;
    e[12].tex = NULL;
    e[12].mode = 0x800000;
    e[12].x = 1.0f;
    e[12].y = 0.0f;
    e[12].z = 0.0f;

    buf.v58 = variant;
    buf.ctx = (int)sourceObj;
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
    buf.v59 = 8;
    buf.v5a = 0;
    buf.v5b = 0x3c;
    buf.count = (GfxCmd*)((u8*)e + 0x138) - e;
    buf.hw[0] = *(s16*)&tab[0x78];
    buf.hw[1] = *(s16*)&tab[0x7a];
    buf.hw[2] = *(s16*)&tab[0x7c];
    buf.hw[3] = *(s16*)&tab[0x7e];
    buf.hw[4] = *(s16*)&tab[0x80];
    buf.hw[5] = *(s16*)&tab[0x82];
    buf.hw[6] = *(s16*)&tab[0x84];
    buf.cmds = e;
    buf.flags = 0x4040000;
    buf.flags |= (flags | 0x80);
    fl = buf.flags;
    if (fl & 1)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, (u8*)(int)lbl_80318D48, 4, &tab[0x50], DLLA5_EFFECT_ID, 0);
}

void dll_A5_func01_nop(void)
{
}

void dll_A5_func00_nop(void)
{
}

/* .sdata2 float-pool constants referenced via extern by sibling dll_00A6 */
