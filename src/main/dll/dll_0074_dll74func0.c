/*
 * dll74func0 (DLL 0x74) - shared save-game / world-progress core lib.
 *
 * A near-clone of the dll_6D core (same exported entry points; this DLL
 * instance differs only in its private effect-list data labels). The retail
 * dll_0074 object carries only func03/func01/func00; the save/cheat helpers
 * (saveFileStruct_unlockCheat / isCheatUnlocked / saveFileStruct_resetVolumes /
 * getSaveFileStruct / loadSaveSettings) are mainDol drift-duplicates whose
 * retail home is dll_0015_curves.
 *   - dll_74_func03: builds the modgfx command list (the spirit/aura particle
 *     effect, a 0/non-0 variant pair) and submits it via
 *     gModgfxInterface->spawnEffect.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0074_dll74func0.h"

/* spawnEffect effect ids for the func03 "0/non-0 variant pair" (docblock). */
#define DLL74_EFFECT_ID_VARIANT0 0x2e
#define DLL74_EFFECT_ID_DEFAULT  0xd9

extern u8 lbl_803146D8[];

void dll_74_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxPointerSpawnPacket buf;
    GfxCmd* e;
    u8* base = (u8*)(int)lbl_803146D8;
    GfxCmd* entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = 0x15;
    entries[0].tex = &base[0x1b0];
    entries[0].mode = 4;
    entries[0].x = 0.0f;
    entries[0].y = 0.0f;
    entries[0].z = 0.0f;
    if (variant == 0)
    {
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = &base[0x1b0];
        entries[1].mode = 2;
        entries[1].x = 0.01f;
        entries[1].y = 1.0f;
        entries[1].z = 0.01f;
        e = &entries[2];
    }
    else
    {
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = &base[0x1b0];
        entries[1].mode = 2;
        entries[1].x = 0.01f;
        entries[1].y = 3.0f;
        entries[1].z = 0.01f;
        e = &entries[2];
    }
    if (variant == 0)
    {
        e->layer = 0;
        e->flags = 0;
        e->tex = NULL;
        e->mode = 0x400000;
        e->x = 0.0f;
        e->y = -90.0f;
        e->z = 0.0f;
        e++;
    }
    else
    {
        e->layer = 0;
        e->flags = 0;
        e->tex = NULL;
        e->mode = 0x400000;
        e->x = 0.0f;
        e->y = -290.0f;
        e->z = 0.0f;
        e++;
    }
    e[0].layer = 1;
    e[0].flags = 0x15;
    e[0].tex = &base[0x1b0];
    e[0].mode = 2;
    e[0].x = 70.0f;
    e[0].y = 1.5f;
    e[0].z = 70.0f;
    e[1].layer = 1;
    e[1].flags = 0xe;
    e[1].tex = &base[0x1f8];
    e[1].mode = 4;
    e[1].x = 255.0f;
    e[1].y = 0.0f;
    e[1].z = 0.0f;
    if (variant == 0)
    {
        e[2].layer = 1;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = 0.0f;
        e[2].y = 4.0f;
        e[2].z = 0.0f;
        e += 3;
    }
    else
    {
        e[2].layer = 1;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = 0.0f;
        e[2].y = -4.0f;
        e[2].z = 0.0f;
        e += 3;
    }
    e[0].layer = 2;
    e[0].flags = 7;
    e[0].tex = &base[0x164];
    e[0].mode = 2;
    e[0].x = 17.0f;
    e[0].y = 1.0f;
    e[0].z = 17.0f;
    e[1].layer = 2;
    e[1].flags = 7;
    e[1].tex = &base[0x174];
    e[1].mode = 2;
    e[1].x = 1.5f;
    e[1].y = 1.0f;
    e[1].z = 1.5f;
    if (variant == 0)
    {
        e[2].layer = 2;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = 0.0f;
        e[2].y = 4.0f;
        e[2].z = 0.0f;
        e += 3;
    }
    else
    {
        e[2].layer = 2;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = 0.0f;
        e[2].y = -4.0f;
        e[2].z = 0.0f;
        e += 3;
    }
    e[0].layer = 2;
    e[0].flags = 0xe;
    e[0].tex = &base[0x1f8];
    e[0].mode = 4;
    e[0].x = 0.0f;
    e[0].y = 0.0f;
    e[0].z = 0.0f;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = 0.0f;
    buf.pos[1] = 0.0f;
    buf.pos[2] = 0.0f;
    buf.col[0] = 0.0f;
    buf.col[1] = 0.0f;
    buf.col[2] = 0.0f;
    buf.scale = 1.0f;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 1) - entries;
    buf.hw[0] = *(s16*)&base[0x214];
    buf.hw[1] = *(s16*)&base[0x216];
    buf.hw[2] = *(s16*)&base[0x218];
    buf.hw[3] = *(s16*)&base[0x21a];
    buf.hw[4] = *(s16*)&base[0x21c];
    buf.hw[5] = *(s16*)&base[0x21e];
    buf.hw[6] = *(s16*)&base[0x220];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] += ((GameObject*)sourceObj)->anim.localPosX;
            buf.pos[1] += ((GameObject*)sourceObj)->anim.localPosY;
            buf.pos[2] += ((GameObject*)sourceObj)->anim.localPosZ;
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
        (*gModgfxInterface)
            ->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803146D8, 0x18, &base[0xd4], DLL74_EFFECT_ID_VARIANT0, 0);
    }
    else
    {
        (*gModgfxInterface)
            ->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803146D8, 0x18, &base[0xd4], DLL74_EFFECT_ID_DEFAULT, 0);
    }
}

void dll_74_func01_nop(void)
{
}

void dll_74_func00_nop(void)
{
}
