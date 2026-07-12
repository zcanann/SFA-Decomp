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
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0074_dll74func0.h"

/* spawnEffect effect ids for the func03 "0/non-0 variant pair" (docblock). */
#define DLL74_EFFECT_ID_VARIANT0 0x2e
#define DLL74_EFFECT_ID_DEFAULT  0xd9

extern u8 lbl_803146D8[];
extern f32 lbl_803E0BB8, lbl_803E0BBC, lbl_803E0BC0, lbl_803E0BC4, lbl_803E0BC8, lbl_803E0BCC;
extern f32 lbl_803E0BD0, lbl_803E0BD4, lbl_803E0BD8, lbl_803E0BDC, lbl_803E0BE0, lbl_803E0BE4;

void dll_74_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
    GfxCmd* e;
    u8* base = (u8*)(int)lbl_803146D8;
    GfxCmd* entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = 0x15;
    entries[0].tex = &base[0x1b0];
    entries[0].mode = 4;
    entries[0].x = lbl_803E0BB8;
    entries[0].y = lbl_803E0BB8;
    entries[0].z = lbl_803E0BB8;
    if (variant == 0)
    {
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = &base[0x1b0];
        entries[1].mode = 2;
        entries[1].x = lbl_803E0BBC;
        entries[1].y = lbl_803E0BC0;
        entries[1].z = lbl_803E0BBC;
        e = &entries[2];
    }
    else
    {
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = &base[0x1b0];
        entries[1].mode = 2;
        entries[1].x = lbl_803E0BBC;
        entries[1].y = lbl_803E0BC4;
        entries[1].z = lbl_803E0BBC;
        e = &entries[2];
    }
    if (variant == 0)
    {
        e->layer = 0;
        e->flags = 0;
        e->tex = NULL;
        e->mode = 0x400000;
        e->x = lbl_803E0BB8;
        e->y = lbl_803E0BC8;
        e->z = lbl_803E0BB8;
        e++;
    }
    else
    {
        e->layer = 0;
        e->flags = 0;
        e->tex = NULL;
        e->mode = 0x400000;
        e->x = lbl_803E0BB8;
        e->y = lbl_803E0BCC;
        e->z = lbl_803E0BB8;
        e++;
    }
    e[0].layer = 1;
    e[0].flags = 0x15;
    e[0].tex = &base[0x1b0];
    e[0].mode = 2;
    e[0].x = lbl_803E0BD0;
    e[0].y = lbl_803E0BD4;
    e[0].z = lbl_803E0BD0;
    e[1].layer = 1;
    e[1].flags = 0xe;
    e[1].tex = &base[0x1f8];
    e[1].mode = 4;
    e[1].x = lbl_803E0BD8;
    e[1].y = lbl_803E0BB8;
    e[1].z = lbl_803E0BB8;
    if (variant == 0)
    {
        e[2].layer = 1;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BDC;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    else
    {
        e[2].layer = 1;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BE0;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    e[0].layer = 2;
    e[0].flags = 7;
    e[0].tex = &base[0x164];
    e[0].mode = 2;
    e[0].x = lbl_803E0BE4;
    e[0].y = lbl_803E0BC0;
    e[0].z = lbl_803E0BE4;
    e[1].layer = 2;
    e[1].flags = 7;
    e[1].tex = &base[0x174];
    e[1].mode = 2;
    e[1].x = lbl_803E0BD4;
    e[1].y = lbl_803E0BC0;
    e[1].z = lbl_803E0BD4;
    if (variant == 0)
    {
        e[2].layer = 2;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BDC;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    else
    {
        e[2].layer = 2;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BE0;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    e[0].layer = 2;
    e[0].flags = 0xe;
    e[0].tex = &base[0x1f8];
    e[0].mode = 4;
    e[0].x = lbl_803E0BB8;
    e[0].y = lbl_803E0BB8;
    e[0].z = lbl_803E0BB8;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0BB8;
    buf.pos[1] = lbl_803E0BB8;
    buf.pos[2] = lbl_803E0BB8;
    buf.col[0] = lbl_803E0BB8;
    buf.col[1] = lbl_803E0BB8;
    buf.col[2] = lbl_803E0BB8;
    buf.scale = lbl_803E0BC0;
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
            buf.pos[0] = lbl_803E0BB8 + ((GameObject*)sourceObj)->anim.localPosX;
            buf.pos[1] = lbl_803E0BB8 + ((GameObject*)sourceObj)->anim.localPosY;
            buf.pos[2] = lbl_803E0BB8 + ((GameObject*)sourceObj)->anim.localPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0BB8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0BB8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0BB8 + ((PartFxSpawnParams*)posSource)->posZ;
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
