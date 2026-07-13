/*
 * DLL 61 (dll61func0) - a thin gameplay-effect DLL exporting three object
 * hooks. func01/func00 are empty no-op slots; func03 builds a
 * fifteen-command modgfx effect list on the stack (texture/blend modes from
 * the lbl_803E085x/6x/7x/8x float constants and the lbl_803128E8 resource
 * blob) and submits it through gModgfxInterface->spawnEffect.
 *
 * The save/cheat helpers (saveFileStruct_unlockCheat / isCheatUnlocked /
 * saveFileStruct_resetVolumes / getSaveFileStruct / loadSaveSettings)
 * that mainDol drift-duplicated into the dll_005E..dll_007B gameplay DLL
 * family live in dll_0015_curves (their retail home); the retail dll_0061
 * object carries only func03/func01/func00.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/gameplay_runtime.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0061_dll61func0.h"

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL61_EFFECT_ID 0x90

extern u8 lbl_803128E8[];
extern int lbl_803DB8C0;
extern f32 lbl_803E0858;

#pragma fp_contract off
void dll_61_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
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
    f32 randScale;
    u8* base = (u8*)(int)lbl_803128E8;
    GfxCmd* entry;
    entry = buf.entries;
    entry[0].layer = 0;
    entry[0].flags = 8;
    entry[0].tex = &base[0xa0];
    entry[0].mode = 4;
    entry[0].x = lbl_803E0858;
    entry[0].y = lbl_803E0858;
    entry[0].z = lbl_803E0858;
    entry[1].layer = 0;
    entry[1].flags = 1;
    entry[1].tex = 0;
    entry[1].mode = 0x2008000;
    entry[1].x = 125.0f;
    entry[1].y = 255.0f;
    entry[1].z = 125.0f;
    entry[2].layer = 0;
    entry[2].flags = 0;
    entry[2].tex = 0;
    entry[2].mode = 0x2080000;
    entry[2].x = lbl_803E0858;
    entry[2].y = 17.0f;
    entry[2].z = -17.0f;
    entry[3].layer = 0;
    entry[3].flags = 9;
    entry[3].tex = &base[0x8c];
    entry[3].mode = 0x80;
    entry[3].x = lbl_803E0858;
    entry[3].y = lbl_803E0858;
    entry[3].z = (f32) * (s16*)sourceObj;
    entry[4].layer = 0;
    entry[4].flags = 0x7a;
    entry[4].tex = 0;
    entry[4].mode = 0x10000;
    entry[4].x = lbl_803E0858;
    entry[4].y = lbl_803E0858;
    entry[4].z = lbl_803E0858;
    entry[5].layer = 0;
    entry[5].flags = 9;
    entry[5].tex = &base[0x8c];
    entry[5].mode = 2;
    randScale = 0.05f * (f32)(int)randomGetRange(0, 0xc);
    randScale = 2.6f + randScale;
    entry[5].x = randScale;
    entry[5].y = randScale;
    entry[5].z = randScale;
    entry[6].layer = 1;
    entry[6].flags = 0;
    entry[6].tex = 0;
    entry[6].mode = 0x10000000;
    entry[6].x = 28.0f;
    entry[6].y = 2.0f;
    entry[6].z = lbl_803E0858;
    entry[7].layer = 1;
    entry[7].flags = 8;
    entry[7].tex = &base[0xa0];
    entry[7].mode = 0x4000;
    entry[7].x = lbl_803E0858;
    entry[7].y = -4.0f;
    entry[7].z = lbl_803E0858;
    entry[8].layer = 1;
    entry[8].flags = 9;
    entry[8].tex = &base[0x8c];
    entry[8].mode = 0x100;
    entry[8].x = 600.0f;
    entry[8].y = lbl_803E0858;
    entry[8].z = lbl_803E0858;
    entry[9].layer = 1;
    entry[9].flags = 0;
    entry[9].tex = 0;
    entry[9].mode = 0x400000;
    entry[9].x = lbl_803E0858;
    entry[9].y = lbl_803E0858;
    entry[9].z = -200.0f;
    entry[10].layer = 1;
    entry[10].flags = 0;
    entry[10].tex = 0;
    entry[10].mode = 0x2080000;
    entry[10].x = lbl_803E0858;
    entry[10].y = 17.0f;
    entry[10].z = -200.0f;
    entry[11].layer = 2;
    entry[11].flags = 8;
    entry[11].tex = &base[0xa0];
    entry[11].mode = 0x4000;
    entry[11].x = lbl_803E0858;
    entry[11].y = -4.0f;
    entry[11].z = lbl_803E0858;
    entry[12].layer = 2;
    entry[12].flags = 9;
    entry[12].tex = &base[0x8c];
    entry[12].mode = 0x100;
    entry[12].x = 600.0f;
    entry[12].y = lbl_803E0858;
    entry[12].z = lbl_803E0858;
    entry[13].layer = 2;
    entry[13].flags = 1;
    entry[13].tex = &lbl_803DB8C0;
    entry[13].mode = 4;
    entry[13].x = lbl_803E0858;
    entry[13].y = lbl_803E0858;
    entry[13].z = lbl_803E0858;
    entry[14].layer = 2;
    entry[14].flags = 0;
    entry[14].tex = 0;
    entry[14].mode = 0x2008000;
    entry[14].x = lbl_803E0858;
    entry[14].y = lbl_803E0858;
    entry[14].z = lbl_803E0858;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0858;
    buf.pos[1] = 17.0f;
    buf.pos[2] = -40.0f;
    buf.col[0] = lbl_803E0858;
    buf.col[1] = lbl_803E0858;
    buf.col[2] = lbl_803E0858;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (GfxCmd*)((u8*)entry + 0x168) - entry;
    buf.hw[0] = *(s16*)&base[0xb0];
    buf.hw[1] = *(s16*)&base[0xb2];
    buf.hw[2] = *(s16*)&base[0xb4];
    buf.hw[3] = *(s16*)&base[0xb6];
    buf.hw[4] = *(s16*)&base[0xb8];
    buf.hw[5] = *(s16*)&base[0xba];
    buf.hw[6] = *(s16*)&base[0xbc];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000010;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E0858 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = 17.0f + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = -40.0f + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0858 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = 17.0f + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = -40.0f + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_803128E8, 8, &base[0x5c], DLL61_EFFECT_ID, 0);
}
#pragma fp_contract reset

void dll_61_func01_nop(void)
{
}

void dll_61_func00_nop(void)
{
}
