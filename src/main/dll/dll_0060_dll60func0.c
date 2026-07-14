/*
 * dll_0060 (gameplay/save-progress DLL) - a thin gameplay-effect DLL
 * exporting three object hooks. func01/func00 are empty no-op slots;
 * func03 builds a thirteen-command modgfx effect list on the stack
 * (texture/blend modes from the lbl_803E083x/4x float constants and the
 * lbl_80312790 resource blob) and submits it through
 * gModgfxInterface->spawnEffect.
 *
 * The save/cheat helpers (saveFileStruct_unlockCheat / isCheatUnlocked /
 * saveFileStruct_resetVolumes / getSaveFileStruct / loadSaveSettings)
 * that mainDol drift-duplicated into the dll_005E..dll_007B gameplay DLL
 * family live in dll_0015_curves (their retail home); the retail dll_0060
 * object carries only func03/func01/func00.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0060_dll60func0.h"

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL60_EFFECT_ID 0x46

extern f32 lbl_803E0830;
extern f32 lbl_803E0834;
extern f32 lbl_803E0838;
extern f32 lbl_803E083C;
extern f32 lbl_803E0840;
extern f32 lbl_803E0844;
extern f32 lbl_803E0848;
extern f32 lbl_803E084C;
extern u8 lbl_80312790[];

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    ModgfxPointerSpawnPacket buf;
    u8* base = (u8*)(int)lbl_80312790;
    GfxCmd* e;
    GfxCmd* entries;
    f32 z4;
    entries = buf.entries;
    e = entries;
    e = (GfxCmd*)((int)e | (int)entries);
    e[0].layer = 0;
    e[0].flags = 0xe;
    e[0].tex = &base[244];
    e[0].mode = 4;
    e[0].x = lbl_803E0830;
    e[0].y = lbl_803E0830;
    e[0].z = lbl_803E0830;
    e[1].layer = 0;
    e[1].flags = 0xe;
    e[1].tex = &base[244];
    e[1].mode = 2;
    e[1].x = lbl_803E0834;
    e[1].y = lbl_803E0834;
    e[1].z = lbl_803E0834;
    e[2].layer = 0;
    e[2].flags = 0xe;
    e[2].tex = &base[244];
    e[2].mode = 8;
    e[2].x = lbl_803E0838 + (f32)(int)randomGetRange(0, 0x69);
    e[2].y = lbl_803E0838 + (f32)(int)randomGetRange(0, 0x69);
    e[2].z = lbl_803E0838 + (f32)(int)randomGetRange(0, 0x69);
    e[3].layer = 0;
    e[3].flags = 0x7a;
    e[3].tex = 0;
    e[3].mode = 0x10000;
    e[3].x = lbl_803E0830;
    e[3].y = lbl_803E0830;
    e[3].z = lbl_803E0830;
    z4 = (f32)(int)randomGetRange(0, 0xfffe);
    e[4].layer = 0;
    e[4].flags = 0;
    e[4].tex = 0;
    e[4].mode = 0x80;
    e[4].x = lbl_803E0830;
    e[4].y = lbl_803E0830;
    e[4].z = z4;
    e[5].layer = 1;
    e[5].flags = 0xa;
    e[5].tex = &base[272];
    e[5].mode = 4;
    e[5].x = lbl_803E083C;
    e[5].y = lbl_803E0830;
    e[5].z = lbl_803E0830;
    e[6].layer = 1;
    e[6].flags = 0xe;
    e[6].tex = &base[244];
    e[6].mode = 2;
    e[6].x = lbl_803E0840;
    e[6].y = lbl_803E0840;
    e[6].z = lbl_803E0840;
    e[7].layer = 2;
    e[7].flags = 0xe;
    e[7].tex = &base[244];
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0844;
    e[7].y = lbl_803E0830;
    e[7].z = lbl_803E0830;
    e[8].layer = 2;
    e[8].flags = 0xe;
    e[8].tex = &base[244];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E0844;
    e[8].y = lbl_803E0830;
    e[8].z = lbl_803E0830;
    e[9].layer = 2;
    e[9].flags = 0x53;
    e[9].tex = 0;
    e[9].mode = 0x800000;
    e[9].x = lbl_803E0848;
    e[9].y = lbl_803E0830;
    e[9].z = lbl_803E0830;
    e[10].layer = 2;
    e[10].flags = 0x54;
    e[10].tex = 0;
    e[10].mode = 0x1800000;
    e[10].x = lbl_803E0848;
    e[10].y = lbl_803E0830;
    e[10].z = lbl_803E084C;
    e[11].layer = 2;
    e[11].flags = 0xa;
    e[11].tex = &base[272];
    e[11].mode = 4;
    e[11].x = lbl_803E0830;
    e[11].y = lbl_803E0830;
    e[11].z = lbl_803E0830;
    e[12].layer = 2;
    e[12].flags = 0xe;
    e[12].tex = &base[244];
    e[12].mode = 2;
    e[12].x = lbl_803E0840;
    e[12].y = lbl_803E0840;
    e[12].z = lbl_803E0840;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0830;
    buf.pos[1] = lbl_803E0840;
    buf.pos[2] = lbl_803E0830;
    buf.col[0] = lbl_803E0830;
    buf.col[1] = lbl_803E0830;
    buf.col[2] = lbl_803E0830;
    buf.scale = lbl_803E0848;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = (e + 13) - entries;
    buf.hw[0] = *(s16*)&base[292];
    buf.hw[1] = *(s16*)&base[294];
    buf.hw[2] = *(s16*)&base[296];
    buf.hw[3] = *(s16*)&base[298];
    buf.hw[4] = *(s16*)&base[300];
    buf.hw[5] = *(s16*)&base[302];
    buf.hw[6] = *(s16*)&base[304];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x1000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
        {
            buf.pos[0] = lbl_803E0830 + ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] = lbl_803E0840 + ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] = lbl_803E0830 + ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0830 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0840 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0830 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80312790, 0xc, &base[140], DLL60_EFFECT_ID, 0);
}

void dll_60_func01_nop(void)
{
}

void dll_60_func00_nop(void)
{
}
