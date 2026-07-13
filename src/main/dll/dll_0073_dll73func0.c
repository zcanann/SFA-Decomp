/*
 * dll73func0 (DLL 0x73) - modgfx spirit/effect spawner DLL.
 *
 * The retail dll_0073 object carries only func03/func01/func00; the
 * save/cheat helpers (saveFileStruct_unlockCheat / isCheatUnlocked /
 * saveFileStruct_resetVolumes / getSaveFileStruct / loadSaveSettings) are
 * mainDol drift-duplicates whose retail home is dll_0015_curves.
 *   - dll_73_func03: builds the modgfx command list (the spirit/aura
 *     particle effect) and submits it via gModgfxInterface->spawnEffect.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx_types.h"
#include "main/dll/dll_0073_dll73func0.h"

/* effect id spawned by this DLL's modgfx emitter (spawnEffect textureAssetId arg). */
#define DLL73_EFFECT_ID 0xd9

extern u8 lbl_803144B0[];
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E0B80 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E0B84 = 0.01f;
__declspec(section ".sdata2") f32 lbl_803E0B88 = 3.0f;
__declspec(section ".sdata2") f32 lbl_803E0B8C = 100.0f;
__declspec(section ".sdata2") f32 lbl_803E0B90 = 200.0f;
__declspec(section ".sdata2") f32 lbl_803E0B94 = 1.5f;
__declspec(section ".sdata2") f32 lbl_803E0B98 = 255.0f;
__declspec(section ".sdata2") f32 lbl_803E0B9C = 2.0f;
__declspec(section ".sdata2") f32 lbl_803E0BA0 = 4.0f;
__declspec(section ".sdata2") f32 lbl_803E0BA4 = -100.0f;
__declspec(section ".sdata2") f32 lbl_803E0BA8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E0BAC = 400.0f;

void dll_73_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
        u8 v58, v59, v5a, v5b, pad2;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_803144B0;
    GfxCmd* e;
    GfxCmd* entries;
    entries = buf.entries;
    e = entries;
    e = (GfxCmd*)((int)e | (int)entries);
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = lbl_803E0B80;
    e[0].y = lbl_803E0B80;
    e[0].z = lbl_803E0B80;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = lbl_803E0B84;
    e[1].y = lbl_803E0B88;
    e[1].z = lbl_803E0B84;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = 0;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E0B80;
    e[2].y = lbl_803E0B8C;
    e[2].z = lbl_803E0B80;
    e[3].layer = 0;
    e[3].flags = 0x124;
    e[3].tex = 0;
    e[3].mode = 0x20000;
    e[3].x = lbl_803E0B80;
    e[3].y = lbl_803E0B80;
    e[3].z = lbl_803E0B80;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = &base[432];
    e[4].mode = 2;
    e[4].x = lbl_803E0B90;
    e[4].y = lbl_803E0B94;
    e[4].z = lbl_803E0B90;
    e[5].layer = 1;
    e[5].flags = 0xe;
    e[5].tex = &base[476];
    e[5].mode = 4;
    e[5].x = lbl_803E0B98;
    e[5].y = lbl_803E0B80;
    e[5].z = lbl_803E0B80;
    e[6].layer = 1;
    e[6].flags = 0x15;
    e[6].tex = &base[432];
    e[6].mode = 0x4000;
    e[6].x = lbl_803E0B9C;
    e[6].y = lbl_803E0BA0;
    e[6].z = lbl_803E0B80;
    e[7].layer = 1;
    e[7].flags = 0;
    e[7].tex = 0;
    e[7].mode = 0x400000;
    e[7].x = lbl_803E0B80;
    e[7].y = lbl_803E0BA4;
    e[7].z = lbl_803E0B80;
    e[8].layer = 1;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 8;
    e[8].x = (f32)(int)randomGetRange(0x64, 0xff);
    e[8].y = lbl_803E0B98;
    e[8].z = lbl_803E0B98;
    e[9].layer = 2;
    e[9].flags = 0x15;
    e[9].tex = &base[432];
    e[9].mode = 0x4000;
    e[9].x = lbl_803E0B9C;
    e[9].y = lbl_803E0BA0;
    e[9].z = lbl_803E0B80;
    e[10].layer = 2;
    e[10].flags = 0x15;
    e[10].tex = &base[432];
    e[10].mode = 8;
    e[10].x = (f32)(int)randomGetRange(0x64, 0xff);
    e[10].y = lbl_803E0B98;
    e[10].z = lbl_803E0B98;
    e[11].layer = 3;
    e[11].flags = 0x124;
    e[11].tex = 0;
    e[11].mode = 0x20000;
    e[11].x = lbl_803E0B80;
    e[11].y = lbl_803E0B80;
    e[11].z = lbl_803E0B80;
    e[12].layer = 3;
    e[12].flags = 0xe;
    e[12].tex = &base[476];
    e[12].mode = 4;
    e[12].x = lbl_803E0B80;
    e[12].y = lbl_803E0B80;
    e[12].z = lbl_803E0B80;
    e[13].layer = 3;
    e[13].flags = 0x15;
    e[13].tex = &base[432];
    e[13].mode = 0x4000;
    e[13].x = lbl_803E0B9C;
    e[13].y = lbl_803E0BA0;
    e[13].z = lbl_803E0B80;
    e[14].layer = 3;
    e[14].flags = 0x15;
    e[14].tex = &base[432];
    e[14].mode = 2;
    e[14].x = lbl_803E0B84;
    e[14].y = lbl_803E0BA8;
    e[14].z = lbl_803E0B84;
    e[15].layer = 3;
    e[15].flags = 0;
    e[15].tex = 0;
    e[15].mode = 0x400000;
    e[15].x = lbl_803E0B80;
    e[15].y = lbl_803E0B8C;
    e[15].z = lbl_803E0B80;
    e[16].layer = 3;
    e[16].flags = 0;
    e[16].tex = 0;
    e[16].mode = 0x80000;
    e[16].x = lbl_803E0B80;
    e[16].y = lbl_803E0BAC;
    e[16].z = lbl_803E0B80;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0B80;
    buf.pos[1] = lbl_803E0B80;
    buf.pos[2] = lbl_803E0B80;
    buf.col[0] = lbl_803E0B80;
    buf.col[1] = lbl_803E0B80;
    buf.col[2] = lbl_803E0B80;
    buf.scale = lbl_803E0BA8;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 17) - entries;
    buf.hw[0] = *(s16*)&base[504];
    buf.hw[1] = *(s16*)&base[506];
    buf.hw[2] = *(s16*)&base[508];
    buf.hw[3] = *(s16*)&base[510];
    buf.hw[4] = *(s16*)&base[512];
    buf.hw[5] = *(s16*)&base[514];
    buf.hw[6] = *(s16*)&base[516];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0B80 + ((GameObject*)sourceObj)->anim.localPosX;
            buf.pos[1] = lbl_803E0B80 + ((GameObject*)sourceObj)->anim.localPosY;
            buf.pos[2] = lbl_803E0B80 + ((GameObject*)sourceObj)->anim.localPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0B80 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0B80 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0B80 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803144B0, 0x18, &base[212], DLL73_EFFECT_ID, 0);
}

void dll_73_func01_nop(void)
{
}

void dll_73_func00_nop(void)
{
}
