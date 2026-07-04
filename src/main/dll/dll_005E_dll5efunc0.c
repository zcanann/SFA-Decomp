/*
 * dll5efunc0 (DLL 0x5E) - save-file / gameplay-state services.
 *
 * Home TU for a block of save and map-event helpers that live in the
 * 0x800e8xxx-0x800eaxxx text range and are called from many object DLLs
 * (the FUN_800exxxx symbols are mirrored as drift duplicates in sibling
 * dll_00xx files; this file holds the canonical bodies the linker resolves).
 *
 * Named entry points cover the gameplay preview/cheat settings struct
 * (cheat-unlock bitset in gGameplayRegisteredDebugOptions, preview RGB
 * volumes, getSaveFileStruct), save load/commit, the map-act flag history
 * tables, and a modgfx particle-sequence spawn (dll_5E_func03). Several
 * tiny dll_5E/5F entry stubs are no-ops.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"
extern ModgfxInterface** gModgfxInterface;
extern u32 FUN_80006768();
extern u32 FUN_8000676c();
extern u32 FUN_80006c20();
extern u32 FUN_80017500();
extern u32 FUN_8005d018();
extern u8 gGameplayPreviewSettings;
extern u32 DAT_803a3e26;
extern u32 DAT_803a3e27;
extern u32 DAT_803a3e28;
extern u32 DAT_803a3e2a;
extern u32 DAT_803a3e2c;
extern u32 DAT_803a3e2d;
extern u32 gGameplayPreviewColorRed;
extern u32 gGameplayPreviewColorGreen;
extern u32 gGameplayPreviewColorBlue;
extern u32 gGameplayRegisteredDebugOptions;
extern u32* DAT_803dd6d0;
extern u32* DAT_803dd6e8;
extern u8 gDll5EFunc03SequenceData[];
extern f32 lbl_803E07C0, lbl_803E07C4, lbl_803E07C8, lbl_803E07CC, lbl_803E07D0, lbl_803E07D4;
extern f32 lbl_803E07D8, lbl_803E07DC, lbl_803E07E0, lbl_803E07E4, lbl_803E07E8, lbl_803E07EC;
extern f32 lbl_803E07F0, lbl_803E07F4, lbl_803E07F8;

void saveFileStruct_unlockCheat(u32 cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
    return;
}

u32 isCheatUnlocked(u32 cheatId)
{
    return gGameplayRegisteredDebugOptions & 1 << (cheatId & 0xff);
}

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
    return;
}

u8* getSaveFileStruct(void)
{
    return &gGameplayPreviewSettings;
}

void loadSaveSettings(u64 arg1, u64 arg2, u64 arg3, u64 arg4,
                      u64 arg5, u64 arg6, u64 arg7,
                      u64 arg8)
{
    FUN_8005d018(DAT_803a3e2a);
    FUN_80017500(arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, DAT_803a3e26);
    FUN_80006c20(DAT_803a3e2c);
    FUN_80006768(DAT_803a3e2d, '\0');
    (**(VtableFn**)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
    (**(VtableFn**)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
    FUN_8000676c((u32)gGameplayPreviewColorGreen, 10, 0, 1, 0);
    FUN_8000676c((u32)gGameplayPreviewColorRed, 10, 1, 0, 0);
    FUN_8000676c((u32)gGameplayPreviewColorBlue, 10, 0, 0, 1);
    return;
}

void dll_5E_func01_nop(void)
{
}

void dll_5E_func00_nop(void)
{
}

void dll_5E_func03(int sourceObj, int variant, u8* posSource, u32 flags)
{
    u8* base = (u8*)(int)gDll5EFunc03SequenceData;
    (*gModgfxInterface)->beginSequence((void*)sourceObj, (u8)variant, 0x12, 3, 9);
    (*gModgfxInterface)->setSequenceParams(&base[0x2cc]);
    (*gModgfxInterface)->addSequenceFlags(flags | 0x4004484);
    (*gModgfxInterface)->resetSequenceSpawns();
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C0, lbl_803E07C4, *(f32*)&lbl_803E07C0, 9, &base[0x1c8]);
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C8, lbl_803E07C4, lbl_803E07CC, 9, &base[0x1dc]);
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C8, lbl_803E07C4, *(f32*)&lbl_803E07C8, 9, &base[0x1f0]);
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07C8, lbl_803E07C4, *(f32*)&lbl_803E07C8, 9, &base[0x204]);
    (*gModgfxInterface)->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(8, lbl_803E07D4, lbl_803E07D8, lbl_803E07DC, 0x24, &base[0x260]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(2, lbl_803E07E0, lbl_803E07E4, *(f32*)&lbl_803E07E0, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, lbl_803E07EC, *(f32*)&lbl_803E07EC, lbl_803E07F0, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(4, lbl_803E07F4, lbl_803E07D0, *(f32*)&lbl_803E07D0, 0x12, &base[0x2a8]);
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, lbl_803E07D0, *(f32*)&lbl_803E07D0, lbl_803E07F8, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, lbl_803E07EC, *(f32*)&lbl_803E07EC, lbl_803E07F0, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, lbl_803E07D0, *(f32*)&lbl_803E07D0, lbl_803E07F8, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(0x1800000, lbl_803E07EC, *(f32*)&lbl_803E07EC, lbl_803E07F0, 0x5e0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(0x4000, lbl_803E07D0, lbl_803E07E8, *(f32*)&lbl_803E07D0, 0x24, &base[0x260]);
    (*gModgfxInterface)->addSequenceSpawn(0x100, lbl_803E07D0, *(f32*)&lbl_803E07D0, lbl_803E07F8, 0, NULL);
    (*gModgfxInterface)->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 0x24, &base[0x260]);
    (*gModgfxInterface)->spawnSequence(posSource, (u8*)(int)gDll5EFunc03SequenceData, 0x24, &base[0x168], 0x10, 0x120, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

u8 gDll5EFunc03SequenceData[748] = {
    4, 76, 0, 0, 0, 0, 0, 0, 0, 0, 3, 39, 0, 0, 253, 61,
    0, 15, 0, 0, 0, 0, 0, 0, 252, 24, 0, 31, 0, 0, 253, 161,
    0, 0, 253, 61, 0, 47, 0, 0, 252, 124, 0, 0, 0, 0, 0, 63,
    0, 0, 253, 161, 0, 0, 2, 195, 0, 79, 0, 0, 0, 0, 0, 0,
    3, 232, 0, 95, 0, 0, 3, 39, 0, 0, 2, 195, 0, 111, 0, 0,
    4, 76, 0, 0, 0, 0, 0, 127, 0, 0, 4, 176, 7, 208, 0, 100,
    0, 0, 0, 31, 3, 39, 7, 208, 253, 161, 0, 15, 0, 31, 0, 100,
    7, 208, 252, 124, 0, 31, 0, 31, 253, 161, 7, 208, 253, 161, 0, 47,
    0, 31, 252, 124, 7, 208, 0, 100, 0, 63, 0, 31, 253, 161, 7, 208,
    3, 39, 0, 79, 0, 31, 0, 0, 7, 208, 4, 76, 0, 95, 0, 31,
    3, 39, 7, 208, 3, 39, 0, 111, 0, 31, 4, 176, 7, 208, 0, 100,
    0, 127, 0, 31, 3, 132, 15, 160, 0, 100, 0, 0, 0, 63, 2, 95,
    15, 160, 253, 161, 0, 15, 0, 63, 255, 156, 15, 160, 252, 124, 0, 31,
    0, 63, 252, 217, 15, 160, 253, 161, 0, 47, 0, 63, 251, 180, 15, 160,
    0, 100, 0, 63, 0, 63, 252, 217, 15, 160, 3, 39, 0, 79, 0, 63,
    0, 100, 15, 160, 4, 76, 0, 95, 0, 63, 2, 95, 15, 160, 3, 39,
    0, 111, 0, 63, 3, 132, 15, 160, 0, 100, 0, 127, 0, 63, 3, 232,
    23, 112, 255, 156, 0, 0, 0, 94, 2, 195, 23, 112, 252, 217, 0, 15,
    0, 94, 0, 0, 23, 112, 251, 180, 0, 31, 0, 94, 253, 61, 23, 112,
    252, 217, 0, 47, 0, 94, 252, 24, 23, 112, 255, 156, 0, 63, 0, 94,
    253, 61, 23, 112, 2, 95, 0, 79, 0, 94, 0, 0, 23, 112, 3, 132,
    0, 95, 0, 94, 2, 195, 23, 112, 2, 95, 0, 111, 0, 94, 3, 232,
    23, 112, 255, 156, 0, 127, 0, 94, 0, 0, 0, 1, 0, 10, 0, 0,
    0, 10, 0, 9, 0, 1, 0, 2, 0, 11, 0, 1, 0, 11, 0, 10,
    0, 2, 0, 3, 0, 12, 0, 2, 0, 12, 0, 11, 0, 3, 0, 4,
    0, 13, 0, 3, 0, 13, 0, 12, 0, 4, 0, 5, 0, 14, 0, 4,
    0, 14, 0, 13, 0, 5, 0, 6, 0, 15, 0, 5, 0, 15, 0, 14,
    0, 6, 0, 7, 0, 16, 0, 6, 0, 16, 0, 15, 0, 7, 0, 8,
    0, 17, 0, 7, 0, 17, 0, 16, 0, 0, 0, 1, 0, 2, 0, 3,
    0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 0, 0, 9, 0, 10,
    0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 0,
    0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23, 0, 24, 0, 25,
    0, 26, 0, 0, 0, 27, 0, 28, 0, 29, 0, 30, 0, 31, 0, 32,
    0, 33, 0, 34, 0, 35, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3,
    0, 4, 0, 5, 0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11,
    0, 12, 0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19,
    0, 20, 0, 21, 0, 22, 0, 23, 0, 24, 0, 25, 0, 26, 0, 27,
    0, 28, 0, 29, 0, 30, 0, 31, 0, 32, 0, 33, 0, 34, 0, 35,
    0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7,
    0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15,
    0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23,
    0, 24, 0, 25, 0, 26, 0, 27, 0, 28, 0, 29, 0, 30, 0, 31,
    0, 32, 0, 33, 0, 34, 0, 35, 0, 9, 0, 10, 0, 11, 0, 12,
    0, 13, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19, 0, 20,
    0, 21, 0, 22, 0, 23, 0, 24, 0, 25, 0, 26, 0, 0, 0, 10,
    0, 120, 0, 80, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 217,
    0, 0, 1, 253, 0, 0, 2, 1, 0, 0, 2, 3,
};
