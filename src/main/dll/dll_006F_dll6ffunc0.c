/*
 * dll6ffunc0 (DLL 0x6F) - shared save-game / world-progress core lib.
 *
 * Owns the gameplay save-state helpers exported through gameplay.h:
 *   - debug-cheat unlock bits (saveFileStruct_unlockCheat / isCheatUnlocked)
 *     packed into gGameplayRegisteredDebugOptions.
 *   - preview color/volume defaults (saveFileStruct_resetVolumes, 0x7f each).
 *   - the save-settings apply path (loadSaveSettings) and the per-map act /
 *     object-position fix-up (FUN_800e8630).
 *   - FUN_800e95e8: the map-act flag setter that mirrors a flag bit across the
 *     map-act table and maintains the recently-changed history ring.
 *   - FUN_800e8f58 / FUN_800e9e9c: new-game / save-slot setup, seeding the
 *     map-act table and the save block.
 *   - FUN_800ea9b8: the visited-map history ring (most-recent-first, depth 5).
 *   - dll_6F_func03: builds a 32-entry modgfx command list (the spirit/aura
 *     particle effect) and submits it via gModgfxInterface->spawnEffect.
 *
 * The map-act / flag tables live at 0x803a3f08.. and 0x80312460..; the visited
 * history ring at 0x803a3be0. Bit indices are split into (word,bit) by the
 * 0x12f flag-word base. These globals are cross-TU; only this DLL writes the
 * debug-option and preview-color globals.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"

/* one modgfx draw command in the dll_6F_func03 effect list */
typedef struct GfxCmd
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

/* Cross-TU main-lib functions and globals this DLL references (home TUs
   un-recovered; left as Ghidra FUN_/DAT_ names). */

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
extern u8 gDll6FGfxCmdResourceTable[];
extern u8 gDll6FGfxCmdTexture;
extern f32 lbl_803E0AB8;
extern f32 lbl_803E0ABC;
extern f32 lbl_803E0AC0;
extern f32 lbl_803E0AC4;
extern f32 lbl_803E0AC8;
extern f32 lbl_803E0ACC;
extern f32 lbl_803E0AD0;
extern f32 lbl_803E0AD4;
extern f32 lbl_803E0AD8;
extern f32 lbl_803E0ADC;
extern f32 lbl_803E0AE0;
extern f32 lbl_803E0AE4;
extern f32 lbl_803E0AE8;
extern f32 lbl_803E0AEC;
extern f32 lbl_803E0AF0;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

void saveFileStruct_unlockCheat(u32 cheatId)
{
    gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (cheatId & 0xff);
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

void dll_6F_func01_nop(void)
{
}

void dll_6F_func00_nop(void)
{
}

void dll_6F_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)gDll6FGfxCmdResourceTable;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x18;
    buf.entries[0].tex = &base[336];
    buf.entries[0].mode = 2;
    buf.entries[0].x = lbl_803E0AB8;
    buf.entries[0].y = lbl_803E0ABC;
    buf.entries[0].z = lbl_803E0AB8;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x18;
    buf.entries[1].tex = &base[336];
    buf.entries[1].mode = 4;
    buf.entries[1].x = lbl_803E0AC0;
    buf.entries[1].y = lbl_803E0AC0;
    buf.entries[1].z = lbl_803E0AC0;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 0x18;
    buf.entries[2].tex = &base[336];
    buf.entries[2].mode = 8;
    buf.entries[2].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[2].y = (*(f32*)&lbl_803E0AC4);
    buf.entries[2].z = lbl_803E0AC0;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x18;
    buf.entries[3].tex = &base[336];
    buf.entries[3].mode = 8;
    buf.entries[3].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[3].y = (*(f32*)&lbl_803E0AC4);
    buf.entries[3].z = lbl_803E0AC0;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 8;
    buf.entries[4].tex = &base[384];
    buf.entries[4].mode = 8;
    buf.entries[4].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[4].y = (*(f32*)&lbl_803E0AC8);
    buf.entries[4].z = lbl_803E0AC0;
    buf.entries[5].layer = 0;
    buf.entries[5].flags = 0xc;
    buf.entries[5].tex = &base[400];
    buf.entries[5].mode = 8;
    buf.entries[5].x = lbl_803E0ACC;
    buf.entries[5].y = lbl_803E0AC0;
    buf.entries[5].z = lbl_803E0AC0;
    buf.entries[6].layer = 0;
    buf.entries[6].flags = 0x7a;
    buf.entries[6].tex = 0;
    buf.entries[6].mode = 0x10000;
    buf.entries[6].x = lbl_803E0AC0;
    buf.entries[6].y = lbl_803E0AC0;
    buf.entries[6].z = lbl_803E0AC0;
    buf.entries[7].layer = 0;
    buf.entries[7].flags = 0x14;
    buf.entries[7].tex = 0;
    buf.entries[7].mode = 0x800000;
    buf.entries[7].x = (*(f32*)&lbl_803E0AD0);
    buf.entries[7].y = lbl_803E0AC0;
    buf.entries[7].z = lbl_803E0AC0;
    buf.entries[8].layer = 0;
    buf.entries[8].flags = 0x11;
    buf.entries[8].tex = 0;
    buf.entries[8].mode = 0x800000;
    buf.entries[8].x = lbl_803E0AD4;
    buf.entries[8].y = lbl_803E0AC0;
    buf.entries[8].z = lbl_803E0AC0;
    buf.entries[9].layer = 0;
    buf.entries[9].flags = 1;
    buf.entries[9].tex = 0;
    buf.entries[9].mode = 0x2008000;
    buf.entries[9].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[9].y = (*(f32*)&lbl_803E0AC8);
    buf.entries[9].z = lbl_803E0AC0;
    buf.entries[10].layer = 0;
    buf.entries[10].flags = 0;
    buf.entries[10].tex = 0;
    buf.entries[10].mode = 0x80000;
    buf.entries[10].x = lbl_803E0AC0;
    buf.entries[10].y = lbl_803E0AD8;
    buf.entries[10].z = lbl_803E0AC0;
    buf.entries[11].layer = 0;
    buf.entries[11].flags = 0;
    buf.entries[11].tex = 0;
    buf.entries[11].mode = 0x100;
    buf.entries[11].x = lbl_803E0AC0;
    buf.entries[11].y = lbl_803E0AC0;
    buf.entries[11].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[12].layer = 1;
    buf.entries[12].flags = 4;
    buf.entries[12].tex = &gDll6FGfxCmdTexture;
    buf.entries[12].mode = 4;
    buf.entries[12].x = lbl_803E0AE0;
    buf.entries[12].y = lbl_803E0AC0;
    buf.entries[12].z = lbl_803E0AC0;
    buf.entries[13].layer = 1;
    buf.entries[13].flags = 8;
    buf.entries[13].tex = &base[384];
    buf.entries[13].mode = 4;
    buf.entries[13].x = lbl_803E0AE4;
    buf.entries[13].y = lbl_803E0AC0;
    buf.entries[13].z = lbl_803E0AC0;
    buf.entries[14].layer = 1;
    buf.entries[14].flags = 0x18;
    buf.entries[14].tex = &base[336];
    buf.entries[14].mode = 0x4000;
    buf.entries[14].x = lbl_803E0AC0;
    buf.entries[14].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[14].z = lbl_803E0AC0;
    buf.entries[15].layer = 1;
    buf.entries[15].flags = 0x7a;
    buf.entries[15].tex = 0;
    buf.entries[15].mode = 0x10000;
    buf.entries[15].x = (*(f32*)&lbl_803E0AD0);
    buf.entries[15].y = lbl_803E0AC0;
    buf.entries[15].z = lbl_803E0AC0;
    buf.entries[16].layer = 1;
    buf.entries[16].flags = 0;
    buf.entries[16].tex = 0;
    buf.entries[16].mode = 0x100;
    buf.entries[16].x = lbl_803E0AC0;
    buf.entries[16].y = lbl_803E0AC0;
    buf.entries[16].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[17].layer = 2;
    buf.entries[17].flags = 4;
    buf.entries[17].tex = &gDll6FGfxCmdTexture;
    buf.entries[17].mode = 4;
    buf.entries[17].x = lbl_803E0AC0;
    buf.entries[17].y = lbl_803E0AC0;
    buf.entries[17].z = lbl_803E0AC0;
    buf.entries[18].layer = 2;
    buf.entries[18].flags = 8;
    buf.entries[18].tex = &base[384];
    buf.entries[18].mode = 4;
    buf.entries[18].x = (*(f32*)&lbl_803E0AC8);
    buf.entries[18].y = lbl_803E0AC0;
    buf.entries[18].z = lbl_803E0AC0;
    buf.entries[19].layer = 2;
    buf.entries[19].flags = 0x18;
    buf.entries[19].tex = &base[336];
    buf.entries[19].mode = 0x4000;
    buf.entries[19].x = lbl_803E0AC0;
    buf.entries[19].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[19].z = lbl_803E0AC0;
    buf.entries[20].layer = 2;
    buf.entries[20].flags = 0;
    buf.entries[20].tex = 0;
    buf.entries[20].mode = 0x80000;
    buf.entries[20].x = lbl_803E0AC0;
    buf.entries[20].y = lbl_803E0AEC;
    buf.entries[20].z = lbl_803E0AC0;
    buf.entries[21].layer = 2;
    buf.entries[21].flags = 0;
    buf.entries[21].tex = 0;
    buf.entries[21].mode = 0x100;
    buf.entries[21].x = lbl_803E0AC0;
    buf.entries[21].y = lbl_803E0AC0;
    buf.entries[21].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[22].layer = 3;
    buf.entries[22].flags = 8;
    buf.entries[22].tex = &base[384];
    buf.entries[22].mode = 4;
    buf.entries[22].x = lbl_803E0AC0;
    buf.entries[22].y = lbl_803E0AC0;
    buf.entries[22].z = lbl_803E0AC0;
    buf.entries[23].layer = 3;
    buf.entries[23].flags = 0xc;
    buf.entries[23].tex = &base[400];
    buf.entries[23].mode = 4;
    buf.entries[23].x = lbl_803E0AF0;
    buf.entries[23].y = lbl_803E0AC0;
    buf.entries[23].z = lbl_803E0AC0;
    buf.entries[24].layer = 3;
    buf.entries[24].flags = 0x18;
    buf.entries[24].tex = &base[336];
    buf.entries[24].mode = 0x4000;
    buf.entries[24].x = lbl_803E0AC0;
    buf.entries[24].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[24].z = lbl_803E0AC0;
    buf.entries[25].layer = 3;
    buf.entries[25].flags = 0;
    buf.entries[25].tex = 0;
    buf.entries[25].mode = 0x100;
    buf.entries[25].x = lbl_803E0AC0;
    buf.entries[25].y = lbl_803E0AC0;
    buf.entries[25].z = (*(f32*)&lbl_803E0ADC);
    buf.entries[26].layer = 4;
    buf.entries[26].flags = 0xc;
    buf.entries[26].tex = &base[400];
    buf.entries[26].mode = 4;
    buf.entries[26].x = lbl_803E0AC0;
    buf.entries[26].y = lbl_803E0AC0;
    buf.entries[26].z = lbl_803E0AC0;
    buf.entries[27].layer = 4;
    buf.entries[27].flags = 0x18;
    buf.entries[27].tex = &base[336];
    buf.entries[27].mode = 0x4000;
    buf.entries[27].x = lbl_803E0AC0;
    buf.entries[27].y = (*(f32*)&lbl_803E0AE8);
    buf.entries[27].z = lbl_803E0AC0;
    buf.entries[28].layer = 4;
    buf.entries[28].flags = 0;
    buf.entries[28].tex = 0;
    buf.entries[28].mode = 0x2008000;
    buf.entries[28].x = (*(f32*)&lbl_803E0AC4);
    buf.entries[28].y = (*(f32*)&lbl_803E0AC8);
    buf.entries[28].z = lbl_803E0AC0;
    buf.entries[29].layer = 4;
    buf.entries[29].flags = 0;
    buf.entries[29].tex = 0;
    buf.entries[29].mode = 0x100;
    buf.entries[29].x = lbl_803E0AC0;
    buf.entries[29].y = lbl_803E0AC0;
    buf.entries[29].z = (*(f32*)&lbl_803E0ADC);
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0AC0;
    buf.pos[1] = lbl_803E0AC0;
    buf.pos[2] = lbl_803E0AC0;
    buf.col[0] = lbl_803E0AC0;
    buf.col[1] = lbl_803E0AC0;
    buf.col[2] = lbl_803E0AC0;
    buf.scale = (*(f32*)&lbl_803E0AD0);
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x18;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.flags = 0x4000084;
    buf.count = 0x14;
    buf.hw[0] = *(s16*)&base[424];
    buf.hw[1] = *(s16*)&base[426];
    buf.hw[2] = *(s16*)&base[428];
    buf.hw[3] = *(s16*)&base[430];
    buf.hw[4] = *(s16*)&base[432];
    buf.hw[5] = *(s16*)&base[434];
    buf.hw[6] = *(s16*)&base[436];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0AC0 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0AC0 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0AC0 + *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0AC0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0AC0 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0AC0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x18, (u8*)(int)gDll6FGfxCmdResourceTable, 0x10, &base[240], 0x48, 0);
}

u8 gDll6FGfxCmdResourceTable[440] = {
    0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 1, 77, 0, 40, 0, 0,
    0, 0, 0, 11, 0, 235, 0, 40, 255, 21, 0, 31, 0, 11, 3, 232,
    0, 0, 0, 0, 0, 0, 0, 31, 3, 85, 0, 0, 254, 159, 0, 15,
    0, 31, 2, 195, 0, 0, 253, 61, 0, 31, 0, 31, 0, 0, 0, 0,
    0, 0, 0, 15, 0, 0, 0, 0, 0, 40, 254, 179, 0, 0, 0, 11,
    255, 22, 0, 40, 255, 21, 0, 31, 0, 11, 0, 0, 0, 0, 252, 24,
    0, 0, 0, 31, 254, 160, 0, 0, 252, 171, 0, 15, 0, 31, 253, 62,
    0, 0, 253, 61, 0, 31, 0, 31, 0, 0, 0, 0, 0, 0, 0, 15,
    0, 0, 254, 179, 0, 40, 0, 0, 0, 0, 0, 11, 255, 21, 0, 40,
    0, 234, 0, 31, 0, 11, 252, 24, 0, 0, 0, 0, 0, 0, 0, 31,
    252, 171, 0, 0, 1, 96, 0, 15, 0, 31, 253, 61, 0, 0, 2, 194,
    0, 31, 0, 31, 0, 0, 0, 0, 0, 0, 0, 15, 0, 0, 0, 0,
    0, 40, 1, 77, 0, 0, 0, 11, 0, 234, 0, 40, 0, 235, 0, 31,
    0, 11, 0, 0, 0, 0, 3, 232, 0, 0, 0, 31, 1, 96, 0, 0,
    3, 85, 0, 15, 0, 31, 2, 194, 0, 0, 2, 195, 0, 31, 0, 31,
    0, 0, 0, 2, 0, 1, 0, 1, 0, 4, 0, 3, 0, 1, 0, 2,
    0, 4, 0, 2, 0, 5, 0, 4, 0, 6, 0, 8, 0, 7, 0, 7,
    0, 10, 0, 9, 0, 7, 0, 8, 0, 10, 0, 8, 0, 11, 0, 10,
    0, 12, 0, 14, 0, 13, 0, 13, 0, 16, 0, 15, 0, 13, 0, 14,
    0, 16, 0, 14, 0, 17, 0, 16, 0, 18, 0, 19, 0, 20, 0, 19,
    0, 22, 0, 21, 0, 19, 0, 20, 0, 22, 0, 20, 0, 23, 0, 22,
    0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7,
    0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15,
    0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 21, 0, 22, 0, 23,
    0, 1, 0, 2, 0, 7, 0, 8, 0, 13, 0, 14, 0, 19, 0, 20,
    0, 3, 0, 4, 0, 5, 0, 9, 0, 10, 0, 11, 0, 15, 0, 16,
    0, 17, 0, 21, 0, 22, 0, 23, 0, 0, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 0, 0, 0, 0, 0,
};

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_80313E78[8] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00030000, dll_6F_func00_nop, dll_6F_func01_nop, (void*)0x00000000, dll_6F_func03 };
