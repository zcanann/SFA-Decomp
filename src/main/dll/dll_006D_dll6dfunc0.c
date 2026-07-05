/*
 * dll6dfunc0 (DLL 0x6D) - shared save-game / world-progress core lib.
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
 *   - dll_6D_func03: builds a 6-entry modgfx command list (the spirit/aura
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

/* one modgfx draw command in the dll_6D_func03 effect list */
typedef struct
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
extern u8 lbl_80313AF0[];
extern f32 lbl_803E0A78;
extern f32 lbl_803E0A7C;
extern f32 lbl_803E0A80;
extern f32 lbl_803E0A84;
extern f32 lbl_803E0A88;
extern f32 lbl_803E0A8C;
extern f32 lbl_803E0A90;

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
}

void dll_6D_func01_nop(void)
{
}

void dll_6D_func00_nop(void)
{
}

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void dll_6D_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)lbl_80313AF0;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0xe;
    buf.entries[0].tex = &base[212];
    buf.entries[0].mode = 0x80;
    buf.entries[0].x = lbl_803E0A78;
    buf.entries[0].y = lbl_803E0A7C;
    buf.entries[0].z = lbl_803E0A78;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 7;
    buf.entries[1].tex = &base[256];
    buf.entries[1].mode = 4;
    buf.entries[1].x = lbl_803E0A78;
    buf.entries[1].y = lbl_803E0A78;
    buf.entries[1].z = lbl_803E0A78;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[240];
    buf.entries[2].mode = 2;
    buf.entries[2].x = (*(f32*)&lbl_803E0A80);
    buf.entries[2].y = (*(f32*)&lbl_803E0A84);
    buf.entries[2].z = (*(f32*)&lbl_803E0A80);
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[256];
    buf.entries[3].mode = 2;
    buf.entries[3].x = (*(f32*)&lbl_803E0A88);
    buf.entries[3].y = (*(f32*)&lbl_803E0A84);
    buf.entries[3].z = (*(f32*)&lbl_803E0A88);
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 0xe;
    buf.entries[4].tex = &base[212];
    buf.entries[4].mode = 0x4000;
    buf.entries[4].x = lbl_803E0A78;
    buf.entries[4].y = lbl_803E0A8C;
    buf.entries[4].z = lbl_803E0A78;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[240];
    buf.entries[5].mode = 4;
    buf.entries[5].x = lbl_803E0A78;
    buf.entries[5].y = lbl_803E0A78;
    buf.entries[5].z = lbl_803E0A78;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A78;
    buf.pos[1] = lbl_803E0A78;
    buf.pos[2] = lbl_803E0A78;
    buf.col[0] = lbl_803E0A78;
    buf.col[1] = lbl_803E0A78;
    buf.col[2] = lbl_803E0A78;
    buf.scale = lbl_803E0A90;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 6;
    buf.hw[0] = *(s16*)&base[272];
    buf.hw[1] = *(s16*)&base[274];
    buf.hw[2] = *(s16*)&base[276];
    buf.hw[3] = *(s16*)&base[278];
    buf.hw[4] = *(s16*)&base[280];
    buf.hw[5] = *(s16*)&base[282];
    buf.hw[6] = *(s16*)&base[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000004;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0A78 + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E0A78 + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0A78 + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0A78 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0A78 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0A78 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80313AF0, 0xc, &base[140], 0x34, 0);
}
