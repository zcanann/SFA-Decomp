/*
 * dll6efunc0 (DLL 0x6E) - gameplay save / preview-settings support, one of
 * a family of near-identical per-DLL copies (dll_005E..dll_007B).
 *
 * Exposes the savegame helper surface declared in main/dll/gameplay.h:
 * cheat-unlock bits in gGameplayRegisteredDebugOptions
 * (saveFileStruct_unlockCheat / isCheatUnlocked), the preview/debug RGB
 * tint (gGameplayPreviewColorRed/Green/Blue, default 0x7f), the
 * getSaveFileStruct accessor over gGameplayPreviewSettings, and the
 * settings load path (loadSaveSettings).
 *
 * The 0x800e... functions are the DLL's exported entry points (called from
 * other TUs by address), not internal helpers:
 *   FUN_800e82d8 - pointer to the save-file struct base.
 *   FUN_800e8630 - snapshots a game-object's placement id and position.
 *   FUN_800e87a8 - pointer to the save-data field.
 *   FUN_800e8b98 - returns the load-state flag.
 *   FUN_800e8f58 - new-game reset: seeds map acts, opens object groups.
 *   FUN_800e95e8 - toggles a map-event object-group flag bit.
 *   FUN_800e9e9c - commits the save.
 *   FUN_800ea8c8 - dispatches a graphics call through the current history slot.
 *   FUN_800ea9ac - returns the current history head.
 *   FUN_800ea9b8 - records a map visit into the visit history.
 *
 * dll_6E_func03 builds a fixed modgfx command list (GfxCmd entries off
 * lbl_80313C30) and submits it via gModgfxInterface->spawnEffect.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

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
extern u8 lbl_80313C30[];
extern f32 lbl_803E0A9C;

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

void dll_6E_func01_nop(void)
{
}

void dll_6E_func00_nop(void)
{
}

void dll_6E_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)lbl_80313C30;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 5;
    buf.entries[0].tex = &base[84];
    buf.entries[0].mode = 4;
    buf.entries[0].x = 255.0f;
    buf.entries[0].y = lbl_803E0A9C;
    buf.entries[0].z = lbl_803E0A9C;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 5;
    buf.entries[1].tex = &base[84];
    buf.entries[1].mode = 2;
    buf.entries[1].x = 0.01f;
    buf.entries[1].y = 0.01f;
    buf.entries[1].z = 0.01f;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 5;
    buf.entries[2].tex = &base[84];
    buf.entries[2].mode = 8;
    buf.entries[2].x = lbl_803E0A9C;
    buf.entries[2].y = 200.0f;
    buf.entries[2].z = lbl_803E0A9C;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x7a;
    buf.entries[3].tex = NULL;
    buf.entries[3].mode = 0x10000;
    buf.entries[3].x = lbl_803E0A9C;
    buf.entries[3].y = lbl_803E0A9C;
    buf.entries[3].z = lbl_803E0A9C;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 5;
    buf.entries[4].tex = &base[84];
    buf.entries[4].mode = 4;
    buf.entries[4].x = lbl_803E0A9C;
    buf.entries[4].y = lbl_803E0A9C;
    buf.entries[4].z = lbl_803E0A9C;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 5;
    buf.entries[5].tex = &base[84];
    buf.entries[5].mode = 2;
    buf.entries[5].x = 4000.0f;
    buf.entries[5].y = 1.0f;
    buf.entries[5].z = 4000.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A9C;
    buf.pos[1] = 10.0f;
    buf.pos[2] = lbl_803E0A9C;
    buf.col[0] = lbl_803E0A9C;
    buf.col[1] = lbl_803E0A9C;
    buf.col[2] = lbl_803E0A9C;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 5;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = 6;
    buf.hw[0] = *(s16*)&base[96];
    buf.hw[1] = *(s16*)&base[98];
    buf.hw[2] = *(s16*)&base[100];
    buf.hw[3] = *(s16*)&base[102];
    buf.hw[4] = *(s16*)&base[104];
    buf.hw[5] = *(s16*)&base[106];
    buf.hw[6] = *(s16*)&base[108];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000010;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0A9C + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = 10.0f + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0A9C + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0A9C + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = 10.0f + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0A9C + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 5, (u8*)(int)lbl_80313C30, 4, &base[52], 0x5e, 0);
}
