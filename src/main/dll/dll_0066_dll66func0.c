/*
 * dll66func0 (DLL 0x66) - gameplay save / preview-settings support, one of
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
 *   FUN_800e82d8 - pointer to the save-file struct base at DAT_803a4460.
 *   FUN_800e8630 - snapshots a game-object's placement id and position into
 *                  a per-mapId player-save slot.
 *   FUN_800e87a8 - pointer to the save-data field DAT_803a45b0.
 *   FUN_800e8b98 - returns the load-state flag DAT_803de100.
 *   FUN_800e8f58 - new-game reset: seeds every map act to 1, opens a fixed
 *                  set of object groups (FUN_800e95e8), writes the header.
 *   FUN_800e95e8 - toggles a map-event object-group flag bit, mirroring it
 *                  across the cached act/group words and the recently-changed
 *                  history ring at DAT_803a3be0.
 *   FUN_800e9e9c - commits the save.
 *   FUN_800ea8c8 - dispatches a graphics call through the current history slot.
 *   FUN_800ea9ac - returns the current history head.
 *   FUN_800ea9b8 - records a map visit into the visit history.
 *
 * dll_66_func03 builds a fixed modgfx command list (GfxCmd entries off
 * lbl_803131A8) and submits it via gModgfxInterface->spawnEffect.
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
extern u64 FUN_80003494();
extern u32 FUN_80006768();
extern u32 FUN_8000676c();
extern u32 FUN_80006770();
extern int FUN_80006b7c();
extern u32 FUN_80006b84();
extern u32 FUN_80006b8c();
extern u32 FUN_80006c20();
extern u32 FUN_80017488();
extern u32 FUN_80017498();
extern u32 FUN_80017500();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern u32 FUN_800176cc();
extern u32 FUN_800176dc();
extern u32 FUN_80042b9c();
extern u32 FUN_8005d018();
extern u32 FUN_80072564();
extern u32 FUN_800d783c();
extern u32 FUN_8011e80c();
extern s64 FUN_80286830();
extern u32 FUN_80286834();
extern u32 FUN_8028687c();
extern u32 FUN_80286880();
extern u32 DAT_802c28f0;
extern u32 DAT_802c28f4;
extern u32 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern u32 DAT_80312630;
extern short DAT_80312632;
extern char DAT_803a3be0;
extern u32 DAT_803a3be1;
extern u32 DAT_803a3be2;
extern u32 DAT_803a3c1c;
extern u32 DAT_803a3dac;
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
extern u8 DAT_803a3f08;
extern u32 DAT_803a3f09;
extern u32 DAT_803a3f0c;
extern u32 DAT_803a3f0e;
extern u32 DAT_803a3f12;
extern u32 DAT_803a3f14;
extern u32 DAT_803a3f15;
extern u32 DAT_803a3f18;
extern u32 DAT_803a3f1a;
extern u32 DAT_803a3f1e;
extern u32 DAT_803a3f21;
extern char DAT_803a3f24;
extern u32 DAT_803a3f25;
extern u32 DAT_803a3f26;
extern u32 DAT_803a3f27;
extern u32 DAT_803a3f28;
extern u32 DAT_803a3f29;
extern u32 DAT_803a3f2b;
extern u32 DAT_803a4070;
extern u32 DAT_803a4074;
extern u32 DAT_803a4078;
extern u32 DAT_803a407c;
extern u32 DAT_803a4460;
extern u32 DAT_803a4465;
extern u32 DAT_803a458c;
extern u32 DAT_803a4590;
extern u32 DAT_803a4594;
extern u32 DAT_803a4599;
extern u32 DAT_803a459a;
extern u32 DAT_803a45aa;
extern u32 DAT_803a45ac;
extern u32 DAT_803a45b0;
extern u32 DAT_803a45b4;
extern u32 DAT_803a45b6;
extern u32 DAT_803a45ba;
extern u32 DAT_803a45bc;
extern u32 DAT_803a45be;
extern u32 DAT_803a45c0;
extern u32 DAT_803a45c2;
extern u32 DAT_803a45f0;
extern u32 DAT_803a45f1;
extern u32 DAT_803a45f2;
extern u32 DAT_803a45f3;
extern u32 DAT_803a4e78;
extern u32 DAT_803dc4f0;
extern u32* DAT_803dd6d0;
extern u32* DAT_803dd6e8;
extern u32 DAT_803de100;
extern u32 DAT_803de104;
extern u32 DAT_803de10c;
extern u32* DAT_803de110;
extern f32 lbl_803E1348;
extern u32 uRam803de108;
extern u8 lbl_803131A8[];
extern f32 lbl_803E0990;
extern f32 lbl_803E0994;
extern f32 lbl_803E0998;
extern f32 lbl_803E099C;
extern f32 lbl_803E09A0;
extern f32 lbl_803E09A4;
extern f32 lbl_803E09A8;
extern f32 lbl_803E09AC;
extern f32 lbl_803E09B0;
extern f32 lbl_803E09B4;
extern f32 lbl_803E09B8;
extern f32 lbl_803E09BC;
extern f32 lbl_803E09C0;

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

void SaveGame_func08_nop(void);

void dll_66_func01_nop(void)
{
}

void dll_66_func00_nop(void)
{
}

void dll_67_func01_nop(void);

void dll_66_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)lbl_803131A8;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x15;
    buf.entries[0].tex = &base[432];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E0990;
    buf.entries[0].y = lbl_803E0990;
    buf.entries[0].z = lbl_803E0990;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x15;
    buf.entries[1].tex = &base[432];
    buf.entries[1].mode = 2;
    buf.entries[1].x = 0.01f;
    buf.entries[1].y = 2.0f;
    buf.entries[1].z = 0.01f;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 0x50;
    buf.entries[2].tex = NULL;
    buf.entries[2].mode = 0x20000000;
    buf.entries[2].x = 999.0f;
    buf.entries[2].y = 18.0f;
    buf.entries[2].z = 19.0f;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0;
    buf.entries[3].tex = NULL;
    buf.entries[3].mode = 0x80000;
    buf.entries[3].x = lbl_803E0990;
    buf.entries[3].y = 450.0f;
    buf.entries[3].z = lbl_803E0990;
    buf.entries[4].layer = 0;
    buf.entries[4].flags = 0;
    buf.entries[4].tex = NULL;
    buf.entries[4].mode = 0x400000;
    buf.entries[4].x = lbl_803E0990;
    buf.entries[4].y = 100.0f;
    buf.entries[4].z = lbl_803E0990;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 0x15;
    buf.entries[5].tex = &base[432];
    buf.entries[5].mode = 2;
    buf.entries[5].x = 200.0f;
    buf.entries[5].y = 1.0f;
    buf.entries[5].z = 200.0f;
    buf.entries[6].layer = 1;
    buf.entries[6].flags = 7;
    buf.entries[6].tex = &base[372];
    buf.entries[6].mode = 4;
    buf.entries[6].x = 255.0f;
    buf.entries[6].y = lbl_803E0990;
    buf.entries[6].z = lbl_803E0990;
    buf.entries[7].layer = 1;
    buf.entries[7].flags = 0x15;
    buf.entries[7].tex = &base[432];
    buf.entries[7].mode = 0x4000;
    buf.entries[7].x = lbl_803E0990;
    buf.entries[7].y = 2.0f;
    buf.entries[7].z = lbl_803E0990;
    buf.entries[8].layer = 1;
    buf.entries[8].flags = 0;
    buf.entries[8].tex = NULL;
    buf.entries[8].mode = 0x100;
    buf.entries[8].x = lbl_803E0990;
    buf.entries[8].y = lbl_803E0990;
    buf.entries[8].z = -150.0f;
    buf.entries[9].layer = 1;
    buf.entries[9].flags = 0;
    buf.entries[9].tex = NULL;
    buf.entries[9].mode = 0x80000;
    buf.entries[9].x = lbl_803E0990;
    buf.entries[9].y = 100.0f;
    buf.entries[9].z = lbl_803E0990;
    buf.entries[10].layer = 1;
    buf.entries[10].flags = 0;
    buf.entries[10].tex = NULL;
    buf.entries[10].mode = 0x400000;
    buf.entries[10].x = lbl_803E0990;
    buf.entries[10].y = lbl_803E0990;
    buf.entries[10].z = lbl_803E0990;
    buf.entries[11].layer = 2;
    buf.entries[11].flags = 0x15;
    buf.entries[11].tex = &base[432];
    buf.entries[11].mode = 0x4000;
    buf.entries[11].x = lbl_803E0990;
    buf.entries[11].y = 2.0f;
    buf.entries[11].z = lbl_803E0990;
    buf.entries[12].layer = 2;
    buf.entries[12].flags = 0;
    buf.entries[12].tex = NULL;
    buf.entries[12].mode = 0x100;
    buf.entries[12].x = lbl_803E0990;
    buf.entries[12].y = lbl_803E0990;
    buf.entries[12].z = -150.0f;
    buf.entries[13].layer = 3;
    buf.entries[13].flags = 0;
    buf.entries[13].tex = NULL;
    buf.entries[13].mode = 0x80000;
    buf.entries[13].x = lbl_803E0990;
    buf.entries[13].y = -450.0f;
    buf.entries[13].z = lbl_803E0990;
    buf.entries[14].layer = 3;
    buf.entries[14].flags = 7;
    buf.entries[14].tex = &base[372];
    buf.entries[14].mode = 4;
    buf.entries[14].x = lbl_803E0990;
    buf.entries[14].y = lbl_803E0990;
    buf.entries[14].z = lbl_803E0990;
    buf.entries[15].layer = 3;
    buf.entries[15].flags = 0x15;
    buf.entries[15].tex = &base[432];
    buf.entries[15].mode = 0x4000;
    buf.entries[15].x = lbl_803E0990;
    buf.entries[15].y = 2.0f;
    buf.entries[15].z = lbl_803E0990;
    buf.entries[16].layer = 3;
    buf.entries[16].flags = 0;
    buf.entries[16].tex = NULL;
    buf.entries[16].mode = 0x100;
    buf.entries[16].x = lbl_803E0990;
    buf.entries[16].y = lbl_803E0990;
    buf.entries[16].z = -150.0f;
    buf.entries[17].layer = 3;
    buf.entries[17].flags = 0x15;
    buf.entries[17].tex = &base[432];
    buf.entries[17].mode = 2;
    buf.entries[17].x = 0.01f;
    buf.entries[17].y = 1.0f;
    buf.entries[17].z = 0.01f;
    buf.entries[18].layer = 3;
    buf.entries[18].flags = 0;
    buf.entries[18].tex = NULL;
    buf.entries[18].mode = 0x400000;
    buf.entries[18].x = lbl_803E0990;
    buf.entries[18].y = 200.0f;
    buf.entries[18].z = lbl_803E0990;
    buf.entries[18].layer = 4;
    buf.entries[18].flags = 0;
    buf.entries[18].tex = NULL;
    buf.entries[18].mode = 0x20000000;
    buf.entries[18].x = 999.0f;
    buf.entries[18].y = 18.0f;
    buf.entries[18].z = 19.0f;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0990;
    buf.pos[1] = lbl_803E0990;
    buf.pos[2] = lbl_803E0990;
    buf.col[0] = lbl_803E0990;
    buf.col[1] = lbl_803E0990;
    buf.col[2] = lbl_803E0990;
    buf.scale = 1.0f;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 20;
    buf.hw[0] = *(s16*)&base[476];
    buf.hw[1] = *(s16*)&base[478];
    buf.hw[2] = *(s16*)&base[480];
    buf.hw[3] = *(s16*)&base[482];
    buf.hw[4] = *(s16*)&base[484];
    buf.hw[5] = *(s16*)&base[486];
    buf.hw[6] = *(s16*)&base[488];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc010080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0990 + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0990 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0990 + *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0990 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0990 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0990 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803131A8, 0x18, &base[212], 0x155, 0);
}

void dll_67_func03(int sourceObj, int variant, int posSource, u32 flags);
