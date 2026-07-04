/*
 * dll_007A (gameplay/save-progress DLL) - cheat-unlock flags, the save
 * preview/settings block (color preview RGB defaulting to 0x7f), the
 * map-event "act" history ring (DAT_803a3be0.., FUN_800ea9b8) and the
 * per-map act-flag propagation pass (FUN_800e95e8), plus a model-fx
 * command-list spawner (dll_7A_func03) that builds a GfxCmd array on the
 * stack and hands it to gModgfxInterface->spawnEffect.
 *
 * Cheat ids index a bitset in gGameplayRegisteredDebugOptions
 * (saveFileStruct_unlockCheat / isCheatUnlocked). The file-scope DAT_/
 * FUN_ symbols are drift duplicates shared across the dll_005E..dll_007B
 * gameplay DLL family (the canonical copy lives in dll_0060).
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/gameplay_runtime.h"

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
extern char DAT_803a3be0;
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
extern u8 lbl_80314BD0[];
extern f32 lbl_803E0D08;
extern f32 lbl_803E0D0C;
extern f32 lbl_803E0D10;
extern f32 lbl_803E0D14;
extern f32 lbl_803E0D18;
extern f32 lbl_803E0D1C;
extern f32 lbl_803E0D20, lbl_803E0D24, lbl_803E0D28, lbl_803E0D2C;

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

enum
{
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void saveFileStruct_resetVolumes(void)
{
    gGameplayPreviewColorRed = SAVEGAME_DEFAULT_VOLUME;
    gGameplayPreviewColorGreen = SAVEGAME_DEFAULT_VOLUME;
    gGameplayPreviewColorBlue = SAVEGAME_DEFAULT_VOLUME;
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

void dll_7A_func01_nop(void)
{
}

void dll_7A_func00_nop(void)
{
}

int dll_7A_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
    u8* base = (u8*)(int)lbl_80314BD0;
    GfxCmd* entries;
    GfxCmd* e;
    int ret;
    ret = 0;
    entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = 8;
    entries[0].tex = &base[0xa0];
    entries[0].mode = 4;
    entries[0].x = lbl_803E0D08;
    entries[0].y = lbl_803E0D08;
    entries[0].z = lbl_803E0D08;
    entries[1].layer = 0;
    entries[1].flags = 8;
    entries[1].tex = &base[0x8c];
    entries[1].mode = 2;
    entries[1].x = lbl_803E0D0C * (f32)(int)
    randomGetRange(10, 15);
    entries[1].y = lbl_803E0D0C * (f32)(int)
    randomGetRange(10, 15);
    entries[1].z = lbl_803E0D10 * (f32)(int)
    randomGetRange(10, 15);
    entries[2].layer = 0;
    entries[2].flags = 9;
    entries[2].tex = &base[0x8c];
    entries[2].mode = 0x80;
    entries[2].x = lbl_803E0D08;
    entries[2].y = lbl_803E0D08;
    entries[2].z = lbl_803E0D14;
    entries[3].layer = 1;
    entries[3].flags = 0x9c;
    entries[3].tex = 0;
    entries[3].mode = 0x800000;
    entries[3].x = lbl_803E0D18;
    entries[3].y = lbl_803E0D1C;
    entries[3].z = lbl_803E0D08;
    entries[4].layer = 1;
    entries[4].flags = 0;
    entries[4].tex = 0;
    entries[4].mode = 0x400000;
    entries[4].x = (f32)(int)
    randomGetRange(-2000, 200);
    entries[4].y = (f32)(int)
    randomGetRange(-200, 200);
    entries[4].z = (f32)(int)
    randomGetRange(-200, 200);
    entries[5].layer = 1;
    entries[5].flags = 9;
    entries[5].tex = &base[0x8c];
    entries[5].mode = 4;
    entries[5].x = lbl_803E0D08;
    entries[5].y = lbl_803E0D08;
    entries[5].z = lbl_803E0D08;
    e = &entries[6];
    if (variant == 0)
    {
        e->layer = 3;
        e->flags = 0;
        e->tex = 0;
        e->mode = 0x20000000;
        e->x = lbl_803E0D20;
        e->y = lbl_803E0D24;
        e->z = lbl_803E0D28;
        e++;
    }
    buf.ctx = sourceObj;
    buf.v44 = variant;
    if (variant == 0)
    {
        buf.pos[0] = lbl_803E0D08;
        buf.pos[1] = lbl_803E0D08;
        buf.pos[2] = lbl_803E0D08;
    }
    else
    {
        buf.pos[0] = lbl_803E0D08;
        buf.pos[1] = lbl_803E0D2C;
        buf.pos[2] = lbl_803E0D08;
    }
    buf.col[0] = lbl_803E0D08;
    buf.col[1] = lbl_803E0D08;
    buf.col[2] = lbl_803E0D08;
    buf.scale = lbl_803E0D1C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = e - entries;
    buf.hw[0] = *(s16*)&base[0xb0];
    buf.hw[1] = *(s16*)&base[0xb2];
    buf.hw[2] = *(s16*)&base[0xb4];
    buf.hw[3] = *(s16*)&base[0xb6];
    buf.hw[4] = *(s16*)&base[0xb8];
    buf.hw[5] = *(s16*)&base[0xba];
    buf.hw[6] = *(s16*)&base[0xbc];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
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
        buf.v58 = 0;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_80314BD0, 8, &base[0x5c], 0x156, 0);
    }
    else if (variant == 1)
    {
        buf.v58 = 0;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_80314BD0, 8, &base[0x5c], 0xc0d, 0);
    }
    return ret;
}
