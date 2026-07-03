/*
 * dll_0060 (gameplay/save-progress DLL) - cheat-unlock flags, the save
 * preview/settings block (color preview RGB defaulting to 0x7f), the
 * map-event "act" history ring (DAT_803a3be0.., FUN_800ea9b8) and the
 * per-map act-flag propagation pass (FUN_800e95e8), plus a model-fx
 * command-list spawner (dll_60_func03) that builds a GfxCmd array on the
 * stack and hands it to gModgfxInterface->spawnEffect.
 *
 * Cheat ids index a bitset in gGameplayRegisteredDebugOptions
 * (saveFileStruct_unlockCheat / isCheatUnlocked). Most file-scope DAT_/
 * FUN_ symbols are drift duplicates shared across the dll_005E..dll_007B
 * gameplay DLL family.
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
extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
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
extern u64 FUN_80286840();
extern u32 FUN_8028687c();
extern u32 FUN_80286880();
extern u32 FUN_8028688c();
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
extern f32 lbl_803E0830;
extern f32 lbl_803E0834;
extern f32 lbl_803E0838;
extern f32 lbl_803E083C;
extern f32 lbl_803E0840;
extern f32 lbl_803E0844;
extern f32 lbl_803E0848;
extern f32 lbl_803E084C;
extern u8 lbl_80312790[];

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

void dll_60_func01_nop(void)
{
}

void dll_60_func00_nop(void)
{
}

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

void dll_60_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
    e[2].x = lbl_803E0838 + (f32)(int)
    randomGetRange(0, 0x69);
    e[2].y = lbl_803E0838 + (f32)(int)
    randomGetRange(0, 0x69);
    e[2].z = lbl_803E0838 + (f32)(int)
    randomGetRange(0, 0x69);
    e[3].layer = 0;
    e[3].flags = 0x7a;
    e[3].tex = 0;
    e[3].mode = 0x10000;
    e[3].x = lbl_803E0830;
    e[3].y = lbl_803E0830;
    e[3].z = lbl_803E0830;
    z4 = (f32)(int)
    randomGetRange(0, 0xfffe);
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
            buf.pos[0] = lbl_803E0830 + *(f32*)(buf.ctx + 0x18);
            buf.pos[1] = lbl_803E0840 + *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = lbl_803E0830 + *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0830 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0840 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0830 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80312790, 0xc, &base[140], 0x46, 0);
}
