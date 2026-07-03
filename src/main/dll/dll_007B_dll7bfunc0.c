/*
 * dll7bfunc0 (DLL 0x7B) - save-file / game-progress support DLL.
 *
 * Exposes the save-file accessors (getSaveFileStruct, cheat-unlock and
 * preview-volume helpers) plus the internal save/load machinery shared by
 * many gameplay DLLs: the per-object placement override table
 * (FUN_800e8630), the map-act flag bookkeeping (FUN_800e95e8), the
 * save-to-card path (FUN_800e8f58 / FUN_800e9e9c) and the visited-map
 * history ring (FUN_800ea9b8). dll_7B_func03 builds a modgfx command list
 * on the stack and submits it (the save-icon / preview effect).
 *
 * The FUN_* entry points are left unrenamed pending symbols.txt updates;
 * renaming them is out of scope here.
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

STATIC_ASSERT(sizeof(GfxCmd) == 0x18);

extern ModgfxInterface** gModgfxInterface;
extern u32 FUN_800033a8();
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
extern u8 gDll7BEffectResourceData[];
extern f32 lbl_803E0D38, lbl_803E0D3C, lbl_803E0D40, lbl_803E0D44, lbl_803E0D48, lbl_803E0D4C;
extern f32 lbl_803E0D50, lbl_803E0D54, lbl_803E0D58, lbl_803E0D5C, lbl_803E0D60, lbl_803E0D64;
extern f32 lbl_803E0D68, lbl_803E0D6C, lbl_803E0D70, lbl_803E0D74, lbl_803E0D78;

static inline u8* Gameplay_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (u8*)objAnim->banks[objAnim->bankIndex];
}

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

void dll_7B_func01_nop(void)
{
}

void dll_7B_func00_nop(void)
{
}

enum
{
    SAVEGAME_SLOT_NONE = -1,
    SAVEGAME_PREVIEW_CHANNEL_DEFAULT = 0x7f,
};

void dll_7B_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
        u8 v58, v59, v5a, v5b, v5c; /* 0x5C: not written, structural pad */
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)gDll7BEffectResourceData;
    GfxCmd* e;
    GfxCmd* entries = buf.entries;
    if (variant == 1)
    {
        *(s16*)&base[0x128] = 0x1130;
    }
    else
    {
        *(s16*)&base[0x128] = 100;
    }
    entries[0].layer = 0;
    entries[0].flags = 0xe;
    entries[0].tex = &base[0xf4];
    entries[0].mode = 4;
    entries[0].x = lbl_803E0D38;
    entries[0].y = lbl_803E0D38;
    entries[0].z = lbl_803E0D38;
    if (variant == 1)
    {
        entries[1].layer = 0;
        entries[1].flags = 0xe;
        entries[1].tex = &base[0xf4];
        entries[1].mode = 2;
        entries[1].x = lbl_803E0D3C;
        entries[1].y = lbl_803E0D3C;
        entries[1].z = lbl_803E0D3C;
        e = &entries[2];
    }
    else
    {
        entries[1].layer = 0;
        entries[1].flags = 0xe;
        entries[1].tex = &base[0xf4];
        entries[1].mode = 2;
        entries[1].x = lbl_803E0D3C;
        entries[1].y = lbl_803E0D40 * (f32)(int)
        randomGetRange(3, 5);
        entries[1].z = lbl_803E0D3C;
        e = &entries[2];
    }
    e[0].layer = 0;
    e[0].flags = 0xe;
    e[0].tex = &base[0xf4];
    e[0].mode = 0x80;
    e[0].x = lbl_803E0D38;
    e[0].y = lbl_803E0D38;
    e[0].z = lbl_803E0D44;
    if (variant == 1)
    {
        e[1].layer = 0;
        e[1].flags = 0xe;
        e[1].tex = &base[0xf4];
        e[1].mode = 0x400000;
        e[1].x = lbl_803E0D48;
        e[1].y = lbl_803E0D4C;
        e[1].z = lbl_803E0D38;
        e[2].layer = 0;
        e[2].flags = 0x190;
        e[2].tex = NULL;
        e[2].mode = 0x20000000;
        e[2].x = lbl_803E0D50;
        e[2].y = lbl_803E0D54;
        e[2].z = lbl_803E0D58;
        e[3].layer = 0;
        e[3].flags = 0;
        e[3].tex = NULL;
        e[3].mode = 0x80000;
        e[3].x = lbl_803E0D5C;
        e[3].y = lbl_803E0D60;
        e[3].z = lbl_803E0D38;
        e += 4;
    }
    else
    {
        e[1].layer = 0;
        e[1].flags = 0xe;
        e[1].tex = &base[0xf4];
        e[1].mode = 0x400000;
        e[1].x = lbl_803E0D64 + (f32)(int)
        randomGetRange(0, 0x14);
        e[1].y = lbl_803E0D4C;
        e[1].z = (f32)(int)
        randomGetRange(0, 0x1e);
        e += 2;
    }
    e[0].layer = 1;
    e[0].flags = 10;
    e[0].tex = &base[0x110];
    e[0].mode = 4;
    e[0].x = lbl_803E0D68;
    e[0].y = lbl_803E0D38;
    e[0].z = lbl_803E0D38;
    e[1].layer = 1;
    e[1].flags = 0xe;
    e[1].tex = &base[0xf4];
    e[1].mode = 2;
    e[1].x = lbl_803E0D3C;
    e[1].y = lbl_803E0D3C;
    e[1].z = lbl_803E0D3C;
    e += 2;
    if (variant != 1)
    {
        e[0].layer = 2;
        e[0].flags = 0xe;
        e[0].tex = &base[0xf4];
        e[0].mode = 0x400000;
        e[0].x = lbl_803E0D6C * (f32)(int)
        randomGetRange(1, 0x28);
        e[0].y = lbl_803E0D38;
        e[0].z = lbl_803E0D38;
        e += 1;
    }
    e[0].layer = 2;
    e[0].flags = 0xe;
    e[0].tex = &base[0xf4];
    e[0].mode = 0x4000;
    e[0].x = lbl_803E0D70 * (f32)(int)
    randomGetRange(-3, 3);
    e[0].y = lbl_803E0D38;
    e[0].z = lbl_803E0D38;
    e[1].layer = 3;
    e[1].flags = 0xe;
    e[1].tex = &base[0xf4];
    e[1].mode = 0x4000;
    e[1].x = lbl_803E0D74;
    e[1].y = lbl_803E0D38;
    e[1].z = lbl_803E0D38;
    e[2].layer = 3;
    e[2].flags = 10;
    e[2].tex = &base[0x110];
    e[2].mode = 4;
    e[2].x = lbl_803E0D38;
    e[2].y = lbl_803E0D38;
    e[2].z = lbl_803E0D38;
    e += 3;
    if (variant == 1)
    {
        e[0].layer = 3;
        e[0].flags = 0;
        e[0].tex = NULL;
        e[0].mode = 0x20000000;
        e[0].x = lbl_803E0D50;
        e[0].y = lbl_803E0D54;
        e[0].z = lbl_803E0D58;
        e += 1;
    }
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0D38;
    buf.pos[1] = lbl_803E0D78;
    buf.pos[2] = lbl_803E0D38;
    buf.col[0] = lbl_803E0D38;
    buf.col[1] = lbl_803E0D38;
    buf.col[2] = lbl_803E0D38;
    buf.scale = lbl_803E0D3C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = randomGetRange(0x18, 0x1c);
    buf.count = e - entries;
    buf.hw[0] = *(s16*)&base[0x124];
    buf.hw[1] = *(s16*)&base[0x126];
    buf.hw[2] = *(s16*)&base[0x128];
    buf.hw[3] = *(s16*)&base[0x12a];
    buf.hw[4] = *(s16*)&base[0x12c];
    buf.hw[5] = *(s16*)&base[0x12e];
    buf.hw[6] = *(s16*)&base[0x130];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x1000000;
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)gDll7BEffectResourceData, 0xc, &base[0x8c], 0x8e, 0);
}

u8 gDll7BEffectResourceData[308] = {
    244, 72, 0, 0, 254, 212, 0, 0, 0, 0, 247, 104, 0, 0, 1, 244,
    0, 6, 0, 0, 252, 24, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0,
    0, 0, 253, 168, 0, 16, 0, 0, 3, 232, 0, 0, 0, 0, 0, 21,
    0, 0, 8, 152, 0, 0, 2, 188, 0, 26, 0, 0, 11, 184, 0, 0,
    1, 44, 0, 31, 0, 0, 244, 72, 3, 32, 0, 0, 0, 0, 0, 31,
    247, 104, 5, 220, 254, 112, 0, 6, 0, 31, 252, 24, 5, 20, 0, 0,
    0, 22, 0, 31, 0, 0, 5, 220, 3, 132, 0, 11, 0, 31, 3, 232,
    4, 176, 254, 212, 0, 16, 0, 31, 8, 152, 5, 220, 0, 0, 0, 26,
    0, 31, 11, 184, 3, 32, 2, 188, 0, 31, 0, 31, 0, 0, 0, 8,
    0, 7, 0, 0, 0, 1, 0, 8, 0, 1, 0, 9, 0, 8, 0, 1,
    0, 2, 0, 9, 0, 2, 0, 10, 0, 9, 0, 2, 0, 3, 0, 10,
    0, 3, 0, 11, 0, 10, 0, 3, 0, 4, 0, 11, 0, 4, 0, 12,
    0, 11, 0, 4, 0, 5, 0, 12, 0, 5, 0, 13, 0, 12, 0, 5,
    0, 6, 0, 13, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
    0, 6, 0, 0, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12,
    0, 13, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
    0, 6, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13,
    0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 8, 0, 9, 0, 10,
    0, 11, 0, 12, 0, 0, 0, 50, 0, 200, 0, 50, 0, 0, 0, 0,
    0, 0, 0, 0,
};
