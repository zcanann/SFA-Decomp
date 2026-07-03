/*
 * dll73func0 (DLL 0x73) - save-file / gameplay-options service DLL.
 *
 * Owns the gameplay preview/options block (gGameplayPreview*) and the
 * registered-debug-cheat bitmask (saveFileStruct_unlockCheat /
 * isCheatUnlocked), and drives new-game setup, the save/load flow and the
 * map-act + visited-map history bookkeeping. FUN_800e8f58 initialises a
 * fresh game (clears the 0x78 per-map act table, seeds the default map
 * acts and the FOX initials), FUN_800e9e9c commits a save, FUN_800e95e8
 * sets/clears a map-act flag (mode -1 = set, -2 = transient clear) and
 * mirrors it into the transient-bit shadow, and FUN_800ea9b8 records a
 * newly-visited map into the 5-entry recent-map history. dll_73_func03 is
 * the modgfx spirit/effect spawner exported to sibling DLLs.
 *
 * Most file-scope FUN_/DAT_ symbols live in this DLL but are exported by
 * name to the sibling savegame DLLs (dll_005E..dll_007B, dll_00A3,
 * dll_0017).
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
extern u8 lbl_803144B0[];
extern f32 lbl_803E0B80;
extern f32 lbl_803E0B84;
extern f32 lbl_803E0B88;
extern f32 lbl_803E0B8C;
extern f32 lbl_803E0B90;
extern f32 lbl_803E0B94;
extern f32 lbl_803E0B98;
extern f32 lbl_803E0B9C;
extern f32 lbl_803E0BA0;
extern f32 lbl_803E0BA4;
extern f32 lbl_803E0BA8;
extern f32 lbl_803E0BAC;

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

void dll_73_func01_nop(void)
{
}

void dll_73_func00_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* lbl = N (byte) */

/* 12b 3-insn patterns. */

/* misc 8b leaves */

/* if (lbl) fn(lbl); */

enum
{
    SAVEGAME_EMPTY_TASK_HINT = -1,
    SAVEGAME_DEFAULT_VOLUME = 0x7f,
};

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
    e[8].x = (f32)(int)
    randomGetRange(0x64, 0xff);
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
    e[10].x = (f32)(int)
    randomGetRange(0x64, 0xff);
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803144B0, 0x18, &base[212], 0xd9, 0);
}
