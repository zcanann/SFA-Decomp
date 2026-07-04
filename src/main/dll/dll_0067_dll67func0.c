/*
 * dll67func0 (DLL 0x67) - save-file / map-event support code shared by
 * the gameplay-control DLLs.
 *
 * Provides the canonical bodies for a cluster of save and map-tracking
 * helpers that sibling DLLs (0x63/0x69/0x6A/0x6B/0x6C/0x6D/0xA3, the
 * 0x72-0x76 family) carry as drift duplicates at the same retail
 * addresses:
 *   - debug/cheat option bitmask (saveFileStruct_unlockCheat,
 *     isCheatUnlocked) over gGameplayRegisteredDebugOptions;
 *   - preview RGB volume reset and the save-settings blob accessor
 *     (saveFileStruct_resetVolumes, getSaveFileStruct, loadSaveSettings);
 *   - the map-event group / act tables (FUN_800e8630, FUN_800e8f58,
 *     FUN_800e95e8, FUN_800ea9b8) that record visited maps, set/clear
 *     act flags and maintain the recent-map history ring;
 *   - the save-game UI entry/teardown (FUN_800e9e9c, FUN_800ea8c8);
 *   - dll_67_func03: builds a modgfx command list and spawns a
 *     gameplay-preview effect.
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

/* Engine/save-system entry points and gameplay-state globals owned by the
   main executable; addresses match the retail map (FUN_/DAT_/lbl_). */

extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
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
extern u8 lbl_803133B8[];
extern f32 lbl_803E09C8;
extern f32 lbl_803E09CC;
extern f32 lbl_803E09D0;
extern f32 lbl_803E09D4;
extern f32 lbl_803E09D8;
extern f32 lbl_803E09DC;

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

void dll_67_func01_nop(void)
{
}

void dll_67_func00_nop(void)
{
}

void dll_67_func03(int sourceObj, int variant, int posSource, u32 flags)
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
        s16 variant;
        s16 modelData[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_803133B8;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 0x15;
    buf.entries[0].tex = &base[432];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E09C8;
    buf.entries[0].y = lbl_803E09C8;
    buf.entries[0].z = lbl_803E09C8;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 0x15;
    buf.entries[1].tex = &base[432];
    buf.entries[1].mode = 2;
    buf.entries[1].x = *(f32*)&lbl_803E09CC;
    buf.entries[1].y = lbl_803E09D0;
    buf.entries[1].z = *(f32*)&lbl_803E09CC;
    buf.entries[2].layer = 1;
    buf.entries[2].flags = 7;
    buf.entries[2].tex = &base[372];
    buf.entries[2].mode = 4;
    buf.entries[2].x = lbl_803E09D4;
    buf.entries[2].y = lbl_803E09C8;
    buf.entries[2].z = lbl_803E09C8;
    buf.entries[3].layer = 1;
    buf.entries[3].flags = 0x15;
    buf.entries[3].tex = &base[432];
    buf.entries[3].mode = 0x4000;
    buf.entries[3].x = lbl_803E09C8;
    buf.entries[3].y = lbl_803E09D8;
    buf.entries[3].z = lbl_803E09C8;
    buf.entries[4].layer = 2;
    buf.entries[4].flags = 0x15;
    buf.entries[4].tex = &base[432];
    buf.entries[4].mode = 0x4000;
    buf.entries[4].x = lbl_803E09C8;
    buf.entries[4].y = lbl_803E09D8;
    buf.entries[4].z = lbl_803E09C8;
    buf.entries[5].layer = 3;
    buf.entries[5].flags = 7;
    buf.entries[5].tex = &base[372];
    buf.entries[5].mode = 4;
    buf.entries[5].x = lbl_803E09C8;
    buf.entries[5].y = lbl_803E09C8;
    buf.entries[5].z = lbl_803E09C8;
    buf.entries[6].layer = 3;
    buf.entries[6].flags = 0x15;
    buf.entries[6].tex = &base[432];
    buf.entries[6].mode = 0x4000;
    buf.entries[6].x = lbl_803E09C8;
    buf.entries[6].y = lbl_803E09D8;
    buf.entries[6].z = lbl_803E09C8;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.variant = variant;
    buf.pos[0] = lbl_803E09C8;
    buf.pos[1] = lbl_803E09C8;
    buf.pos[2] = lbl_803E09C8;
    buf.col[0] = lbl_803E09C8;
    buf.col[1] = lbl_803E09C8;
    buf.col[2] = lbl_803E09C8;
    buf.scale = lbl_803E09DC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 7;
    buf.modelData[0] = *(s16*)&base[476];
    buf.modelData[1] = *(s16*)&base[478];
    buf.modelData[2] = *(s16*)&base[480];
    buf.modelData[3] = *(s16*)&base[482];
    buf.modelData[4] = *(s16*)&base[484];
    buf.modelData[5] = *(s16*)&base[486];
    buf.modelData[6] = *(s16*)&base[488];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc010040;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (*(void**)&buf.ctx != 0)
        {
            buf.pos[0] = lbl_803E09C8 + *(f32*)(buf.ctx + 0x18);
            buf.pos[1] = lbl_803E09C8 + *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = lbl_803E09C8 + *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E09C8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E09C8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E09C8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803133B8, 0x18, &base[212], 0xe3, 0);
}
