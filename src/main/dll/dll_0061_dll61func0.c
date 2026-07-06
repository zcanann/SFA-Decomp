/*
 * DLL 61 (dll61func0): savegame preview/debug settings plus a Modgfx effect
 * spawner. Exposes cheat-unlock and preview-volume/color accessors over the
 * gameplay save struct, applies those settings on load, and builds a GfxCmd
 * command table dispatched through gModgfxInterface->spawnEffect.
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
extern u8 lbl_803128E8[];
extern int lbl_803DB8C0;
extern f32 lbl_803E0858;

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
}

void dll_61_func01_nop(void)
{
}

void dll_61_func00_nop(void)
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

#pragma fp_contract off
void dll_61_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    f32 randScale;
    u8* base = (u8*)(int)lbl_803128E8;
    GfxCmd* entry;
    entry = buf.entries;
    entry[0].layer = 0;
    entry[0].flags = 8;
    entry[0].tex = &base[0xa0];
    entry[0].mode = 4;
    entry[0].x = lbl_803E0858;
    entry[0].y = lbl_803E0858;
    entry[0].z = lbl_803E0858;
    entry[1].layer = 0;
    entry[1].flags = 1;
    entry[1].tex = 0;
    entry[1].mode = 0x2008000;
    entry[1].x = 125.0f;
    entry[1].y = 255.0f;
    entry[1].z = 125.0f;
    entry[2].layer = 0;
    entry[2].flags = 0;
    entry[2].tex = 0;
    entry[2].mode = 0x2080000;
    entry[2].x = lbl_803E0858;
    entry[2].y = 17.0f;
    entry[2].z = -17.0f;
    entry[3].layer = 0;
    entry[3].flags = 9;
    entry[3].tex = &base[0x8c];
    entry[3].mode = 0x80;
    entry[3].x = lbl_803E0858;
    entry[3].y = lbl_803E0858;
    entry[3].z = (f32) * (s16*)sourceObj;
    entry[4].layer = 0;
    entry[4].flags = 0x7a;
    entry[4].tex = 0;
    entry[4].mode = 0x10000;
    entry[4].x = lbl_803E0858;
    entry[4].y = lbl_803E0858;
    entry[4].z = lbl_803E0858;
    entry[5].layer = 0;
    entry[5].flags = 9;
    entry[5].tex = &base[0x8c];
    entry[5].mode = 2;
    randScale = 2.6f + 0.05f * (f32)(int)
    randomGetRange(0, 0xc);
    entry[5].x = randScale;
    entry[5].y = randScale;
    entry[5].z = randScale;
    entry[6].layer = 1;
    entry[6].flags = 0;
    entry[6].tex = 0;
    entry[6].mode = 0x10000000;
    entry[6].x = 28.0f;
    entry[6].y = 2.0f;
    entry[6].z = lbl_803E0858;
    entry[7].layer = 1;
    entry[7].flags = 8;
    entry[7].tex = &base[0xa0];
    entry[7].mode = 0x4000;
    entry[7].x = lbl_803E0858;
    entry[7].y = -4.0f;
    entry[7].z = lbl_803E0858;
    entry[8].layer = 1;
    entry[8].flags = 9;
    entry[8].tex = &base[0x8c];
    entry[8].mode = 0x100;
    entry[8].x = 600.0f;
    entry[8].y = lbl_803E0858;
    entry[8].z = lbl_803E0858;
    entry[9].layer = 1;
    entry[9].flags = 0;
    entry[9].tex = 0;
    entry[9].mode = 0x400000;
    entry[9].x = lbl_803E0858;
    entry[9].y = lbl_803E0858;
    entry[9].z = -200.0f;
    entry[10].layer = 1;
    entry[10].flags = 0;
    entry[10].tex = 0;
    entry[10].mode = 0x2080000;
    entry[10].x = lbl_803E0858;
    entry[10].y = 17.0f;
    entry[10].z = -200.0f;
    entry[11].layer = 2;
    entry[11].flags = 8;
    entry[11].tex = &base[0xa0];
    entry[11].mode = 0x4000;
    entry[11].x = lbl_803E0858;
    entry[11].y = -4.0f;
    entry[11].z = lbl_803E0858;
    entry[12].layer = 2;
    entry[12].flags = 9;
    entry[12].tex = &base[0x8c];
    entry[12].mode = 0x100;
    entry[12].x = 600.0f;
    entry[12].y = lbl_803E0858;
    entry[12].z = lbl_803E0858;
    entry[13].layer = 2;
    entry[13].flags = 1;
    entry[13].tex = &lbl_803DB8C0;
    entry[13].mode = 4;
    entry[13].x = lbl_803E0858;
    entry[13].y = lbl_803E0858;
    entry[13].z = lbl_803E0858;
    entry[14].layer = 2;
    entry[14].flags = 0;
    entry[14].tex = 0;
    entry[14].mode = 0x2008000;
    entry[14].x = lbl_803E0858;
    entry[14].y = lbl_803E0858;
    entry[14].z = lbl_803E0858;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0858;
    buf.pos[1] = 17.0f;
    buf.pos[2] = -40.0f;
    buf.col[0] = lbl_803E0858;
    buf.col[1] = lbl_803E0858;
    buf.col[2] = lbl_803E0858;
    buf.scale = 1.0f;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (GfxCmd*)((u8*)entry + 0x168) - entry;
    buf.hw[0] = *(s16*)&base[0xb0];
    buf.hw[1] = *(s16*)&base[0xb2];
    buf.hw[2] = *(s16*)&base[0xb4];
    buf.hw[3] = *(s16*)&base[0xb6];
    buf.hw[4] = *(s16*)&base[0xb8];
    buf.hw[5] = *(s16*)&base[0xba];
    buf.hw[6] = *(s16*)&base[0xbc];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000010;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E0858 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = 17.0f + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = -40.0f + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0858 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = 17.0f + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = -40.0f + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)lbl_803128E8, 8, &base[0x5c], 0x90, 0);
}
#pragma fp_contract reset
