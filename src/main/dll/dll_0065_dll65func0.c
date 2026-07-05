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
extern u8 lbl_80312E58[];
extern f32 lbl_803E0930;
extern f32 lbl_803E0934;
extern f32 lbl_803E0938;
extern f32 lbl_803E093C;
extern f32 lbl_803E0940;
extern f32 lbl_803E0944;
extern f32 lbl_803E0948;
extern f32 lbl_803E094C;
extern f32 lbl_803E0950;
extern f32 lbl_803E0954;
extern f32 lbl_803E0958;
extern f32 lbl_803E095C;

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

void dll_65_func01_nop(void)
{
}

void dll_65_func00_nop(void)
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

void dll_65_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    GfxCmd* e = buf.entries;
    u8* base = (u8*)(int)lbl_80312E58;
    u8 cnt;
    if (variant == 1)
    {
        *(s16*)&base[274] = 0;
    }
    cnt = *(u8*)(*(int*)(sourceObj + 76) + 26);
    e[0].layer = 0;
    e[0].flags = 7;
    e[0].tex = &base[240];
    e[0].mode = 8;
    e[0].x = lbl_803E0930;
    e[0].y = lbl_803E0930;
    e[0].z = lbl_803E0930;
    e[1].layer = 0;
    e[1].flags = 7;
    e[1].tex = &base[256];
    e[1].mode = 8;
    e[1].x = lbl_803E0934;
    e[1].y = lbl_803E0934;
    e[1].z = lbl_803E0934;
    e[2].layer = 0;
    e[2].flags = 0xe;
    e[2].tex = &base[212];
    e[2].mode = 4;
    e[2].x = lbl_803E0938;
    e[2].y = lbl_803E0938;
    e[2].z = lbl_803E0938;
    e[3].layer = 0;
    e[3].flags = 7;
    e[3].tex = &base[256];
    e[3].mode = 2;
    e[3].x = lbl_803E093C;
    e[3].y = lbl_803E0940;
    e[3].z = lbl_803E093C;
    e[4].layer = 0;
    e[4].flags = 7;
    e[4].tex = &base[240];
    e[4].mode = 2;
    e[4].x = lbl_803E0944;
    e[4].y = lbl_803E0948;
    e[4].z = lbl_803E0944;
    e[5].layer = 1;
    e[5].layer = 1;
    e[5].flags = 0x12;
    e[5].tex = &base[212];
    e[5].mode = 0x100;
    e[5].x = lbl_803E0938;
    e[5].y = lbl_803E0938;
    e[5].z = lbl_803E094C;
    e[6].layer = 1;
    e[6].flags = 7;
    e[6].tex = &base[240];
    e[6].mode = 4;
    e[6].x = lbl_803E0950;
    e[6].y = lbl_803E0938;
    e[6].z = lbl_803E0938;
    e[7].layer = 1;
    e[7].flags = 7;
    e[7].tex = &base[256];
    e[7].mode = 4;
    e[7].x = lbl_803E0954;
    e[7].y = lbl_803E0938;
    e[7].z = lbl_803E0938;
    e[8].layer = 2;
    e[8].flags = 0x12;
    e[8].tex = &base[212];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E0958;
    e[8].y = lbl_803E0938;
    e[8].z = lbl_803E0938;
    e[9].layer = 3;
    e[9].flags = 1;
    e[9].tex = 0;
    e[9].mode = 0x2000;
    e[9].x = lbl_803E0938;
    e[9].y = lbl_803E0938;
    e[9].z = lbl_803E0938;
    e[10].layer = 4;
    e[10].flags = 7;
    e[10].tex = &base[240];
    e[10].mode = 4;
    e[10].x = lbl_803E0938;
    e[10].y = lbl_803E0938;
    e[10].z = lbl_803E0938;
    e[11].layer = 4;
    e[11].flags = 7;
    e[11].tex = &base[256];
    e[11].mode = 4;
    e[11].x = lbl_803E0938;
    e[11].y = lbl_803E0938;
    e[11].z = lbl_803E0938;
    e[12].layer = 4;
    e[12].flags = 0x12;
    e[12].tex = &base[212];
    e[12].mode = 0x4000;
    e[12].x = lbl_803E0958;
    e[12].y = lbl_803E0938;
    e[12].z = lbl_803E0938;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0938;
    buf.pos[1] = lbl_803E0938;
    buf.pos[2] = lbl_803E0938;
    buf.col[0] = lbl_803E0938;
    buf.col[1] = lbl_803E0938;
    buf.col[2] = lbl_803E0938;
    if (cnt != 0)
    {
        buf.scale = lbl_803E095C * (f32)(u32)cnt;
    }
    else
    {
        buf.scale = lbl_803E0948;
    }
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 13;
    buf.hw[0] = *(s16*)&base[272];
    buf.hw[1] = *(s16*)&base[274];
    buf.hw[2] = *(s16*)&base[276];
    buf.hw[3] = *(s16*)&base[278];
    buf.hw[4] = *(s16*)&base[280];
    buf.hw[5] = *(s16*)&base[282];
    buf.hw[6] = *(s16*)&base[284];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x40000c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)buf.ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80312E58, 0xc, &base[140], 0x40, 0);
}
