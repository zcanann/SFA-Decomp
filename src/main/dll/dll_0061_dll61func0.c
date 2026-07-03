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
extern u8 lbl_803128E8[];
extern int lbl_803DB8C0;
extern f32 lbl_803E0858;
extern f32 lbl_803E085C;
extern f32 lbl_803E0860;
extern f32 lbl_803E0864;
extern f32 lbl_803E0868;
extern f32 lbl_803E0870;
extern f32 lbl_803E0874;
extern f32 lbl_803E0878;
extern f32 lbl_803E087C;
extern f32 lbl_803E0880;
extern f32 lbl_803E0884;
extern f32 lbl_803E088C;
extern f32 lbl_803E086C;
extern f32 lbl_803E0888;

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

void SaveGame_func08_nop(void);

void dll_61_func01_nop(void)
{
}

void dll_61_func00_nop(void)
{
}

void dll_62_func01_nop(void);

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
    f32 t;
    u8* base = (u8*)(int)lbl_803128E8;
    GfxCmd* e;
    e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 8;
    e[0].tex = &base[0xa0];
    e[0].mode = 4;
    e[0].x = lbl_803E0858;
    e[0].y = lbl_803E0858;
    e[0].z = lbl_803E0858;
    e[1].layer = 0;
    e[1].flags = 1;
    e[1].tex = 0;
    e[1].mode = 0x2008000;
    e[1].x = 125.0f;
    e[1].y = 255.0f;
    e[1].z = 125.0f;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = 0;
    e[2].mode = 0x2080000;
    e[2].x = lbl_803E0858;
    e[2].y = 17.0f;
    e[2].z = -17.0f;
    e[3].layer = 0;
    e[3].flags = 9;
    e[3].tex = &base[0x8c];
    e[3].mode = 0x80;
    e[3].x = lbl_803E0858;
    e[3].y = lbl_803E0858;
    e[3].z = (f32) * (s16*)sourceObj;
    e[4].layer = 0;
    e[4].flags = 0x7a;
    e[4].tex = 0;
    e[4].mode = 0x10000;
    e[4].x = lbl_803E0858;
    e[4].y = lbl_803E0858;
    e[4].z = lbl_803E0858;
    e[5].layer = 0;
    e[5].flags = 9;
    e[5].tex = &base[0x8c];
    e[5].mode = 2;
    t = 2.6f + 0.05f * (f32)(int)
    randomGetRange(0, 0xc);
    e[5].x = t;
    e[5].y = t;
    e[5].z = t;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = 0;
    e[6].mode = 0x10000000;
    e[6].x = 28.0f;
    e[6].y = 2.0f;
    e[6].z = lbl_803E0858;
    e[7].layer = 1;
    e[7].flags = 8;
    e[7].tex = &base[0xa0];
    e[7].mode = 0x4000;
    e[7].x = lbl_803E0858;
    e[7].y = -4.0f;
    e[7].z = lbl_803E0858;
    e[8].layer = 1;
    e[8].flags = 9;
    e[8].tex = &base[0x8c];
    e[8].mode = 0x100;
    e[8].x = 600.0f;
    e[8].y = lbl_803E0858;
    e[8].z = lbl_803E0858;
    e[9].layer = 1;
    e[9].flags = 0;
    e[9].tex = 0;
    e[9].mode = 0x400000;
    e[9].x = lbl_803E0858;
    e[9].y = lbl_803E0858;
    e[9].z = -200.0f;
    e[10].layer = 1;
    e[10].flags = 0;
    e[10].tex = 0;
    e[10].mode = 0x2080000;
    e[10].x = lbl_803E0858;
    e[10].y = 17.0f;
    e[10].z = -200.0f;
    e[11].layer = 2;
    e[11].flags = 8;
    e[11].tex = &base[0xa0];
    e[11].mode = 0x4000;
    e[11].x = lbl_803E0858;
    e[11].y = -4.0f;
    e[11].z = lbl_803E0858;
    e[12].layer = 2;
    e[12].flags = 9;
    e[12].tex = &base[0x8c];
    e[12].mode = 0x100;
    e[12].x = 600.0f;
    e[12].y = lbl_803E0858;
    e[12].z = lbl_803E0858;
    e[13].layer = 2;
    e[13].flags = 1;
    e[13].tex = &lbl_803DB8C0;
    e[13].mode = 4;
    e[13].x = lbl_803E0858;
    e[13].y = lbl_803E0858;
    e[13].z = lbl_803E0858;
    e[14].layer = 2;
    e[14].flags = 0;
    e[14].tex = 0;
    e[14].mode = 0x2008000;
    e[14].x = lbl_803E0858;
    e[14].y = lbl_803E0858;
    e[14].z = lbl_803E0858;
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
    buf.count = (GfxCmd*)((u8*)e + 0x168) - e;
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

void dll_62_func03(int sourceObj, int variant, int posSource, u32 flags);
