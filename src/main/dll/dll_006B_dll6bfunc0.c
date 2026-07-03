/*
 * dll_006B (dll6bfunc0) - a small gameplay DLL whose only live export is
 * func03: a one-shot spawner that builds a 6-command Modgfx draw list on
 * the stack and submits it through (*gModgfxInterface)->spawnEffect. The
 * command template and its geometry/colour constants are read from the
 * lbl_80313A40 data blob and the lbl_803E0A* float pool. When the request
 * flag bit 0 is set, the world position is taken either from the source
 * object (sourceObj+0x18..0x20) or from the PartFxSpawnParams packet.
 *
 * func00/func01 are the DLL's empty lifecycle hooks. (The Ghidra dump of
 * this TU also carried a large block of mainDol drift duplicates -
 * save-file/cheat/map-history helpers - that the linker drops at this
 * address range; only these three functions belong to DLL 0x6B.)
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
extern u8 lbl_80313A40[];
extern f32 lbl_803E0A58;
extern f32 lbl_803E0A5C;
extern f32 lbl_803E0A60;
extern f32 lbl_803E0A64;
extern f32 lbl_803E0A68;
extern f32 lbl_803E0A6C;
extern f32 lbl_803E0A70;

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

void dll_6B_func01_nop(void)
{
}

void dll_6B_func00_nop(void)
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

void dll_6B_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)lbl_80313A40;
    int ctx;
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 5;
    buf.entries[0].tex = &base[84];
    buf.entries[0].mode = 4;
    buf.entries[0].x = lbl_803E0A58;
    buf.entries[0].y = lbl_803E0A5C;
    buf.entries[0].z = lbl_803E0A5C;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 5;
    buf.entries[1].tex = &base[84];
    buf.entries[1].mode = 2;
    buf.entries[1].x = lbl_803E0A60;
    buf.entries[1].y = lbl_803E0A60;
    buf.entries[1].z = lbl_803E0A60;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 5;
    buf.entries[2].tex = &base[84];
    buf.entries[2].mode = 8;
    buf.entries[2].x = lbl_803E0A64;
    buf.entries[2].y = lbl_803E0A64;
    buf.entries[2].z = lbl_803E0A64;
    buf.entries[3].layer = 0;
    buf.entries[3].flags = 0x7a;
    buf.entries[3].tex = 0;
    buf.entries[3].mode = 0x10000;
    buf.entries[3].x = lbl_803E0A5C;
    buf.entries[3].y = lbl_803E0A5C;
    buf.entries[3].z = lbl_803E0A5C;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 5;
    buf.entries[4].tex = &base[84];
    buf.entries[4].mode = 4;
    buf.entries[4].x = lbl_803E0A5C;
    buf.entries[4].y = lbl_803E0A5C;
    buf.entries[4].z = lbl_803E0A5C;
    buf.entries[5].layer = 1;
    buf.entries[5].flags = 5;
    buf.entries[5].tex = &base[84];
    buf.entries[5].mode = 2;
    buf.entries[5].x = (*(f32*)&lbl_803E0A68);
    buf.entries[5].y = (*(f32*)&lbl_803E0A6C);
    buf.entries[5].z = (*(f32*)&lbl_803E0A68);
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A5C;
    buf.pos[1] = (*(f32*)&lbl_803E0A70);
    buf.pos[2] = lbl_803E0A5C;
    buf.col[0] = lbl_803E0A5C;
    buf.col[1] = lbl_803E0A5C;
    buf.col[2] = lbl_803E0A5C;
    buf.scale = (*(f32*)&lbl_803E0A6C);
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
            buf.pos[0] = lbl_803E0A5C + *(f32*)(ctx + 0x18);
            buf.pos[1] = lbl_803E0A70 + *(f32*)(ctx + 0x1c);
            buf.pos[2] = lbl_803E0A5C + *(f32*)(ctx + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E0A5C + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0A70 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0A5C + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 5, (u8*)(int)lbl_80313A40, 4, &base[52], 0x5e, 0);
}
