/*
 * dll63func0 (DLL 0x63) - gameplay save/preview-settings and map-event
 * flag bookkeeping.
 *
 * Provides the savegame helper surface (declared in main/dll/gameplay.h):
 * cheat-unlock bits in gGameplayRegisteredDebugOptions, the preview/debug
 * colour settings (gGameplayPreviewColorRed/Green/Blue, default 0x7f), the
 * getSaveFileStruct accessor over gGameplayPreviewSettings, settings load
 * (loadSaveSettings), and the new-game reset path (newGame_reset) that seeds
 * every map act to 1, opens a fixed set of object groups (setObjGroupStatus),
 * and writes the save header.
 *
 * saveObjectPos stashes an object's position into a per-mapId slot table
 * (the saveGame_unsaveObjectPos sibling). setObjGroupStatus toggles a map-event
 * object-group flag bit, mirroring it across the group/act tables and into
 * the recently-changed history ring at DAT_803a3be0. advanceMapHistory advances
 * the map-visit history.
 *
 * dll_63_func03 builds a per-object bone-particle command list (GfxCmd
 * entries) and submits it via gModgfxInterface->spawnEffect; variant
 * selects the texture/offset set and posSource supplies an optional
 * scale/position from a PartFxSpawnParams packet.
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
extern u8 lbl_80312BD8[];
extern f32 lbl_803E08C8, lbl_803E08CC, lbl_803E08D0, lbl_803E08D4, lbl_803E08D8, lbl_803E08DC;
extern f32 lbl_803E08E0, lbl_803E08E4, lbl_803E08E8, lbl_803E08EC, lbl_803E08F0, lbl_803E08F4;
extern f32 lbl_803E08F8, lbl_803E08FC;

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

void dll_63_func01_nop(void)
{
}

void dll_63_func00_nop(void)
{
}

#pragma inline_max_size(4000)
static inline void dll_63_func03Body(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
    u32 flag;
    int i;
    s16* rec;
    GfxCmd* entries;
    GfxCmd* cmd;
    u8* base = (u8*)(int)lbl_80312BD8;
    if (variant == 1)
    {
        *(s16*)&base[0x112] = 0;
    }
    flag = *(u8*)(*(u8**)&((GameObject*)sourceObj)->anim.placementData + 0x1a);
    if (variant == 2)
    {
        for (i = 0, rec = (s16*)base; i < 14; i++)
        {
            if (rec[0] > 0)
            {
                rec[0] += randomGetRange(0, 800);
            }
            else if (rec[0] < 0)
            {
                rec[0] -= randomGetRange(0, 800);
            }
            if (rec[1] > 0)
            {
                rec[0] += randomGetRange(0, 300);
            }
            else if (rec[1] < 0)
            {
                rec[0] -= randomGetRange(0, 300);
            }
            if (rec[2] > 0)
            {
                rec[0] += randomGetRange(0, 800);
            }
            else if (rec[2] < 0)
            {
                rec[0] -= randomGetRange(0, 800);
            }
            rec += 5;
        }
    }
    entries = buf.entries;
    if (variant == 2)
    {
        entries[0].layer = 0;
        entries[0].flags = 7;
        entries[0].tex = &base[0xf0];
        entries[0].mode = 8;
        entries[0].x = lbl_803E08C8;
        entries[0].y = lbl_803E08C8;
        entries[0].z = lbl_803E08C8;
        entries[1].layer = 0;
        entries[1].flags = 7;
        entries[1].tex = &base[0x100];
        entries[1].mode = 8;
        entries[1].x = lbl_803E08CC;
        entries[1].y = lbl_803E08CC;
        entries[1].z = lbl_803E08CC;
        cmd = &entries[2];
    }
    else
    {
        entries[0].layer = 0;
        entries[0].flags = 7;
        entries[0].tex = &base[0xf0];
        entries[0].mode = 8;
        entries[0].x = lbl_803E08D0;
        entries[0].y = lbl_803E08D0;
        entries[0].z = lbl_803E08D0;
        entries[1].layer = 0;
        entries[1].flags = 7;
        entries[1].tex = &base[0x100];
        entries[1].mode = 8;
        entries[1].x = lbl_803E08CC;
        entries[1].y = lbl_803E08CC;
        entries[1].z = lbl_803E08CC;
        cmd = &entries[2];
    }
    cmd->layer = 0;
    cmd->flags = 0xe;
    cmd->tex = &base[0xd4];
    cmd->mode = 4;
    cmd->x = lbl_803E08D4;
    cmd->y = lbl_803E08D4;
    cmd->z = lbl_803E08D4;
    if (variant != 3 || posSource == 0)
    {
        cmd[1].layer = 0;
        cmd[1].flags = 7;
        cmd[1].tex = &base[0x100];
        cmd[1].mode = 2;
        cmd[1].x = lbl_803E08D8;
        cmd[1].y = lbl_803E08DC;
        cmd[1].z = lbl_803E08D8;
        cmd[2].layer = 0;
        cmd[2].flags = 7;
        cmd[2].tex = &base[0xf0];
        cmd[2].mode = 2;
        cmd[2].x = lbl_803E08E0;
        cmd[2].y = lbl_803E08E4;
        cmd[2].z = lbl_803E08E0;
        cmd += 3;
    }
    else
    {
        cmd[1].layer = 0;
        cmd[1].flags = 7;
        cmd[1].tex = &base[0x100];
        cmd[1].mode = 2;
        cmd[1].x = lbl_803E08D8 * ((PartFxSpawnParams*)posSource)->scale;
        cmd[1].y = lbl_803E08DC * ((PartFxSpawnParams*)posSource)->scale;
        cmd[1].z = lbl_803E08D8 * ((PartFxSpawnParams*)posSource)->scale;
        cmd[2].layer = 0;
        cmd[2].flags = 7;
        cmd[2].tex = &base[0xf0];
        cmd[2].mode = 2;
        cmd[2].x = lbl_803E08E0 * ((PartFxSpawnParams*)posSource)->scale;
        cmd[2].y = ((PartFxSpawnParams*)posSource)->scale;
        cmd[2].z = lbl_803E08E0 * ((PartFxSpawnParams*)posSource)->scale;
        cmd += 3;
    }
    cmd[0].layer = 1;
    cmd[0].flags = 7;
    cmd[0].tex = &base[0xf0];
    cmd[0].mode = 4;
    cmd[0].x = lbl_803E08E8;
    cmd[0].y = lbl_803E08D4;
    cmd[0].z = lbl_803E08D4;
    cmd[1].layer = 1;
    cmd[1].flags = 7;
    cmd[1].tex = &base[0x100];
    cmd[1].mode = 4;
    cmd[1].x = lbl_803E08EC;
    cmd[1].y = lbl_803E08D4;
    cmd[1].z = lbl_803E08D4;
    cmd[2].layer = 1;
    cmd[2].flags = 0xe;
    cmd[2].tex = &base[0xd4];
    cmd[2].mode = 0x100;
    cmd[2].x = lbl_803E08D4;
    cmd[2].y = lbl_803E08D4;
    cmd[2].z = lbl_803E08F0;
    cmd[3].layer = 1;
    cmd[3].flags = 0xe;
    cmd[3].tex = &base[0xd4];
    cmd[3].mode = 0x4000;
    cmd[3].x = lbl_803E08F4;
    cmd[3].y = lbl_803E08D4;
    cmd[3].z = lbl_803E08D4;
    cmd[4].layer = 2;
    cmd[4].flags = 0xe;
    cmd[4].tex = &base[0xd4];
    cmd[4].mode = 0x100;
    cmd[4].x = lbl_803E08D4;
    cmd[4].y = lbl_803E08D4;
    cmd[4].z = lbl_803E08F0;
    cmd[5].layer = 2;
    cmd[5].flags = 0xe;
    cmd[5].tex = &base[0xd4];
    cmd[5].mode = 0x4000;
    cmd[5].x = lbl_803E08F4;
    cmd[5].y = lbl_803E08D4;
    cmd[5].z = lbl_803E08D4;
    cmd[6].layer = 3;
    cmd[6].flags = 0xe;
    cmd[6].tex = &base[0xd4];
    cmd[6].mode = 0x100;
    cmd[6].x = lbl_803E08D4;
    cmd[6].y = lbl_803E08D4;
    cmd[6].z = lbl_803E08F0;
    cmd[7].layer = 3;
    cmd[7].flags = 0xe;
    cmd[7].tex = &base[0xd4];
    cmd[7].mode = 0x4000;
    cmd[7].x = lbl_803E08F4;
    cmd[7].y = lbl_803E08D4;
    cmd[7].z = lbl_803E08D4;
    cmd[8].layer = 4;
    cmd[8].flags = 1;
    cmd[8].tex = NULL;
    cmd[8].mode = 0x2000;
    cmd[8].x = lbl_803E08D4;
    cmd[8].y = lbl_803E08D4;
    cmd[8].z = lbl_803E08D4;
    cmd[9].layer = 5;
    cmd[9].flags = 7;
    cmd[9].tex = &base[0xf0];
    cmd[9].mode = 4;
    cmd[9].x = lbl_803E08D4;
    cmd[9].y = lbl_803E08D4;
    cmd[9].z = lbl_803E08D4;
    cmd[10].layer = 5;
    cmd[10].flags = 7;
    cmd[10].tex = &base[0x100];
    cmd[10].mode = 4;
    cmd[10].x = lbl_803E08D4;
    cmd[10].y = lbl_803E08D4;
    cmd[10].z = lbl_803E08D4;
    cmd[11].layer = 5;
    cmd[11].flags = 0xe;
    cmd[11].tex = &base[0xd4];
    cmd[11].mode = 0x100;
    cmd[11].x = lbl_803E08D4;
    cmd[11].y = lbl_803E08D4;
    cmd[11].z = lbl_803E08F0;
    cmd[12].layer = 5;
    cmd[12].flags = 0xe;
    cmd[12].tex = &base[0xd4];
    cmd[12].mode = 0x4000;
    cmd[12].x = lbl_803E08F4;
    cmd[12].y = lbl_803E08D4;
    cmd[12].z = lbl_803E08D4;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E08D4;
    buf.pos[1] = lbl_803E08F8;
    buf.pos[2] = lbl_803E08D4;
    buf.col[0] = lbl_803E08D4;
    buf.col[1] = lbl_803E08D4;
    buf.col[2] = lbl_803E08D4;
    if (flag != 0)
    {
        buf.scale = lbl_803E08FC * flag;
    }
    else
    {
        buf.scale = lbl_803E08E4;
    }
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (cmd + 13) - entries;
    buf.hw[0] = *(s16*)&base[0x110];
    buf.hw[1] = *(s16*)&base[0x112];
    buf.hw[2] = *(s16*)&base[0x114];
    buf.hw[3] = *(s16*)&base[0x116];
    buf.hw[4] = *(s16*)&base[0x118];
    buf.hw[5] = *(s16*)&base[0x11a];
    buf.hw[6] = *(s16*)&base[0x11c];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x40000c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, base, 0xc, &base[0x8c], 0x40, 0);
    base++;
}

void dll_63_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    dll_63_func03Body(sourceObj, variant, posSource, flags);
}
#pragma inline_max_size reset
