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
    s16* p;
    GfxCmd* entries;
    GfxCmd* e;
    u8* base = (u8*)(int)lbl_80312BD8;
    if (variant == 1)
    {
        *(s16*)&base[0x112] = 0;
    }
    flag = *(u8*)(*(u8**)&((GameObject*)sourceObj)->anim.placementData + 0x1a);
    if (variant == 2)
    {
        for (i = 0, p = (s16*)base; i < 14; i++)
        {
            if (p[0] > 0)
            {
                p[0] += randomGetRange(0, 800);
            }
            else if (p[0] < 0)
            {
                p[0] -= randomGetRange(0, 800);
            }
            if (p[1] > 0)
            {
                p[0] += randomGetRange(0, 300);
            }
            else if (p[1] < 0)
            {
                p[0] -= randomGetRange(0, 300);
            }
            if (p[2] > 0)
            {
                p[0] += randomGetRange(0, 800);
            }
            else if (p[2] < 0)
            {
                p[0] -= randomGetRange(0, 800);
            }
            p += 5;
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
        e = &entries[2];
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
        e = &entries[2];
    }
    e->layer = 0;
    e->flags = 0xe;
    e->tex = &base[0xd4];
    e->mode = 4;
    e->x = lbl_803E08D4;
    e->y = lbl_803E08D4;
    e->z = lbl_803E08D4;
    if (variant != 3 || posSource == 0)
    {
        e[1].layer = 0;
        e[1].flags = 7;
        e[1].tex = &base[0x100];
        e[1].mode = 2;
        e[1].x = lbl_803E08D8;
        e[1].y = lbl_803E08DC;
        e[1].z = lbl_803E08D8;
        e[2].layer = 0;
        e[2].flags = 7;
        e[2].tex = &base[0xf0];
        e[2].mode = 2;
        e[2].x = lbl_803E08E0;
        e[2].y = lbl_803E08E4;
        e[2].z = lbl_803E08E0;
        e += 3;
    }
    else
    {
        e[1].layer = 0;
        e[1].flags = 7;
        e[1].tex = &base[0x100];
        e[1].mode = 2;
        e[1].x = lbl_803E08D8 * ((PartFxSpawnParams*)posSource)->scale;
        e[1].y = lbl_803E08DC * ((PartFxSpawnParams*)posSource)->scale;
        e[1].z = lbl_803E08D8 * ((PartFxSpawnParams*)posSource)->scale;
        e[2].layer = 0;
        e[2].flags = 7;
        e[2].tex = &base[0xf0];
        e[2].mode = 2;
        e[2].x = lbl_803E08E0 * ((PartFxSpawnParams*)posSource)->scale;
        e[2].y = ((PartFxSpawnParams*)posSource)->scale;
        e[2].z = lbl_803E08E0 * ((PartFxSpawnParams*)posSource)->scale;
        e += 3;
    }
    e[0].layer = 1;
    e[0].flags = 7;
    e[0].tex = &base[0xf0];
    e[0].mode = 4;
    e[0].x = lbl_803E08E8;
    e[0].y = lbl_803E08D4;
    e[0].z = lbl_803E08D4;
    e[1].layer = 1;
    e[1].flags = 7;
    e[1].tex = &base[0x100];
    e[1].mode = 4;
    e[1].x = lbl_803E08EC;
    e[1].y = lbl_803E08D4;
    e[1].z = lbl_803E08D4;
    e[2].layer = 1;
    e[2].flags = 0xe;
    e[2].tex = &base[0xd4];
    e[2].mode = 0x100;
    e[2].x = lbl_803E08D4;
    e[2].y = lbl_803E08D4;
    e[2].z = lbl_803E08F0;
    e[3].layer = 1;
    e[3].flags = 0xe;
    e[3].tex = &base[0xd4];
    e[3].mode = 0x4000;
    e[3].x = lbl_803E08F4;
    e[3].y = lbl_803E08D4;
    e[3].z = lbl_803E08D4;
    e[4].layer = 2;
    e[4].flags = 0xe;
    e[4].tex = &base[0xd4];
    e[4].mode = 0x100;
    e[4].x = lbl_803E08D4;
    e[4].y = lbl_803E08D4;
    e[4].z = lbl_803E08F0;
    e[5].layer = 2;
    e[5].flags = 0xe;
    e[5].tex = &base[0xd4];
    e[5].mode = 0x4000;
    e[5].x = lbl_803E08F4;
    e[5].y = lbl_803E08D4;
    e[5].z = lbl_803E08D4;
    e[6].layer = 3;
    e[6].flags = 0xe;
    e[6].tex = &base[0xd4];
    e[6].mode = 0x100;
    e[6].x = lbl_803E08D4;
    e[6].y = lbl_803E08D4;
    e[6].z = lbl_803E08F0;
    e[7].layer = 3;
    e[7].flags = 0xe;
    e[7].tex = &base[0xd4];
    e[7].mode = 0x4000;
    e[7].x = lbl_803E08F4;
    e[7].y = lbl_803E08D4;
    e[7].z = lbl_803E08D4;
    e[8].layer = 4;
    e[8].flags = 1;
    e[8].tex = NULL;
    e[8].mode = 0x2000;
    e[8].x = lbl_803E08D4;
    e[8].y = lbl_803E08D4;
    e[8].z = lbl_803E08D4;
    e[9].layer = 5;
    e[9].flags = 7;
    e[9].tex = &base[0xf0];
    e[9].mode = 4;
    e[9].x = lbl_803E08D4;
    e[9].y = lbl_803E08D4;
    e[9].z = lbl_803E08D4;
    e[10].layer = 5;
    e[10].flags = 7;
    e[10].tex = &base[0x100];
    e[10].mode = 4;
    e[10].x = lbl_803E08D4;
    e[10].y = lbl_803E08D4;
    e[10].z = lbl_803E08D4;
    e[11].layer = 5;
    e[11].flags = 0xe;
    e[11].tex = &base[0xd4];
    e[11].mode = 0x100;
    e[11].x = lbl_803E08D4;
    e[11].y = lbl_803E08D4;
    e[11].z = lbl_803E08F0;
    e[12].layer = 5;
    e[12].flags = 0xe;
    e[12].tex = &base[0xd4];
    e[12].mode = 0x4000;
    e[12].x = lbl_803E08F4;
    e[12].y = lbl_803E08D4;
    e[12].z = lbl_803E08D4;
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
    buf.count = (e + 13) - entries;
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
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, base, 0xc, &base[0x8c], 0x40, 0);
    base++;
}

void dll_63_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    dll_63_func03Body(sourceObj, variant, posSource, flags);
}
#pragma inline_max_size reset
