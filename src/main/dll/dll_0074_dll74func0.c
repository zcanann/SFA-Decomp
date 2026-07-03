/*
 * dll74func0 (DLL 0x74) - shared save-game / world-progress core lib.
 *
 * A near-clone of the dll_6D core (same exported entry points; this DLL
 * instance differs only in its private effect-list data labels). Owns the
 * gameplay save-state helpers exported through gameplay.h:
 *   - debug-cheat unlock bits (saveFileStruct_unlockCheat / isCheatUnlocked)
 *     packed into gGameplayRegisteredDebugOptions.
 *   - preview color/volume defaults (saveFileStruct_resetVolumes, 0x7f each).
 *   - the save-settings apply path (loadSaveSettings) and the per-map act /
 *     object-position fix-up (FUN_800e8630, name TBD).
 *   - the map-act flag setter that mirrors a flag bit across the map-act table
 *     and maintains the recently-changed history ring (FUN_800e95e8, name TBD).
 *   - new-game / save-slot setup, seeding the map-act table and the save block
 *     (FUN_800e8f58 / FUN_800e9e9c, names TBD).
 *   - the visited-map history ring, most-recent-first, depth 5 (FUN_800ea9b8,
 *     name TBD).
 *   - dll_74_func03: builds the modgfx command list (the spirit/aura particle
 *     effect, a 0/non-0 variant pair) and submits it via
 *     gModgfxInterface->spawnEffect.
 *
 * The map-act / flag tables live at 0x803a3f08.. and 0x80312460..; the visited
 * history ring at 0x803a3be0. Bit indices are split into (word,bit) by the
 * 0x12f flag-word base. These globals are cross-TU; only this DLL writes the
 * debug-option and preview-color globals.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"
#include "main/mapEventTypes.h"
#include "main/dll/modgfx.h"

/* one modgfx draw command in the dll_74_func03 effect list */
typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;
extern u8 gGameplayPreviewSettings;
extern u32 gGameplayPreviewColorRed;
extern u32 gGameplayPreviewColorGreen;
extern u32 gGameplayPreviewColorBlue;
extern u32 gGameplayRegisteredDebugOptions;
extern f32 lbl_803E1348;
extern u32 uRam803de108;
extern u8 lbl_803146D8[];
extern f32 lbl_803E0BB8, lbl_803E0BBC, lbl_803E0BC0, lbl_803E0BC4, lbl_803E0BC8, lbl_803E0BCC;
extern f32 lbl_803E0BD0, lbl_803E0BD4, lbl_803E0BD8, lbl_803E0BDC, lbl_803E0BE0, lbl_803E0BE4;

/* Cross-TU main-lib functions and globals this DLL references (home TUs
   un-recovered; left as Ghidra FUN_/DAT_ names). */

extern void* memset(void* dst, int val, u32 n);
extern void* memcpy(void* dst, const void* src, u32 n);
extern u32 FUN_80006768();
extern u32 FUN_8000676c();
extern u32 FUN_80006c20();
extern u32 FUN_80017500();
extern u32 FUN_8005d018();
extern u32 DAT_803a3e26;
extern u32 DAT_803a3e27;
extern u32 DAT_803a3e28;
extern u32 DAT_803a3e2a;
extern u32 DAT_803a3e2c;
extern u32 DAT_803a3e2d;
extern u32* DAT_803dd6d0;
extern u32* DAT_803dd6e8;

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

void dll_74_func01_nop(void)
{
}

void dll_74_func00_nop(void)
{
}

void dll_74_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
    GfxCmd* e;
    u8* base = (u8*)(int)lbl_803146D8;
    GfxCmd* entries = buf.entries;
    entries[0].layer = 0;
    entries[0].flags = 0x15;
    entries[0].tex = &base[0x1b0];
    entries[0].mode = 4;
    entries[0].x = lbl_803E0BB8;
    entries[0].y = lbl_803E0BB8;
    entries[0].z = lbl_803E0BB8;
    if (variant == 0)
    {
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = &base[0x1b0];
        entries[1].mode = 2;
        entries[1].x = lbl_803E0BBC;
        entries[1].y = lbl_803E0BC0;
        entries[1].z = lbl_803E0BBC;
        e = &entries[2];
    }
    else
    {
        entries[1].layer = 0;
        entries[1].flags = 0x15;
        entries[1].tex = &base[0x1b0];
        entries[1].mode = 2;
        entries[1].x = lbl_803E0BBC;
        entries[1].y = lbl_803E0BC4;
        entries[1].z = lbl_803E0BBC;
        e = &entries[2];
    }
    if (variant == 0)
    {
        e->layer = 0;
        e->flags = 0;
        e->tex = NULL;
        e->mode = 0x400000;
        e->x = lbl_803E0BB8;
        e->y = lbl_803E0BC8;
        e->z = lbl_803E0BB8;
        e++;
    }
    else
    {
        e->layer = 0;
        e->flags = 0;
        e->tex = NULL;
        e->mode = 0x400000;
        e->x = lbl_803E0BB8;
        e->y = lbl_803E0BCC;
        e->z = lbl_803E0BB8;
        e++;
    }
    e[0].layer = 1;
    e[0].flags = 0x15;
    e[0].tex = &base[0x1b0];
    e[0].mode = 2;
    e[0].x = lbl_803E0BD0;
    e[0].y = lbl_803E0BD4;
    e[0].z = lbl_803E0BD0;
    e[1].layer = 1;
    e[1].flags = 0xe;
    e[1].tex = &base[0x1f8];
    e[1].mode = 4;
    e[1].x = lbl_803E0BD8;
    e[1].y = lbl_803E0BB8;
    e[1].z = lbl_803E0BB8;
    if (variant == 0)
    {
        e[2].layer = 1;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BDC;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    else
    {
        e[2].layer = 1;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BE0;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    e[0].layer = 2;
    e[0].flags = 7;
    e[0].tex = &base[0x164];
    e[0].mode = 2;
    e[0].x = lbl_803E0BE4;
    e[0].y = lbl_803E0BC0;
    e[0].z = lbl_803E0BE4;
    e[1].layer = 2;
    e[1].flags = 7;
    e[1].tex = &base[0x174];
    e[1].mode = 2;
    e[1].x = lbl_803E0BD4;
    e[1].y = lbl_803E0BC0;
    e[1].z = lbl_803E0BD4;
    if (variant == 0)
    {
        e[2].layer = 2;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BDC;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    else
    {
        e[2].layer = 2;
        e[2].flags = 0x15;
        e[2].tex = &base[0x1b0];
        e[2].mode = 0x4000;
        e[2].x = lbl_803E0BB8;
        e[2].y = lbl_803E0BE0;
        e[2].z = lbl_803E0BB8;
        e += 3;
    }
    e[0].layer = 2;
    e[0].flags = 0xe;
    e[0].tex = &base[0x1f8];
    e[0].mode = 4;
    e[0].x = lbl_803E0BB8;
    e[0].y = lbl_803E0BB8;
    e[0].z = lbl_803E0BB8;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0BB8;
    buf.pos[1] = lbl_803E0BB8;
    buf.pos[2] = lbl_803E0BB8;
    buf.col[0] = lbl_803E0BB8;
    buf.col[1] = lbl_803E0BB8;
    buf.col[2] = lbl_803E0BB8;
    buf.scale = lbl_803E0BC0;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 1) - entries;
    buf.hw[0] = *(s16*)&base[0x214];
    buf.hw[1] = *(s16*)&base[0x216];
    buf.hw[2] = *(s16*)&base[0x218];
    buf.hw[3] = *(s16*)&base[0x21a];
    buf.hw[4] = *(s16*)&base[0x21c];
    buf.hw[5] = *(s16*)&base[0x21e];
    buf.hw[6] = *(s16*)&base[0x220];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E0BB8 + ((GameObject*)sourceObj)->anim.localPosX;
            buf.pos[1] = lbl_803E0BB8 + ((GameObject*)sourceObj)->anim.localPosY;
            buf.pos[2] = lbl_803E0BB8 + ((GameObject*)sourceObj)->anim.localPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0BB8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0BB8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0BB8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0)
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803146D8, 0x18, &base[0xd4], 0x2e, 0);
    }
    else
    {
        (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803146D8, 0x18, &base[0xd4], 0xd9, 0);
    }
}
