/*
 * dll99func0 (DLL 0x99) - a model/screen effect emitter sharing foodbag's
 * modgfx command-list pattern (cf. dll_009A_dll9afunc0.c). func00/func01 are
 * empty entry stubs (defined below in reverse address order: func01 then
 * func00); func03 fills a GfxBuf of nine command entries from the
 * .sdata2 float table at lbl_803E1340.. and the per-entry flag/texture/anim
 * table at lbl_80317AF8, then dispatches it through gModgfxInterface->spawnEffect.
 *
 * The "variant" argument (1 vs. other) selects between two x-offset constants
 * for entry 1 and two scale constants for entry 2. When effect flag bit 0 is
 * set, the spawn position is offset by the source object's world position
 * (sourceObj+0x18) and/or the posSource frame (posSource+0xc).
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/savegame.h"

/* one modgfx command entry; mirrors ScreenFxPart's layout */
typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
    u8 pad; /* +0x17: pads entry stride to 0x18 */
} GfxCmd;

/* command buffer handed to spawnEffect; mirrors ScreenFxHdr + inline entries */
typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04: source object */
    u8 pad0[0x18]; /* +0x08..+0x1f: fields not written by this fn */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 unk_3c; /* +0x3c */
    u32 unk_40; /* +0x40 */
    s16 variant; /* +0x44 */
    s16 hw[7]; /* +0x46: anim params from the table */
    u32 flags; /* +0x54 */
    u8 unk_58, unk_59, unk_5a, unk_5b, unk_5c; /* +0x58..+0x5c */
    s8 count; /* +0x5d: entry count */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_803DB950[8];
extern u8 lbl_80317AF8[];

extern f32 lbl_803E1340;
extern f32 lbl_803E1344;
extern f32 lbl_803E1348;
extern f32 lbl_803E134C;
extern f32 lbl_803E1350;
extern f32 lbl_803E1354;
extern f32 lbl_803E1358;
extern f32 lbl_803E135C;
extern f32 lbl_803E1360;
extern f32 lbl_803E1364;
extern f32 lbl_803E1368;

void dll_99_func01_nop(void)
{
}

void dll_99_func00_nop(void)
{
}

#pragma inline_max_size(2000)
static inline void dll_99_func03Body(u8* table, int sourceObj, int variant, int posSource, u32 flags, int arg5, f32* extraArgs)
{
    GfxBuf buf;
    GfxCmd* entry;
    f32 scale = lbl_803E1340;
    if (extraArgs != NULL)
    {
        scale = *extraArgs;
    }
    entry = buf.entries;
    entry[0].layer = 0;
    entry[0].flags = 5;
    entry[0].tex = table + 0x60;
    entry[0].mode = 4;
    entry[0].x = lbl_803E1344;
    entry[0].y = lbl_803E1344;
    entry[0].z = lbl_803E1344;
    entry[1].layer = 0;
    entry[1].flags = 1;
    entry[1].tex = lbl_803DB950;
    entry[1].mode = 4;
    if (variant == 1)
    {
        entry[1].x = lbl_803E1348;
    }
    else
    {
        entry[1].x = lbl_803E134C;
    }
    entry[1].y = lbl_803E1344;
    entry[1].z = lbl_803E1344;
    entry[2].layer = 0;
    entry[2].flags = 6;
    entry[2].tex = table + 0x54;
    entry[2].mode = 2;
    if (variant == 1)
    {
        entry[2].z = entry[2].y = entry[2].x = lbl_803E1350 * scale;
    }
    else
    {
        entry[2].z = entry[2].y = entry[2].x = lbl_803E1354 * scale;
    }
    entry[3].layer = 1;
    entry[3].flags = 6;
    entry[3].tex = table + 0x54;
    entry[3].mode = 0x4000;
    entry[3].x = lbl_803E1358;
    entry[3].y = lbl_803E1340;
    entry[3].z = lbl_803E1344;
    entry[4].layer = 1;
    entry[4].flags = 6;
    entry[4].tex = table + 0x54;
    entry[4].mode = 2;
    entry[4].x = lbl_803E135C;
    entry[4].y = lbl_803E135C;
    entry[4].z = lbl_803E1360;
    entry[5].layer = 2;
    entry[5].flags = 6;
    entry[5].tex = table + 0x54;
    entry[5].mode = 0x4000;
    entry[5].x = lbl_803E1358;
    entry[5].y = lbl_803E1340;
    entry[5].z = lbl_803E1344;
    entry[6].layer = 2;
    entry[6].flags = 6;
    entry[6].tex = table + 0x54;
    entry[6].mode = 2;
    entry[6].x = lbl_803E1364;
    entry[6].y = lbl_803E1364;
    entry[6].z = lbl_803E1340;
    entry[7].layer = 3;
    entry[7].flags = 6;
    entry[7].tex = table + 0x54;
    entry[7].mode = 0x4000;
    entry[7].x = lbl_803E1358;
    entry[7].y = lbl_803E1340;
    entry[7].z = lbl_803E1344;
    entry[8].layer = 3;
    entry[8].flags = 1;
    entry[8].tex = lbl_803DB950;
    entry[8].mode = 4;
    entry[8].x = lbl_803E1344;
    entry[8].y = lbl_803E1344;
    entry[8].z = lbl_803E1344;
    buf.unk_58 = 0;
    buf.ctx = sourceObj;
    buf.variant = variant;
    buf.pos[0] = lbl_803E1344;
    buf.pos[1] = lbl_803E1344;
    buf.pos[2] = lbl_803E1344;
    buf.col[0] = lbl_803E1344;
    buf.col[1] = lbl_803E1344;
    buf.col[2] = lbl_803E1344;
    buf.scale = lbl_803E1368;
    buf.unk_40 = 1;
    buf.unk_3c = 0;
    buf.unk_59 = 6;
    buf.unk_5a = 0;
    buf.unk_5b = 0;
    buf.count = (GfxCmd*)((u8*)entry + 0xd8) - entry;
    buf.hw[0] = *(s16*)(table + 0x6c);
    buf.hw[1] = *(s16*)(table + 0x6e);
    buf.hw[2] = *(s16*)(table + 0x70);
    buf.hw[3] = *(s16*)(table + 0x72);
    buf.hw[4] = *(s16*)(table + 0x74);
    buf.hw[5] = *(s16*)(table + 0x76);
    buf.hw[6] = *(s16*)(table + 0x78);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000410; /* default effect flag set; bit0 enables position offset below */
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)sourceObj != 0 && (u32)posSource != 0)
        {
            buf.pos[0] = lbl_803E1344 + (((GameObject*)(sourceObj))->anim.worldPosX + ((PartFxSpawnParams*)posSource)->posX);
            buf.pos[1] = lbl_803E1344 + (((GameObject*)(sourceObj))->anim.worldPosY + ((PartFxSpawnParams*)posSource)->posY);
            buf.pos[2] = lbl_803E1344 + (((GameObject*)(sourceObj))->anim.worldPosZ + ((PartFxSpawnParams*)posSource)->posZ);
        }
        else if ((u32)sourceObj != 0)
        {
            buf.pos[0] += ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else if ((u32)posSource != 0)
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 6, table, 4, table + 0x3c, 0x3c, 0);    table++;
}

void dll_99_func03(int sourceObj, int variant, int posSource, u32 flags, int arg5, f32* extraArgs)
{
    dll_99_func03Body(lbl_80317AF8, sourceObj, variant, posSource, flags, arg5, extraArgs);
}
#pragma inline_max_size reset

