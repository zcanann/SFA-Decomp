/*
 * dll98func0 (DLL 0x98) - a model/screen effect emitter sharing foodbag's
 * modgfx command-list pattern (cf. dll_0099_dll99func0.c). func00/func01 are
 * empty entry stubs (defined below in reverse address order: func01 then
 * func00); func03 fills a GfxBuf of nine command entries from the .sdata2
 * float table at lbl_803E1318.. and the per-entry flag/texture/anim table at
 * lbl_803178B0, then dispatches it through gModgfxInterface->spawnEffect.
 *
 * The extraArgs argument (zero vs. non-zero) selects between two y-offset
 * constants for entries 3/4/6/7 and the spawn-position offset. When effect
 * flag bit 0 is set, the spawn position is offset by the source object's
 * world position (ctx+0x18) or the posSource frame (posSource+0xc).
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/savegame.h"
#include "main/gameplay_runtime.h"

/* one modgfx command entry; mirrors ScreenFxPart's layout */
typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

/* command buffer handed to spawnEffect; mirrors ScreenFxHdr + inline entries */
typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04: source object */
    u8 pad0[0x18]; /* +0x08..+0x1f */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 unk_3c; /* +0x3c */
    u32 unk_40; /* +0x40 */
    s16 unk_44; /* +0x44 */
    s16 hw[7]; /* +0x46: anim params from the table */
    u32 flags; /* +0x54 */
    u8 unk_58, unk_59, unk_5a, unk_5b, unk_5c; /* +0x58..+0x5c */
    s8 count; /* +0x5d: entry count */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

extern ModgfxInterface** gModgfxInterface;
extern u8 lbl_803178B0[];
extern f32 lbl_803E1318;
extern f32 lbl_803E131C;
extern f32 lbl_803E1320;
extern f32 lbl_803E1324;
extern f32 lbl_803E1328;
extern f32 lbl_803E132C;
extern f32 lbl_803E1330;
extern f32 lbl_803E1334;
extern f32 lbl_803E1338;
extern f32 lbl_803E133C;

void dll_98_func01_nop(void)
{
}

void dll_98_func00_nop(void)
{
}

void dll_98_func03(int sourceObj, int variant, int posSource, u32 flags, int arg5, int extraArgs)
{
    GfxBuf buf;
    u8* table = (u8*)(int)lbl_803178B0;
    GfxCmd* entry;
    int anim;
    *(s16*)(table + 0x216) = randomGetRange(0, 0x1e) + 0x1e;
    *(volatile s16*)(table + 0x218) = *(volatile s16*)(table + 0x216);
    entry = buf.entries;
    entry[0].layer = 0;
    entry[0].flags = 0x12;
    entry[0].tex = table + 0x1dc;
    entry[0].mode = 4;
    entry[0].x = lbl_803E1318;
    entry[0].y = lbl_803E1318;
    entry[0].z = lbl_803E1318;
    entry[1].layer = 0;
    entry[1].flags = 0x12;
    entry[1].tex = table + 0x1dc;
    entry[1].mode = 2;
    entry[1].z = entry[1].x = lbl_803E131C;
    entry[1].y = lbl_803E1320;
    entry[2].layer = 1;
    entry[2].flags = 0x12;
    entry[2].tex = table + 0x1dc;
    entry[2].mode = 4;
    entry[2].x = lbl_803E1324;
    entry[2].y = lbl_803E1318;
    entry[2].z = lbl_803E1318;
    entry[3].layer = 1;
    entry[3].flags = 0x12;
    entry[3].tex = table + 0x1dc;
    entry[3].mode = 0x400000;
    entry[3].x = lbl_803E1318;
    if ((u32)extraArgs != 0)
    {
        entry[3].y = lbl_803E1328;
    }
    else
    {
        entry[3].y = lbl_803E132C;
    }
    entry[3].z = lbl_803E1318;
    entry[4].layer = 1;
    entry[4].flags = 0x12;
    entry[4].tex = table + 0x1dc;
    entry[4].mode = 0x4000;
    entry[4].x = lbl_803E1318;
    if ((u32)extraArgs != 0)
    {
        entry[4].y = lbl_803E1330;
    }
    else
    {
        entry[4].y = lbl_803E1334;
    }
    entry[4].z = lbl_803E1318;
    entry[5].layer = 2;
    entry[5].flags = 0x12;
    entry[5].tex = table + 0x1dc;
    entry[5].mode = 4;
    entry[5].x = lbl_803E1318;
    entry[5].y = lbl_803E1318;
    entry[5].z = lbl_803E1318;
    entry[6].layer = 2;
    entry[6].flags = 0x12;
    entry[6].tex = table + 0x1dc;
    entry[6].mode = 0x400000;
    entry[6].x = lbl_803E1318;
    if ((u32)extraArgs != 0)
    {
        entry[6].y = lbl_803E1328;
    }
    else
    {
        entry[6].y = lbl_803E132C;
    }
    entry[6].z = lbl_803E1318;
    entry[7].layer = 2;
    entry[7].flags = 0x12;
    entry[7].tex = table + 0x1dc;
    entry[7].mode = 0x4000;
    entry[7].x = lbl_803E1318;
    if ((u32)extraArgs != 0)
    {
        entry[7].y = lbl_803E1330;
    }
    else
    {
        entry[7].y = lbl_803E1334;
    }
    entry[7].z = lbl_803E1318;
    entry[8].layer = 2;
    entry[8].flags = 0x12;
    entry[8].tex = table + 0x1dc;
    entry[8].mode = 2;
    entry[8].x = lbl_803E1330;
    entry[8].y = lbl_803E1330;
    entry[8].z = lbl_803E1330;
    buf.unk_58 = 0;
    buf.ctx = sourceObj;
    buf.unk_44 = variant;
    buf.pos[0] = *(f32*)&lbl_803E1318;
    if ((u32)extraArgs != 0)
    {
        buf.pos[1] = lbl_803E1338;
    }
    else
    {
        buf.pos[1] = lbl_803E133C;
    }
    buf.pos[2] = *(f32*)&lbl_803E1318;
    buf.col[0] = *(f32*)&lbl_803E1318;
    buf.col[1] = *(f32*)&lbl_803E1318;
    buf.col[2] = *(f32*)&lbl_803E1318;
    buf.scale = lbl_803E1330;
    buf.unk_40 = 1;
    buf.unk_3c = 0;
    buf.unk_59 = 0x12;
    buf.unk_5a = 0;
    buf.unk_5b = 0x10;
    buf.flags = 0x4080400; /* bit 0 enables position offset below */
    buf.count = (GfxCmd*)((u8*)entry + 0xd8) - entry;
    buf.hw[0] = *(s16*)(table + 0x214);
    buf.hw[1] = *(s16*)(table + 0x216);
    buf.hw[2] = *(s16*)(table + 0x218);
    buf.hw[3] = *(s16*)(table + 0x21a);
    buf.hw[4] = *(s16*)(table + 0x21c);
    buf.hw[5] = *(s16*)(table + 0x21e);
    buf.hw[6] = *(s16*)(table + 0x220);
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)buf.ctx != 0)
        {
            buf.pos[0] += ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] = lbl_803E1318 + ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1318 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0)
    {
        anim = 0x3e9;
    }
    else if (variant == 1)
    {
        anim = 0x3f0;
    }
    else
    {
        anim = 0x3f3;
    }
    (*gModgfxInterface)
        ->spawnEffect(&buf, 0, 0x12, (u32)extraArgs != 0 ? table + 0xb4 : (u8*)(int)lbl_803178B0, 0x10,
                      table + 0x168, anim, 0);
}
