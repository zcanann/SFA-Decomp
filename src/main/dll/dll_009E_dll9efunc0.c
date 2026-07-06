/*
 * dll9efunc0 (DLL 0x9E) - one of the per-effect pickup/modgfx spawners.
 *
 * dll_9E_func03 builds a fixed list of 14 modgfx draw commands (GfxCmd
 * entries[], one mode/blend + xyz per command, texture sub-tables taken
 * from the lbl_80318260 data blob) plus the surrounding spawn header
 * (colour, position, scale, the seven s16 params at base+0x1f8..+0x204),
 * then hands the whole packet to (*gModgfxInterface)->spawnEffect.
 *
 * The spawn flag word starts at 0xC0100C0 and ORs in the caller's flags;
 * bit 0 means "anchor to a world position": from sourceObj+0x18 when a
 * source object was passed, otherwise from posSource+0xc.
 *
 * func00/func01 are the empty DLL entry-table slots for this object.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/pickup.h"

extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

/* lbl_80318260: shared texture + halfword table; lbl_803E1418..1440:
 * gfx-constant pool. Home TU unknown. */
extern u8 lbl_80318260[];
extern f32 lbl_803E1418;
extern f32 lbl_803E141C;
extern f32 lbl_803E1420;
extern f32 lbl_803E1424;
extern f32 lbl_803E1428;
extern f32 lbl_803E142C;
extern f32 lbl_803E1430;
extern f32 lbl_803E1434;
extern f32 lbl_803E1438;
extern f32 lbl_803E143C;
extern f32 lbl_803E1440;

void dll_9E_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds; /* +0x00 */
        int sourceObj; /* +0x04 */
        u8 pad0[0x18]; /* +0x08 */
        f32 col[3]; /* +0x20 */
        f32 pos[3]; /* +0x2c */
        f32 scale; /* +0x38 */
        u32 unk_3c; /* +0x3c */
        u32 unk_40; /* +0x40 */
        s16 variant; /* +0x44 */
        s16 unk_46[7]; /* +0x46 */
        u32 spawnFlags; /* +0x54 */
        u8 unk_58, unk_59, unk_5a, unk_5b, unk_5c; /* +0x58..+0x5c */
        s8 count; /* +0x5d */
        u8 pad1[2]; /* +0x5e */
        GfxCmd entries[32]; /* +0x60 */
    } buf;
    u8* base = (u8*)(int)lbl_80318260;
    GfxCmd* e = buf.entries;
    u32 spawnFlags;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[0x1b0];
    e[0].mode = 4;
    e[0].x = lbl_803E1418;
    e[0].y = lbl_803E1418;
    e[0].z = lbl_803E1418;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[0x1b0];
    e[1].mode = 2;
    e[1].x = lbl_803E141C;
    e[1].y = lbl_803E1420;
    e[1].z = lbl_803E141C;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E1418;
    e[2].y = lbl_803E1424;
    e[2].z = lbl_803E1418;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = &base[0x1b0];
    e[3].mode = 2;
    e[3].x = lbl_803E1428;
    e[3].y = lbl_803E1428;
    e[3].z = lbl_803E1428;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &base[0x174];
    e[4].mode = 4;
    e[4].x = lbl_803E142C;
    e[4].y = lbl_803E1418;
    e[4].z = lbl_803E1418;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &base[0x1b0];
    e[5].mode = 0x4000;
    e[5].x = lbl_803E1430;
    e[5].y = lbl_803E1418;
    e[5].z = lbl_803E1418;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x400000;
    e[6].x = lbl_803E1418;
    e[6].y = lbl_803E1418;
    e[6].z = lbl_803E1418;
    e[7].layer = 2;
    e[7].flags = 0x7a;
    e[7].tex = NULL;
    e[7].mode = 0x10000;
    e[7].x = lbl_803E1418;
    e[7].y = lbl_803E1418;
    e[7].z = lbl_803E1418;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &base[0x1b0];
    e[8].mode = 8;
    e[8].x = lbl_803E1434;
    e[8].y = lbl_803E1438;
    e[8].z = lbl_803E1418;
    e[9].layer = 2;
    e[9].flags = 0x15;
    e[9].tex = &base[0x1b0];
    e[9].mode = 0x4000;
    e[9].x = lbl_803E1430;
    e[9].y = lbl_803E1418;
    e[9].z = lbl_803E1418;
    e[10].layer = 2;
    e[10].flags = 0;
    e[10].tex = NULL;
    e[10].mode = 0x400000;
    e[10].x = lbl_803E1418;
    e[10].y = lbl_803E143C;
    e[10].z = lbl_803E1418;
    e[11].layer = 3;
    e[11].flags = 0x15;
    e[11].tex = &base[0x1b0];
    e[11].mode = 0x4000;
    e[11].x = lbl_803E1430;
    e[11].y = lbl_803E1418;
    e[11].z = lbl_803E1418;
    e[12].layer = 3;
    e[12].flags = 0;
    e[12].tex = NULL;
    e[12].mode = 0x400000;
    e[12].x = lbl_803E1418;
    e[12].y = lbl_803E143C;
    e[12].z = lbl_803E1418;
    e[13].layer = 3;
    e[13].flags = 7;
    e[13].tex = &base[0x174];
    e[13].mode = 4;
    e[13].x = lbl_803E1418;
    e[13].y = lbl_803E1418;
    e[13].z = lbl_803E1418;

    buf.unk_58 = 0;
    buf.sourceObj = (int)sourceObj;
    buf.variant = variant;
    buf.pos[0] = lbl_803E1418;
    buf.pos[1] = lbl_803E1418;
    buf.pos[2] = lbl_803E1418;
    buf.col[0] = lbl_803E1418;
    buf.col[1] = lbl_803E1418;
    buf.col[2] = lbl_803E1418;
    buf.scale = lbl_803E1440;
    buf.unk_40 = 2;
    buf.unk_3c = 7;
    buf.unk_59 = 0xe;
    buf.unk_5a = 0;
    buf.unk_5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 336) - e;
    buf.unk_46[0] = *(s16*)&base[0x1f8];
    buf.unk_46[1] = *(s16*)&base[0x1fa];
    buf.unk_46[2] = *(s16*)&base[0x1fc];
    buf.unk_46[3] = *(s16*)&base[0x1fe];
    buf.unk_46[4] = *(s16*)&base[0x200];
    buf.unk_46[5] = *(s16*)&base[0x202];
    buf.unk_46[6] = *(s16*)&base[0x204];
    buf.cmds = e;
    spawnFlags = 0xc0100c0;
    buf.spawnFlags = spawnFlags;
    spawnFlags |= flags;
    buf.spawnFlags = spawnFlags;
    if (spawnFlags & 1)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E1418 + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E1418 + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E1418 + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E1418 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1418 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1418 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80318260, 0x18, &base[0xd4], 0x46c, 0);
}


void dll_9E_func01_nop(void)
{
}

void dll_9E_func00_nop(void)
{
}
