/*
 * dlla0func0 (DLL 0x00A0) - spawns a layered model-graphics (modgfx)
 * effect for a source object.
 *
 * dll_A0_func03 builds a fixed command list of GfxCmd descriptors plus a
 * spawn-context header on the stack and hands it to
 * (*gModgfxInterface)->spawnEffect. Each GfxCmd selects a texture sub-asset
 * (offset into lbl_803186B0) and a per-layer blend/draw mode with a
 * position/scale triple pulled from the lbl_803E14xx float table; the
 * `variant` argument swaps one descriptor's Y component. The base spawn
 * flags are SPAWN_FLAGS_BASE; when its low bit (SPAWN_FLAG_USE_POSITION)
 * survives the caller's `flags`, the effect origin is offset by the source
 * object's world position (or by posSource when sourceObj is NULL).
 *
 * func00/func01 are exported no-ops (other DLL entry slots).
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/pickup.h"

extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode;    /* 0x00: blend/draw mode */
    f32 x, y, z; /* 0x04 0x08 0x0c: per-axis scale/offset */
    void* tex;   /* 0x10: texture sub-asset pointer */
    u16 flags;   /* 0x14 */
    u8 layer;    /* 0x16: draw layer */
} GfxCmd;

/* base spawn flags; low bit positions the effect at the source object */
#define SPAWN_FLAGS_BASE 0xc010480
#define SPAWN_FLAG_USE_POSITION 1

extern u8 lbl_803186B0[]; /* texture/asset table */
extern f32 lbl_803E1488;  /* float constant table (0.0f, offsets, etc.) */
extern f32 lbl_803E148C;
extern f32 lbl_803E1490;
extern f32 lbl_803E1494;
extern f32 lbl_803E1498;
extern f32 lbl_803E149C;
extern f32 lbl_803E14A0;
extern f32 lbl_803E14A4;
extern f32 lbl_803E14A8;
extern f32 lbl_803E14AC;
extern f32 lbl_803E14B0;

void dll_A0_func03(u8* sourceObj, int variant, int posSource, u32 flags)
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
    u8* tab = lbl_803186B0;
    GfxCmd* entry = buf.entries;
    GfxCmd* cmd;
    u32 fl;

    entry[0].layer = 0;
    entry[0].flags = 0x15;
    entry[0].tex = &tab[0x1b0];
    entry[0].mode = 4;
    entry[0].x = lbl_803E1488;
    entry[0].y = lbl_803E1488;
    entry[0].z = lbl_803E1488;
    if (variant == 0)
    {
        entry[1].layer = 0;
        entry[1].flags = 0x15;
        entry[1].tex = &tab[0x1b0];
        entry[1].mode = 2;
        entry[1].x = lbl_803E148C;
        entry[1].y = lbl_803E1490;
        entry[1].z = lbl_803E148C;
        cmd = entry + 2;
    }
    else
    {
        entry[1].layer = 0;
        entry[1].flags = 0x15;
        entry[1].tex = &tab[0x1b0];
        entry[1].mode = 2;
        entry[1].x = lbl_803E148C;
        entry[1].y = lbl_803E1494;
        entry[1].z = lbl_803E148C;
        cmd = entry + 2;
    }
    cmd[0].layer = 1;
    cmd[0].flags = 0x15;
    cmd[0].tex = &tab[0x1b0];
    cmd[0].mode = 2;
    cmd[0].x = lbl_803E1498;
    cmd[0].y = lbl_803E1498;
    cmd[0].z = lbl_803E1498;
    cmd[1].layer = 1;
    cmd[1].flags = 7;
    cmd[1].tex = &tab[0x174];
    cmd[1].mode = 4;
    cmd[1].x = lbl_803E149C;
    cmd[1].y = lbl_803E1488;
    cmd[1].z = lbl_803E1488;
    cmd[2].layer = 1;
    cmd[2].flags = 0x15;
    cmd[2].tex = &tab[0x1b0];
    cmd[2].mode = 0x4000;
    cmd[2].x = lbl_803E14A0;
    cmd[2].y = lbl_803E14A4;
    cmd[2].z = lbl_803E1488;
    cmd[3].layer = 2;
    cmd[3].flags = 7;
    cmd[3].tex = &tab[0x174];
    cmd[3].mode = 2;
    cmd[3].x = lbl_803E14A8;
    cmd[3].y = lbl_803E14A4;
    cmd[3].z = lbl_803E14A8;
    cmd[4].layer = 2;
    cmd[4].flags = 7;
    cmd[4].tex = &tab[0x184];
    cmd[4].mode = 2;
    cmd[4].x = lbl_803E14AC;
    cmd[4].y = lbl_803E14A4;
    cmd[4].z = lbl_803E14AC;
    cmd[5].layer = 2;
    cmd[5].flags = 0x15;
    cmd[5].tex = &tab[0x1b0];
    cmd[5].mode = 0x4000;
    cmd[5].x = lbl_803E14A0;
    cmd[5].y = lbl_803E14A4;
    cmd[5].z = lbl_803E1488;
    cmd[6].layer = 3;
    cmd[6].flags = 7;
    cmd[6].tex = &tab[0x174];
    cmd[6].mode = 4;
    cmd[6].x = lbl_803E1488;
    cmd[6].y = lbl_803E1488;
    cmd[6].z = lbl_803E1488;
    cmd[7].layer = 3;
    cmd[7].flags = 0x15;
    cmd[7].tex = &tab[0x1b0];
    cmd[7].mode = 0x4000;
    cmd[7].x = lbl_803E14B0;
    cmd[7].y = lbl_803E14A4;
    cmd[7].z = lbl_803E1488;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1488;
    buf.pos[1] = lbl_803E1488;
    buf.pos[2] = lbl_803E1488;
    buf.col[0] = lbl_803E1488;
    buf.col[1] = lbl_803E1488;
    buf.col[2] = lbl_803E1488;
    buf.scale = lbl_803E14A4;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = &cmd[8] - entry;
    buf.hw[0] = *(s16*)&tab[0x1f8];
    buf.hw[1] = *(s16*)&tab[0x1fa];
    buf.hw[2] = *(s16*)&tab[0x1fc];
    buf.hw[3] = *(s16*)&tab[0x1fe];
    buf.hw[4] = *(s16*)&tab[0x200];
    buf.hw[5] = *(s16*)&tab[0x202];
    buf.hw[6] = *(s16*)&tab[0x204];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    fl = SPAWN_FLAGS_BASE;
    buf.flags = fl;
    fl |= flags;
    buf.flags = fl;
    if (fl & SPAWN_FLAG_USE_POSITION)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E1488 + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E1488 + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E1488 + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E1488 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1488 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1488 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, tab, 0x18, &tab[0xd4], 0x1d9, 0);
}

void dll_A0_func01_nop(void)
{
}

void dll_A0_func00_nop(void)
{
}
