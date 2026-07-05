/*
 * dll_00A1 func0 - pickup/collectible visual effect spawner (DLL 0xA1).
 *
 * dll_A1_func03 is the per-pickup effect builder: it fills a stack-resident
 * ModgfxInterface spawn request with 14 layered GfxCmd draw entries (the
 * sparkle/glint sprite stack) plus a header block (colour, scale, position,
 * flag word), then hands it to (*gModgfxInterface)->spawnEffect. When request
 * flag bit 0 is set the effect is anchored to a world position taken either
 * from sourceObj (+0x18 vector) or, when sourceObj is null, from posSource
 * (+0x0c vector). func00/func01 are empty DLL entry-point stubs.
 *
 * All draw geometry/colour constants come from .sdata2 (lbl_803E14xx) and the
 * sprite asset table lbl_803188D8 (.data); both are owned elsewhere.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/pickup.h"

extern ModgfxInterface** gModgfxInterface;

typedef struct
{
    u32 mode;    /* 0x00 */
    f32 x, y, z; /* 0x04 0x08 0x0c */
    void* tex;   /* 0x10 */
    u16 flags;   /* 0x14 */
    u8 layer;    /* 0x16 */
} GfxCmd;

/* base spawn flags; low bit positions the effect at the source object */
#define SPAWN_FLAGS_BASE 0xc0104c0
#define SPAWN_FLAG_USE_POSITION 1

extern u8 lbl_803188D8[];
extern f32 lbl_803E14B8;
extern f32 lbl_803E14BC;
extern f32 lbl_803E14C0;
extern f32 lbl_803E14C4;
extern f32 lbl_803E14C8;
extern f32 lbl_803E14CC;
extern f32 lbl_803E14D0;
extern f32 lbl_803E14D4;
extern f32 lbl_803E14D8;
extern f32 lbl_803E14DC;

void dll_A1_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 unk_3c;
        u32 unk_40;
        s16 variant; /* 0x44 */
        s16 hw[7];
        u32 flags;
        u8 unk_58, unk_59, unk_5a, unk_5b, unk_5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* assets = (u8*)(int)lbl_803188D8;
    GfxCmd* cmd = buf.entries;

    cmd[0].layer = 0;
    cmd[0].flags = 0x15;
    cmd[0].tex = &assets[0x1b0];
    cmd[0].mode = 4;
    cmd[0].x = lbl_803E14B8;
    cmd[0].y = lbl_803E14B8;
    cmd[0].z = lbl_803E14B8;
    cmd[1].layer = 0;
    cmd[1].flags = 0x15;
    cmd[1].tex = &assets[0x1b0];
    cmd[1].mode = 2;
    cmd[1].x = lbl_803E14BC;
    cmd[1].y = lbl_803E14BC;
    cmd[1].z = lbl_803E14C0;
    cmd[2].layer = 1;
    cmd[2].flags = 0x15;
    cmd[2].tex = &assets[0x1b0];
    cmd[2].mode = 4;
    cmd[2].x = lbl_803E14C4;
    cmd[2].y = lbl_803E14B8;
    cmd[2].z = lbl_803E14B8;
    cmd[3].layer = 1;
    cmd[3].flags = 0x15;
    cmd[3].tex = &assets[0x1b0];
    cmd[3].mode = 0x4000;
    cmd[3].x = lbl_803E14C8;
    cmd[3].y = lbl_803E14CC;
    cmd[3].z = lbl_803E14B8;
    cmd[4].layer = 1;
    cmd[4].flags = 0x15;
    cmd[4].tex = &assets[0x1b0];
    cmd[4].mode = 2;
    cmd[4].x = lbl_803E14D0;
    cmd[4].y = lbl_803E14D0;
    cmd[4].z = lbl_803E14D4;
    cmd[5].layer = 2;
    cmd[5].flags = 0x15;
    cmd[5].tex = &assets[0x1b0];
    cmd[5].mode = 0x4000;
    cmd[5].x = lbl_803E14C8;
    cmd[5].y = lbl_803E14CC;
    cmd[5].z = lbl_803E14B8;
    cmd[6].layer = 3;
    cmd[6].flags = 1;
    cmd[6].tex = NULL;
    cmd[6].mode = 0x2000;
    cmd[6].x = lbl_803E14B8;
    cmd[6].y = lbl_803E14B8;
    cmd[6].z = lbl_803E14B8;
    cmd[7].layer = 4;
    cmd[7].flags = 0x15;
    cmd[7].tex = &assets[0x1b0];
    cmd[7].mode = 2;
    cmd[7].x = lbl_803E14D8;
    cmd[7].y = lbl_803E14D8;
    cmd[7].z = lbl_803E14C8;
    cmd[8].layer = 4;
    cmd[8].flags = 0x15;
    cmd[8].tex = &assets[0x1b0];
    cmd[8].mode = 0x4000;
    cmd[8].x = lbl_803E14C8;
    cmd[8].y = lbl_803E14CC;
    cmd[8].z = lbl_803E14B8;
    cmd[9].layer = 4;
    cmd[9].flags = 0x6dd;
    cmd[9].tex = NULL;
    cmd[9].mode = 0x800000;
    cmd[9].x = lbl_803E14C8;
    cmd[9].y = lbl_803E14B8;
    cmd[9].z = lbl_803E14B8;
    cmd[10].layer = 5;
    cmd[10].flags = 0x15;
    cmd[10].tex = &assets[0x1b0];
    cmd[10].mode = 0x4000;
    cmd[10].x = lbl_803E14C8;
    cmd[10].y = lbl_803E14CC;
    cmd[10].z = lbl_803E14B8;
    cmd[11].layer = 5;
    cmd[11].flags = 0x6de;
    cmd[11].tex = NULL;
    cmd[11].mode = 0x800000;
    cmd[11].x = lbl_803E14D0;
    cmd[11].y = lbl_803E14B8;
    cmd[11].z = lbl_803E14B8;
    cmd[12].layer = 5;
    cmd[12].flags = 0x6dd;
    cmd[12].tex = NULL;
    cmd[12].mode = 0x800000;
    cmd[12].x = lbl_803E14C8;
    cmd[12].y = lbl_803E14B8;
    cmd[12].z = lbl_803E14B8;
    cmd[13].layer = 6;
    cmd[13].flags = 4;
    cmd[13].tex = NULL;
    cmd[13].mode = 0x2000;
    cmd[13].x = lbl_803E14B8;
    cmd[13].y = lbl_803E14B8;
    cmd[13].z = lbl_803E14B8;

    buf.unk_58 = 0;
    buf.ctx = (int)sourceObj;
    buf.variant = variant;
    buf.pos[0] = lbl_803E14B8;
    buf.pos[1] = lbl_803E14B8;
    buf.pos[2] = lbl_803E14B8;
    buf.col[0] = lbl_803E14B8;
    buf.col[1] = lbl_803E14B8;
    buf.col[2] = lbl_803E14B8;
    buf.scale = lbl_803E14DC;
    buf.unk_40 = 2;
    buf.unk_3c = 7;
    buf.unk_59 = 0xe;
    buf.unk_5a = 0;
    buf.unk_5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)cmd + 0x150) - cmd;
    buf.hw[0] = *(s16*)&assets[0x1f8];
    buf.hw[1] = *(s16*)&assets[0x1fa];
    buf.hw[2] = *(s16*)&assets[0x1fc];
    buf.hw[3] = *(s16*)&assets[0x1fe];
    buf.hw[4] = *(s16*)&assets[0x200];
    buf.hw[5] = *(s16*)&assets[0x202];
    buf.hw[6] = *(s16*)&assets[0x204];
    buf.cmds = cmd;
    buf.flags = SPAWN_FLAGS_BASE;
    buf.flags |= flags;
    if (buf.flags & SPAWN_FLAG_USE_POSITION)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E14B8 + ((GameObject*)(sourceObj))->anim.worldPosX;
            buf.pos[1] = lbl_803E14B8 + ((GameObject*)(sourceObj))->anim.worldPosY;
            buf.pos[2] = lbl_803E14B8 + ((GameObject*)(sourceObj))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E14B8 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E14B8 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E14B8 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_803188D8, 0x18, &assets[0xd4], 0x203, 0);
}


void dll_A1_func01_nop(void)
{
}

void dll_A1_func00_nop(void)
{
}
