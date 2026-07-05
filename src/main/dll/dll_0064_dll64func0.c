/*
 * dll64func0 (DLL 0x64) - particle/effect spawner front-end.
 *
 * dll_64_func03 builds a fixed nine-command Modgfx effect description on
 * the stack (the GfxCmd entries[] table, each a textured billboard layer
 * read out of the lbl_80312D18 model-data blob) and submits it through
 * gModgfxInterface->spawnEffect. The overall effect scale tracks the
 * source object's placement byte at offset 0x1a; when bit 0 of the caller
 * flags requests world placement the base position is taken from either
 * the source object (offset 0x18..0x20) or the PartFxSpawnParams packet.
 * func01 and func00 (in binary address order) are the DLL's empty no-op
 * entry-table slots.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

/* matches GfxCmd in dll_00A3_dlla3func0.c */
typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80312D18[];
extern f32 lbl_803E0908;
extern f32 lbl_803E090C;
extern f32 lbl_803E0910;
extern f32 lbl_803E0914;
extern f32 lbl_803E0918;
extern f32 lbl_803E091C;
extern f32 lbl_803E0920;
extern f32 lbl_803E0924;

void dll_64_func01_nop(void)
{
}

void dll_64_func00_nop(void)
{
}

void dll_64_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
        u8 v58, v59, v5a, v5b, v5c; /* v5c left unwritten - target has no store to sp+0x5c */
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u32 flag;
    u8* base = (u8*)(int)lbl_80312D18;
    if (variant == 1)
    {
        *(s16*)&base[0x112] = 0;
    }
    flag = *(u8*)(*(u8**)&((GameObject*)sourceObj)->anim.placementData + 0x1a);
    buf.entries[0].layer = 0;
    buf.entries[0].flags = 7;
    buf.entries[0].tex = &base[0xf0];
    buf.entries[0].mode = 2;
    buf.entries[0].x = lbl_803E0908;
    buf.entries[0].y = lbl_803E090C;
    buf.entries[0].z = lbl_803E0908;
    buf.entries[1].layer = 0;
    buf.entries[1].flags = 7;
    buf.entries[1].tex = &base[0x100];
    buf.entries[1].mode = 2;
    buf.entries[1].x = lbl_803E0910;
    buf.entries[1].y = lbl_803E0914;
    buf.entries[1].z = lbl_803E0910;
    buf.entries[2].layer = 0;
    buf.entries[2].flags = 0xe;
    buf.entries[2].tex = &base[0xd4];
    buf.entries[2].mode = 4;
    buf.entries[2].x = lbl_803E0918;
    buf.entries[2].y = lbl_803E0918;
    buf.entries[2].z = lbl_803E0918;
    buf.entries[3].layer = 1;
    buf.entries[3].flags = 7;
    buf.entries[3].tex = &base[0x100];
    buf.entries[3].mode = 4;
    buf.entries[3].x = lbl_803E091C;
    buf.entries[3].y = lbl_803E0918;
    buf.entries[3].z = lbl_803E0918;
    buf.entries[4].layer = 1;
    buf.entries[4].flags = 0xe;
    buf.entries[4].tex = &base[0xd4];
    buf.entries[4].mode = 0x100;
    buf.entries[4].x = lbl_803E0918;
    buf.entries[4].y = lbl_803E0918;
    buf.entries[4].z = lbl_803E0920;
    buf.entries[5].layer = 2;
    buf.entries[5].flags = 0xe;
    buf.entries[5].tex = &base[0xd4];
    buf.entries[5].mode = 0x100;
    buf.entries[5].x = lbl_803E0918;
    buf.entries[5].y = lbl_803E0918;
    buf.entries[5].z = lbl_803E0920;
    buf.entries[6].layer = 3;
    buf.entries[6].flags = 1;
    buf.entries[6].tex = 0;
    buf.entries[6].mode = 0x2000;
    buf.entries[6].x = lbl_803E0918;
    buf.entries[6].y = lbl_803E0918;
    buf.entries[6].z = lbl_803E0918;
    buf.entries[7].layer = 4;
    buf.entries[7].flags = 7;
    buf.entries[7].tex = &base[0x100];
    buf.entries[7].mode = 4;
    buf.entries[7].x = lbl_803E0918;
    buf.entries[7].y = lbl_803E0918;
    buf.entries[7].z = lbl_803E0918;
    buf.entries[8].layer = 4;
    buf.entries[8].flags = 0xe;
    buf.entries[8].tex = &base[0xd4];
    buf.entries[8].mode = 0x100;
    buf.entries[8].x = lbl_803E0918;
    buf.entries[8].y = lbl_803E0918;
    buf.entries[8].z = lbl_803E0920;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0918;
    buf.pos[1] = lbl_803E0918;
    buf.pos[2] = lbl_803E0918;
    buf.col[0] = lbl_803E0918;
    buf.col[1] = lbl_803E0918;
    buf.col[2] = lbl_803E0918;
    if (flag != 0)
    {
        buf.scale = lbl_803E0924 * flag;
    }
    else
    {
        buf.scale = lbl_803E090C;
    }
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = 9;
    buf.hw[0] = *(s16*)&base[0x110];
    buf.hw[1] = *(s16*)&base[0x112];
    buf.hw[2] = *(s16*)&base[0x114];
    buf.hw[3] = *(s16*)&base[0x116];
    buf.hw[4] = *(s16*)&base[0x118];
    buf.hw[5] = *(s16*)&base[0x11a];
    buf.hw[6] = *(s16*)&base[0x11c];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4040080;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
        {
            buf.pos[0] += ((GameObject*)buf.ctx)->anim.worldPosX;
            buf.pos[1] += ((GameObject*)buf.ctx)->anim.worldPosY;
            buf.pos[2] += ((GameObject*)buf.ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0xe, (u8*)(int)lbl_80312D18, 0xc, &base[0x8c], 0x5e0, 0);
}
