/*
 * dll71func0 (DLL 0x71) - a one-shot particle-effect spawner.
 *
 * The single real export, dll_71_func03, fills a stacked modgfx command
 * list (14 GfxCmd entries across four render layers, sourced from the
 * lbl_803E0B* float pool and the lbl_80314060 texture/param blob) and
 * hands it to gModgfxInterface->spawnEffect. When flag bit 0 is set the
 * spawn position is taken from the source object (sourceObj+0x18..0x20)
 * or, if none, from the PartFxSpawnParams packet at posSource. The two
 * trailing entry points are the DLL's empty func00/func01 slots.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/gameplay.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80314060[];
extern f32 lbl_803E0B38;
extern f32 lbl_803E0B3C;
extern f32 lbl_803E0B40;
extern f32 lbl_803E0B44;
extern f32 lbl_803E0B48;
extern f32 lbl_803E0B4C;
extern f32 lbl_803E0B50;
extern f32 lbl_803E0B54;
extern f32 lbl_803E0B58;

void dll_71_func01_nop(void)
{
}

void dll_71_func00_nop(void)
{
}

void dll_71_func03(int sourceObj, int variant, int posSource, u32 flags)
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
        u8 v58, v59, v5a, v5b, pad5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)lbl_80314060;
    GfxCmd* e = buf.entries;
    int ctx;
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &base[432];
    e[0].mode = 4;
    e[0].x = lbl_803E0B38;
    e[0].y = lbl_803E0B38;
    e[0].z = lbl_803E0B38;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &base[432];
    e[1].mode = 2;
    e[1].x = lbl_803E0B3C;
    e[1].y = lbl_803E0B40;
    e[1].z = lbl_803E0B3C;
    e[2].layer = 0;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x400000;
    e[2].x = lbl_803E0B38;
    e[2].y = lbl_803E0B44;
    e[2].z = lbl_803E0B38;
    e[3].layer = 0;
    e[3].flags = 0x124;
    e[3].tex = NULL;
    e[3].mode = 0x20000;
    e[3].x = lbl_803E0B38;
    e[3].y = lbl_803E0B38;
    e[3].z = lbl_803E0B38;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = &base[432];
    e[4].mode = 2;
    e[4].x = lbl_803E0B48;
    e[4].y = lbl_803E0B4C;
    e[4].z = lbl_803E0B48;
    e[5].layer = 1;
    e[5].flags = 0xe;
    e[5].tex = &base[476];
    e[5].mode = 4;
    e[5].x = lbl_803E0B50;
    e[5].y = lbl_803E0B38;
    e[5].z = lbl_803E0B38;
    e[6].layer = 1;
    e[6].flags = 0x15;
    e[6].tex = &base[432];
    e[6].mode = 0x4000;
    e[6].x = lbl_803E0B40;
    e[6].y = lbl_803E0B40;
    e[6].z = lbl_803E0B38;
    e[7].layer = 1;
    e[7].flags = 0;
    e[7].tex = NULL;
    e[7].mode = 0x400000;
    e[7].x = lbl_803E0B38;
    e[7].y = lbl_803E0B54;
    e[7].z = lbl_803E0B38;
    e[8].layer = 2;
    e[8].flags = 0x15;
    e[8].tex = &base[432];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E0B40;
    e[8].y = lbl_803E0B40;
    e[8].z = lbl_803E0B38;
    e[9].layer = 3;
    e[9].flags = 0x124;
    e[9].tex = NULL;
    e[9].mode = 0x20000;
    e[9].x = lbl_803E0B38;
    e[9].y = lbl_803E0B38;
    e[9].z = lbl_803E0B38;
    e[10].layer = 3;
    e[10].flags = 0xe;
    e[10].tex = &base[476];
    e[10].mode = 4;
    e[10].x = lbl_803E0B38;
    e[10].y = lbl_803E0B38;
    e[10].z = lbl_803E0B38;
    e[11].layer = 3;
    e[11].flags = 0x15;
    e[11].tex = &base[432];
    e[11].mode = 0x4000;
    e[11].x = lbl_803E0B40;
    e[11].y = lbl_803E0B40;
    e[11].z = lbl_803E0B38;
    e[12].layer = 3;
    e[12].flags = 0x15;
    e[12].tex = &base[432];
    e[12].mode = 2;
    e[12].x = lbl_803E0B3C;
    e[12].y = lbl_803E0B58;
    e[12].z = lbl_803E0B3C;
    e[13].layer = 3;
    e[13].flags = 0;
    e[13].tex = NULL;
    e[13].mode = 0x400000;
    e[13].x = lbl_803E0B38;
    e[13].y = lbl_803E0B44;
    e[13].z = lbl_803E0B38;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0B38;
    buf.pos[1] = lbl_803E0B38;
    buf.pos[2] = lbl_803E0B38;
    buf.col[0] = lbl_803E0B38;
    buf.col[1] = lbl_803E0B38;
    buf.col[2] = lbl_803E0B38;
    buf.scale = lbl_803E0B58;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 14) - buf.entries;
    buf.hw[0] = *(s16*)&base[504];
    buf.hw[1] = *(s16*)&base[506];
    buf.hw[2] = *(s16*)&base[508];
    buf.hw[3] = *(s16*)&base[510];
    buf.hw[4] = *(s16*)&base[512];
    buf.hw[5] = *(s16*)&base[514];
    buf.hw[6] = *(s16*)&base[516];
    buf.cmds = buf.entries;
    buf.flags = 0xc0100c0;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E0B38 + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E0B38 + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E0B38 + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0B38 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E0B38 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E0B38 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, (u8*)(int)lbl_80314060, 0x18, &base[212], 0x154, 0);
}
