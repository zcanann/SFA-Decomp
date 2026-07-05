/*
 * DLL 0x59 (dll59func0) - a thin gameplay-effect DLL exporting three
 * object hooks. func00/func01 are empty no-op slots; func03 builds an
 * nine-command modgfx effect list on the stack (texture/blend modes
 * from the lbl_803E06xx float constants and the lbl_80311C58 resource
 * blob) and submits it through gModgfxInterface->spawnEffect. When the
 * effect's flag bit 0 is set, the spawn position is offset either by the
 * source object's local position (object 0x18/0x1c/0x20) or, if absent,
 * by the PartFxSpawnParams packet at posSource.
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

extern u8 lbl_80311C58[];
extern f32 lbl_803E06F0;
extern f32 lbl_803E06F4;
extern f32 lbl_803E06F8;
extern f32 lbl_803E06FC;
extern f32 lbl_803E0700;
extern f32 lbl_803E0704;
extern f32 lbl_803E0708;
extern f32 lbl_803E070C;

void dll_59_func01_nop(void)
{
}

void dll_59_func00_nop(void)
{
}

void dll_59_func03(int sourceObj, int variant, int posSource, u32 flags)
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
    u8* base = (u8*)(int)lbl_80311C58;
    GfxCmd* e = buf.entries;
    int ctx;
    f32 one;
    f32 zero;
    e[0].layer = 1;
    e[0].flags = 0x11;
    e[0].tex = &base[220];
    e[0].mode = 0x4000;
    e[0].x = (zero = lbl_803E06F0);
    e[0].y = lbl_803E06F4;
    e[0].z = zero;
    e[1].layer = 1;
    e[1].flags = 0x10;
    e[1].tex = &base[256];
    e[1].mode = 2;
    e[1].x = lbl_803E06F8;
    e[1].y = lbl_803E06F8;
    e[1].z = lbl_803E06F8;
    e[2].layer = 1;
    e[2].flags = 0x11;
    e[2].tex = &base[220];
    e[2].mode = 0x100;
    e[2].x = zero;
    e[2].y = zero;
    e[2].z = lbl_803E06FC;
    e[3].layer = 1;
    e[3].flags = 2;
    e[3].tex = NULL;
    e[3].mode = 0x4000000;
    e[3].x = (one = lbl_803E0700);
    e[3].y = zero;
    e[3].z = zero;
    e[4].layer = 2;
    e[4].flags = 2;
    e[4].tex = NULL;
    e[4].mode = 0x4000000;
    e[4].x = one;
    e[4].y = zero;
    e[4].z = zero;
    e[5].layer = 2;
    e[5].flags = 0x11;
    e[5].tex = &base[220];
    e[5].mode = 0x4000;
    e[5].x = zero;
    e[5].y = lbl_803E06F4;
    e[5].z = zero;
    e[6].layer = 2;
    e[6].flags = 0x11;
    e[6].tex = &base[220];
    e[6].mode = 4;
    e[6].x = zero;
    e[6].y = zero;
    e[6].z = zero;
    e[7].layer = 2;
    e[7].flags = 0x11;
    e[7].tex = &base[220];
    e[7].mode = 0x100;
    e[7].x = zero;
    e[7].y = zero;
    e[7].z = lbl_803E0704;
    e[8].layer = 2;
    e[8].flags = 0x10;
    e[8].tex = &base[256];
    e[8].mode = 2;
    e[8].x = lbl_803E0708;
    e[8].y = lbl_803E0708;
    e[8].z = lbl_803E0708;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.v44 = variant;
    buf.pos[0] = zero;
    buf.pos[1] = lbl_803E070C;
    buf.pos[2] = zero;
    buf.col[0] = zero;
    buf.col[1] = zero;
    buf.col[2] = zero;
    buf.scale = one;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x11;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = (e + 9) - buf.entries;
    buf.hw[0] = *(s16*)&base[288];
    buf.hw[1] = *(s16*)&base[290];
    buf.hw[2] = *(s16*)&base[292];
    buf.hw[3] = *(s16*)&base[294];
    buf.hw[4] = *(s16*)&base[296];
    buf.hw[5] = *(s16*)&base[298];
    buf.hw[6] = *(s16*)&base[300];
    buf.cmds = buf.entries;
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((void*)ctx != NULL)
        {
            buf.pos[0] = lbl_803E06F0 + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = lbl_803E070C + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = lbl_803E06F0 + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E06F0 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E070C + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E06F0 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x11, (u8*)(int)lbl_80311C58, 8, &base[172], 0xc0d, 0);
}
