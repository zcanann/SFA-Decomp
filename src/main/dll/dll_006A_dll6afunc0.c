/*
 * dll_6A (dll6afunc0) - particle/gfx spawn helper for a DLL object.
 *
 * The unit owns three entry points:
 *   dll_6A_func00_nop / dll_6A_func01_nop - empty stubs.
 *   dll_6A_func03 - builds a 10-command graphics command list (GfxCmd[])
 *     on the stack from a layout table (lbl_803138A0) and a set of shared
 *     float constants, then submits it via gModgfxInterface->spawnEffect.
 *     Bit 0 of the spawn-context flags word (buf.spawnFlags) enables
 *     world-position override: non-null sourceObj uses the GameObject
 *     world position, null uses posSource as a PartFxSpawnParams packet.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_803138A0[];
extern f32 lbl_803E0A28;
extern f32 lbl_803E0A2C;
extern f32 lbl_803E0A30;
extern f32 lbl_803E0A34;
extern f32 lbl_803E0A38;
extern f32 lbl_803E0A3C;
extern f32 lbl_803E0A40;
extern f32 lbl_803E0A44;
extern f32 lbl_803E0A48;
extern f32 lbl_803E0A4C;

void dll_6A_func01_nop(void)
{
}

void dll_6A_func00_nop(void)
{
}

void dll_6A_func03(u8* sourceObj, int variant, PartFxSpawnParams* posSource, u32 flags)
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
        u32 spawnFlags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* tab = (u8*)(int)lbl_803138A0;
    GfxCmd* e = buf.entries;
    e[0].layer = 0;
    e[0].flags = 0x12;
    e[0].tex = &tab[296];
    e[0].mode = 4;
    e[0].x = lbl_803E0A28;
    e[0].y = lbl_803E0A28;
    e[0].z = lbl_803E0A28;
    e[1].layer = 0;
    e[1].flags = 0x12;
    e[1].tex = &tab[296];
    e[1].mode = 2;
    e[1].x = lbl_803E0A2C;
    e[1].y = lbl_803E0A30;
    e[1].z = lbl_803E0A2C;
    e[2].layer = 0;
    e[2].flags = 9;
    e[2].tex = &tab[276];
    e[2].mode = 8;
    e[2].x = (f32)(u32)tab[variant * 3 + 368];
    e[2].y = (f32)(u32)tab[variant * 3 + 369];
    e[2].z = (f32)(u32)tab[variant * 3 + 370];
    e[3].layer = 1;
    e[3].flags = 0x12;
    e[3].tex = &tab[296];
    e[3].mode = 4;
    e[3].x = lbl_803E0A34;
    e[3].y = lbl_803E0A28;
    e[3].z = lbl_803E0A28;
    e[4].layer = 1;
    e[4].flags = 0x12;
    e[4].tex = &tab[296];
    e[4].mode = 2;
    e[4].x = lbl_803E0A38;
    e[4].y = lbl_803E0A3C;
    e[4].z = lbl_803E0A38;
    e[5].layer = 3;
    e[5].flags = 0x12;
    e[5].tex = &tab[296];
    e[5].mode = 0x100;
    e[5].x = lbl_803E0A28;
    e[5].y = lbl_803E0A28;
    e[5].z = lbl_803E0A40;
    e[6].layer = 4;
    e[6].flags = 2;
    e[6].tex = (void*)0;
    e[6].mode = 0x2000;
    e[6].x = lbl_803E0A28;
    e[6].y = lbl_803E0A28;
    e[6].z = lbl_803E0A28;
    e[7].layer = 5;
    e[7].flags = 0x12;
    e[7].tex = &tab[296];
    e[7].mode = 4;
    e[7].x = lbl_803E0A28;
    e[7].y = lbl_803E0A28;
    e[7].z = lbl_803E0A28;
    e[8].layer = 5;
    e[8].flags = 0x12;
    e[8].tex = &tab[296];
    e[8].mode = 2;
    e[8].x = lbl_803E0A44;
    e[8].y = lbl_803E0A48;
    e[8].z = lbl_803E0A44;
    e[9].layer = 5;
    e[9].flags = 0x7a;
    e[9].tex = (void*)0;
    e[9].mode = 0x10000;
    e[9].x = lbl_803E0A28;
    e[9].y = lbl_803E0A28;
    e[9].z = lbl_803E0A28;
    buf.v58 = 0;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A28;
    buf.pos[1] = lbl_803E0A28;
    buf.pos[2] = lbl_803E0A28;
    buf.col[0] = lbl_803E0A28;
    buf.col[1] = lbl_803E0A28;
    buf.col[2] = lbl_803E0A28;
    buf.scale = lbl_803E0A4C;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 0x12;
    buf.v5a = 0;
    buf.v5b = 0x10;
    buf.count = (e + 10) - buf.entries;
    buf.hw[0] = *(s16*)&tab[352];
    buf.hw[1] = *(s16*)&tab[354];
    buf.hw[2] = *(s16*)&tab[356];
    buf.hw[3] = *(s16*)&tab[358];
    buf.hw[4] = *(s16*)&tab[360];
    buf.hw[5] = *(s16*)&tab[362];
    buf.hw[6] = *(s16*)&tab[364];
    buf.cmds = buf.entries;
    buf.spawnFlags = 0x5000004;
    buf.spawnFlags |= flags;
    if ((buf.spawnFlags & 1) != 0)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E0A28 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = lbl_803E0A28 + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = lbl_803E0A28 + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E0A28 + posSource->posX;
            buf.pos[1] = lbl_803E0A28 + posSource->posY;
            buf.pos[2] = lbl_803E0A28 + posSource->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x12, &lbl_803138A0[0], 0x10, &lbl_803138A0[180], 0x3e, 0);
}
