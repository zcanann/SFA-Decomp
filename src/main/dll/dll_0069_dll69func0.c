/*
 * DLL 0x69 entry-point table (func0 object).
 *
 * dll_69_func03 builds a stack list of GfxCmd records describing a layered
 * 2D/billboard effect and submits it through gModgfxInterface->spawnEffect.
 * The layout is read from the shared resource at lbl_803137F8; the constant
 * vector pool lbl_803E0A00.. supplies the per-entry positions/scales.
 *   - variant selects the effect group passed to spawnEffect (0xc11 for
 *     variant 2, else 0x5e0) and toggles command-list flag 0x40000.
 *   - overrideParams (a/b/c/d) override the default layer-1/4 colour words.
 *   - sourceObj scales entry 1 by the object's rootMotionScale and seeds
 *     entry 2's depth; posSource supplies the spawn position.
 * func00/func01 are the table's no-op slots.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern u8 lbl_803137F8[];
extern f32 lbl_803E0A00, lbl_803E0A04, lbl_803E0A08, lbl_803E0A0C, lbl_803E0A10, lbl_803E0A14, lbl_803E0A18;

void dll_69_func01_nop(void)
{
}

void dll_69_func00_nop(void)
{
}

void dll_69_func03(u8* sourceObj, int variant, u8* posSource, u32 flags, int unused, int* overrideParams)
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
        u8 v58, v59, v5a, v5b, pad_5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    GfxCmd* e;
    GfxCmd* entries;
    u8* base = (u8*)(int)lbl_803137F8;
    int b = 0x30;
    int c = 0x31;
    int a = 1;
    int d = 0x50;
    entries = buf.entries;
    if (overrideParams != NULL)
    {
        a = overrideParams[0];
        b = overrideParams[1];
        c = overrideParams[2];
        d = overrideParams[3];
    }
    entries[0].layer = 0;
    entries[0].flags = 8;
    entries[0].tex = &base[0x68];
    entries[0].mode = 4;
    entries[0].x = lbl_803E0A00;
    entries[0].y = lbl_803E0A00;
    entries[0].z = lbl_803E0A00;
    entries[1].layer = 0;
    entries[1].flags = 8;
    entries[1].tex = &base[0x68];
    entries[1].mode = 2;
    if (sourceObj != NULL)
    {
        entries[1].x = lbl_803E0A04 * ((GameObject*)sourceObj)->anim.rootMotionScale;
        entries[1].y = lbl_803E0A08 * ((GameObject*)sourceObj)->anim.rootMotionScale;
        entries[1].z = lbl_803E0A04 * ((GameObject*)sourceObj)->anim.rootMotionScale;
    }
    else
    {
        entries[1].x = lbl_803E0A04;
        entries[1].y = lbl_803E0A08;
        entries[1].z = lbl_803E0A04;
    }
    entries[2].layer = 0;
    entries[2].flags = 0;
    entries[2].tex = NULL;
    entries[2].mode = 0x80;
    entries[2].x = lbl_803E0A00;
    entries[2].y = lbl_803E0A00;
    if (sourceObj != NULL)
    {
        entries[2].z = (f32) * (s16*)sourceObj;
    }
    else
    {
        entries[2].z = lbl_803E0A00;
    }
    entries[3].layer = 1;
    entries[3].flags = 8;
    entries[3].tex = &base[0x68];
    entries[3].mode = 4;
    entries[3].x = lbl_803E0A0C;
    entries[3].y = lbl_803E0A00;
    entries[3].z = lbl_803E0A00;
    entries[4].layer = 1;
    entries[4].flags = d;
    entries[4].tex = NULL;
    entries[4].mode = 0x20000000;
    entries[4].x = a;
    entries[4].y = b;
    entries[4].z = c;
    e = &entries[5];
    if (variant == 0)
    {
        e->layer = 2;
        e->flags = 0x3b;
        e->tex = NULL;
        e->mode = 0x1800000;
        e->x = lbl_803E0A10;
        e->y = lbl_803E0A00;
        e->z = lbl_803E0A14;
        e++;
    }
    e[0].layer = 2;
    e[0].flags = 0;
    e[0].tex = NULL;
    e[0].mode = 0x100;
    e[0].x = lbl_803E0A00;
    e[0].y = lbl_803E0A00;
    e[0].z = lbl_803E0A18;
    e[1].layer = 3;
    e[1].flags = 1;
    e[1].tex = NULL;
    e[1].mode = 0x2000;
    e[1].x = lbl_803E0A00;
    e[1].y = lbl_803E0A00;
    e[1].z = lbl_803E0A00;
    e[2].layer = 4;
    e[2].flags = 8;
    e[2].tex = &base[0x68];
    e[2].mode = 4;
    e[2].x = lbl_803E0A00;
    e[2].y = lbl_803E0A00;
    e[2].z = lbl_803E0A00;
    e[3].layer = 4;
    e[3].flags = 0;
    e[3].tex = NULL;
    e[3].mode = 0x20000000;
    e[3].x = a;
    e[3].y = b;
    e[3].z = c;
    buf.v58 = variant;
    buf.ctx = sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E0A00;
    if (posSource != NULL)
    {
        buf.pos[1] = ((PartFxSpawnParams*)posSource)->posY;
    }
    else
    {
        buf.pos[1] = lbl_803E0A00;
    }
    buf.pos[2] = *(f32*)&lbl_803E0A00;
    buf.col[0] = *(f32*)&lbl_803E0A00;
    buf.col[1] = *(f32*)&lbl_803E0A00;
    buf.col[2] = *(f32*)&lbl_803E0A00;
    buf.scale = lbl_803E0A10;
    buf.v3c = 0;
    buf.v40 = 1;
    buf.v59 = 8;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (e + 4) - entries;
    buf.hw[0] = *(s16*)&base[0x78];
    buf.hw[1] = *(s16*)&base[0x7a];
    buf.hw[2] = *(s16*)&base[0x7c];
    buf.hw[3] = *(s16*)&base[0x7e];
    buf.hw[4] = *(s16*)&base[0x80];
    buf.hw[5] = *(s16*)&base[0x82];
    buf.hw[6] = *(s16*)&base[0x84];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags | 0x80;
    if (variant == 2)
    {
        buf.flags ^= 0x40000LL;
    }
    else
    {
        buf.flags |= 0x40000LL;
    }
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != NULL)
        {
            buf.pos[0] += ((GameObject*)(buf.ctx))->anim.worldPosX;
            buf.pos[1] += ((GameObject*)(buf.ctx))->anim.worldPosY;
            buf.pos[2] += ((GameObject*)(buf.ctx))->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 8, (u8*)(int)lbl_803137F8, 4, &base[0x50], variant == 2 ? 0xc11 : 0x5e0,
                                     0);
}

