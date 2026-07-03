/*
 * dll79func0 (DLL 0x79) - a model-graphics effect spawner.
 *
 * dll_79_func03 builds a stack-resident GfxCmd command list describing a
 * multi-layer billboard/sprite effect, selected by `variant` (0, 1 or 2),
 * then hands it to the modgfx interface's spawnEffect. Per variant it lays
 * down a different sequence of GfxCmd entries (each with a draw mode, blend
 * flags, texture and x/y/z parameters pulled from the lbl_803E0Cxx constant
 * pool), copies seven s16 tuning half-words out of the shared model-effect
 * block (gDll79EffectModelBlock), optionally offsets the effect position by the source
 * object's world position (or the PartFxSpawnParams packet) when flag bit 0
 * is set, and finally spawns effect id 0x156/0x89/0x23b for variant 0/1/2.
 *
 * dll_79_func00_nop / dll_79_func01_nop are the DLL's empty entry stubs.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"

typedef struct
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

extern ModgfxInterface** gModgfxInterface;
extern u8 gDll79EffectModelBlock[];
extern u8 lbl_803DB8D8;
extern f32 lbl_803E0CB0, lbl_803E0CB4, lbl_803E0CB8, lbl_803E0CBC, lbl_803E0CC0, lbl_803E0CC4;
extern f32 lbl_803E0CC8, lbl_803E0CCC, lbl_803E0CD0, lbl_803E0CD4, lbl_803E0CD8, lbl_803E0CDC;
extern f32 lbl_803E0CE0, lbl_803E0CE4, lbl_803E0CE8, lbl_803E0CEC, lbl_803E0CF0, lbl_803E0CF4;
extern f32 lbl_803E0CF8, lbl_803E0CFC;

void dll_79_func01_nop(void)
{
}

void dll_79_func00_nop(void)
{
}

int dll_79_func03(u8* sourceObj, int variant, u8* posSource, u32 flags)
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
        u8 v58, v59, v5a, v5b, pad5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* base = (u8*)(int)gDll79EffectModelBlock;
    GfxCmd* e;
    GfxCmd* entries;
    int ret;
    ret = 0;
    entries = buf.entries;
    e = entries;
    e = (GfxCmd*)((int)e | (int)entries);
    if (variant == 0)
    {
        e[0].layer = 0;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x80;
        e[0].x = lbl_803E0CB0;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB4;
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = &base[0x8c];
        e[1].mode = 2;
        e[1].x = lbl_803E0CB8;
        e[1].y = lbl_803E0CB8;
        e[1].z = lbl_803E0CBC;
        e += 2;
    }
    else if (variant == 1)
    {
        f32 t;
        *(s16*)&base[0xb2] = 0x50;
        *(s16*)&base[0xb4] = 0x118;
        e[0].layer = 0;
        e[0].flags = 0x69;
        e[0].tex = NULL;
        e[0].mode = 0x1800000;
        e[0].x = lbl_803E0CC0;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = &base[0x8c];
        e[1].mode = 2;
        t = lbl_803E0CC4 * (f32)(int)randomGetRange(0, 0xc);
        e[1].x = lbl_803E0CC8 + t;
        e[1].y = lbl_803E0CC8 + t;
        e[1].z = lbl_803E0CCC + t;
        e[2].layer = 0;
        e[2].flags = 9;
        e[2].tex = &base[0x8c];
        e[2].mode = 0x80;
        e[2].x = lbl_803E0CB0;
        e[2].y = lbl_803E0CB0;
        e[2].z = lbl_803E0CD0;
        e[3].layer = 0;
        e[3].flags = 8;
        e[3].tex = &base[0xa0];
        e[3].mode = 4;
        e[3].x = lbl_803E0CD4;
        e[3].y = lbl_803E0CB0;
        e[3].z = lbl_803E0CB0;
        e += 4;
    }
    else if (variant == 2)
    {
        f32 t;
        *(s16*)&base[0xb2] = 0x50;
        *(s16*)&base[0xb4] = 0x50;
        e[0].layer = 0;
        e[0].flags = 0x1fc;
        e[0].tex = NULL;
        e[0].mode = 0x1800000;
        e[0].x = lbl_803E0CC0;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 0;
        e[1].flags = 8;
        e[1].tex = &base[0x8c];
        e[1].mode = 2;
        t = lbl_803E0CC4 * (f32)(int)randomGetRange(0, 0xc);
        e[1].x = lbl_803E0CD8 + t;
        e[1].y = lbl_803E0CD8 + t;
        e[1].z = lbl_803E0CDC + t;
        e[2].layer = 0;
        e[2].flags = 0x8c;
        e[2].tex = NULL;
        e[2].mode = 0x20000000;
        e[2].x = lbl_803E0CE0;
        e[2].y = lbl_803E0CE4;
        e[2].z = lbl_803E0CE8;
        e[3].layer = 0;
        e[3].flags = 9;
        e[3].tex = &base[0x8c];
        e[3].mode = 0x80;
        e[3].x = lbl_803E0CB0;
        e[3].y = lbl_803E0CB0;
        e[3].z = lbl_803E0CD0;
        e += 4;
    }
    if (variant == 0)
    {
        e[0].layer = 1;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x4000;
        e[0].x = lbl_803E0CB0;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 1;
        e[1].flags = 8;
        e[1].tex = &base[0x8c];
        e[1].mode = 2;
        e[1].x = lbl_803E0CEC;
        e[1].y = lbl_803E0CEC;
        e[1].z = lbl_803E0CEC;
        e += 2;
    }
    else if (variant == 1)
    {
        e[0].layer = 1;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x4000;
        e[0].x = lbl_803E0CB0;
        e[0].y = lbl_803E0CF0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 1;
        e[1].flags = 0x8f;
        e[1].tex = NULL;
        e[1].mode = 0x1800000;
        e[1].x = lbl_803E0CDC;
        e[1].y = lbl_803E0CB0;
        e[1].z = lbl_803E0CB0;
        e[2].layer = 0;
        e[2].flags = 4;
        e[2].tex = &lbl_803DB8D8;
        e[2].mode = 2;
        e[2].x = lbl_803E0CC0;
        e[2].y = lbl_803E0CC0;
        e[2].z = lbl_803E0CF4;
        e += 3;
    }
    else if (variant == 2)
    {
        e[0].layer = 1;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x4000;
        e[0].x = lbl_803E0CB0;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 1;
        e[1].flags = 0x1fd;
        e[1].tex = NULL;
        e[1].mode = 0x1800000;
        e[1].x = lbl_803E0CF4;
        e[1].y = lbl_803E0CB0;
        e[1].z = lbl_803E0CB0;
        e += 2;
    }
    if (variant == 0)
    {
        e[0].layer = 1;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x100;
        e[0].x = lbl_803E0CF8;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e += 1;
    }
    else if (variant == 1)
    {
        e[0].layer = 1;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x100;
        e[0].x = lbl_803E0CFC;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e += 1;
    }
    else if (variant == 2)
    {
        e[0].layer = 1;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x100;
        e[0].x = lbl_803E0CFC;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e += 1;
    }
    if (variant == 0)
    {
        e[0].layer = 2;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x100;
        e[0].x = lbl_803E0CF8;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 2;
        e[1].flags = 9;
        e[1].tex = &base[0x8c];
        e[1].mode = 4;
        e[1].x = lbl_803E0CB0;
        e[1].y = lbl_803E0CB0;
        e[1].z = lbl_803E0CB0;
        e += 2;
    }
    else if (variant == 1)
    {
        e[0].layer = 2;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x100;
        e[0].x = lbl_803E0CFC;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e += 1;
    }
    else if (variant == 2)
    {
        e[0].layer = 2;
        e[0].flags = 9;
        e[0].tex = &base[0x8c];
        e[0].mode = 0x100;
        e[0].x = lbl_803E0CFC;
        e[0].y = lbl_803E0CB0;
        e[0].z = lbl_803E0CB0;
        e[1].layer = 2;
        e[1].flags = 9;
        e[1].tex = &base[0x8c];
        e[1].mode = 4;
        e[1].x = lbl_803E0CB0;
        e[1].y = lbl_803E0CB0;
        e[1].z = lbl_803E0CB0;
        e += 2;
    }
    if (variant == 2)
    {
        e[0].layer = 3;
        e[0].flags = 0;
        e[0].tex = NULL;
        e[0].mode = 0x20000000;
        e[0].x = lbl_803E0CE0;
        e[0].y = lbl_803E0CE4;
        e[0].z = lbl_803E0CE8;
        e += 1;
    }
    buf.ctx = sourceObj;
    buf.v44 = variant;
    if (variant == 0)
    {
        buf.pos[0] = lbl_803E0CB0;
        buf.pos[1] = lbl_803E0CB0;
        buf.pos[2] = lbl_803E0CB0;
    }
    else
    {
        buf.pos[0] = lbl_803E0CB0;
        buf.pos[1] = lbl_803E0CB0;
        buf.pos[2] = lbl_803E0CB0;
    }
    buf.col[0] = lbl_803E0CB0;
    buf.col[1] = lbl_803E0CB0;
    buf.col[2] = lbl_803E0CB0;
    buf.scale = lbl_803E0CC0;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 9;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = e - entries;
    buf.hw[0] = *(s16*)&base[0xb0];
    buf.hw[1] = *(s16*)&base[0xb2];
    buf.hw[2] = *(s16*)&base[0xb4];
    buf.hw[3] = *(s16*)&base[0xb6];
    buf.hw[4] = *(s16*)&base[0xb8];
    buf.hw[5] = *(s16*)&base[0xba];
    buf.hw[6] = *(s16*)&base[0xbc];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    buf.flags = 0x4000000;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if (buf.ctx != 0)
        {
            buf.pos[0] += *(f32*)(buf.ctx + 0x18);
            buf.pos[1] += *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] += *(f32*)(buf.ctx + 0x20);
        }
        else
        {
            buf.pos[0] += ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] += ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] += ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    if (variant == 0)
    {
        buf.v58 = 0;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)gDll79EffectModelBlock, 8, &base[0x5c], 0x156, 0);
    }
    else if (variant == 1)
    {
        buf.v58 = 0;
        buf.flags |= 4;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)gDll79EffectModelBlock, 8, &base[0x5c], 0x89, 0);
    }
    else if (variant == 2)
    {
        buf.v58 = 0;
        buf.flags |= 4;
        ret = (*gModgfxInterface)->spawnEffect(&buf, 0, 9, (u8*)(int)gDll79EffectModelBlock, 8, &base[0x5c], 0x23b, 0);
    }
    return ret;
}

u8 gDll79EffectModelBlock[] = {
    0x03, 0xE8, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3,
    0xFD, 0x3D, 0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0xFC, 0x18,
    0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0xFD, 0x3D, 0xFD, 0x3D, 0x01, 0x90,
    0x00, 0x00, 0x00, 0x1F, 0xFC, 0x18, 0x00, 0x00, 0x01, 0x90, 0x00, 0x1F,
    0x00, 0x1F, 0xFD, 0x3D, 0x02, 0xC3, 0x01, 0x90, 0x00, 0x00, 0x00, 0x1F,
    0x00, 0x00, 0x03, 0xE8, 0x01, 0x90, 0x00, 0x1F, 0x00, 0x1F, 0x02, 0xC3,
    0x02, 0xC3, 0x01, 0x90, 0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00, 0x00,
    0xFB, 0xB4, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x08, 0x00, 0x01, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x08, 0x00, 0x03, 0x00, 0x04, 0x00, 0x08, 0x00, 0x04, 0x00, 0x05,
    0x00, 0x08, 0x00, 0x05, 0x00, 0x06, 0x00, 0x08, 0x00, 0x06, 0x00, 0x07,
    0x00, 0x08, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
    0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
    0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0x00, 0x32,
    0x00, 0x1E, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
