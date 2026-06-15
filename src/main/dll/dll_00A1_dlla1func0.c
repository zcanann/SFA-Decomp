#include "main/effect_interfaces.h"
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


void dll_A1_func03(u8* sourceObj, int variant, u8* posSource, uint flags)
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
        u8 v58, v59, v5a, v5b, v5c, count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    u8* tab = (u8*)(int)lbl_803188D8;
    GfxCmd* e = buf.entries;
    u32 fl;

    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &tab[0x1b0];
    e[0].mode = 4;
    e[0].x = lbl_803E14B8;
    e[0].y = lbl_803E14B8;
    e[0].z = lbl_803E14B8;
    e[1].layer = 0;
    e[1].flags = 0x15;
    e[1].tex = &tab[0x1b0];
    e[1].mode = 2;
    e[1].x = lbl_803E14BC;
    e[1].y = lbl_803E14BC;
    e[1].z = lbl_803E14C0;
    e[2].layer = 1;
    e[2].flags = 0x15;
    e[2].tex = &tab[0x1b0];
    e[2].mode = 4;
    e[2].x = lbl_803E14C4;
    e[2].y = lbl_803E14B8;
    e[2].z = lbl_803E14B8;
    e[3].layer = 1;
    e[3].flags = 0x15;
    e[3].tex = &tab[0x1b0];
    e[3].mode = 0x4000;
    e[3].x = lbl_803E14C8;
    e[3].y = lbl_803E14CC;
    e[3].z = lbl_803E14B8;
    e[4].layer = 1;
    e[4].flags = 0x15;
    e[4].tex = &tab[0x1b0];
    e[4].mode = 2;
    e[4].x = lbl_803E14D0;
    e[4].y = lbl_803E14D0;
    e[4].z = lbl_803E14D4;
    e[5].layer = 2;
    e[5].flags = 0x15;
    e[5].tex = &tab[0x1b0];
    e[5].mode = 0x4000;
    e[5].x = lbl_803E14C8;
    e[5].y = lbl_803E14CC;
    e[5].z = lbl_803E14B8;
    e[6].layer = 3;
    e[6].flags = 1;
    e[6].tex = (void*)0;
    e[6].mode = 0x2000;
    e[6].x = lbl_803E14B8;
    e[6].y = lbl_803E14B8;
    e[6].z = lbl_803E14B8;
    e[7].layer = 4;
    e[7].flags = 0x15;
    e[7].tex = &tab[0x1b0];
    e[7].mode = 2;
    e[7].x = lbl_803E14D8;
    e[7].y = lbl_803E14D8;
    e[7].z = lbl_803E14C8;
    e[8].layer = 4;
    e[8].flags = 0x15;
    e[8].tex = &tab[0x1b0];
    e[8].mode = 0x4000;
    e[8].x = lbl_803E14C8;
    e[8].y = lbl_803E14CC;
    e[8].z = lbl_803E14B8;
    e[9].layer = 4;
    e[9].flags = 0x6dd;
    e[9].tex = (void*)0;
    e[9].mode = 0x800000;
    e[9].x = lbl_803E14C8;
    e[9].y = lbl_803E14B8;
    e[9].z = lbl_803E14B8;
    e[10].layer = 5;
    e[10].flags = 0x15;
    e[10].tex = &tab[0x1b0];
    e[10].mode = 0x4000;
    e[10].x = lbl_803E14C8;
    e[10].y = lbl_803E14CC;
    e[10].z = lbl_803E14B8;
    e[11].layer = 5;
    e[11].flags = 0x6de;
    e[11].tex = (void*)0;
    e[11].mode = 0x800000;
    e[11].x = lbl_803E14D0;
    e[11].y = lbl_803E14B8;
    e[11].z = lbl_803E14B8;
    e[12].layer = 5;
    e[12].flags = 0x6dd;
    e[12].tex = (void*)0;
    e[12].mode = 0x800000;
    e[12].x = lbl_803E14C8;
    e[12].y = lbl_803E14B8;
    e[12].z = lbl_803E14B8;
    e[13].layer = 6;
    e[13].flags = 4;
    e[13].tex = (void*)0;
    e[13].mode = 0x2000;
    e[13].x = lbl_803E14B8;
    e[13].y = lbl_803E14B8;
    e[13].z = lbl_803E14B8;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E14B8;
    buf.pos[1] = lbl_803E14B8;
    buf.pos[2] = lbl_803E14B8;
    buf.col[0] = lbl_803E14B8;
    buf.col[1] = lbl_803E14B8;
    buf.col[2] = lbl_803E14B8;
    buf.scale = lbl_803E14DC;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = (GfxCmd*)((u8*)e + 0x150) - e;
    buf.hw[0] = *(s16*)&tab[0x1f8];
    buf.hw[1] = *(s16*)&tab[0x1fa];
    buf.hw[2] = *(s16*)&tab[0x1fc];
    buf.hw[3] = *(s16*)&tab[0x1fe];
    buf.hw[4] = *(s16*)&tab[0x200];
    buf.hw[5] = *(s16*)&tab[0x202];
    buf.hw[6] = *(s16*)&tab[0x204];
    buf.cmds = e;
    buf.flags = 0xc0104c0;
    buf.flags |= flags;
    fl = buf.flags;
    if (fl & 1)
    {
        if (sourceObj != 0)
        {
            buf.pos[0] = lbl_803E14B8 + *(f32*)(sourceObj + 0x18);
            buf.pos[1] = lbl_803E14B8 + *(f32*)(sourceObj + 0x1c);
            buf.pos[2] = lbl_803E14B8 + *(f32*)(sourceObj + 0x20);
        }
        else
        {
            buf.pos[0] = lbl_803E14B8 + *(f32*)(posSource + 0xc);
            buf.pos[1] = lbl_803E14B8 + *(f32*)(posSource + 0x10);
            buf.pos[2] = lbl_803E14B8 + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, tab, 0x18, &tab[0xd4], 0x203, 0);
}


void dll_A1_func01_nop(void)
{
}

void dll_A1_func00_nop(void)
{
}

void dll_A2_func01_nop(void);
