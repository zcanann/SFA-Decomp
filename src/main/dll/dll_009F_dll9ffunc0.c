/*
 * dll9ffunc0 (DLL 0x9F) - builds a layered ModGfx effect command list and
 * submits it via gModgfxInterface->spawnEffect (effect id 0x46c).
 *
 * dll_9F_func03 fills a stack command buffer with up to 17 GfxCmd entries
 * (an optional leading entry keyed off *sourceObj, then a fixed 16-entry
 * body) plus a header of colours, position, scale and seven halfwords read
 * from the effect's data table (gDll9fEffectDataTable). The base draw flags
 * (0xC0104C0) are OR'd with the caller's flags; bit 0 means "position the
 * effect", taken from the GameObject's world position when sourceObj is set,
 * otherwise from posSource+0xC. The float constants (lbl_803E14xx) are the
 * per-entry coordinates. dll_9F_func00/01_nop are empty DLL slots.
 *
 * Sibling DLL 0xA0 (dll_00A0_dlla0func0.c) is the same builder with a
 * different table/effect id.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern ModgfxInterface** gModgfxInterface;

/* base draw flags before OR'ing the caller's flags */
#define DLL9F_EFFECT_BASE_FLAGS 0xc0104c0
/* spawnEffect effect id for this DLL */
#define DLL9F_EFFECT_ID 0x46c
/* fl bit 0: derive effect position from sourceObj / posSource */
#define DLL9F_FLAG_POSITIONED 0x1

typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

extern u8 gDll9fEffectDataTable[];
extern f32 lbl_803E1448;
extern f32 lbl_803E144C;
extern f32 lbl_803E1450;
extern f32 lbl_803E1454;
extern f32 lbl_803E1458;
extern f32 lbl_803E145C;
extern f32 lbl_803E1460;
extern f32 lbl_803E1464;
extern f32 lbl_803E1468;
extern f32 lbl_803E146C;
extern f32 lbl_803E1470;
extern f32 lbl_803E1474;
extern f32 lbl_803E1478;
extern f32 lbl_803E147C;

void dll_9F_func03(short* sourceObj, int variant, int posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale; /* +0x38 */
        u32 v3c; /* +0x3c: unknown */
        u32 v40; /* +0x40: unknown */
        s16 v44; /* +0x44: variant */
        s16 hw[7]; /* +0x46 */
        u32 flags; /* +0x54 */
        u8 v58; /* +0x58: unknown */
        u8 v59; /* +0x59: unknown */
        u8 v5a; /* +0x5a: unknown */
        u8 v5b; /* +0x5b: unknown */
        u8 v5c; /* +0x5c: unwritten */
        s8 count; /* +0x5d */
        u8 pad1[2]; /* +0x5e */
        GfxCmd entries[32]; /* +0x60 */
    } buf;
    u8* tab = gDll9fEffectDataTable;
    GfxCmd* base = buf.entries;
    GfxCmd* e = base;
    int head = *sourceObj;
    u32 fl;

    if (head != 0)
    {
        e->layer = 0;
        e->flags = 0x15;
        e->tex = &tab[0x1b0];
        e->mode = 0x80;
        e->x = lbl_803E1448;
        e->y = lbl_803E1448;
        e->z = head;
        e = base + 1;
    }
    e[0].layer = 0;
    e[0].flags = 0x15;
    e[0].tex = &tab[0x1b0];
    e[0].mode = 4;
    e[0].x = lbl_803E1448;
    e[0].y = lbl_803E1448;
    e[0].z = lbl_803E1448;
    e[1].layer = 0;
    e[1].flags = 7;
    e[1].tex = &tab[0x164];
    e[1].mode = 2;
    e[1].x = lbl_803E144C;
    e[1].y = lbl_803E144C;
    e[1].z = lbl_803E1450;
    e[2].layer = 0;
    e[2].flags = 7;
    e[2].tex = &tab[0x174];
    e[2].mode = 2;
    e[2].x = lbl_803E1454;
    e[2].y = lbl_803E1454;
    e[2].z = lbl_803E1450;
    e[3].layer = 0;
    e[3].flags = 7;
    e[3].tex = &tab[0x184];
    e[3].mode = 2;
    e[3].x = lbl_803E144C;
    e[3].y = lbl_803E144C;
    e[3].z = lbl_803E1450;
    e[4].layer = 1;
    e[4].flags = 7;
    e[4].tex = &tab[0x174];
    e[4].mode = 4;
    e[4].x = lbl_803E1458;
    e[4].y = lbl_803E1448;
    e[4].z = lbl_803E1448;
    e[5].layer = 1;
    e[5].flags = 0x15;
    e[5].tex = &tab[0x1b0];
    e[5].mode = 0x4000;
    e[5].x = lbl_803E145C;
    e[5].y = lbl_803E1460;
    e[5].z = lbl_803E1448;
    e[6].layer = 1;
    e[6].flags = 0;
    e[6].tex = NULL;
    e[6].mode = 0x400000;
    e[6].x = lbl_803E1448;
    e[6].y = lbl_803E1448;
    e[6].z = lbl_803E1464;
    e[7].layer = 2;
    e[7].flags = 0x15;
    e[7].tex = &tab[0x1b0];
    e[7].mode = 0x4000;
    e[7].x = lbl_803E145C;
    e[7].y = lbl_803E1460;
    e[7].z = lbl_803E1448;
    e[8].layer = 2;
    e[8].flags = 0;
    e[8].tex = NULL;
    e[8].mode = 0x400000;
    e[8].x = lbl_803E1448;
    e[8].y = lbl_803E1448;
    e[8].z = lbl_803E1468;
    e[9].layer = 2;
    e[9].flags = 0x15;
    e[9].tex = &tab[0x1b0];
    e[9].mode = 8;
    e[9].x = lbl_803E146C;
    e[9].y = lbl_803E146C;
    e[9].z = lbl_803E1470;
    e[10].layer = 3;
    e[10].flags = 0x15;
    e[10].tex = &tab[0x1b0];
    e[10].mode = 0x4000;
    e[10].x = lbl_803E145C;
    e[10].y = lbl_803E145C;
    e[10].z = lbl_803E1448;
    e[11].layer = 3;
    e[11].flags = 0;
    e[11].tex = NULL;
    e[11].mode = 0x400000;
    e[11].x = lbl_803E1448;
    e[11].y = lbl_803E1448;
    e[11].z = lbl_803E1474;
    e[12].layer = 3;
    e[12].flags = 0x15;
    e[12].tex = &tab[0x1b0];
    e[12].mode = 8;
    e[12].x = lbl_803E146C;
    e[12].y = lbl_803E146C;
    e[12].z = lbl_803E146C;
    e[13].layer = 4;
    e[13].flags = 0x15;
    e[13].tex = &tab[0x1b0];
    e[13].mode = 0x4000;
    e[13].x = lbl_803E145C;
    e[13].y = lbl_803E145C;
    e[13].z = lbl_803E1448;
    e[14].layer = 4;
    e[14].flags = 7;
    e[14].tex = &tab[0x174];
    e[14].mode = 4;
    e[14].x = lbl_803E1448;
    e[14].y = lbl_803E1448;
    e[14].z = lbl_803E1448;
    e[15].layer = 4;
    e[15].flags = 0;
    e[15].tex = NULL;
    e[15].mode = 0x400000;
    e[15].x = lbl_803E1448;
    e[15].y = lbl_803E1448;
    e[15].z = lbl_803E1478;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1448;
    buf.pos[1] = lbl_803E1448;
    buf.pos[2] = lbl_803E1448;
    buf.col[0] = lbl_803E1448;
    buf.col[1] = lbl_803E1448;
    buf.col[2] = lbl_803E1448;
    buf.scale = lbl_803E147C;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x1e;
    buf.count = &e[16] - base;
    buf.hw[0] = *(s16*)&tab[0x1f8];
    buf.hw[1] = *(s16*)&tab[0x1fa];
    buf.hw[2] = *(s16*)&tab[0x1fc];
    buf.hw[3] = *(s16*)&tab[0x1fe];
    buf.hw[4] = *(s16*)&tab[0x200];
    buf.hw[5] = *(s16*)&tab[0x202];
    buf.hw[6] = *(s16*)&tab[0x204];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    fl = DLL9F_EFFECT_BASE_FLAGS;
    buf.flags = fl;
    fl |= flags;
    buf.flags = fl;
    if (fl & DLL9F_FLAG_POSITIONED)
    {
        if (sourceObj != NULL)
        {
            buf.pos[0] = lbl_803E1448 + ((GameObject*)sourceObj)->anim.worldPosX;
            buf.pos[1] = lbl_803E1448 + ((GameObject*)sourceObj)->anim.worldPosY;
            buf.pos[2] = lbl_803E1448 + ((GameObject*)sourceObj)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = lbl_803E1448 + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = lbl_803E1448 + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = lbl_803E1448 + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0x15, tab, 0x18, &tab[0xd4], DLL9F_EFFECT_ID, 0);
}

void dll_9F_func01_nop(void)
{
}

void dll_9F_func00_nop(void)
{
}

u8 gDll9fEffectDataTable[520] = {
    0, 0, 3, 232, 0, 0, 0, 0, 0, 0, 3, 98, 1, 244, 0, 0,
    0, 22, 0, 0, 3, 98, 254, 12, 0, 0, 0, 44, 0, 0, 0, 0,
    252, 24, 0, 0, 0, 63, 0, 0, 252, 158, 254, 12, 0, 0, 0, 44,
    0, 0, 252, 158, 1, 244, 0, 0, 0, 22, 0, 0, 0, 0, 3, 232,
    0, 0, 0, 0, 0, 0, 0, 0, 3, 232, 11, 184, 0, 0, 0, 15,
    3, 98, 1, 244, 11, 184, 0, 22, 0, 15, 3, 98, 254, 12, 11, 184,
    0, 44, 0, 15, 0, 0, 252, 24, 11, 184, 0, 63, 0, 15, 252, 158,
    254, 12, 11, 184, 0, 44, 0, 15, 252, 158, 1, 244, 11, 184, 0, 22,
    0, 15, 0, 0, 3, 232, 11, 184, 0, 0, 0, 15, 0, 0, 3, 232,
    23, 112, 0, 0, 0, 31, 3, 98, 1, 244, 23, 112, 0, 22, 0, 31,
    3, 98, 254, 12, 23, 112, 0, 44, 0, 31, 0, 0, 252, 24, 23, 112,
    0, 63, 0, 31, 252, 158, 254, 12, 23, 112, 0, 44, 0, 31, 252, 158,
    1, 244, 23, 112, 0, 22, 0, 31, 0, 0, 3, 232, 23, 112, 0, 0,
    0, 31, 0, 0, 0, 0, 0, 1, 0, 8, 0, 0, 0, 8, 0, 7,
    0, 1, 0, 2, 0, 9, 0, 1, 0, 9, 0, 8, 0, 2, 0, 3,
    0, 10, 0, 2, 0, 10, 0, 9, 0, 3, 0, 4, 0, 11, 0, 3,
    0, 11, 0, 10, 0, 4, 0, 5, 0, 12, 0, 4, 0, 12, 0, 11,
    0, 5, 0, 6, 0, 13, 0, 5, 0, 13, 0, 12, 0, 7, 0, 8,
    0, 15, 0, 7, 0, 15, 0, 14, 0, 8, 0, 9, 0, 16, 0, 8,
    0, 16, 0, 15, 0, 9, 0, 10, 0, 17, 0, 9, 0, 17, 0, 16,
    0, 10, 0, 11, 0, 18, 0, 10, 0, 18, 0, 17, 0, 11, 0, 12,
    0, 19, 0, 11, 0, 19, 0, 18, 0, 12, 0, 13, 0, 20, 0, 12,
    0, 20, 0, 19, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
    0, 6, 0, 0, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12,
    0, 13, 0, 0, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19,
    0, 20, 0, 0, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5,
    0, 6, 0, 14, 0, 15, 0, 16, 0, 17, 0, 18, 0, 19, 0, 20,
    0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7,
    0, 8, 0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15,
    0, 16, 0, 17, 0, 18, 0, 19, 0, 20, 0, 0, 0, 7, 0, 8,
    0, 9, 0, 10, 0, 11, 0, 12, 0, 13, 0, 14, 0, 15, 0, 16,
    0, 17, 0, 18, 0, 19, 0, 20, 0, 0, 0, 50, 0, 250, 0, 250,
    0, 50, 0, 0, 0, 0, 0, 0,
};

/* .sdata2 float-pool constants referenced via extern by sibling stubs */
const f32 lbl_803E1488 = 0.0f;
const f32 lbl_803E148C = 0.035f;
const f32 lbl_803E1490 = -0.45f;
const f32 lbl_803E1494 = 0.45f;
const f32 lbl_803E1498 = 10.0f;
const f32 lbl_803E149C = 255.0f;
const f32 lbl_803E14A0 = -6.0f;
const f32 lbl_803E14A4 = 1.0f;
const f32 lbl_803E14A8 = 2.0f;
const f32 lbl_803E14AC = 4.0f;
const f32 lbl_803E14B0 = 6.0f;
const f32 lbl_803E14B4 = 0.0f;
const f32 lbl_803E14B8 = 0.0f;
const f32 lbl_803E14BC = 0.01f;
const f32 lbl_803E14C0 = 0.05f;
const f32 lbl_803E14C4 = 255.0f;
const f32 lbl_803E14C8 = 1.0f;
const f32 lbl_803E14CC = -6.0f;
const f32 lbl_803E14D0 = 5.0f;
const f32 lbl_803E14D4 = 500.0f;
const f32 lbl_803E14D8 = 3.5f;
const f32 lbl_803E14DC = 2.0f;
const f32 lbl_803E14E0 = 0.0f;
const f32 lbl_803E14E4 = 0.05f;
const f32 lbl_803E14E8 = -0.35f;
const f32 lbl_803E14EC = 255.0f;
const f32 lbl_803E14F0 = 4.0f;
const f32 lbl_803E14F4 = 8.0f;
const f32 lbl_803E14F8 = 10.0f;
const f32 lbl_803E14FC = 1.0f;
const f32 lbl_803E1500 = -4.0f;
const f32 lbl_803E1504 = 0.0f;
const f32 lbl_803E1508 = 0.0f;
const f32 lbl_803E150C = 1.0f;
const f32 lbl_803E1510 = 1.26f;
const f32 lbl_803E1514 = 1.9f;
const f32 lbl_803E1518 = 255.0f;
const f32 lbl_803E151C = 3.0f;
const f32 lbl_803E1520 = 2.0f;
const f32 lbl_803E1524 = 25.0f;
