#include "main/effect_interfaces.h"
#include "main/dll/screens.h"


extern u32 randomGetRange(int min, int max);


/*
 * --INFO--
 *
 * Function: dll_9A_func03
 * EN v1.0 Address: 0x800FC5B8
 * EN v1.0 Size: 2428b
 * EN v1.1 Address: 0x800FC854
 * EN v1.1 Size: 2436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* dll_9A_func03 rewritten below (after shared screen-fx typedefs). */

/*
 * --INFO--
 *
 * Function: dll_9B_func03
 * EN v1.0 Address: 0x800FCF3C
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x800FD1D8
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    u32 flags;
    f32 x;
    f32 y;
    f32 z;
    u8* tex;
    u16 id;
    u8 state;
} ScreenFxPart; /* 0x18 */

typedef struct
{
    ScreenFxPart* parts; /* 0x00 */
    int target; /* 0x04 */
    u8 pad0[0x18]; /* 0x08 */
    f32 ax, ay, az; /* 0x20 */
    f32 bx, by, bz; /* 0x2c */
    f32 r; /* 0x38 */
    u32 c7; /* 0x3c */
    u32 c2; /* 0x40 */
    s16 b; /* 0x44 */
    s16 anim[7]; /* 0x46 */
    u32 flags; /* 0x54 */
    u8 v0, v1, v2, v3; /* 0x58 */
    u8 pad1; /* 0x5c */
    s8 count; /* 0x5d */
    u8 pad2[2]; /* 0x5e */
} ScreenFxHdr; /* 0x60 */


extern u8 lbl_80317BD8[];
extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E13A0;
extern f32 lbl_803E13A4;
extern f32 lbl_803E13A8;
extern f32 lbl_803E13AC;
extern f32 lbl_803E13B0;
extern f32 lbl_803E13B4;
extern f32 lbl_803E13B8;
extern f32 lbl_803E13BC;
extern f32 lbl_803E13C0;
extern f32 lbl_803E13C4;

typedef struct
{
    s16 v[7];
} ScreenSeq;

extern u8 lbl_802C2180[];
extern u8 lbl_80317B98[];
extern u8 lbl_803DB958;
extern u8 lbl_803DB960;
extern u8 lbl_803DB964;
extern f32 lbl_803E1370;
extern f32 lbl_803E1374;
extern f32 lbl_803E1378;
extern f32 lbl_803E137C;
extern f32 lbl_803E1380;
extern f32 lbl_803E1384;
extern f32 lbl_803E1388;
extern f32 lbl_803E138C;
extern f32 lbl_803E1390;
extern f32 lbl_803E1394;

void dll_9A_func03(int a, int b, int p, uint flags);

void dll_9B_func03(int a, int b, int p, uint flags);

/*
 * --INFO--
 *
 * Function: dll_9C_func03
 * EN v1.0 Address: 0x800FD2B4
 * EN v1.0 Size: 1160b
 * EN v1.1 Address: 0x800FD550
 * EN v1.1 Size: 1160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_80317E00[];
extern f32 lbl_803E13C8;
extern f32 lbl_803E13CC;
extern f32 lbl_803E13D0;
extern f32 lbl_803E13D4;
extern f32 lbl_803E13D8;
extern f32 lbl_803E13DC;
extern f32 lbl_803E13E0;
extern f32 lbl_803E13E4;
extern f32 lbl_803E13E8;

void dll_9C_func03(int a, int b, int p, uint flags)
{
    ScreenFxHdr hdr;
    ScreenFxPart parts[32];
    u8* base = (u8*)lbl_80317E00;
    ScreenFxPart* pp = parts;
    ScreenFxPart* cur;
    int idx;

    parts[0].state = 0;
    parts[0].id = 0x15;
    parts[0].tex = base + 0x1b0;
    parts[0].flags = 4;
    parts[0].x = lbl_803E13C8;
    parts[0].y = lbl_803E13C8;
    parts[0].z = lbl_803E13C8;
    parts[1].state = 0;
    parts[1].id = 0x15;
    parts[1].tex = base + 0x1b0;
    parts[1].flags = 2;
    parts[1].x = lbl_803E13CC;
    parts[1].y = lbl_803E13D0;
    parts[1].z = lbl_803E13CC;
    cur = pp + 2;
    if (b != 1)
    {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x400000;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13C8;
        cur++;
    }
    if (b == 1)
    {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x80;
        cur->x = (f32) * (s16*)(p + 4);
        cur->y = (f32) * (s16*)(p + 2);
        cur->z = (f32) * (s16*)(p + 0);
        cur++;
    }
    if (b == 1)
    {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = *(f32*)(p + 0x10) / lbl_803E13D4;
        cur->z = lbl_803E13D4;
    }
    else
    {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = lbl_803E13D8;
        cur->z = lbl_803E13D4;
    }
    cur[1].state = 1;
    cur[1].id = 0xe;
    cur[1].tex = base + 0x1dc;
    cur[1].flags = 4;
    cur[1].x = lbl_803E13DC;
    cur[1].y = lbl_803E13C8;
    cur[1].z = lbl_803E13C8;
    cur[2].state = 1;
    cur[2].id = 0x15;
    cur[2].tex = base + 0x1b0;
    cur[2].flags = 0x4000;
    cur[2].x = lbl_803E13D0;
    cur[2].y = lbl_803E13E0;
    cur[2].z = lbl_803E13C8;
    cur += 3;
    if (b != 1)
    {
        cur->state = 1;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x100;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13E4;
        cur++;
    }
    cur[0].state = 2;
    cur[0].id = 0x15;
    cur[0].tex = base + 0x1b0;
    cur[0].flags = 0x4000;
    cur[0].x = lbl_803E13D0;
    cur[0].y = lbl_803E13E0;
    cur[0].z = lbl_803E13C8;
    cur[1].state = 3;
    cur[1].id = 0x15;
    cur[1].tex = base + 0x1b0;
    cur[1].flags = 0x4000;
    cur[1].x = lbl_803E13D0;
    cur[1].y = lbl_803E13E0;
    cur[1].z = lbl_803E13C8;
    cur[2].state = 3;
    cur[2].id = 0xe;
    cur[2].tex = base + 0x1dc;
    cur[2].flags = 4;
    cur[2].x = lbl_803E13C8;
    cur[2].y = lbl_803E13C8;
    cur[2].z = lbl_803E13C8;
    cur[3].state = 1;

    hdr.v0 = 0;
    hdr.target = a;
    hdr.b = (s16)b;
    hdr.bx = lbl_803E13C8;
    hdr.by = lbl_803E13C8;
    hdr.bz = lbl_803E13C8;
    hdr.ax = lbl_803E13C8;
    hdr.ay = lbl_803E13C8;
    hdr.az = lbl_803E13C8;
    hdr.r = lbl_803E13E8;
    hdr.c2 = 2;
    hdr.c7 = 7;
    hdr.v1 = 0xe;
    hdr.v2 = 0;
    hdr.v3 = 0x1e;
    hdr.count = (s8)(((u8*)(cur + 3) - (u8*)pp) / 0x18);
    idx = b * 7;
    hdr.anim[0] = *(s16*)((u8*)(base + idx * 2) + 0x1f8);
    hdr.anim[1] = *(s16*)((u8*)(base + (idx + 1) * 2) + 0x1f8);
    hdr.anim[2] = *(s16*)((u8*)(base + (idx + 2) * 2) + 0x1f8);
    hdr.anim[3] = *(s16*)((u8*)(base + (idx + 3) * 2) + 0x1f8);
    hdr.anim[4] = *(s16*)((u8*)(base + (idx + 4) * 2) + 0x1f8);
    hdr.anim[5] = *(s16*)((u8*)(base + (idx + 5) * 2) + 0x1f8);
    hdr.anim[6] = *(s16*)((u8*)(base + (idx + 6) * 2) + 0x1f8);
    hdr.parts = parts;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0)
    {
        if ((void*)a != NULL)
        {
            hdr.bx = lbl_803E13C8 + *(f32*)(a + 0x18);
            hdr.by = lbl_803E13C8 + *(f32*)(a + 0x1c);
            hdr.bz = lbl_803E13C8 + *(f32*)(a + 0x20);
        }
        else
        {
            hdr.bx = lbl_803E13C8 + *(f32*)(p + 0xc);
            hdr.by = lbl_803E13C8 + *(f32*)(p + 0x10);
            hdr.bz = lbl_803E13C8 + *(f32*)(p + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&hdr, 0, 0x15, base, 0x18, base + 0xd4, 0x154, 0);
}


/* Trivial nops */
void dll_9A_func01_nop(void);

void dll_9A_func00_nop(void);

void dll_9B_func01_nop(void);

void dll_9B_func00_nop(void);

void dll_9C_func01_nop(void)
{
}

void dll_9C_func00_nop(void)
{
}
