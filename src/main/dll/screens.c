#include "ghidra_import.h"
#include "main/dll/screens.h"


#pragma peephole off
#pragma scheduling off
extern u32 randomGetRange(int min, int max);
extern int FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();

extern undefined4 DAT_802c2900;
extern undefined4 DAT_802c2904;
extern undefined4 DAT_802c2908;
extern undefined4 DAT_802c290c;
extern undefined4 DAT_803187e8;
extern undefined4 DAT_80318828;
extern undefined4 DAT_803188fc;
extern undefined DAT_803189d8;
extern undefined DAT_80318a04;
extern undefined4 DAT_80318a20;
extern undefined4 DAT_80318a22;
extern undefined4 DAT_80318a24;
extern undefined4 DAT_80318a26;
extern undefined4 DAT_80318a28;
extern undefined4 DAT_80318a2a;
extern undefined4 DAT_80318a2c;
extern undefined4 DAT_80318a50;
extern undefined4 DAT_80318b24;
extern undefined DAT_80318c00;
extern undefined DAT_80318c2c;
extern undefined4 DAT_80318c48;
extern undefined4 DAT_803dc5b8;
extern undefined4 DAT_803dc5c0;
extern undefined DAT_803dc5c4;
extern undefined4* DAT_803dd6fc;
extern f64 DOUBLE_803e2018;
extern f64 DOUBLE_803e2070;
extern f32 lbl_803E1FF0;
extern f32 lbl_803E1FF4;
extern f32 lbl_803E1FF8;
extern f32 lbl_803E1FFC;
extern f32 lbl_803E2000;
extern f32 lbl_803E2004;
extern f32 lbl_803E2008;
extern f32 lbl_803E200C;
extern f32 lbl_803E2010;
extern f32 lbl_803E2014;
extern f32 lbl_803E2020;
extern f32 lbl_803E2024;
extern f32 lbl_803E2028;
extern f32 lbl_803E202C;
extern f32 lbl_803E2030;
extern f32 lbl_803E2034;
extern f32 lbl_803E2038;
extern f32 lbl_803E203C;
extern f32 lbl_803E2040;
extern f32 lbl_803E2044;
extern f32 lbl_803E2048;
extern f32 lbl_803E204C;
extern f32 lbl_803E2050;
extern f32 lbl_803E2054;
extern f32 lbl_803E2058;
extern f32 lbl_803E205C;
extern f32 lbl_803E2060;
extern f32 lbl_803E2064;
extern f32 lbl_803E2068;

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
typedef struct {
    u32 flags;
    f32 x;
    f32 y;
    f32 z;
    u8 *tex;
    u16 id;
    u8 state;
} ScreenFxPart; /* 0x18 */

typedef struct {
    ScreenFxPart *parts; /* 0x00 */
    int target;          /* 0x04 */
    u8 pad0[0x18];       /* 0x08 */
    f32 ax, ay, az;      /* 0x20 */
    f32 bx, by, bz;      /* 0x2c */
    f32 r;               /* 0x38 */
    u32 c7;              /* 0x3c */
    u32 c2;              /* 0x40 */
    s16 b;               /* 0x44 */
    s16 anim[7];         /* 0x46 */
    u32 flags;           /* 0x54 */
    u8 v0, v1, v2, v3;   /* 0x58 */
    u8 pad1;             /* 0x5c */
    s8 count;            /* 0x5d */
    u8 pad2[2];          /* 0x5e */
} ScreenFxHdr; /* 0x60 */

typedef void (*ModgfxLaunchFn)(ScreenFxHdr *hdr, int a, int b, u8 *c, int d, u8 *e, int f, int g);

typedef struct {
    u8 pad[0x1f8];
    s16 anims[21];
} ScreenAnimTable;

extern u8 lbl_80317BD8[];
extern int *gModgfxInterface;
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

typedef struct {
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

void dll_9A_func03(int a, int b, int p, uint flags)
{
    ScreenSeq seq;
    ScreenFxPart parts[32];
    ScreenFxHdr hdr;
    ScreenFxPart *cur;
    ScreenFxPart *pp;
    f32 rz;
    f32 ry;

    seq = *(ScreenSeq *)lbl_802C2180;
    seq.v[1] += randomGetRange(0, 0x14);
    seq.v[2] += randomGetRange(-0x14, 0x14);
    seq.v[3] += randomGetRange(-0x14, 0x14);
    seq.v[4] += randomGetRange(-0x14, 0x14);
    pp = parts;
    cur = pp;
    if (b == 0) {
        cur->state = 0;
        cur->id = 3;
        cur->tex = &lbl_803DB964;
        cur->flags = 8;
        cur->x = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->z = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        cur++;
    } else if (b == 1) {
        cur->state = 0;
        cur->id = 3;
        cur->tex = &lbl_803DB964;
        cur->flags = 8;
        cur->x = (f32)(s32)(randomGetRange(0, 0x1e) + 0xe1);
        cur->y = (f32)(s32)(randomGetRange(0, 0x69) + 0x8c);
        cur->z = (f32)(s32)(randomGetRange(0, 0x41) + 0x78);
        cur++;
    }
    rz = (f32)(s32)randomGetRange(-0x36b0, 0x36b0);
    ry = (f32)(s32)randomGetRange(-0x2ee0, 0x2ee0);
    cur[0].state = 0;
    cur[0].id = 0;
    cur[0].tex = 0;
    cur[0].flags = 0x80;
    cur[0].x = lbl_803E1370;
    cur[0].y = ry;
    cur[0].z = rz;
    cur[1].state = 0;
    cur[1].id = 3;
    cur[1].tex = &lbl_803DB964;
    cur[1].flags = 4;
    cur[1].x = lbl_803E1370;
    cur[1].y = lbl_803E1370;
    cur[1].z = lbl_803E1370;
    cur[2].state = 0;
    cur[2].id = 3;
    cur[2].tex = &lbl_803DB964;
    cur[2].flags = 2;
    cur[2].x = lbl_803E1374;
    cur[2].y = lbl_803E137C * (f32)(s32)randomGetRange(0, 0x32) + lbl_803E1378;
    cur[2].z = lbl_803E137C * (f32)(s32)randomGetRange(4, 6) + lbl_803E1380;
    cur[3].state = 1;
    cur[3].id = 1;
    cur[3].tex = &lbl_803DB960;
    cur[3].flags = 4;
    cur[3].x = lbl_803E1384;
    cur[3].y = lbl_803E1370;
    cur[3].z = lbl_803E1370;
    cur[4].state = 1;
    cur[4].id = 0;
    cur[4].tex = &lbl_803DB960;
    cur[4].flags = 0x4000;
    cur[4].x = lbl_803E1388;
    cur[4].y = lbl_803E1370;
    cur[4].z = lbl_803E1370;
    cur[5].state = 1;
    cur[5].id = 3;
    cur[5].tex = &lbl_803DB964;
    cur[5].flags = 2;
    cur[5].x = lbl_803E138C;
    cur[5].y = lbl_803E1390;
    cur[5].z = lbl_803E1390;
    cur[6].state = 1;
    cur[6].id = 0;
    cur[6].tex = 0;
    cur[6].flags = 0x80;
    cur[6].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[6].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[6].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[7].state = 2;
    cur[7].id = 0;
    cur[7].tex = 0;
    cur[7].flags = 0x80;
    cur[7].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[7].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[7].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[8].state = 2;
    cur[8].id = 0;
    cur[8].tex = &lbl_803DB960;
    cur[8].flags = 0x4000;
    cur[8].x = lbl_803E1388;
    cur[8].y = lbl_803E1370;
    cur[8].z = lbl_803E1370;
    cur[9].state = 3;
    cur[9].id = 0;
    cur[9].tex = 0;
    cur[9].flags = 0x80;
    cur[9].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[9].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[9].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[10].state = 3;
    cur[10].id = 0;
    cur[10].tex = &lbl_803DB960;
    cur[10].flags = 0x4000;
    cur[10].x = lbl_803E1388;
    cur[10].y = lbl_803E1370;
    cur[10].z = lbl_803E1370;
    cur[11].state = 4;
    cur[11].id = 0;
    cur[11].tex = 0;
    cur[11].flags = 0x80;
    cur[11].x = (f32)(s32)randomGetRange(-32000, 32000);
    cur[11].y = ry * (f32)(s32)randomGetRange(-1, 1);
    cur[11].z = rz * (f32)(s32)randomGetRange(-1, 1);
    cur[12].state = 4;
    cur[12].id = 0;
    cur[12].tex = &lbl_803DB960;
    cur[12].flags = 0x4000;
    cur[12].x = lbl_803E1388;
    cur[12].y = lbl_803E1370;
    cur[12].z = lbl_803E1370;
    cur[13].state = 4;
    cur[13].id = 1;
    cur[13].tex = &lbl_803DB960;
    cur[13].flags = 4;
    cur[13].x = lbl_803E1370;
    cur[13].y = lbl_803E1370;
    cur[13].z = lbl_803E1370;

    hdr.v0 = 0;
    hdr.target = a;
    hdr.b = (s16)b;
    hdr.bx = lbl_803E1370;
    if (b == 0) {
        hdr.by = lbl_803E1370;
    } else if (b == 1) {
        hdr.by = lbl_803E1394;
    }
    hdr.bz = lbl_803E1370;
    hdr.ax = lbl_803E1370;
    hdr.ay = lbl_803E1370;
    hdr.az = lbl_803E1370;
    hdr.r = lbl_803E1390;
    hdr.c2 = 1;
    hdr.c7 = 0;
    hdr.v1 = 3;
    hdr.v2 = 0;
    hdr.v3 = 0;
    hdr.count = (s8)(((u8 *)(cur + 14) - (u8 *)pp) / 0x18);
    hdr.anim[0] = seq.v[0];
    hdr.anim[1] = seq.v[1];
    hdr.anim[2] = seq.v[2];
    hdr.anim[3] = seq.v[3];
    hdr.anim[4] = seq.v[4];
    hdr.anim[5] = seq.v[5];
    hdr.anim[6] = seq.v[6];
    hdr.parts = parts;
    hdr.flags = 0x4000400;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0) {
        if ((void *)hdr.target != NULL && (void *)p != NULL) {
            hdr.bx = hdr.bx + (*(f32 *)(hdr.target + 0x18) + *(f32 *)(p + 0xc));
            hdr.by = hdr.by + (*(f32 *)(hdr.target + 0x1c) + *(f32 *)(p + 0x10));
            hdr.bz = hdr.bz + (*(f32 *)(hdr.target + 0x20) + *(f32 *)(p + 0x14));
        } else if ((void *)hdr.target != NULL) {
            hdr.bx = hdr.bx + *(f32 *)(hdr.target + 0x18);
            hdr.by = hdr.by + *(f32 *)(hdr.target + 0x1c);
            hdr.bz = hdr.bz + *(f32 *)(hdr.target + 0x20);
        } else if ((void *)p != NULL) {
            hdr.bx = hdr.bx + *(f32 *)(p + 0xc);
            hdr.by = hdr.by + *(f32 *)(p + 0x10);
            hdr.bz = hdr.bz + *(f32 *)(p + 0x14);
        }
    }
    (*(ModgfxLaunchFn)*(int *)(*gModgfxInterface + 8))(&hdr, 0, 3, lbl_80317B98, 1, &lbl_803DB958,
                                                       0x31, 0);
}

void dll_9B_func03(int a, int b, int p, uint flags)
{
    ScreenFxHdr hdr;
    u8 buf[440];
    ScreenFxPart parts[14];
    ScreenFxPart *pp = parts;
    u8 *base = (u8 *)lbl_80317BD8;

    parts[0].state = 0;
    parts[0].id = 0x15;
    parts[0].tex = base + 0x1b0;
    parts[0].flags = 4;
    parts[0].x = lbl_803E13A0;
    parts[0].y = lbl_803E13A0;
    parts[0].z = lbl_803E13A0;
    parts[1].state = 0;
    parts[1].id = 0x15;
    parts[1].tex = base + 0x1b0;
    parts[1].flags = 2;
    parts[1].x = lbl_803E13A4;
    parts[1].y = lbl_803E13A8;
    parts[1].z = lbl_803E13A4;
    parts[2].state = 0;
    parts[2].id = 0;
    parts[2].tex = 0;
    parts[2].flags = 0x400000;
    parts[2].x = lbl_803E13A0;
    parts[2].y = lbl_803E13AC;
    parts[2].z = lbl_803E13A0;
    parts[3].state = 0;
    parts[3].id = 0x124;
    parts[3].tex = 0;
    parts[3].flags = 0x20000;
    parts[3].x = lbl_803E13A0;
    parts[3].y = lbl_803E13A0;
    parts[3].z = lbl_803E13A0;
    parts[4].state = 1;
    parts[4].id = 0x15;
    parts[4].tex = base + 0x1b0;
    parts[4].flags = 2;
    parts[4].x = lbl_803E13B0;
    parts[4].y = lbl_803E13B4;
    parts[4].z = lbl_803E13B0;
    parts[5].state = 1;
    parts[5].id = 0xe;
    parts[5].tex = base + 0x1dc;
    parts[5].flags = 4;
    parts[5].x = lbl_803E13B8;
    parts[5].y = lbl_803E13A0;
    parts[5].z = lbl_803E13A0;
    parts[6].state = 1;
    parts[6].id = 0x15;
    parts[6].tex = base + 0x1b0;
    parts[6].flags = 0x4000;
    parts[6].x = lbl_803E13A8;
    parts[6].y = lbl_803E13BC;
    parts[6].z = lbl_803E13A0;
    parts[7].state = 1;
    parts[7].id = 0;
    parts[7].tex = 0;
    parts[7].flags = 0x400000;
    parts[7].x = lbl_803E13A0;
    parts[7].y = lbl_803E13C0;
    parts[7].z = lbl_803E13A0;
    parts[8].state = 2;
    parts[8].id = 0x15;
    parts[8].tex = base + 0x1b0;
    parts[8].flags = 0x4000;
    parts[8].x = lbl_803E13A8;
    parts[8].y = lbl_803E13BC;
    parts[8].z = lbl_803E13A0;
    parts[9].state = 3;
    parts[9].id = 0x124;
    parts[9].tex = 0;
    parts[9].flags = 0x20000;
    parts[9].x = lbl_803E13A0;
    parts[9].y = lbl_803E13A0;
    parts[9].z = lbl_803E13A0;
    parts[10].state = 3;
    parts[10].id = 0xe;
    parts[10].tex = base + 0x1dc;
    parts[10].flags = 4;
    parts[10].x = lbl_803E13A0;
    parts[10].y = lbl_803E13A0;
    parts[10].z = lbl_803E13A0;
    parts[11].state = 3;
    parts[11].id = 0x15;
    parts[11].tex = base + 0x1b0;
    parts[11].flags = 0x4000;
    parts[11].x = lbl_803E13A8;
    parts[11].y = lbl_803E13BC;
    parts[11].z = lbl_803E13A0;
    parts[12].state = 3;
    parts[12].id = 0x15;
    parts[12].tex = base + 0x1b0;
    parts[12].flags = 2;
    parts[12].x = lbl_803E13A4;
    parts[12].y = lbl_803E13C4;
    parts[12].z = lbl_803E13A4;
    parts[13].state = 3;
    parts[13].id = 0;
    parts[13].tex = 0;
    parts[13].flags = 0x400000;
    parts[13].x = lbl_803E13A0;
    parts[13].y = lbl_803E13AC;
    parts[13].z = lbl_803E13A0;

    hdr.v0 = 0;
    hdr.target = a;
    hdr.b = (s16)b;
    hdr.bx = lbl_803E13A0;
    hdr.by = lbl_803E13A0;
    hdr.bz = lbl_803E13A0;
    hdr.ax = lbl_803E13A0;
    hdr.ay = lbl_803E13A0;
    hdr.az = lbl_803E13A0;
    hdr.r = lbl_803E13C4;
    hdr.c2 = 2;
    hdr.c7 = 7;
    hdr.v1 = 0xe;
    hdr.v2 = 0;
    hdr.v3 = 0x1e;
    hdr.count = (s8)((buf - (u8 *)pp) / 0x18);
    hdr.anim[0] = *(s16 *)(base + 0x1f8);
    hdr.anim[1] = *(s16 *)(base + 0x1fa);
    hdr.anim[2] = *(s16 *)(base + 0x1fc);
    hdr.anim[3] = *(s16 *)(base + 0x1fe);
    hdr.anim[4] = *(s16 *)(base + 0x200);
    hdr.anim[5] = *(s16 *)(base + 0x202);
    hdr.anim[6] = *(s16 *)(base + 0x204);
    hdr.parts = pp;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0) {
        if ((void *)a != NULL) {
            hdr.bx = lbl_803E13A0 + *(f32 *)(a + 0x18);
            hdr.by = lbl_803E13A0 + *(f32 *)(a + 0x1c);
            hdr.bz = lbl_803E13A0 + *(f32 *)(a + 0x20);
        } else {
            hdr.bx = lbl_803E13A0 + *(f32 *)(p + 0xc);
            hdr.by = lbl_803E13A0 + *(f32 *)(p + 0x10);
            hdr.bz = lbl_803E13A0 + *(f32 *)(p + 0x14);
        }
    }
    (*(ModgfxLaunchFn)*(int *)(*gModgfxInterface + 8))(&hdr, 0, 0x15, base, 0x18, base + 0xd4,
                                                       0x156, 0);
}

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
    u8 *base = (u8 *)lbl_80317E00;
    ScreenFxPart *pp = parts;
    ScreenFxPart *cur;
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
    if (b != 1) {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x400000;
        cur->x = lbl_803E13C8;
        cur->y = lbl_803E13C8;
        cur->z = lbl_803E13C8;
        cur++;
    }
    if (b == 1) {
        cur->state = 0;
        cur->id = 0;
        cur->tex = 0;
        cur->flags = 0x80;
        cur->x = (f32)*(s16 *)(p + 4);
        cur->y = (f32)*(s16 *)(p + 2);
        cur->z = (f32)*(s16 *)(p + 0);
        cur++;
    }
    if (b == 1) {
        cur->state = 1;
        cur->id = 0x15;
        cur->tex = base + 0x1b0;
        cur->flags = 2;
        cur->x = lbl_803E13D4;
        cur->y = *(f32 *)(p + 0x10) / lbl_803E13D4;
        cur->z = lbl_803E13D4;
    } else {
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
    if (b != 1) {
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
    hdr.count = (s8)(((u8 *)(cur + 3) - (u8 *)pp) / 0x18);
    idx = b * 7;
    hdr.anim[0] = *(s16 *)((u8 *)(base + idx * 2) + 0x1f8);
    hdr.anim[1] = *(s16 *)((u8 *)(base + (idx + 1) * 2) + 0x1f8);
    hdr.anim[2] = *(s16 *)((u8 *)(base + (idx + 2) * 2) + 0x1f8);
    hdr.anim[3] = *(s16 *)((u8 *)(base + (idx + 3) * 2) + 0x1f8);
    hdr.anim[4] = *(s16 *)((u8 *)(base + (idx + 4) * 2) + 0x1f8);
    hdr.anim[5] = *(s16 *)((u8 *)(base + (idx + 5) * 2) + 0x1f8);
    hdr.anim[6] = *(s16 *)((u8 *)(base + (idx + 6) * 2) + 0x1f8);
    hdr.parts = parts;
    hdr.flags = 0xc010480;
    hdr.flags |= flags;
    if ((hdr.flags & 1) != 0) {
        if ((void *)a != NULL) {
            hdr.bx = lbl_803E13C8 + *(f32 *)(a + 0x18);
            hdr.by = lbl_803E13C8 + *(f32 *)(a + 0x1c);
            hdr.bz = lbl_803E13C8 + *(f32 *)(a + 0x20);
        } else {
            hdr.bx = lbl_803E13C8 + *(f32 *)(p + 0xc);
            hdr.by = lbl_803E13C8 + *(f32 *)(p + 0x10);
            hdr.bz = lbl_803E13C8 + *(f32 *)(p + 0x14);
        }
    }
    (*(ModgfxLaunchFn)*(int *)(*gModgfxInterface + 8))(&hdr, 0, 0x15, base, 0x18, base + 0xd4,
                                                       0x154, 0);
}


/* Trivial nops */
void dll_9A_func01_nop(void) {}
void dll_9A_func00_nop(void) {}
void dll_9B_func01_nop(void) {}
void dll_9B_func00_nop(void) {}
void dll_9C_func01_nop(void) {}
void dll_9C_func00_nop(void) {}
