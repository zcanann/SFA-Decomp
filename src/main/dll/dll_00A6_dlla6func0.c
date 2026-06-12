#include "main/effect_interfaces.h"
#include "main/dll/pickup.h"


extern u8 lbl_80318038[];
extern ModgfxInterface** gModgfxInterface;
extern f32 lbl_803E1600;
extern f32 lbl_803E1604;
extern f32 lbl_803E1608;
extern f32 lbl_803E160C;
extern f32 lbl_803E1610;
extern f32 lbl_803E1614;
extern f32 lbl_803E1618;
extern f32 lbl_803E161C;
extern f32 lbl_803E1620;
extern f32 lbl_803E1624;

/*
 * --INFO--
 *
 * Function: dll_9D_func03
 * EN v1.0 Address: 0x800FD744
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FD9E0
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct
{
    u32 mode; /* +0x00 */
    f32 x, y, z; /* +0x04 +0x08 +0x0c */
    void* tex; /* +0x10 */
    u16 flags; /* +0x14 */
    u8 layer; /* +0x16 */
} GfxCmd;

typedef struct
{
    GfxCmd* cmds; /* +0x00 */
    int ctx; /* +0x04 */
    u8 pad0[0x18]; /* +0x08 */
    f32 col[3]; /* +0x20 */
    f32 pos[3]; /* +0x2c */
    f32 scale; /* +0x38 */
    u32 v3c; /* +0x3c */
    u32 v40; /* +0x40 */
    s16 v44; /* +0x44 */
    s16 hw[7]; /* +0x46 */
    u32 flags; /* +0x54 */
    u8 v58, v59, v5a, v5b, v5c, count; /* +0x58..+0x5d */
    u8 pad1[2]; /* +0x5e */
    GfxCmd entries[32]; /* +0x60 */
} GfxBuf;

extern f32 lbl_803E13F8;
extern f32 lbl_803E13FC;
extern f32 lbl_803E1400;
extern f32 lbl_803E1404;
extern f32 lbl_803E1408;
extern f32 lbl_803E140C;
extern f32 lbl_803E1410;
extern f32 lbl_803E1414;

void dll_9D_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_9E_func03
 * EN v1.0 Address: 0x800FDA98
 * EN v1.0 Size: 888b
 */
extern u8 lbl_80318260[];
extern f32 lbl_803E1418;
extern f32 lbl_803E141C;
extern f32 lbl_803E1420;
extern f32 lbl_803E1424;
extern f32 lbl_803E1428;
extern f32 lbl_803E142C;
extern f32 lbl_803E1430;
extern f32 lbl_803E1434;
extern f32 lbl_803E1438;
extern f32 lbl_803E143C;
extern f32 lbl_803E1440;

void dll_9E_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_9F_func03
 * EN v1.0 Address: 0x800FDE18
 * EN v1.0 Size: 1056b
 */
extern u8 lbl_80318488[];
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

void dll_9F_func03(short* sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_A0_func03
 * EN v1.0 Address: 0x800FD820
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FE4DC
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803186B0[];
extern f32 lbl_803E1488;
extern f32 lbl_803E148C;
extern f32 lbl_803E1490;
extern f32 lbl_803E1494;
extern f32 lbl_803E1498;
extern f32 lbl_803E149C;
extern f32 lbl_803E14A0;
extern f32 lbl_803E14A4;
extern f32 lbl_803E14A8;
extern f32 lbl_803E14AC;
extern f32 lbl_803E14B0;

void dll_A0_func03(u8* sourceObj, int variant, int posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_A1_func03
 * EN v1.0 Address: 0x800FD884
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FE844
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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

void dll_A1_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_A2_func03
 * EN v1.0 Address: 0x800FD8F0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800FEBC4
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_80318B00[];
extern f32 lbl_803E14E0;
extern f32 lbl_803E14E4;
extern f32 lbl_803E14E8;
extern f32 lbl_803E14EC;
extern f32 lbl_803E14F0;
extern f32 lbl_803E14F4;
extern f32 lbl_803E14F8;
extern f32 lbl_803E14FC;
extern f32 lbl_803E1500;

void dll_A2_func03(u8* sourceObj, int variant, u8* posSource, uint flags);

/*
 * --INFO--
 *
 * Function: dll_A5_func03
 * EN v1.0 Address: 0x800FD954
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800FEF20
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_80318D48[];
extern f32 lbl_803E1508;
extern f32 lbl_803E150C;
extern f32 lbl_803E1510;
extern f32 lbl_803E1514;
extern f32 lbl_803E1518;
extern f32 lbl_803E151C;
extern f32 lbl_803E1520;
extern f32 lbl_803E1524;
extern u8 lbl_803DB970;
extern u8 lbl_803DB978;

void dll_A5_func03(short* sourceObj, int variant, u8* posSource, uint flags);

extern u8 lbl_80318E40[];
extern f32 lbl_803E1570;
extern f32 lbl_803E1574;
extern f32 lbl_803E1578;
extern f32 lbl_803E157C;
extern f32 lbl_803E1580;
extern f32 lbl_803E1584;
extern f32 lbl_803E1588;

void dll_A7_func03(short* sourceObj, int variant, u8* posSource, uint flags, undefined4 arg5, uint* extraArgs);

/*
 * --INFO--
 *
 * Function: dll_A6_func03
 * EN v1.0 Address: 0x800FF004
 * EN v1.0 Size: 1684b
 */
extern u32 randomGetRange(int min, int max);
extern u8 lbl_80318DF0[];
extern u8 lbl_80318E10[];
extern u8 lbl_803DB980;
extern u8 lbl_803DB988;
extern f32 lbl_803E1530;
extern f32 lbl_803E1534;
extern f32 lbl_803E1538;
extern f32 lbl_803E153C;
extern f32 lbl_803E1540;
extern f32 lbl_803E1544;
extern f32 lbl_803E1548;
extern f32 lbl_803E154C;
extern f32 lbl_803E1550;
extern f32 lbl_803E1554;
extern f32 lbl_803E1558;
extern f32 lbl_803E155C;
extern f32 lbl_803E1560;
extern f32 lbl_803E1564;

void dll_A6_func03(short* sourceObj, int variant, u8* posSource, uint flags)
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
    GfxCmd* e = buf.entries;
    GfxCmd* p = e;
    f32 zr;
    f32 yr;
    u32 fl;

    if (variant == 0)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &lbl_803DB988;
        p->mode = 8;
        p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p->y = (f32)(int)(randomGetRange(0, 0x14) + 0x87);
        p->z = (f32)(int)(randomGetRange(0, 0x14) + 0x41);
        p++;
    }
    else if (variant == 1)
    {
        p->layer = 0;
        p->flags = 3;
        p->tex = &lbl_803DB988;
        p->mode = 8;
        p->y = p->x = (f32)(int)(randomGetRange(0, 0x5a) + 0x87);
        p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
        p++;
    }
    zr = (f32)(int)
    randomGetRange(0, 0xfffe);
    yr = (f32)(int)
    randomGetRange(-3000, -12000);
    p[0].layer = 0;
    p[0].flags = 0;
    p[0].tex = (void*)0;
    p[0].mode = 0x80;
    p[0].x = lbl_803E1530;
    p[0].y = yr;
    p[0].z = zr;
    p[1].layer = 0;
    p[1].flags = 3;
    p[1].tex = &lbl_803DB988;
    p[1].mode = 4;
    p[1].x = lbl_803E1530;
    p[1].y = lbl_803E1530;
    p[1].z = lbl_803E1530;
    p[2].layer = 0;
    p[2].flags = 3;
    p[2].tex = &lbl_803DB988;
    p[2].mode = 2;
    p[2].x = lbl_803E1534;
    p[2].y = lbl_803E153C * (f32)(int)
    randomGetRange(0, 0x19) + lbl_803E1538;
    p[2].z = lbl_803E153C * (f32)(int)
    randomGetRange(0, 10) + lbl_803E1540;
    p[3].layer = 1;
    p[3].flags = 3;
    p[3].tex = &lbl_803DB988;
    p[3].mode = 4;
    if (randomGetRange(0, 10) == 0)
    {
        p[3].x = lbl_803E1544 + (f32)(int)
        randomGetRange(0, 0x1e);
    }
    else
    {
        p[3].x = lbl_803E1548 + (f32)(int)
        randomGetRange(0, 10);
    }
    p[3].y = lbl_803E1530;
    p[3].z = lbl_803E1530;
    p[4].layer = 1;
    p[4].flags = 0;
    p[4].tex = (void*)0;
    p[4].mode = 0x80;
    p[4].x = lbl_803E1530;
    p[4].y = lbl_803E1530;
    p[4].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[5].layer = 1;
    p[5].flags = 3;
    p[5].tex = &lbl_803DB988;
    p[5].mode = 2;
    p[5].x = lbl_803E154C;
    p[5].y = lbl_803E1550;
    p[5].z = lbl_803E1554;
    p[6].layer = 2;
    p[6].flags = 0;
    p[6].tex = (void*)0;
    p[6].mode = 0x80;
    p[6].x = lbl_803E1530;
    p[6].y = lbl_803E1530;
    p[6].z = (f32)(int)
    randomGetRange(0, 0xfffe);
    p[7].layer = 2;
    p[7].flags = 3;
    p[7].tex = &lbl_803DB988;
    p[7].mode = 4;
    p[7].x = lbl_803E1530;
    p[7].y = lbl_803E1530;
    p[7].z = lbl_803E1530;
    p[8].layer = 2;
    p[8].flags = 3;
    p[8].tex = &lbl_803DB988;
    p[8].mode = 2;
    p[8].x = lbl_803E1558;
    p[8].y = lbl_803E155C;
    p[8].z = lbl_803E1560;

    buf.v58 = 0;
    buf.ctx = (int)sourceObj;
    buf.v44 = variant;
    buf.pos[0] = lbl_803E1530;
    buf.pos[1] = lbl_803E1530;
    buf.pos[2] = lbl_803E1530;
    buf.col[0] = lbl_803E1530;
    buf.col[1] = lbl_803E1530;
    buf.col[2] = lbl_803E1530;
    buf.scale = lbl_803E1564;
    buf.v40 = 1;
    buf.v3c = 0;
    buf.v59 = 3;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = &p[9] - e;
    buf.hw[0] = *(s16*)&lbl_80318E10[0];
    buf.hw[1] = *(s16*)&lbl_80318E10[2];
    buf.hw[2] = *(s16*)&lbl_80318E10[4];
    buf.hw[3] = *(s16*)&lbl_80318E10[6];
    buf.hw[4] = *(s16*)&lbl_80318E10[8];
    buf.hw[5] = *(s16*)&lbl_80318E10[10];
    buf.hw[6] = *(s16*)&lbl_80318E10[12];
    buf.cmds = (GfxCmd*)((u8*)&buf + 0x60);
    fl = 0x4000400;
    buf.flags = fl;
    fl |= flags;
    buf.flags = fl;
    if (fl & 1)
    {
        if (sourceObj != 0 && posSource != 0)
        {
            buf.pos[0] = lbl_803E1530 + (*(f32*)(sourceObj + 0xc) + *(f32*)(posSource + 0xc));
            buf.pos[1] = lbl_803E1530 + (*(f32*)(sourceObj + 0xe) + *(f32*)(posSource + 0x10));
            buf.pos[2] = lbl_803E1530 + (*(f32*)(sourceObj + 0x10) + *(f32*)(posSource + 0x14));
        }
        else if (sourceObj != 0)
        {
            buf.pos[0] = buf.pos[0] + *(f32*)(sourceObj + 0xc);
            buf.pos[1] = buf.pos[1] + *(f32*)(buf.ctx + 0x1c);
            buf.pos[2] = buf.pos[2] + *(f32*)(buf.ctx + 0x20);
        }
        else if (posSource != 0)
        {
            buf.pos[0] = buf.pos[0] + *(f32*)(posSource + 0xc);
            buf.pos[1] = buf.pos[1] + *(f32*)(posSource + 0x10);
            buf.pos[2] = buf.pos[2] + *(f32*)(posSource + 0x14);
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 3, lbl_80318DF0, 1, &lbl_803DB980, 0x26a, 0);
}


/*
 * --INFO--
 *
 * Function: dll_A8_func03
 * EN v1.0 Address: 0x800FFB44
 * EN v1.0 Size: 952b
 */
extern u8 lbl_80318EE8[];
extern f32 lbl_803E1598;
extern f32 lbl_803E159C;
extern f32 lbl_803E15A0;
extern f32 lbl_803E15A4;
extern f32 lbl_803E15A8;
extern f32 lbl_803E15AC;
extern f32 lbl_803E15B0;
extern f32 lbl_803E15B4;
extern f32 lbl_803E15B8;
extern f32 lbl_803E15BC;
extern f32 lbl_803E15C0;
extern f32 lbl_803E15C4;
extern f32 lbl_803E15C8;

void dll_A8_func03(u8* sourceObj, int variant, u8* posSource, uint flags, undefined4 arg5, u8* extraArgs);

/*
 * --INFO--
 *
 * Function: dll_A9_func03
 * EN v1.0 Address: 0x800FFF04
 * EN v1.0 Size: 948b
 */
extern u8 lbl_80319028[];
extern f32 lbl_803E15D0;
extern f32 lbl_803E15D4;
extern f32 lbl_803E15D8;
extern f32 lbl_803E15DC;
extern f32 lbl_803E15E0;
extern f32 lbl_803E15E4;
extern f32 lbl_803E15E8;
extern f32 lbl_803E15EC;
extern f32 lbl_803E15F0;
extern f32 lbl_803E15F4;
extern f32 lbl_803E15F8;
extern f32 lbl_803E15FC;

void dll_A9_func03(u8* sourceObj, int variant, u8* posSource, uint flags, undefined4 arg5, u8* extraArgs);

extern u8 lbl_80319168[];

void dll_AA_func03(int sourceObj, int variant, u8* posSource, u8* seqFlags);

/* Trivial 4b 0-arg blr leaves. */
void dll_9D_func01_nop(void);

void dll_9D_func00_nop(void);

void dll_9E_func01_nop(void);

void dll_9E_func00_nop(void);

void dll_9F_func01_nop(void);

void dll_9F_func00_nop(void);

void dll_A0_func01_nop(void);

void dll_A0_func00_nop(void);

void dll_A1_func01_nop(void);

void dll_A1_func00_nop(void);

void dll_A2_func01_nop(void);

void dll_A2_func00_nop(void);

void DummyA4_release(void);

void DummyA4_initialise(void);

void dll_A5_func01_nop(void);

void dll_A5_func00_nop(void);

void dll_A6_func01_nop(void)
{
}

void dll_A6_func00_nop(void)
{
}

void dll_A7_func01_nop(void);

void dll_A7_func00_nop(void);

void dll_A8_func01_nop(void);

void dll_A8_func00_nop(void);

void dll_A9_func01_nop(void);

void dll_A9_func00_nop(void);

void dll_AA_func01_nop(void);

void dll_AA_func00_nop(void);

/* 8b "li r3, N; blr" returners. */
int DummyA4_func03_ret_0(void);
