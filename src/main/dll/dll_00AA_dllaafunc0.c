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

void dll_A6_func03(short* sourceObj, int variant, u8* posSource, uint flags);


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

void dll_AA_func03(int sourceObj, int variant, u8* posSource, u8* seqFlags)
{
    u8* tab = (u8*)(int)lbl_80319168;
    f32 scale;

    scale = lbl_803E1600;
    if (posSource != 0)
    {
        scale = *(f32*)(posSource + 8) / lbl_803E1604;
    }
    (*gModgfxInterface)->beginSequence((void*)sourceObj, (u8)variant, 0x15, 1, 0);
    (*gModgfxInterface)->setSequenceParams(&tab[0x1dc]);
    (*gModgfxInterface)->addSequenceFlags((u32)seqFlags);
    (*gModgfxInterface)->resetSequenceSpawns();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E1608, lbl_803E160C, lbl_803E160C, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->addSequenceSpawn
        (2, lbl_803E1610, lbl_803E1614, lbl_803E1610, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->addSequenceSpawn
        (0x400000, lbl_803E160C, lbl_803E1618, lbl_803E160C, 0, (void*)0);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E161C, lbl_803E160C, lbl_803E160C, 7, &tab[0x174]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E1620, lbl_803E160C, lbl_803E160C, 7, &tab[0x174]);
    (*gModgfxInterface)->addSequenceSpawn
        (2, scale, lbl_803E1624, scale, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E160C, lbl_803E160C, lbl_803E160C, 7, &tab[0x174]);
    (*gModgfxInterface)->spawnSequence
        (posSource, (u8*)(int)lbl_80319168, 0x15, &tab[0xd4], 0x18, 0x3e9, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

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

void dll_A6_func01_nop(void);

void dll_A6_func00_nop(void);

void dll_A7_func01_nop(void);

void dll_A7_func00_nop(void);

void dll_A8_func01_nop(void);

void dll_A8_func00_nop(void);

void dll_A9_func01_nop(void);

void dll_A9_func00_nop(void);

void dll_AA_func01_nop(void)
{
}

void dll_AA_func00_nop(void)
{
}

/* 8b "li r3, N; blr" returners. */
int DummyA4_func03_ret_0(void);
