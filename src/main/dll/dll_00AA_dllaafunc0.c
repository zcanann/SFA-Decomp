#include "main/effect_interfaces.h"

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
        (4, lbl_803E1608, lbl_803E160C, *(f32*)&lbl_803E160C, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->addSequenceSpawn
        (2, lbl_803E1610, lbl_803E1614, *(f32*)&lbl_803E1610, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->addSequenceSpawn
        (0x400000, lbl_803E160C, lbl_803E1618, *(f32*)&lbl_803E160C, 0, (void*)0);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E161C, lbl_803E160C, *(f32*)&lbl_803E160C, 7, &tab[0x174]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E1620, lbl_803E160C, *(f32*)&lbl_803E160C, 7, &tab[0x174]);
    (*gModgfxInterface)->addSequenceSpawn
        (2, scale, lbl_803E1624, scale, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn
        (4, lbl_803E160C, lbl_803E160C, lbl_803E160C, 7, &tab[0x174]);
    (*gModgfxInterface)->spawnSequence
        (posSource, (u8*)(int)lbl_80319168, 0x15, &tab[0xd4], 0x18, 0x3e9, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

void dll_9D_func01_nop(void);

void dll_AA_func01_nop(void)
{
}

void dll_AA_func00_nop(void)
{
}

int DummyA4_func03_ret_0(void);
