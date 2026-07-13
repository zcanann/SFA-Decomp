/*
 * dllaafunc0 (DLL 0xAA) - a modgfx sequence-effect spawner.
 *
 * dll_AA_func03 drives gModgfxInterface to build and emit a multi-spawn
 * particle "sequence" (sequence id 0x15): it begins the sequence on the
 * source object, applies the caller's seqFlags, then queues several
 * addSequenceSpawn layers - their position/scale/lifetime triples come
 * from f32 literals (pooled by the compiler at lbl_803E1600..lbl_803E1624)
 * and a shared asset table (lbl_80319168). When posSource is supplied, one
 * spawn's scale is taken from the spawn-param packet (posSource + 8)
 * divided by 5. func00/func01 are the DLL's unused entry-point stubs.
 */
#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/dll_00AA_dllaafunc0.h"

extern u8 lbl_80319168[];

void dll_AA_func03(int sourceObj, int variant, u8* posSource, u32 seqFlags)
{
    u8* tab = (u8*)(int)lbl_80319168;
    f32 scale;

    scale = 8.0f;
    if (posSource != 0)
    {
        scale = ((PartFxSpawnParams*)posSource)->scale / 5.0f;
    }
    (*gModgfxInterface)->beginSequence((void*)sourceObj, (u8)variant, 0x15, 1, 0);
    (*gModgfxInterface)->setSequenceParams(&tab[0x1dc]);
    (*gModgfxInterface)->addSequenceFlags(seqFlags);
    (*gModgfxInterface)->resetSequenceSpawns();
    (*gModgfxInterface)->addSequenceSpawn(4, 0.65f, 0.0f, 0.0f, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->addSequenceSpawn(2, 0.5f, 1.0f, 0.5f, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->addSequenceSpawn(0x400000, 0.0f, -100.0f, 0.0f, 0, NULL);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(4, 160.0f, 0.0f, 0.0f, 7, &tab[0x174]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(4, 255.0f, 0.0f, 0.0f, 7, &tab[0x174]);
    (*gModgfxInterface)->addSequenceSpawn(2, scale, 3.0f, scale, 0x15, &tab[0x1b0]);
    (*gModgfxInterface)->nextSequenceParam();
    (*gModgfxInterface)->addSequenceSpawn(4, 0.0f, 0.0f, 0.0f, 7, &tab[0x174]);
    (*gModgfxInterface)->spawnSequence(posSource, (u8*)(int)lbl_80319168, 0x15, &tab[0xd4], 0x18, 0x3e9, 0);
    (*gModgfxInterface)->getLastSpawnHandle();
}

void dll_AA_func01_nop(void)
{
}

void dll_AA_func00_nop(void)
{
}
