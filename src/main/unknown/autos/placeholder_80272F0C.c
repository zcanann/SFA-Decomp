#include "ghidra_import.h"
#include "main/audio/synth_job.h"
#include "main/unknown/autos/placeholder_80272F0C.h"

extern u8 lbl_803BD150[];
extern SynthJob synthJobTable[];
extern u8 synthJobTableCountdown;
extern u8 synthJobTablePeriod;
extern u32 lbl_803DE284;

/*
 * --INFO--
 *
 * Function: synthInitJobTable
 * EN v1.0 Address: 0x80272EA4
 * EN v1.0 Size: 200b
 *
 * MWCC auto-unrolls this loop x8; residual is the remainder-loop preheader
 * being placed at the end of the function in the target (block-layout cap).
 */
void synthInitJobTable(void)
{
    int i;

    synthJobTableCountdown = 0;
    synthJobTablePeriod = 3;
    for (i = 0; i < lbl_803BD150[0x210]; i++) {
        synthJobTable[i].state = 0;
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void) {}
