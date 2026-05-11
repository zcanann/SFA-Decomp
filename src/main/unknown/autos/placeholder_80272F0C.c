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
 */
#pragma scheduling off
#pragma peephole off
void synthInitJobTable(void)
{
    int count;
    int progress;
    SynthJob *outerEntry;
    SynthJob *tailEntry;
    int outerLoops;
    int tailRemaining;

    synthJobTableCountdown = 0;
    synthJobTablePeriod = 3;
    count = lbl_803BD150[0x210];
    progress = 0;
    if (count != 0) {
        if (8 < count) {
            outerLoops = (count - 1) >> 3;
            outerEntry = synthJobTable;
            if ((int)(count - 8) > 0) {
                do {
                    outerEntry[0].state = 0;
                    progress += 8;
                    outerEntry[1].state = 0;
                    outerEntry[2].state = 0;
                    outerEntry[3].state = 0;
                    outerEntry[4].state = 0;
                    outerEntry[5].state = 0;
                    outerEntry[6].state = 0;
                    outerEntry[7].state = 0;
                    outerEntry += 8;
                    outerLoops--;
                } while (outerLoops != 0);
            }
        }
        tailEntry = synthJobTable + progress;
        tailRemaining = count - progress;
        if (progress < (int)count) {
            do {
                tailEntry->state = 0;
                tailEntry++;
                tailRemaining--;
            } while (tailRemaining != 0);
        }
    }
    lbl_803DE284 = 0;
}

void fn_80272F6C(void) {}
#pragma peephole reset
#pragma scheduling reset
