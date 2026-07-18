#ifndef MAIN_AUDIO_HW_SAMPLE_H_
#define MAIN_AUDIO_HW_SAMPLE_H_

#include "ghidra_import.h"

void hwSetVirtualSampleLoopBuffer(int slot, u32 valueA, u32 valueB);
u32 hwGetVirtualSampleState(u32 voice);
u8 hwGetSampleType(int slot);
u16 hwGetSampleID(int slot);
void hwSetStreamLoopPS(int slot, u8 value);

#endif /* MAIN_AUDIO_HW_SAMPLE_H_ */
