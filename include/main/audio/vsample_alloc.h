#ifndef MAIN_AUDIO_VSAMPLE_ALLOC_H_
#define MAIN_AUDIO_VSAMPLE_ALLOC_H_

#include "ghidra_import.h"

void synthInitVirtualSampleTable(void);
u32 synthClaimVirtualSampleSlot(u8 voice);

#endif /* MAIN_AUDIO_VSAMPLE_ALLOC_H_ */
