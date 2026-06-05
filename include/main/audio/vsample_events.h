#ifndef MAIN_AUDIO_VSAMPLE_EVENTS_H_
#define MAIN_AUDIO_VSAMPLE_EVENTS_H_

#include "ghidra_import.h"

void synthHandleVirtualSampleDone(u32 packed);
void synthAdvanceVirtualSampleEntry(void *entry, u32 elapsed);

#endif /* MAIN_AUDIO_VSAMPLE_EVENTS_H_ */
