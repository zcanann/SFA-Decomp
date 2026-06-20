#ifndef MAIN_AUDIO_HW_INIT_H_
#define MAIN_AUDIO_HW_INIT_H_

#include "ghidra_import.h"

void snd_handle_irq(void);
int hwInit(u32 *sampleRate, u8 valueA, u8 valueB, u32 flags);
void hwExit(void);
void hwSetTimeOffset(int value);
u8 hwGetTimeOffset(void);
u32 hwIsActive(u32 slot);
void hwSetMesgCallback(u32 value);
void hwSetPriority(int slot, u32 value);
void hwInitSamplePlayback(int slot, u16 value70, u32 *values, u32 resetAdsr, u32 priority, u32 value18, u32 resetSrc, u32 itdMode);

#endif /* MAIN_AUDIO_HW_INIT_H_ */
