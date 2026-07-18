#ifndef MAIN_AUDIO_HW_INIT_H_
#define MAIN_AUDIO_HW_INIT_H_

#include "ghidra_import.h"
#include "main/audio/dsp_voice.h"

void snd_handle_irq(void);
int hwInit(u32 *sampleRate, u16 numVoices, u16 numStudios, u32 flags);
void hwExit(void);
void hwSetTimeOffset(int value);
u8 hwGetTimeOffset(void);
u32 hwIsActive(u32 slot);
void hwSetMesgCallback(u32 value);
void hwSetPriority(int slot, u32 value);
void hwInitSamplePlayback(u32 voice, u16 sampleId, SAMPLE_INFO *sampleInfo,
                          u32 resetAdsr, u32 priority, u32 callbackUserValue,
                          u32 resetSrc, u32 itdMode);

#endif /* MAIN_AUDIO_HW_INIT_H_ */
