#ifndef MAIN_AUDIO_HW_SAMPLEMEM_H_
#define MAIN_AUDIO_HW_SAMPLEMEM_H_

#include "ghidra_import.h"
#include "main/audio/data_ref.h"

void hwSaveSample(SAMPLE_HEADER **sample, void **ptr);
void hwRemoveSample(SAMPLE_HEADER *sample, void *ptr);
void hwSyncSampleMem(void);
void hwFrameDone(void);

typedef struct SalHooks {
  void *(*mallocHook)(u32 size);
  void (*freeHook)(void *ptr);
} SalHooks;

void sndSetHooks(const SalHooks *hooks);
void hwDisableHRTF(void);
u32 hwGetVirtualSampleID(u32 voice);
u32 hwVoiceInStartup(u32 voice);

#endif /* MAIN_AUDIO_HW_SAMPLEMEM_H_ */
