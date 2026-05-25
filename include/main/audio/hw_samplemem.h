#ifndef MAIN_AUDIO_HW_SAMPLEMEM_H_
#define MAIN_AUDIO_HW_SAMPLEMEM_H_

#include "ghidra_import.h"

void hwSaveSample(u32 **sample, void **ptr);
void hwRemoveSample(u32 *sample, void *ptr);
void hwSyncSampleMem(void);
void hwFrameDone(void);

typedef struct SalHooks {
  void *(*mallocHook)(u32 size);
  void (*freeHook)(void *ptr);
} SalHooks;

void sndSetHooks(const SalHooks *hooks);
void hwDisableHRTF(void);
int hwGetVirtualSampleID(int slot);
int hwVoiceInStartup(int slot);

#endif /* MAIN_AUDIO_HW_SAMPLEMEM_H_ */
