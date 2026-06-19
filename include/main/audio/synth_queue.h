#ifndef MAIN_AUDIO_SYNTH_QUEUE_H_
#define MAIN_AUDIO_SYNTH_QUEUE_H_

#include "ghidra_import.h"

int seqStartPlay(int param_1, int param_2, int param_3, int *param_4, u32 *param_5,
                u8 param_6, u16 param_7);


/* extern-cleanup: defining-file public prototypes */
void synthQueueHandle(u32 handle);
void synthFreeHandle(u32 handle);

#endif /* MAIN_AUDIO_SYNTH_QUEUE_H_ */
