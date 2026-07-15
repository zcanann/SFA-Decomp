#ifndef MAIN_AUDIO_SYNTH_JOBS_H_
#define MAIN_AUDIO_SYNTH_JOBS_H_

#include "ghidra_import.h"

void streamHandle(void);
void streamCorrectLoops(void);
void streamKill(u32 voice);
void streamOutputModeChanged(void);
int dataInsertKeymap(u16 keymapId, void *data);
int dataRemoveKeymap(u16 keymapId);

#endif /* MAIN_AUDIO_SYNTH_JOBS_H_ */
