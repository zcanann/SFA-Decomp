#ifndef MAIN_AUDIO_SYNTH_JOBS_H_
#define MAIN_AUDIO_SYNTH_JOBS_H_

#include "ghidra_import.h"

void synthUpdateJobTable(void);
void doNothing_802737E8(void);
void synthCancelJob(int voice);
void synthRefreshJobVolumes(void);
int dataInsertKeymap(u16 keymapId, void *data);
int dataRemoveKeymap(u16 keymapId);

#endif /* MAIN_AUDIO_SYNTH_JOBS_H_ */
