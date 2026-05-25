#ifndef MAIN_AUDIO_SND_CORE_H_
#define MAIN_AUDIO_SND_CORE_H_

#include "ghidra_import.h"

void sndQuit(void);
void sndSetMaxVoices(u8 valueA, u8 valueB);
u8 sndIsInstalled(void);
void salApplyMatrix(f32 *matrix, f32 *vec, f32 *out);
void salNormalizeVector(f32 *v);
void inpSetGlobalMIDIDirtyFlag(u8 index, u8 group, u32 flags);

#endif /* MAIN_AUDIO_SND_CORE_H_ */
