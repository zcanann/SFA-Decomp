#ifndef MAIN_AUDIO_SYNTH_HANDLE_H_
#define MAIN_AUDIO_SYNTH_HANDLE_H_

#include "src/main/audio/synth_internal.h"

void synthUpdateHandle(u32 value0, u32 value1, u32 handle, s32 mode);
void fn_8026D880(SynthStartRequest* request, u32* outHandle, u8 noLock);
u8* synthReadVariablePair(u8* input, u16* value0, s16* value1);

#endif /* MAIN_AUDIO_SYNTH_HANDLE_H_ */
