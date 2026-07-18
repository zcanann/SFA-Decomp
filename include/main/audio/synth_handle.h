#ifndef MAIN_AUDIO_SYNTH_HANDLE_H_
#define MAIN_AUDIO_SYNTH_HANDLE_H_

#include "ghidra_import.h"

struct SynthStartRequest;

void synthUpdateHandle(u8 volume, u16 time, u32 handle, u8 mode);
void synthStartHandleFromRequest(struct SynthStartRequest* request, u32* outHandle, u8 noLock);
u8* synthReadVariablePair(u8* input, u16* value0, s16* value1);

#endif /* MAIN_AUDIO_SYNTH_HANDLE_H_ */
