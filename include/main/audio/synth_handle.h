#ifndef MAIN_AUDIO_SYNTH_HANDLE_H_
#define MAIN_AUDIO_SYNTH_HANDLE_H_

#include "ghidra_import.h"
#include "src/main/audio/synth_internal.h"

void synthUpdateHandle(u32 value0, u32 value1, u32 handle, s32 mode);
void fn_8026D880(SynthStartRequest* request, u32* outHandle, u8 noLock);
u8* fn_8026DDB4(u8* p, u16* tagOut, s16* valueOut);

#endif /* MAIN_AUDIO_SYNTH_HANDLE_H_ */
