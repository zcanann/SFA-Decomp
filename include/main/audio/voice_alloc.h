#ifndef MAIN_AUDIO_VOICE_ALLOC_H_
#define MAIN_AUDIO_VOICE_ALLOC_H_

#include "ghidra_import.h"

u32 voiceAllocate(u8 priority, u8 maxInstances, u16 key, u8 streamKind);
void voiceFree(int state);

#endif /* MAIN_AUDIO_VOICE_ALLOC_H_ */
