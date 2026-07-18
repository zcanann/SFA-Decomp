#ifndef MAIN_AUDIO_VOICE_ALLOC_H_
#define MAIN_AUDIO_VOICE_ALLOC_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

u32 voiceAllocate(u8 priority, u8 maxInstances, u16 key, u8 streamKind);
void voiceFree(McmdVoiceState *voice);

#endif /* MAIN_AUDIO_VOICE_ALLOC_H_ */
