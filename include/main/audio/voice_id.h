#ifndef MAIN_AUDIO_VOICE_ID_H_
#define MAIN_AUDIO_VOICE_ID_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void vidRemoveVoice(McmdVoiceState* state);
u32 vidMakeRoot(McmdVoiceState* voice);
u32 vidMakeNew(McmdVoiceState* state, int returnNewId);
int vidGetInternalId(u32 id);
void voiceRemovePriority(int state);

#endif /* MAIN_AUDIO_VOICE_ID_H_ */
