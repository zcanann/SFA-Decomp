#ifndef MAIN_AUDIO_VOICE_ID_H_
#define MAIN_AUDIO_VOICE_ID_H_

#include "ghidra_import.h"

void vidRemoveVoice(int state);
int vidMakeRoot(int state);
u32 vidMakeNew(int state, int returnNewId);
int vidGetInternalId(u32 id);
void voiceRemovePriority(int state);

#endif /* MAIN_AUDIO_VOICE_ID_H_ */
