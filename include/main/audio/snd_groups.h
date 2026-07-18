#ifndef MAIN_AUDIO_SND_GROUPS_H_
#define MAIN_AUDIO_SND_GROUPS_H_

#include "ghidra_import.h"
#include "main/audio/snd_groups_api.h"
#include "main/audio/synth_queue.h"

void InsertData(u16 id, void *data, u8 dataType, u32 remove);
void audioFn_8027b690(u16 *ref, void *data, u8 dataType, u32 remove);
u32 seqPlaySong(u16 groupId, u16 songId, void* arrangement, SynthPlayParams* params,
                u8 noLock, u8 studio);
u32 sndSeqPlayEx(u16 groupId, u16 songId, void* arrangement, SynthPlayParams* params, u8 studio);

#endif /* MAIN_AUDIO_SND_GROUPS_H_ */
