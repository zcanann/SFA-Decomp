#ifndef MUSYX_SND_GROUPS_H_
#define MUSYX_SND_GROUPS_H_

#include "types.h"
#include "musyx/snd_groups_api.h"
#include "musyx/synth_queue.h"

void dataInitStack(void);

u32 seqPlaySong(u16 groupId, u16 songId, void* arrangement, SynthPlayParams* params,
                u8 noLock, u8 studio);
u32 sndSeqPlayEx(u16 groupId, u16 songId, void* arrangement, SynthPlayParams* params, u8 studio);

#endif /* MUSYX_SND_GROUPS_H_ */
