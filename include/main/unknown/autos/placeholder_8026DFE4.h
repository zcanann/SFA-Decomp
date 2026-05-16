#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8026DFE4_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8026DFE4_H_

#include "src/main/audio/synth_internal.h"

SynthSequenceEvent* synthGetNextChannelEvent(u8 channel);
void synthInsertChannelEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8026DFE4_H_ */
