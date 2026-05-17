#ifndef MAIN_AUDIO_SYNTH_SEQUENCE_H_
#define MAIN_AUDIO_SYNTH_SEQUENCE_H_

#include "ghidra_import.h"

typedef struct SynthSequenceEvent SynthSequenceEvent;
typedef struct SynthSequenceQueue SynthSequenceQueue;

u8 *synthReadVariablePair(u8 *input, u16 *value0, s16 *value1);
SynthSequenceEvent *synthGetNextChannelEvent(u8 channel);
void synthInsertChannelEvent(SynthSequenceQueue *queue, SynthSequenceEvent *event);

#endif /* MAIN_AUDIO_SYNTH_SEQUENCE_H_ */
