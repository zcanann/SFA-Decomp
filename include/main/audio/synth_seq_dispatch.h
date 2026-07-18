#ifndef MAIN_AUDIO_SYNTH_SEQ_DISPATCH_H_
#define MAIN_AUDIO_SYNTH_SEQ_DISPATCH_H_

#include "ghidra_import.h"

typedef struct SynthSequenceEvent SynthSequenceEvent;

SynthSequenceEvent* synthHandleSequenceEvent(SynthSequenceEvent* event, u8 groupIndex, u32* loopFlag);
void fn_8026E864(void);
void fn_8026E90C(u8 voice);
u32 synthProcessChannelEventQueue(u8 groupIndex, u32 deltaTime);

#endif /* MAIN_AUDIO_SYNTH_SEQ_DISPATCH_H_ */
