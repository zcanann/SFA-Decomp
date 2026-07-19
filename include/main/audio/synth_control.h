#ifndef MAIN_AUDIO_SYNTH_CONTROL_H_
#define MAIN_AUDIO_SYNTH_CONTROL_H_

#include "ghidra_import.h"

void synthExit(void);
void sndSeqStop(u32 handle);
void sndSeqSpeed(u32 handle, u16 speed);
void sndSeqContinue(u32 handle);
void sndSeqMute(u32 handle, u32 mute, u32 time);


/* extern-cleanup: defining-file public prototypes */
void synthInit(u32 sampleRate, u32 voiceCount);

#endif /* MAIN_AUDIO_SYNTH_CONTROL_H_ */
