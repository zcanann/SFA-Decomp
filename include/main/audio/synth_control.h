#ifndef MAIN_AUDIO_SYNTH_CONTROL_H_
#define MAIN_AUDIO_SYNTH_CONTROL_H_

#include "ghidra_import.h"

void synthSetFade(u8 value, u16 time, u8 selector, u8 action, u32 handle);
u32 synthIsFadeActive(u32 fadeIndex);
void synthSetFadeAction(u32 fadeIndex, u8 action);
void synthExit(void);
void sndSeqStop(u32 handle);
void sndSeqSpeed(u32 handle, u32 speed);
void sndSeqContinue(u32 handle);
void sndSeqMute(u32 handle, u32 mute, u32 time);

#endif /* MAIN_AUDIO_SYNTH_CONTROL_H_ */
