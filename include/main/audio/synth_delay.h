#ifndef MAIN_AUDIO_SYNTH_DELAY_H_
#define MAIN_AUDIO_SYNTH_DELAY_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

u32 synthFXSetCtrl(u32 handle, u8 controller, u8 value);
u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value);
void synthFXCloneMidiSetup(McmdVoiceState *dstVoice, McmdVoiceState *srcVoice);
u32 synthSendKeyOff(u32 handle);

#endif /* MAIN_AUDIO_SYNTH_DELAY_H_ */
