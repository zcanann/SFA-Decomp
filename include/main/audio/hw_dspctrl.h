#ifndef MAIN_AUDIO_HW_DSPCTRL_H_
#define MAIN_AUDIO_HW_DSPCTRL_H_

#include "ghidra_import.h"
#include "main/audio/dsp_voice.h"

void salBuildCommandList(s16 *dest, u32 nsDelay);
void salHandleAuxProcessing(void);
void salActivateVoice(DSPvoice *voice, u8 studio);
void salDeactivateVoice(DSPvoice *voice);
u32 salAddStudioInput(DSPstudioinfo *studio, SND_STUDIO_INPUT *input);
u32 salRemoveStudioInput(DSPstudioinfo *studio, SND_STUDIO_INPUT *input);

#endif /* MAIN_AUDIO_HW_DSPCTRL_H_ */
