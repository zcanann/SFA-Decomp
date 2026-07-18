#ifndef MAIN_AUDIO_SAL_STUDIO_H_
#define MAIN_AUDIO_SAL_STUDIO_H_

#include "ghidra_import.h"
#include "main/audio/dsp_voice.h"

u32 salInitDspCtrl(u8 numVoices, u8 numStudios, u32 defaultStudioDPL2);
void salInitHRTFBuffer(void);
u32 salExitDspCtrl(void);
void salActivateStudio(u8 studio, u32 isMaster, SND_STUDIO_TYPE type);
void salDeactivateStudio(u8 studio);
u32 salCheckVolErrorAndResetDelta(u16 *dspVolume, u16 *dspDelta, u16 *lastVolume,
                                  u16 targetVolume, u16 *resetFlags, u16 resetMask);
void HandleDepopVoice(DSPstudioinfo *studio, DSPvoice *voice);
void SortVoices(DSPvoice **voices, int left, int right);

#endif /* MAIN_AUDIO_SAL_STUDIO_H_ */
