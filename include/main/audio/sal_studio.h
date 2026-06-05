#ifndef MAIN_AUDIO_SAL_STUDIO_H_
#define MAIN_AUDIO_SAL_STUDIO_H_

#include "ghidra_import.h"

void salInitDspCtrl(void);
void salInitHRTFBuffer(void);
int salExitDspCtrl(void);
void salActivateStudio(u8 idx, u8 a, int b);
void salDeactivateStudio(u8 idx);
int salCheckVolErrorAndResetDelta(u16 *active, u16 *direction, u16 *current, u16 target, u16 *stepFlags,
                u16 mask);
void HandleDepopVoice(int accum, int *voiceRef);
void SortVoices(int *items, int left, int right);

#endif /* MAIN_AUDIO_SAL_STUDIO_H_ */
