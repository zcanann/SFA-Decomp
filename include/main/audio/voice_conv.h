#ifndef MAIN_AUDIO_VOICE_CONV_H_
#define MAIN_AUDIO_VOICE_CONV_H_

#include "ghidra_import.h"

void voiceInitRegistrationTables(void);
int voiceScaleSampleRate(u16 x);
u32 voiceGetPitchRatio(u8 noteIn, u32 packed);
u32 voiceConvertDbToLinear(u32 dbCents);

#endif /* MAIN_AUDIO_VOICE_CONV_H_ */
