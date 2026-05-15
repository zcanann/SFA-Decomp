#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8027A3E0_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8027A3E0_H_

#include "ghidra_import.h"

void voiceInitRegistrationTables(void);
int voiceScaleSampleRate(u16 x);
u32 voiceGetPitchRatio(u8 noteIn, u32 packed);
u32 voiceConvertDbToLinear(u32 dbCents);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_8027A3E0_H_ */
