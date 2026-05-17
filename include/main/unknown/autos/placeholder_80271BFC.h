#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80271BFC_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80271BFC_H_

#include "ghidra_import.h"

void synthVolume(u32 volume, u32 timeMs, u32 target, u8 action, u32 handle);
int synthIsFadeOutActive(u8 voiceIdx);
void synthSetMusicVolumeType(u32 voiceIdx, u8 value);
int synthHWMessageHandler(int mode, u32 arg);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80271BFC_H_ */
