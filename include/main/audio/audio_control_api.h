#ifndef MAIN_AUDIO_AUDIO_CONTROL_API_H_
#define MAIN_AUDIO_AUDIO_CONTROL_API_H_

#include "types.h"

void audioStopByMask(int mask);
void audioReset(void);
int audioIsResetting(void);
void audioStopAll(void);
void audioUpdate(void);
void audioSetVolumes(int volume, int time, int musicFlag, int fxFlag, int streamFlag);
void audioSetSoundMode(int mode, u8 forceFlag);
int audioInit(void);
void audioFn_8000b694(u32 value);
int return0x64_8000A378(void);
void doNothing_8000CF54(int unused);

#endif /* MAIN_AUDIO_AUDIO_CONTROL_API_H_ */
