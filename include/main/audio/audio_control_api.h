#ifndef MAIN_AUDIO_AUDIO_CONTROL_API_H_
#define MAIN_AUDIO_AUDIO_CONTROL_API_H_

#include "types.h"

typedef void (*AudioSetVolumesU8Fn)(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag);
typedef u8 (*AudioInitU8Fn)(void);
typedef void (*AudioNoOpIntFn)(int unused);

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
void doNothing_8000CF54(void);

#define audioSetVolumesU8 ((AudioSetVolumesU8Fn)audioSetVolumes)
#define audioInitU8 ((AudioInitU8Fn)audioInit)
#define doNothing_8000CF54Int ((AudioNoOpIntFn)doNothing_8000CF54)

#endif /* MAIN_AUDIO_AUDIO_CONTROL_API_H_ */
