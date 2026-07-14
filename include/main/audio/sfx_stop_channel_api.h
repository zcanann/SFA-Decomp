#ifndef MAIN_AUDIO_SFX_STOP_CHANNEL_API_H_
#define MAIN_AUDIO_SFX_STOP_CHANNEL_API_H_

#include "types.h"

void Sfx_StopObjectChannel(u32 obj, u32 channel);

#define Sfx_StopObjectChannelPtrLegacy(obj, channel)                                                               \
    ((void (*)(void*, int))Sfx_StopObjectChannel)((void*)(obj), (channel))

#endif /* MAIN_AUDIO_SFX_STOP_CHANNEL_API_H_ */
