#ifndef MAIN_AUDIO_SFX_CHANNEL_QUERY_API_H_
#define MAIN_AUDIO_SFX_CHANNEL_QUERY_API_H_

#include "types.h"

s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel);

#define Sfx_IsPlayingFromObjectChannelPtrLegacy(obj, channel)                                                  \
    ((s32 (*)(void*, int))Sfx_IsPlayingFromObjectChannel)((void*)(obj), (channel))

#define Sfx_IsPlayingFromObjectChannelIntLegacy(obj, channel)                                                  \
    ((int (*)(int, int))Sfx_IsPlayingFromObjectChannel)((obj), (channel))

#endif /* MAIN_AUDIO_SFX_CHANNEL_QUERY_API_H_ */
