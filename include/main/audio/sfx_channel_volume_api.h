#ifndef MAIN_AUDIO_SFX_CHANNEL_VOLUME_API_H_
#define MAIN_AUDIO_SFX_CHANNEL_VOLUME_API_H_

#include "types.h"

void Sfx_SetObjectChannelVolume(u32 obj, u32 channel, u8 volume, f32 volumeScale);

#define Sfx_SetObjectChannelVolumeIntU8Legacy(obj, channel, volume, scale)                                      \
    ((void (*)(int, int, u8, f32))Sfx_SetObjectChannelVolume)((obj), (channel), (volume), (scale))

#define Sfx_SetObjectChannelVolumePtrU8Legacy(obj, channel, volume, scale)                                      \
    ((void (*)(void*, int, u8, f32))Sfx_SetObjectChannelVolume)((void*)(obj), (channel), (volume), (scale))

#define Sfx_SetObjectChannelVolumePtrIntLegacy(obj, channel, volume, scale)                                     \
    ((void (*)(void*, int, int, f32))Sfx_SetObjectChannelVolume)((void*)(obj), (channel), (volume), (scale))

#define Sfx_SetObjectChannelVolumePtrU32Legacy(obj, channel, volume, scale)                                     \
    ((void (*)(void*, int, u32, f32))Sfx_SetObjectChannelVolume)((void*)(obj), (channel), (volume), (scale))

#define Sfx_SetObjectChannelVolumeScaleFirstLegacy(scale, obj, channel, volume)                                \
    ((void (*)(f32, int, int, int))Sfx_SetObjectChannelVolume)((scale), (obj), (channel), (volume))

#endif /* MAIN_AUDIO_SFX_CHANNEL_VOLUME_API_H_ */
