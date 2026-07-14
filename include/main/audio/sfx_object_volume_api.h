#ifndef MAIN_AUDIO_SFX_OBJECT_VOLUME_API_H_
#define MAIN_AUDIO_SFX_OBJECT_VOLUME_API_H_

#include "types.h"

void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);

#define Sfx_SetObjectSfxVolumeIntLegacy(obj, sfxId, volume, scale)                                        \
    ((void (*)(int, int, int, f32))Sfx_SetObjectSfxVolume)((obj), (sfxId), (volume), (scale))

#define Sfx_SetObjectSfxVolumePtrLegacy(obj, sfxId, volume, scale)                                        \
    ((void (*)(void*, int, int, f32))Sfx_SetObjectSfxVolume)((void*)(obj), (sfxId), (volume), (scale))

#define Sfx_SetObjectSfxVolumeU32IntLegacy(obj, sfxId, volume, scale)                                     \
    ((void (*)(u32, u32, int, f32))Sfx_SetObjectSfxVolume)((obj), (sfxId), (volume), (scale))

#endif /* MAIN_AUDIO_SFX_OBJECT_VOLUME_API_H_ */
