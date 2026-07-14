#ifndef MAIN_AUDIO_SFX_POSITION_API_H_
#define MAIN_AUDIO_SFX_POSITION_API_H_

#include "types.h"

void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u16 sfxId);

#define Sfx_PlayAtPositionFromObjectIntFirstLegacy(obj, x, y, z, sfxId)                                  \
    ((void (*)(int, f32, f32, f32, int))Sfx_PlayAtPositionFromObject)((obj), (x), (y), (z), (sfxId))

#define Sfx_PlayAtPositionFromObjectPtrFirstLegacy(obj, x, y, z, sfxId)                                  \
    ((void (*)(void*, f32, f32, f32, int))Sfx_PlayAtPositionFromObject)((void*)(obj), (x), (y), (z),     \
                                                                          (sfxId))

#define Sfx_PlayAtPositionFromObjectU32FirstU16Legacy(obj, x, y, z, sfxId)                               \
    ((void (*)(u32, f32, f32, f32, u16))Sfx_PlayAtPositionFromObject)((obj), (x), (y), (z), (sfxId))

#define Sfx_PlayAtPositionFromObjectPtrCanonicalLegacy(x, y, z, obj, sfxId)                              \
    ((void (*)(f32, f32, f32, void*, u16))Sfx_PlayAtPositionFromObject)((x), (y), (z), (void*)(obj),     \
                                                                          (sfxId))

#define Sfx_PlayAtPositionFromObjectIntSfxFirstLegacy(obj, sfxId, x, y, z)                               \
    ((void (*)(int, int, f32, f32, f32))Sfx_PlayAtPositionFromObject)((obj), (sfxId), (x), (y), (z))

#endif /* MAIN_AUDIO_SFX_POSITION_API_H_ */
