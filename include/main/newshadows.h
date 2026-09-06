#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "types.h"
#include "main/texture.h"

void blendTextures(Texture* src1, Texture* src2, f32 blend, Texture* dst);
void updateHeavyFogTexture(int intensity);

void newshadows_captureReflectionTextures(void);
void newshadows_loadReflectionColorTexture(int id);
void* newshadows_allocTexture512(void);
void newshadows_releaseTextureEntry(void* textureEntry);

/* extern-cleanup: defining-file public prototypes */
void newshadows_initProceduralTextures(void);
f32 newshadows_getDistortionWaveOffset(void);
void newshadows_drawReflectionTexture(void);
void newshadows_beginFrame(void);
void newshadows_freeDistortionTexture(void);
void newshadows_createDistortionTexture(void);

u32 newshadows_getReflectionColorTexture(void);
void newshadows_getReflectionDepthTexture(u32* out);
void newshadows_getCausticTexture(u32* out);
void newshadows_getDiskTexture(u32* out);
void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY);
u32 newshadows_getReflectionGradientTexture(void);
void newshadows_getSnowFlashTexture(u32* out);
void newshadows_getHeatHazeTexture(Texture** out);
void newshadows_getRingTexture(Texture** out);
void newshadows_getLightningTexture(Texture** out);
void newshadows_getHeavyFogTexture(Texture** out);
void newshadows_getDistortionTexture(Texture** out);
void newshadows_getRadialTexture(Texture** out);
void newshadows_getRampTexture(u32* out);
void newshadows_loadBumpTexture(int texMapId);
void newshadows_loadWhirlpoolTexture(int id);
void newshadows_getNoiseTextureFrames(Texture*** tableOut, int* frameCountOut);
void newshadows_loadSmallReflectionTexture(int id);

#endif /* MAIN_NEWSHADOWS_H_ */
