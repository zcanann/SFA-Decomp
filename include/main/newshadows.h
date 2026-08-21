#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "types.h"
#include "main/texture.h"

void updateReflectionTextures(void);
void selectReflectionTexture(int id);
void* textureAlloc512(void);
void newshadows_releaseTextureEntry(void* textureEntry);


/* extern-cleanup: defining-file public prototypes */
void newShadowsInitProceduralTextures(void);
f32 getNewShadowDistortionWaveOffset(void);
void drawReflectionTexture(void);
void newShadowsBeginFrame(void);
void freeNewShadowDistortionTexture(void);
void createNewShadowDistortionTexture(void);

u32 getReflectionTexture1(void);
void getReflectionTexture2(u32* out);
void getNewShadowCausticTexture(u32* out);
void getNewShadowDiskTexture(u32* out);
void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY);
u32 getNewShadowReflectionGradientTexture(void);
void getNewShadowSnowFlashTexture(u32* out);
void getNewShadowHeatHazeTexture(Texture** out);
void getNewShadowRingTexture(Texture** out);
void getNewShadowLightningTexture(Texture** out);
void getNewShadowHeavyFogTexture(Texture** out);
void getNewShadowDistortionTexture(Texture** out);
void getNewShadowRadialTexture(Texture** out);
void getNewShadowRampTexture(u32* out);
void loadNewShadowBumpTexture(int texMapId);
void selectWhirlpoolTexture(int id);
void getNewShadowNoiseTextureFrames(Texture*** tableOut, int* frameCountOut);
void loadNewShadowSmallReflectionTexture(int id);

#endif /* MAIN_NEWSHADOWS_H_ */
