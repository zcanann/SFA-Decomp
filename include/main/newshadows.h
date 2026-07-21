#ifndef MAIN_NEWSHADOWS_H_
#define MAIN_NEWSHADOWS_H_

#include "ghidra_import.h"
#include "main/texture.h"

void updateReflectionTextures(void);
void selectReflectionTexture(int id);
void* textureAlloc512(void);
void findSomething(void* needle);


/* extern-cleanup: defining-file public prototypes */
void initFn_8006d020(void);
f32 getNewShadowDistortionWaveOffset(void);
void drawReflectionTexture(void);
void maybeHudFn_8006c91c(void);
void freeNewShadowDistortionTexture(void);
void createNewShadowDistortionTexture(void);

u32 getReflectionTexture1(void);
void getReflectionTexture2(u32* out);
void getNewShadowCausticTexture(u32* out);
void getNewShadowDiskTexture(u32* out);
void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY);
u32 getNewShadowReflectionGradientTexture(void);
void getNewShadowSnowFlashTexture(u32* out);
void fn_8006C504(Texture** out);
void getNewShadowRingTexture(Texture** out);
void getNewShadowLightningTexture(Texture** out);
void getNewShadowHeavyFogTexture(Texture** out);
void getNewShadowDistortionTexture(Texture** out);
void getNewShadowRadialTexture(Texture** out);
void getNewShadowRampTexture(u32* out);
void loadNewShadowBumpTexture(int texMapId);
void fn_8006C6A4(int id);
void getNewShadowNoiseTextureFrames(Texture*** tableOut, int* frameCountOut);
void loadNewShadowSmallReflectionTexture(int id);

#endif /* MAIN_NEWSHADOWS_H_ */
