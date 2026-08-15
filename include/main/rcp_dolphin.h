#ifndef MAIN_RCP_DOLPHIN_H_
#define MAIN_RCP_DOLPHIN_H_

#include "types.h"
#include "main/rcp_dolphin_api.h"

/* TEX0.tab/TEX1.tab/TEXPRE.tab entry (bankWord): high bits select source map, */
/* bits 29..24 are the mipmap/animation-frame count. */
#define TEX_TAB_MAP_A           0x80000000u
#define TEX_TAB_MAP_B           0x40000000u
#define TEX_TAB_MIP_COUNT_SHIFT 24
#define TEX_TAB_MIP_COUNT_MASK  0x3f

/* extern-cleanup: defining-file public prototypes */
void loadTextureFiles(void);
void Rcp_InitDistortionEffects(void);
void* getLoadedTexture(int key);
u8 Rcp_GetViewFinderHudEnabled(void);
void Rcp_SetViewFinderHudEnabled(u8 x);
void ShaderDef_free(void** def);
void Rcp_UpdateDistortionTextures(void);
void loadNextMap(void);

#endif /* MAIN_RCP_DOLPHIN_H_ */
