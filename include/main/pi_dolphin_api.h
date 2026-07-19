#ifndef MAIN_PI_DOLPHIN_API_H_
#define MAIN_PI_DOLPHIN_API_H_

#include "types.h"
#include "main/pi_frame_api.h"
#include "main/pi_dolphin_path_api.h"

double SeekTwiceBeforeRead(void);
int loadAndDecompressDataFile();
int mapGetDirIdx(int idx);
u8 isHeavyFogEnabled(void);
void disableHeavyFog(void);
void enableHeavyFog(f32 top, f32 bottom, f32 red, f32 green, f32 blue, u8 mode);
void fn_8004D6D8(void);
void fn_80050F2C(void);
void fn_8004D230(void);
void fn_8004D928(void);
void setColor_803db5d0(u8 r, u8 g, u8 b);
void gxTextureFn_8004bf88(void* params, u8 colorEnabled, u8 alphaEnabled, int* colorSelection,
                          int* alphaSelection);
void fn_8004C7AC(void* yTexture, void* uTexture, void* vTexture, s16 width, s16 height);
void fn_8004C1E4(u8 level, f32 scale);
void* Shader_getLayer(void* shader, int layerIdx);
void fn_8004CE0C(void* viewMtx);
void fn_8004DA54(char* shader);
void fn_8004E0FC(void);
void fn_8004EECC(u8* color);
void renderHeavyFog(void* fogColor);
void fn_8004EF9C(int* color);
void fn_8004F080(void);
void fn_8004F2B0(void);
void fn_8004F380(f32 scale, int* color, f32* position);
void fn_8004F6D8(f32 scale, int* color, f32* position, u8* chanColor);
void fn_8004FA30(f32 scale, int* color, f32* position);
void fn_8004FDA0(u8* texture, void* texMtx, u8* color);
void textureFn_8004ff20(void* texture, f32* texMtx, void* color, int unused);
void fn_80051528(void* texture, void* texMtx);
void gxTextureFn_80050e28(u8 mode);
int textureFn_80050ad8(void* texture, int stageCount, u8 mode, u32 indirectTextureId);
void textureFn_80051348(void* textureRef, u8 objectFlags);
void fn_800510F0(void* textureRef, u8 hasBaseTexture, u8 mode);
void fn_80050FF4(u8 mode);
void fn_8005011C(u8* objectInstance);
void fn_80050558(u8* texture, void* texMtx, int stageMode, int componentMode, int variant);
void fn_80050A28(int scale);
void textureFn_8004c330(void* texture, void* texMtx);
void gxTextureFn_8004d5b4(void* renderOp);

void mapsBinGetRomlistSize(int idx, int* out1, int* out2, int* out3, int p5);

extern s16 gObjMapBlockInfo[];
extern s16 sMapFileNameAdjacencyTable[];
extern char sAssetIndexOverflowError[];

#endif /* MAIN_PI_DOLPHIN_API_H_ */
