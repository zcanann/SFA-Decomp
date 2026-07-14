#ifndef MAIN_PI_DOLPHIN_API_H_
#define MAIN_PI_DOLPHIN_API_H_

#include "types.h"
#include "main/pi_frame_api.h"

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
int fn_8004B218(void* search, u32 timeout);
void gxTextureFn_8004bf88(void* params, u8 colorEnabled, u8 alphaEnabled, int* colorSelection,
                          int* alphaSelection);
void* Shader_getLayer(void* shader, int layerIdx);
void fn_8004CE0C(void* viewMtx);
void fn_8004DA54(char* shader);
void fn_8004E0FC(void);
void fn_8004EECC(void);
void renderHeavyFog(void* fogColor);
void fn_8004EF9C(int* color);
void fn_8004F080(void);
void fn_8004F2B0(void);
void fn_8004F380(f32 scale, int* color, f32* position);
void fn_8004F6D8(f32 scale, int* color, f32* position);
void fn_8004FA30(f32 scale, int* color, f32* position);
void fn_8004FDA0(u8* texture, void* texMtx);
void fn_80051528(void* texture, void* texMtx);
void gxTextureFn_80050e28(u8 mode);
int textureFn_80050ad8(void* texture, int stageCount, u8 mode, u32 indirectTextureId);
void textureFn_80051348(void* textureRef, u8 objectFlags);
void fn_800510F0(void* textureRef, u8 hasBaseTexture, u8 mode);
void fn_80050FF4(u8 mode);
void fn_8005011C(int objectInstance);
void fn_80050558(u8* texture, void* texMtx, int stageMode, int componentMode, int variant);
void fn_80050A28(int scale);
void textureFn_8004c330(void* texture, void* texMtx);
void gxTextureFn_8004d5b4(void* renderOp);

#define fn_8004EECCColorLegacy(color) \
    (((void (*)(u8*))fn_8004EECC)((color)))
#define fn_8004F380Legacy(color, position) \
    (((void (*)(u8*, int*))fn_8004F380)((color), (position)))
#define fn_8004F6D8Legacy(color, position, chanColor) \
    (((void (*)(u8*, int*, u8*))fn_8004F6D8)((color), (position), (chanColor)))
#define fn_8004FA30FloatPosLegacy(color, position) \
    (((void (*)(u8*, f32*))fn_8004FA30)((color), (position)))
#define fn_8004FA30IntPosLegacy(color, position) \
    (((void (*)(u8*, int*))fn_8004FA30)((color), (position)))
#define fn_8004FDA0ColorLegacy(texture, texMtx, color) \
    (((void (*)(int*, void*, u8*))fn_8004FDA0)((texture), (texMtx), (color)))
#define gxTextureFn_80050e28IntLegacy(mode) \
    (((void (*)(int))gxTextureFn_80050e28)((mode)))
#define textureFn_80050ad8ByteLegacy(texture, stageCount, mode, indirectTextureId) \
    (((u8 (*)(void*, int, int, u32))textureFn_80050ad8)( \
        (texture), (stageCount), (mode), (indirectTextureId)))
#define textureFn_80051348IntLegacy(textureRef, objectFlags) \
    (((void (*)(u32, int))textureFn_80051348)((textureRef), (objectFlags)))
#define fn_800510F0IntLegacy(textureRef, hasBaseTexture, mode) \
    (((void (*)(u32, int, int))fn_800510F0)((textureRef), (hasBaseTexture), (mode)))
#define fn_80050FF4IntLegacy(mode) \
    (((void (*)(int))fn_80050FF4)((mode)))
#define fn_8005011CMatrixLegacy(matrix) \
    (((void (*)(f32*))fn_8005011C)((matrix)))
#define fn_80050558IntLegacy(texture, texMtx, stageMode, componentMode, variant) \
    (((void (*)(u32, int, int, int, int))fn_80050558)( \
        (texture), (texMtx), (stageMode), (componentMode), (variant)))

#endif /* MAIN_PI_DOLPHIN_API_H_ */
