#ifndef MAIN_PI_DOLPHIN_API_H_
#define MAIN_PI_DOLPHIN_API_H_

#include "types.h"
#include "main/pi_frame_api.h"

double SeekTwiceBeforeRead(void);
int GXFlush_(u8 visible, int unused);
int loadAndDecompressDataFile();
int mapGetDirIdx(int idx);
u32 mapLoadDataFile(int mapId, int fileId);
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

#endif /* MAIN_PI_DOLPHIN_API_H_ */
