#ifndef MAIN_DLL_CLOUDACTION_H_
#define MAIN_DLL_CLOUDACTION_H_

#include "global.h"
#include "main/dll/cloudaction_interface.h"

typedef struct CloudEnvTbl {
    s32 mainCloudAssetIds[5];
    s32 upperCloudAssetIds[4];
    s32 lowerCloudAssetIds[5];
} CloudEnvTbl;

STATIC_ASSERT(sizeof(CloudEnvTbl) == 0x38);

extern CloudEnvTbl gCloudActionEnvTbl;
extern f32 gCloudActionGlareQuadSize[2];
extern s32 lbl_803DB618[2];

void cloudaction_func08_nop(void);
void cloudaction_func09_nop(void);
void cloudaction_func10_nop(void);
void cloudaction_func11_nop(void);
void cloudaction_func12_nop(void);
void cloudaction_free(void);
void cloudaction_scrollTexture(void);
void cloudaction_onMapSetup(void);
void cloudaction_update(int p1, int p2, u8* state, int p4, int val);
void cloudaction_release(void);
void cloudaction_initialise(void);
void renderClouds(int a, int b, int c, int d);
void* cloudGetLayerTexture(f32* outOffsetS, f32* outOffsetT);

#endif /* MAIN_DLL_CLOUDACTION_H_ */
