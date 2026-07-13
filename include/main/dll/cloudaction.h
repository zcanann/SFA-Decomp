#ifndef MAIN_DLL_CLOUDACTION_H_
#define MAIN_DLL_CLOUDACTION_H_

#include "global.h"

typedef struct CloudEnvTbl
{
    s32 mainCloudAssetIds[5];
    s32 upperCloudAssetIds[4];
    s32 lowerCloudAssetIds[5];
} CloudEnvTbl;

STATIC_ASSERT(sizeof(CloudEnvTbl) == 0x38);

extern CloudEnvTbl gCloudActionEnvTbl;
extern volatile f32 gCloudActionGlareQuadSize;
extern s32 lbl_803DB618[2];
extern const f32 lbl_803DF2B4;
extern const f32 lbl_803DF2C0;
extern const f32 lbl_803DF2C4;
extern const f32 lbl_803DF2C8;
extern const f32 lbl_803DF2CC;
extern const f32 lbl_803DF2D0;
extern const f32 lbl_803DF2D4;
extern const f32 lbl_803DF2D8;
extern const f32 lbl_803DF2DC;

void cloudaction_func08_nop(void);
void cloudaction_func09_nop(void);
void cloudaction_free(void);
void cloudaction_func05(void);
void cloudaction_onMapSetup(void);
void cloudaction_update(int p1, int p2, u8* state, int p4, int val);
void cloudaction_release(void);
void cloudaction_initialise(void);
void renderClouds(int a, int b, int c, int d);

#endif /* MAIN_DLL_CLOUDACTION_H_ */
