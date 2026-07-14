#ifndef MAIN_CLOUD_ACTION_RUNTIME_H_
#define MAIN_CLOUD_ACTION_RUNTIME_H_

#include "global.h"
#include "main/game_object.h"

typedef struct CloudActionRuntime {
    GameObject *mainCloudObj;
    GameObject *upperCloudObj;
    GameObject *lowerCloudObj;
    s32 mainCloudAssetId;
    s32 upperCloudAssetId;
    s32 lowerCloudAssetId;
    u8 textureScrollStep;
    u8 pad19;
    u8 layerRenderEnabled;
    u8 pad1B;
    u32 pad1C;
} CloudActionRuntime;

STATIC_ASSERT(sizeof(CloudActionRuntime) == 0x20);
STATIC_ASSERT(offsetof(CloudActionRuntime, mainCloudAssetId) == 0x0C);
STATIC_ASSERT(offsetof(CloudActionRuntime, textureScrollStep) == 0x18);
STATIC_ASSERT(offsetof(CloudActionRuntime, pad1C) == 0x1C);

extern CloudActionRuntime lbl_8039AB28;

#endif
