#ifndef MAIN_CLOUD_LAYER_STATE_H_
#define MAIN_CLOUD_LAYER_STATE_H_

#include "global.h"
#include "main/game_object.h"

extern f32 gCloudOverridePositionZ;
extern f32 gCloudOverridePositionY;
extern f32 gCloudOverridePositionX;
extern u8 gCloudOverridePositionValid;
extern GameObject *lbl_803DD1F0[2];

#define gCloudOverrideObject lbl_803DD1F0[0]

#endif
