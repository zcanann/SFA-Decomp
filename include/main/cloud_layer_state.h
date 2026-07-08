#ifndef MAIN_CLOUD_LAYER_STATE_H_
#define MAIN_CLOUD_LAYER_STATE_H_

#include "global.h"
#include "main/game_object.h"

extern f32 lbl_803DD1E0;
extern f32 lbl_803DD1E4;
extern f32 lbl_803DD1E8;
extern u8 cloudOverridePosition;
extern GameObject *lbl_803DD1F0;

#define gCloudOverridePositionZ lbl_803DD1E0
#define gCloudOverridePositionY lbl_803DD1E4
#define gCloudOverridePositionX lbl_803DD1E8
#define gCloudOverridePositionValid cloudOverridePosition
#define gCloudOverrideObject lbl_803DD1F0

#endif
