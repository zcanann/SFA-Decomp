#ifndef MAIN_CLOUD_LAYER_STATE_H_
#define MAIN_CLOUD_LAYER_STATE_H_

#include "global.h"
#include "game/objects/object.h"

extern f32 gCloudOverridePositionZ;
extern f32 gCloudOverridePositionY;
extern f32 gCloudOverridePositionX;
extern u8 gCloudOverridePositionValid;
extern GameObject *gCloudOverrideObjectStorage[2];

#define gCloudOverrideObject gCloudOverrideObjectStorage[0]

#endif
