#ifndef MAIN_DLL_DR_DLL_0280_DRCLOUDPER_H_
#define MAIN_DLL_DR_DLL_0280_DRCLOUDPER_H_

#include "global.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

typedef struct DrCloudPerState
{
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 planeDistance;
} DrCloudPerState;

typedef struct DrCloudPerSetup
{
    ObjPlacement head;
    s8 yawByte;
    s8 cloudIndex;
    u8 pad1A[0x1e - 0x1a];
    s16 gameBit;
} DrCloudPerSetup;

int DR_CloudPer_activate(GameObject* obj);
int DR_CloudPer_selectActiveCloud(GameObject* obj);
int DR_CloudPer_getExtraSize(void);
int DR_CloudPer_getObjectTypeId(void);
void DR_CloudPer_free(GameObject* obj);
void DR_CloudPer_render(void);
void DR_CloudPer_hitDetect(void);
void DR_CloudPer_update(void);
void DR_CloudPer_init(GameObject* cloud, DrCloudPerSetup* setup);
void DR_CloudPer_release(void);
void DR_CloudPer_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0280_DRCLOUDPER_H_ */
