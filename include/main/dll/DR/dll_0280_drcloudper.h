#ifndef MAIN_DLL_DR_DLL_0280_DRCLOUDPER_H_
#define MAIN_DLL_DR_DLL_0280_DRCLOUDPER_H_

#include "global.h"

typedef struct DrCloudPerState
{
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 planeDistance;
} DrCloudPerState;

typedef struct DrCloudPerObject
{
    s16 yaw;
    u8 pad02[0x0c - 0x02];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad18[0x4c - 0x18];
    void* setup;
    u8 pad50[0xac - 0x50];
    s8 mapDir;
    u8 padAD[0xb0 - 0xad];
    u16 flagsB0;
    u8 padB2[0xb8 - 0xb2];
    DrCloudPerState* state;
} DrCloudPerObject;

typedef struct DrCloudPerSetup
{
    u8 pad00[0x18];
    s8 yawByte;
    s8 cloudIndex;
    u8 pad1A[0x1e - 0x1a];
    s16 gameBit;
} DrCloudPerSetup;

STATIC_ASSERT(offsetof(DrCloudPerObject, posX) == 0x0c);
STATIC_ASSERT(offsetof(DrCloudPerObject, setup) == 0x4c);
STATIC_ASSERT(offsetof(DrCloudPerObject, mapDir) == 0xac);
STATIC_ASSERT(offsetof(DrCloudPerObject, flagsB0) == 0xb0);
STATIC_ASSERT(offsetof(DrCloudPerObject, state) == 0xb8);


int DR_CloudPer_setScale(int obj);
int DR_CloudPer_selectActiveCloud(int obj);
int DR_CloudPer_getExtraSize(void);
int DR_CloudPer_getObjectTypeId(void);
void DR_CloudPer_free(int obj);
void DR_CloudPer_render(void);
void DR_CloudPer_hitDetect(void);
void DR_CloudPer_update(void);
void DR_CloudPer_init(int obj, int setup);
void DR_CloudPer_release(void);
void DR_CloudPer_initialise(void);

#endif /* MAIN_DLL_DR_DLL_0280_DRCLOUDPER_H_ */
