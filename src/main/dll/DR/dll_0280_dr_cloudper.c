#include "main/dll/dll_80220608_shared.h"
#include "main/mapEventTypes.h"

typedef struct DrCloudPerState {
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    f32 planeDistance;
} DrCloudPerState;

typedef struct DrCloudPerObject {
    s16 yaw;
    u8 pad02[0x0c - 0x02];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad18[0x4c - 0x18];
    void *setup;
    u8 pad50[0xac - 0x50];
    s8 mapDir;
    u8 padAD[0xb0 - 0xad];
    u16 flagsB0;
    u8 padB2[0xb8 - 0xb2];
    DrCloudPerState *state;
} DrCloudPerObject;

typedef struct DrCloudPerSetup {
    u8 pad00[0x18];
    s8 yawByte;
    s8 cloudIndex;
    u8 pad1A[0x1e - 0x1a];
    s16 gameBit;
} DrCloudPerSetup;

#pragma peephole on
#pragma scheduling on
int drcloudper_getExtraSize(void) { return 0x10; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drcloudper_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drcloudper_free(int obj)
{
    ObjGroup_RemoveObject(obj, 0x13);
    ObjGroup_RemoveObject(obj, 0x39);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_update(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drcloudper_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int drcloudper_setScale(int obj)
{
    DrCloudPerObject *cloud = (DrCloudPerObject *)obj;
    DrCloudPerSetup *setup = (DrCloudPerSetup *)cloud->setup;
    if ((u32)GameBit_Get(setup->gameBit) == 0) {
        return 0;
    }
    GameBit_Set(0x7a9, setup->cloudIndex);
    ((MapEventInterface *)*gMapEventInterface)->setAnimEvent(cloud->mapDir, 0xc, 1);
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(2, obj, -1);
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int drcloudper_selectActiveCloud(int obj)
{
    DrCloudPerObject *cloud = (DrCloudPerObject *)obj;
    DrCloudPerSetup *setup = (DrCloudPerSetup *)cloud->setup;

    GameBit_Set(0x7a9, setup->cloudIndex);
    (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drcloudper_init(int obj, int setup)
{
    DrCloudPerObject *cloud;
    DrCloudPerSetup *setupData;
    DrCloudPerState *state;

    ObjGroup_AddObject(obj, 0x13);
    ObjGroup_AddObject(obj, 0x39);
    cloud = (DrCloudPerObject *)obj;
    setupData = (DrCloudPerSetup *)setup;
    cloud->yaw = (s16)(setupData->yawByte << 8);
    state = cloud->state;
    state->normalX = fn_80293E80(lbl_803E6BF0 * (f32)cloud->yaw / lbl_803E6BF4);
    state->normalY = lbl_803E6BF8;
    state->normalZ = sin(lbl_803E6BF0 * (f32)cloud->yaw / lbl_803E6BF4);
    state->planeDistance =
        -(state->normalZ * cloud->posZ) +
        (state->normalX * cloud->posX + state->normalY * cloud->posY);
    cloud->flagsB0 |= 0xe000;
    if (setupData->cloudIndex == GameBit_Get(0x7a9)) {
        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(cloud->mapDir, 0xc, 1);
    }
}
#pragma scheduling reset
#pragma peephole reset
