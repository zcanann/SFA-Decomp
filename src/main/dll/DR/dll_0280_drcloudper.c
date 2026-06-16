/*
 * drcloudper (DLL 0x280) - a cloud-perimeter trigger plane.
 *
 * init derives a vertical clip plane (normal + distance) from the
 * placement yaw byte and the object's position, joins the trigger and
 * surface object groups, and enables this cloud's map anim event if it
 * is the currently selected active cloud. setScale arms the cloud (when
 * its placement game bit is set) by recording it as the active cloud and
 * running the enable sequence; selectActiveCloud switches the active
 * cloud and runs the select sequence.
 */
#include "main/dll/dll_80220608_shared.h"

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

#define DRCLOUDPER_GROUP_TRIGGER 0x13
#define DRCLOUDPER_GROUP_SURFACE 0x39
#define DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT 0x7a9
#define DRCLOUDPER_MAP_ANIM_EVENT 0x0c
#define DRCLOUDPER_OBJECT_FLAGS 0xe000

int drcloudper_getExtraSize(void) { return 0x10; }

int drcloudper_getObjectTypeId(void) { return 0; }

void drcloudper_free(int obj)
{
    ObjGroup_RemoveObject(obj, DRCLOUDPER_GROUP_TRIGGER);
    ObjGroup_RemoveObject(obj, DRCLOUDPER_GROUP_SURFACE);
}

void drcloudper_render(void)
{
}

void drcloudper_hitDetect(void)
{
}

void drcloudper_update(void)
{
}

void drcloudper_release(void)
{
}

void drcloudper_initialise(void)
{
}

int drcloudper_setScale(int obj)
{
    DrCloudPerObject* cloud = (DrCloudPerObject*)obj;
    DrCloudPerSetup* setup = (DrCloudPerSetup*)cloud->setup;
    if ((u32)GameBit_Get(setup->gameBit) == 0)
    {
        return 0;
    }
    GameBit_Set(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT, setup->cloudIndex);
    (*gMapEventInterface)->setObjGroupStatus(cloud->mapDir, DRCLOUDPER_MAP_ANIM_EVENT, 1);
    (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
    return 1;
}

int drcloudper_selectActiveCloud(int obj)
{
    DrCloudPerObject* cloud = (DrCloudPerObject*)obj;
    DrCloudPerSetup* setup = (DrCloudPerSetup*)cloud->setup;

    GameBit_Set(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT, setup->cloudIndex);
    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
    return 0;
}

void drcloudper_init(int obj, int setup)
{
    DrCloudPerObject* cloud;
    DrCloudPerSetup* setupData;
    DrCloudPerState* state;

    ObjGroup_AddObject(obj, DRCLOUDPER_GROUP_TRIGGER);
    ObjGroup_AddObject(obj, DRCLOUDPER_GROUP_SURFACE);
    cloud = (DrCloudPerObject*)obj;
    setupData = (DrCloudPerSetup*)setup;
    {
        int yawTmp = setupData->yawByte << 8;
        cloud->yaw = (s16)yawTmp;
    }
    state = cloud->state;
    state->normalX = mathSinf(lbl_803E6BF0 * (f32)cloud->yaw / lbl_803E6BF4);
    state->normalY = lbl_803E6BF8;
    state->normalZ = mathCosf(lbl_803E6BF0 * (f32)cloud->yaw / lbl_803E6BF4);
    state->planeDistance =
        -(state->normalZ * cloud->posZ +
          (state->normalX * cloud->posX + state->normalY * cloud->posY));
    cloud->flagsB0 |= DRCLOUDPER_OBJECT_FLAGS;
    if (setupData->cloudIndex == GameBit_Get(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT))
    {
        (*gMapEventInterface)->setObjGroupStatus(cloud->mapDir, DRCLOUDPER_MAP_ANIM_EVENT, 1);
    }
}
