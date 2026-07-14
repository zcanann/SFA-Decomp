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
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/obj_group.h"
#include "main/objseq.h"
#include "main/object_descriptor.h"

#include "main/dll/DR/dll_0280_drcloudper.h"

__declspec(section ".sdata2") f32 lbl_803E6BF0 = 3.1415927f;
__declspec(section ".sdata2") f32 lbl_803E6BF4 = 32768.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E6BF8 = 0.0f;
__declspec(section ".sdata2") f32 lbl_803E6BFC = 0.0f;
#pragma explicit_zero_data off

#define DRCLOUDPER_GROUP_TRIGGER        0x13
#define DRCLOUDPER_GROUP_SURFACE        0x39
#define DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT 0x7a9
#define DRCLOUDPER_MAP_ANIM_EVENT       0x0c
#define DRCLOUDPER_OBJECT_FLAGS         0xe000

int DR_CloudPer_setScale(int obj)
{
    DrCloudPerObject* cloud = (DrCloudPerObject*)obj;
    DrCloudPerSetup* setup = (DrCloudPerSetup*)cloud->setup;
    if ((u32)mainGetBit(setup->gameBit) == 0)
    {
        return 0;
    }
    mainSetBits(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT, setup->cloudIndex);
    (*gMapEventInterface)->setObjGroupStatus(cloud->mapDir, DRCLOUDPER_MAP_ANIM_EVENT, 1);
    (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
    return 1;
}

int DR_CloudPer_selectActiveCloud(int obj)
{
    DrCloudPerObject* cloud = (DrCloudPerObject*)obj;
    DrCloudPerSetup* setup = (DrCloudPerSetup*)cloud->setup;

    mainSetBits(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT, setup->cloudIndex);
    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
    return 0;
}

int DR_CloudPer_getExtraSize(void)
{
    return 0x10;
}

int DR_CloudPer_getObjectTypeId(void)
{
    return 0;
}

void DR_CloudPer_free(int obj)
{
    ObjGroup_RemoveObject(obj, DRCLOUDPER_GROUP_TRIGGER);
    ObjGroup_RemoveObject(obj, DRCLOUDPER_GROUP_SURFACE);
}

void DR_CloudPer_render(void)
{
}

void DR_CloudPer_hitDetect(void)
{
}

void DR_CloudPer_update(void)
{
}

void DR_CloudPer_init(int obj, int setup)
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
        cloud->yaw = yawTmp;
    }
    state = cloud->state;
    state->normalX = mathSinf(lbl_803E6BF0 * cloud->yaw / lbl_803E6BF4);
    state->normalY = lbl_803E6BF8;
    state->normalZ = mathCosf(lbl_803E6BF0 * cloud->yaw / lbl_803E6BF4);
    state->planeDistance =
        -(state->normalZ * cloud->posZ + (state->normalX * cloud->posX + state->normalY * cloud->posY));
    cloud->flagsB0 |= DRCLOUDPER_OBJECT_FLAGS;
    if (setupData->cloudIndex == mainGetBit(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT))
    {
        (*gMapEventInterface)->setObjGroupStatus(cloud->mapDir, DRCLOUDPER_MAP_ANIM_EVENT, 1);
    }
}

void DR_CloudPer_release(void)
{
}

void DR_CloudPer_initialise(void)
{
}

ObjectDescriptor12 gDrCloudPerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)DR_CloudPer_initialise,
    (ObjectDescriptorCallback)DR_CloudPer_release,
    0,
    (ObjectDescriptorCallback)DR_CloudPer_init,
    (ObjectDescriptorCallback)DR_CloudPer_update,
    (ObjectDescriptorCallback)DR_CloudPer_hitDetect,
    (ObjectDescriptorCallback)DR_CloudPer_render,
    (ObjectDescriptorCallback)DR_CloudPer_free,
    (ObjectDescriptorCallback)DR_CloudPer_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)DR_CloudPer_getExtraSize,
    (ObjectDescriptorCallback)DR_CloudPer_setScale,
    (ObjectDescriptorCallback)DR_CloudPer_selectActiveCloud,
};
