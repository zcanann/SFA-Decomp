/*
 * DR_CloudPer (DLL 640) - a cloud-perimeter trigger plane.
 *
 * init derives a vertical clip plane (normal + distance) from the
 * placement yaw byte and the object's position, joins the trigger and
 * surface object groups, and enables this cloud's map anim event if it
 * is the currently selected active cloud. DR_CloudPer_activate arms the cloud (when
 * its placement game bit is set) by recording it as the active cloud and
 * running the enable sequence; selectActiveCloud switches the active
 * cloud and runs the select sequence.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "dlls/object_descriptor.h"

#include "main/dll/DR/dll_0280_drcloudper.h"
#include "main/objtype.h"


#define DRCLOUDPER_GROUP_TRIGGER        0x13
#define DRCLOUDPER_GROUP_SURFACE        0x39
#define DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT 0x7a9
#define DRCLOUDPER_MAP_ANIM_EVENT       0x0c

int DR_CloudPer_activate(GameObject* obj)
{
    GameObject* cloud = obj;
    DrCloudPerSetup* setup = (DrCloudPerSetup*)cloud->anim.placementData;
    if (mainGetBit(setup->gameBit) == 0)
    {
        return 0;
    }
    mainSetBits(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT, setup->cloudIndex);
    (*gMapEventInterface)->setObjGroupStatus(cloud->anim.mapEventSlot, DRCLOUDPER_MAP_ANIM_EVENT, 1);
    (*gObjectTriggerInterface)->runSequence(2, obj, -1);
    return 1;
}

int DR_CloudPer_selectActiveCloud(GameObject* obj)
{
    GameObject* cloud = obj;
    DrCloudPerSetup* setup = (DrCloudPerSetup*)cloud->anim.placementData;

    mainSetBits(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT, setup->cloudIndex);
    (*gObjectTriggerInterface)->runSequence(1, obj, -1);
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

void DR_CloudPer_free(GameObject* obj)
{
    objFreeObjectType(obj, DRCLOUDPER_GROUP_TRIGGER);
    objFreeObjectType(obj, DRCLOUDPER_GROUP_SURFACE);
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

void DR_CloudPer_init(GameObject* cloud, DrCloudPerSetup* setup)
{
    DrCloudPerSetup* setupData;
    DrCloudPerState* state;

    objAddObjectType(cloud, DRCLOUDPER_GROUP_TRIGGER);
    objAddObjectType(cloud, DRCLOUDPER_GROUP_SURFACE);
    setupData = setup;
    {
        int yawTmp = setupData->yawByte << 8;
        cloud->anim.rotX = yawTmp;
    }
    state = cloud->extra;
    state->normalX = mathSinf(3.1415927f * cloud->anim.rotX / 32768.0f);
    state->normalY = 0.0f;
    state->normalZ = mathCosf(3.1415927f * cloud->anim.rotX / 32768.0f);
    state->planeDistance =
        -(state->normalZ * cloud->anim.localPosZ +
          (state->normalX * cloud->anim.localPosX + state->normalY * cloud->anim.localPosY));
    cloud->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED | OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_UPDATE_DISABLED;
    if (setupData->cloudIndex == mainGetBit(DRCLOUDPER_ACTIVE_CLOUD_GAMEBIT))
    {
        (*gMapEventInterface)->setObjGroupStatus(cloud->anim.mapEventSlot, DRCLOUDPER_MAP_ANIM_EVENT, 1);
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
    (ObjectDescriptorCallback)DR_CloudPer_activate,
    (ObjectDescriptorCallback)DR_CloudPer_selectActiveCloud,
};
