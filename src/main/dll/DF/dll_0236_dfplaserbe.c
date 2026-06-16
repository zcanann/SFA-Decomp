/*
 * DragonRock Palace laser-beam object (DLL 0x236; "DFP_LaserBe") - a
 * legacy/disabled object: every callback (init/update/render/free) only
 * logs "No Longer supported" via OSReport.
 */
#include "dolphin/os.h"
#include "main/dll/CF/laser.h"
#include "main/textblock.h"

int laser_getExtraSize(void)
{
    return 0;
}

int laser_getObjectTypeId(void)
{
    return 0;
}

void laser_freeUnsupported(void)
{
    OSReport(sTextBlockInitNoLongerSupported);
    return;
}

void laser_renderUnsupported(void)
{
    OSReport(sTextBlockInitNoLongerSupported);
    return;
}

void laser_hitDetectUnsupported(void)
{
}

void laser_updateUnsupported(void)
{
    OSReport(sTextBlockInitNoLongerSupported);
    return;
}

void laser_init(void)
{
    OSReport(sLaserInitNoLongerSupported);
    return;
}

void laser_releaseUnsupported(void)
{
}

void laser_initialiseUnsupported(void)
{
}

ObjectDescriptor gLaserUnsupportedObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    laser_initialiseUnsupported,
    laser_releaseUnsupported,
    0,
    laser_init,
    laser_updateUnsupported,
    laser_hitDetectUnsupported,
    laser_renderUnsupported,
    laser_freeUnsupported,
    (ObjectDescriptorCallback)laser_getObjectTypeId,
    laser_getExtraSize,
};

char sTextBlockInitNoLongerSupported[] = "<textblock.c Init>No Longer supported \n";
char sLaserInitNoLongerSupported[] = "<laser.c Init>No Longer supported \n";
static u32 sLaserUnsupportedDataPad = 0;
