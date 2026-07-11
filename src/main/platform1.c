#include "dolphin/os.h"
#include "main/dll/VF/platform1.h"

int platform1_getExtraSize(void)
{
    return 0;
}

int platform1_getObjectTypeId(void)
{
    return 0;
}

void platform1_free(void)
{
}

void platform1_drawUnsupported(void)
{
    OSReport(sPlatform1DrawNoLongerSupported);
    return;
}

void platform1_hitDetect(void)
{
}

void platform1_controlUnsupported(void)
{
    OSReport(sPlatform1ControlNoLongerSupported);
    return;
}

void platform1_init(void)
{
    OSReport(sPlatform1InitNoLongerSupported);
    return;
}

void platform1_release(void)
{
}

void platform1_initialise(void)
{
}

ObjectDescriptor gPlatform1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    platform1_initialise,
    platform1_release,
    0,
    platform1_init,
    platform1_controlUnsupported,
    platform1_hitDetect,
    platform1_drawUnsupported,
    platform1_free,
    (ObjectDescriptorCallback)platform1_getObjectTypeId,
    platform1_getExtraSize,
};

char sPlatform1DrawNoLongerSupported[] = "<platform1 draw>No Longer supported \n";
char sPlatform1ControlNoLongerSupported[] = "<platform1 control>No Longer supported \n";
/* Explicit length 44 (string data is 38 bytes; NUL-fill supplies the 6-byte
 * retail pad gap_07_80329DCA_data) so .data ends 8-aligned at +0xB8 as in
 * retail. The 2-/3-byte gaps after the first two strings are ordinary 4-byte
 * object alignment and need no explicit padding. */
char sPlatform1InitNoLongerSupported[] = "<platform1 Init>No Longer supported \n";
