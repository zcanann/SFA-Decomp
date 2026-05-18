#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/VF/platform1.h"
#include "main/object_descriptor.h"

int platform1_getExtraSize(void)
{
  return 0;
}

int platform1_func08(void)
{
  return 0;
}

void platform1_free(void)
{
}

#pragma scheduling off
#pragma peephole off
void platform1_renderUnsupported(void)
{
  OSReport(sPlatform1DrawNoLongerSupported);
  return;
}

void platform1_hitDetect(void)
{
}

void platform1_updateUnsupported(void)
{
  OSReport(sPlatform1ControlNoLongerSupported);
  return;
}

void platform1_initUnsupported(void)
{
  OSReport(sPlatform1InitNoLongerSupported);
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
    platform1_initUnsupported,
    platform1_updateUnsupported,
    platform1_hitDetect,
    platform1_renderUnsupported,
    platform1_free,
    (ObjectDescriptorCallback)platform1_func08,
    platform1_getExtraSize,
};

char sPlatform1DrawNoLongerSupported[] = "<platform1 draw>No Longer supported \n";
static u8 sPlatform1StringPad0[] = { 0, 0 };
char sPlatform1ControlNoLongerSupported[] = "<platform1 control>No Longer supported \n";
static u8 sPlatform1StringPad1[] = { 0, 0, 0 };
char sPlatform1InitNoLongerSupported[] = "<platform1 Init>No Longer supported \n";
static u8 sPlatform1StringPad2[] = { 0, 0, 0, 0, 0, 0 };
