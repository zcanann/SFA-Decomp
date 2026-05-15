#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/VF/platform1.h"

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

u32 gPlatform1ObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)platform1_initialise,
    (u32)platform1_release,
    0,
    (u32)platform1_initUnsupported,
    (u32)platform1_updateUnsupported,
    (u32)platform1_hitDetect,
    (u32)platform1_renderUnsupported,
    (u32)platform1_free,
    (u32)platform1_func08,
    (u32)platform1_getExtraSize,
};

char sPlatform1DrawNoLongerSupported[] = "<platform1 draw>No Longer supported \n";
static u8 sPlatform1StringPad0[] = { 0, 0 };
char sPlatform1ControlNoLongerSupported[] = "<platform1 control>No Longer supported \n";
static u8 sPlatform1StringPad1[] = { 0, 0, 0 };
char sPlatform1InitNoLongerSupported[] = "<platform1 Init>No Longer supported \n";
static u8 sPlatform1StringPad2[] = { 0, 0, 0, 0, 0, 0 };
