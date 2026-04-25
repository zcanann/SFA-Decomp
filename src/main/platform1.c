#include "ghidra_import.h"
#include "dolphin/os.h"

extern char sPlatform1DrawNoLongerSupported[];
extern char sPlatform1ControlNoLongerSupported[];
extern char sPlatform1InitNoLongerSupported[];

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
#pragma scheduling reset

void platform1_release(void)
{
}

void platform1_initialise(void)
{
}
