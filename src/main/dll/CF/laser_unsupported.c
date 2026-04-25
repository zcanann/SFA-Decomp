#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/CF/laser.h"

extern char sTextBlockInitNoLongerSupported[];
extern char sLaserInitNoLongerSupported[];

int laser_getExtraSizeUnsupported(void)
{
  return 0;
}

int laser_func08(void)
{
  return 0;
}

#pragma scheduling off
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

void laser_initUnsupported(void)
{
  OSReport(sLaserInitNoLongerSupported);
  return;
}
#pragma scheduling reset

void laser_releaseUnsupported(void)
{
}

void laser_initialiseUnsupported(void)
{
}
