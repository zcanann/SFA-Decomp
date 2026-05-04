#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/CF/laser.h"
#include "main/textblock.h"

int laser_getExtraSizeUnsupported(void)
{
  return 0;
}

int laser_func08(void)
{
  return 0;
}

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset

void laser_releaseUnsupported(void)
{
}

void laser_initialiseUnsupported(void)
{
}
