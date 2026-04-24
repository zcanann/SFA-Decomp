#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/CF/laser.h"

extern char sTextBlockInitNoLongerSupported[];

/*
 * --INFO--
 *
 * Function: laser_freeUnsupported
 * EN v1.0 Address: 0x80208FEC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80209624
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_freeUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

/*
 * --INFO--
 *
 * Function: laser_renderUnsupported
 * EN v1.0 Address: 0x80209018
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80209650
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_renderUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

/*
 * --INFO--
 *
 * Function: laser_updateUnsupported
 * EN v1.0 Address: 0x80209048
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80209680
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_updateUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}
