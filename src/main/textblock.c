#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/textblock.h"

extern char sTextBlockInitNoLongerSupported[];

/*
 * --INFO--
 *
 * Function: textblock_initUnsupported
 * EN v1.0 Address: 0x8020930C
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80209624
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void textblock_initUnsupported(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

/*
 * --INFO--
 *
 * Function: textblock_initUnsupported_01
 * EN v1.0 Address: 0x80209338
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80209650
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void textblock_initUnsupported_01(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}

/*
 * --INFO--
 *
 * Function: textblock_initUnsupported_02
 * EN v1.0 Address: 0x80209364
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80209680
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void textblock_initUnsupported_02(void)
{
  OSReport(sTextBlockInitNoLongerSupported);
  return;
}
