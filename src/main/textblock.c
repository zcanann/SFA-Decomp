#include "ghidra_import.h"
#include "dolphin/os.h"

extern char sTextBlockNoLongerSupported[];

int textblockObj_getExtraSize(void)
{
  return 0;
}

int textblockObj_func08(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: textblockObj_freeUnsupported
 * EN v1.0 Address: 0x80209820
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void textblockObj_freeUnsupported(void)
{
  OSReport(sTextBlockNoLongerSupported);
  return;
}

void textblockObj_render(void)
{
}

void textblockObj_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: textblockObj_updateUnsupported
 * EN v1.0 Address: 0x80209854
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void textblockObj_updateUnsupported(void)
{
  OSReport(sTextBlockNoLongerSupported);
  return;
}

/*
 * --INFO--
 *
 * Function: textblockObj_initUnsupported
 * EN v1.0 Address: 0x80209880
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void textblockObj_initUnsupported(void)
{
  OSReport(sTextBlockNoLongerSupported);
  return;
}
#pragma scheduling reset

void textblockObj_release(void)
{
}

void textblockObj_initialise(void)
{
}
