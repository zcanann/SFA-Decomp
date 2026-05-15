#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/textblock.h"

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
#pragma peephole off
void textblockObj_freeUnsupported(void)
{
  OSReport(sTextBlockObjInitNoLongerSupported);
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
  OSReport(sTextBlockObjInitNoLongerSupported);
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
  OSReport(sTextBlockObjInitNoLongerSupported);
  return;
}
#pragma peephole reset
#pragma scheduling reset

void textblockObj_release(void)
{
}

void textblockObj_initialise(void)
{
}

u32 gTextBlockObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)textblockObj_initialise,
    (u32)textblockObj_release,
    0,
    (u32)textblockObj_initUnsupported,
    (u32)textblockObj_updateUnsupported,
    (u32)textblockObj_hitDetect,
    (u32)textblockObj_render,
    (u32)textblockObj_freeUnsupported,
    (u32)textblockObj_func08,
    (u32)textblockObj_getExtraSize,
};

char sTextBlockObjInitNoLongerSupported[] = "<textblock.c Init>No Longer supported \n";
