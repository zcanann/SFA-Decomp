#include "ghidra_import.h"
#include "main/dll/dll_B0.h"

extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_80100d2c
 * EN v1.0 Address: 0x80100D2C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80100d2c(void)
{
  return *(undefined *)(gCamcontrolState + 0x138);
}
