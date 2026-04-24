#include "ghidra_import.h"
#include "main/dll/dll_B0.h"

extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_80100c90
 * EN v1.0 Address: 0x80100C90
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80100D2C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80100c90(void)
{
  return *(undefined *)(gCamcontrolState + 0x138);
}
