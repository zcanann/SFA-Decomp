#include "ghidra_import.h"
#include "main/dll/dll_BA.h"

extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_80101980
 * EN v1.0 Address: 0x80101980
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80101C10
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80101980(undefined param_1)
{
  *(undefined *)(gCamcontrolState + 0x139) = param_1;
  return;
}
