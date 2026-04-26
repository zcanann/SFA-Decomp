#include "ghidra_import.h"
#include "main/dll/dll_147.h"

extern undefined8 ObjGroup_RemoveObject();

/*
 * --INFO--
 *
 * Function: FUN_8017adb4
 * EN v1.0 Address: 0x8017ADB4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017B2D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017adb4(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x53);
  return;
}
