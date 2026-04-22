#include "ghidra_import.h"
#include "main/dll/dll_4B.h"

extern undefined4* DAT_803dd720;

/*
 * --INFO--
 *
 * Function: FUN_8011c150
 * EN v1.0 Address: 0x8011C150
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011c150(void)
{
  (**(code **)(*DAT_803dd720 + 8))();
  return;
}
