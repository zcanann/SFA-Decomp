#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"

/*
 * --INFO--
 *
 * Function: FUN_801e18cc
 * EN v1.0 Address: 0x801E18CC
 * EN v1.0 Size: 16b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801e18cc(int param_1)
{
  return (int)*(char *)(*(int *)(param_1 + 0xb8) + 0x70);
}
