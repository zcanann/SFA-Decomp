#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"

/*
 * --INFO--
 *
 * Function: DBbonedust_getState
 * EN v1.0 Address: 0x801E1588
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x801E18CC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int DBbonedust_getState(int param_1)
{
  return (int)*(char *)(*(int *)(param_1 + 0xb8) + 0x70);
}
