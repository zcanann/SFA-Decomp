#include "ghidra_import.h"
#include "main/dll/dll_1DF.h"

extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();

/*
 * --INFO--
 *
 * Function: enemymushroom_update
 * EN v1.0 Address: 0x801D1E24
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801D23AC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void enemymushroom_update(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (visible != 0) {
    FUN_8003b818(param_1);
    ObjPath_GetPointWorldPosition(param_1,0,(float *)(iVar1 + 0x20),(undefined4 *)(iVar1 + 0x24),
                 (float *)(iVar1 + 0x28),0);
  }
  return;
}
