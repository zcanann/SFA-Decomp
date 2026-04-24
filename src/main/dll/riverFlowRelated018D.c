#include "ghidra_import.h"
#include "main/dll/riverFlowRelated018D.h"

extern undefined4 FUN_8001f448();
extern undefined4 FUN_8003709c();

extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de810;

/*
 * --INFO--
 *
 * Function: FUN_801bee40
 * EN v1.0 Address: 0x801BEC70
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801BEE40
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bee40(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_8003709c(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,1);
  if (DAT_803de810 != 0) {
    FUN_8001f448(DAT_803de810);
  }
  return;
}
