#include "ghidra_import.h"
#include "main/dll/DB/DBwaterflow.h"

extern uint FUN_80020078();
extern undefined4 FUN_80037a5c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_801dfa9c();

extern undefined4* DAT_803dd6d4;

/*
 * --INFO--
 *
 * Function: FUN_801dfe50
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801DFE50
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfe50(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dfe84
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801DFE84
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfe84(undefined2 *param_1)
{
  uint uVar1;
  
  *param_1 = 0x2000;
  uVar1 = FUN_80020078(0x75);
  if (uVar1 == 0) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dfee4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801DFEE4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfee4(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dff38
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801DFF38
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dff38(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dff70
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801DFF70
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dff70(int param_1)
{
  FUN_80037a5c(param_1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dffc0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801DFFC0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dffc0(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}
