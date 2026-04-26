#include "ghidra_import.h"
#include "main/dll/DB/DBwaterflow.h"

extern uint FUN_80017690();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 FUN_8003b818();

extern undefined4* DAT_803dd6d4;

/*
 * --INFO--
 *
 * Function: FUN_801dfa28
 * EN v1.0 Address: 0x801DFA28
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DFE50
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfa28(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dfa50
 * EN v1.0 Address: 0x801DFA50
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x801DFE84
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfa50(undefined2 *param_1)
{
  uint uVar1;
  
  *param_1 = 0x2000;
  uVar1 = FUN_80017690(0x75);
  if (uVar1 == 0) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dfab4
 * EN v1.0 Address: 0x801DFAB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DFEE4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfab4(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801dfab8
 * EN v1.0 Address: 0x801DFAB8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DFF38
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfab8(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dfae0
 * EN v1.0 Address: 0x801DFAE0
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801DFF70
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfae0(int param_1)
{
  ObjMsg_AllocQueue(param_1,2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801dfb04
 * EN v1.0 Address: 0x801DFB04
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DFFC0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801dfb04(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}
