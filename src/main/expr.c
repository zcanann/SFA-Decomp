#include "ghidra_import.h"
#include "main/dll/anim_internal.h"
#include "main/expr.h"

extern undefined4 FUN_8003b818();

/*
 * --INFO--
 *
 * Function: FUN_801feb30
 * EN v1.0 Address: 0x801FEB30
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801FF044
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801feb30(int param_1)
{
  AnimBehaviorObject *obj;
  AnimBehaviorState *runtimeState;
  char cVar1;
  char in_r8;
  
  obj = (AnimBehaviorObject *)param_1;
  runtimeState = obj->runtimeState;
  if ((((in_r8 != '\0') && (cVar1 = runtimeState->state, cVar1 != '\f')) &&
      (cVar1 != '\x04')) && (cVar1 != '\v')) {
    FUN_8003b818(param_1);
  }
  return;
}
