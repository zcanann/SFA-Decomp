#include "ghidra_import.h"
#include "main/dll/anim_internal.h"
#include "main/expr.h"

extern undefined4 FUN_8003b818();

/*
 * --INFO--
 *
 * Function: dbegg_update
 * EN v1.0 Address: 0x801FEB30
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801FF044
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dbegg_update(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  AnimBehaviorObject *obj;
  AnimBehaviorState *runtimeState;
  char cVar1;
  
  obj = (AnimBehaviorObject *)param_1;
  runtimeState = obj->runtimeState;
  if ((((visible != 0) && (cVar1 = runtimeState->state, cVar1 != '\f')) &&
      (cVar1 != '\x04')) && (cVar1 != '\v')) {
    FUN_8003b818(param_1);
  }
  return;
}
