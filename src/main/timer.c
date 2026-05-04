#include "ghidra_import.h"
#include "main/dll/anim_internal.h"
#include "main/timer.h"

extern undefined4 FUN_80017a98();
extern int ObjHits_GetPriorityHit();
extern int FUN_800620e8();

extern f32 lbl_803E6EB4;

/*
 * --INFO--
 *
 * Function: FUN_801feb30
 * EN v1.0 Address: 0x801FEB30
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x801FF094
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801feb30(int *param_1)
{
  AnimBehaviorObject *obj;
  AnimBehaviorState *runtimeState;
  float fVar1;
  int iVar2;
  
  obj = (AnimBehaviorObject *)param_1;
  runtimeState = obj->runtimeState;
  iVar2 = ObjHits_GetPriorityHit((int)param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if ((iVar2 == 0x12) && (runtimeState->state != 4)) {
    FUN_80017a98();
  }
  if (runtimeState->state != 9) {
    iVar2 = FUN_800620e8(param_1 + 0x20,param_1 + 3,(float *)0x1,(int *)0x0,param_1,8,0xffffffff,
                         0xff,0);
    fVar1 = lbl_803E6EB4;
    if (iVar2 != 0) {
      param_1[9] = (int)-(lbl_803E6EB4 * (float)param_1[9] - (float)param_1[9]);
      param_1[0xb] = (int)-(fVar1 * (float)param_1[0xb] - (float)param_1[0xb]);
    }
  }
  param_1[0x20] = param_1[3];
  param_1[0x21] = param_1[4];
  param_1[0x22] = param_1[5];
  return;
}
