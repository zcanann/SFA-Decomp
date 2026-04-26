#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern int fn_8000BB18();
extern int GameBit_Get();
extern undefined4 GameBit_Set();
extern int fn_800221A0(int min,int max);
extern int fn_80038024();
extern int fn_801D4CD0(SHthorntailObject *obj);

extern undefined4* lbl_803DCAAC;
extern f64 lbl_803E5428;

/*
 * --INFO--
 *
 * Function: SHthorntail_updateRootControlMode2
 * EN v1.0 Address: 0x801D56C4
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x801D5CB4
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void SHthorntail_updateRootControlMode2(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int eventIsSet;
  int randomTime;

  runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
  case SHTHORNTAIL_LOCOMOTION_1:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_2:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_3:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_4:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_5:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_6:
    eventIsSet = fn_801D4CD0(obj);
    if (eventIsSet != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
      return;
    }
    if (runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
      fn_8000BB18(0,0x409);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer = (float)randomTime;
    }
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_7:
    if (runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE2_EVENT) {
      GameBit_Get(0x1a0);
      eventIsSet = GameBit_Get();
      if (eventIsSet == 0) {
        return;
      }
      (**(code **)(*lbl_803DCAAC + 0x50))((int)obj->animObjId,3,0);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer = (float)randomTime;
    }
    else {
      eventIsSet = GameBit_Get(0x1a0);
      if ((eventIsSet == 0) && (eventIsSet = fn_80038024((int)obj), eventIsSet != 0)) {
        runtime->behaviorFlags = runtime->behaviorFlags | 4;
        runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE2_EVENT;
        (**(code **)(*lbl_803DCAAC + 0x50))((int)obj->animObjId,3,1);
        GameBit_Set(0x199,1);
        return;
      }
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable = gSHthorntailRootControlMode2Locomotion8ImpactSfxTable + 6;
  }
  SHthorntail_updateState(obj,runtime);
}
#pragma scheduling reset
