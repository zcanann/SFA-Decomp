#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern int fn_8000BB18();
extern int fn_8001FFB4();
extern undefined4 fn_800200E8();
extern undefined4 fn_800221A0();
extern int fn_80038024();
extern int fn_801D4CD0();

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
void SHthorntail_updateRootControlMode2(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int eventIsSet;
  uint randomTime;

  runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case 6:
    eventIsSet = fn_801D4CD0();
    if (eventIsSet != 0) {
      runtime->behaviorState = 0xe;
      return;
    }
    if (runtime->behaviorState == 0xe) {
      fn_8000BB18(0,0x409);
      runtime->behaviorState = 0;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer =
          (float)((double)CONCAT44(0x43300000,randomTime ^ 0x80000000) - lbl_803E5428);
    }
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case 7:
    if (runtime->behaviorState == 0xf) {
      fn_8001FFB4(0x1a0);
      eventIsSet = fn_8001FFB4();
      if (eventIsSet == 0) {
        return;
      }
      (**(code **)(*lbl_803DCAAC + 0x50))((int)obj->animObjId,3,0);
      runtime->behaviorState = 0;
      randomTime = fn_800221A0(1000,2000);
      runtime->idleTimer =
          (float)((double)CONCAT44(0x43300000,randomTime ^ 0x80000000) - lbl_803E5428);
    }
    else {
      eventIsSet = fn_8001FFB4(0x1a0);
      if ((eventIsSet == 0) && (eventIsSet = fn_80038024((int)obj), eventIsSet != 0)) {
        runtime->behaviorFlags = runtime->behaviorFlags | 4;
        runtime->behaviorState = 0xf;
        (**(code **)(*lbl_803DCAAC + 0x50))((int)obj->animObjId,3,1);
        fn_800200E8(0x199,1);
        return;
      }
    }
    break;
  case 8:
    runtime->impactSfxTable = gSHthorntailRootControlMode2Locomotion8ImpactSfxTable + 6;
  }
  SHthorntail_updateState(obj,runtime);
}
