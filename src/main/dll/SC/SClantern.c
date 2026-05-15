#include "main/dll/SC/SClantern.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 Sfx_PlayAtPositionFromObject();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objGetAnimStateField35c_2();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286888();
extern undefined4 Obj_GetPlayerObject();

extern ObjAnimEventList gSClanternObjAnimEvents;
extern undefined4* lbl_803DCAAC;
extern f32 timeDelta;
extern f32 lbl_803E5498;

/*
 * --INFO--
 *
 * Function: SHthorntail_init
 * EN v1.0 Address: 0x801D6C04
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_init(f32 moveStepScale, int obj)
{
  undefined4 advanceResult;
  u8 *event;
  int pointIndex;
  int i;
  float local_28;
  float local_24;
  float local_20;
  pointIndex = 0;
  gSClanternObjAnimEvents.triggerCount = 0;
  gSClanternObjAnimEvents.rootCurveValid = 0;
  advanceResult = ObjAnim_AdvanceCurrentMove(moveStepScale,timeDelta,obj,&gSClanternObjAnimEvents);
  if (gSClanternObjAnimEvents.rootCurveValid != 0) {
    *(short *)obj = *(short *)obj + gSClanternObjAnimEvents.rootPitch;
  }
  event = gSClanternObjAnimEvents.triggeredIds;
  for (i = 0; i < gSClanternObjAnimEvents.triggerCount; i++) {
    switch(*event) {
    case 1:
    case 3:
      pointIndex = 1;
      break;
    case 2:
    case 4:
      pointIndex = 2;
      break;
    case 9:
      Sfx_PlayFromObject(obj,0x2f4);
    }
    event++;
  }
  if ((pointIndex != 0) &&
      (ObjPath_GetPointWorldPosition(obj,pointIndex - 1,&local_28,&local_24,&local_20,0),
       ((*(short *)(obj + 0xa0) != 0x1b || (lbl_803E5498 <= *(float *)(obj + 0x98)))))) {
    Sfx_PlayAtPositionFromObject((double)local_28,(double)local_24,(double)local_20,obj,0x415);
  }
  FUN_80286888(advanceResult);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: playerFn_801d6d58
 * EN v1.0 Address: 0x801D6D58
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 playerFn_801d6d58(void)
{
  undefined4 playerObj;

  (*(code *)(*lbl_803DCAAC + 0x74))();
  playerObj = Obj_GetPlayerObject();
  objGetAnimStateField35c_2(playerObj,0xff);
  return 2;
}
#pragma peephole reset
#pragma scheduling reset
